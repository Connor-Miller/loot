//! Convergence classifier — the ADR 0001 merger/relay rule as a pure module.
//!
//! When an incoming [`Change`] meets the local tree, each touched path gets a
//! [`MergeOutcome`]. This module owns that decision and nothing else: it does
//! no storage, no disk, no crypto. It reaches the repo only through a narrow
//! [`KeyOracle`] seam — `open(oid, now) -> Option<plaintext>` — so it is fully
//! unit-testable with a fake oracle.
//!
//! The rule (ADR 0001), per path:
//!   - path absent locally, or same content address -> `Converged`
//!   - concurrent same-path edit, we can open both -> line-set merge
//!     (identical / subset -> `Merged`, otherwise -> `Conflict`)
//!   - concurrent same-path edit, we can't open it -> `RelayedUnmerged`
//!     (the relay role: defer the merge to a keyholder, never drop a side)

use crate::{MergeOutcome, Oid, Visibility};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// A path -> (content address, visibility) view. Both the local tree and an
/// incoming change's tree are this shape; the classifier works on the shape, so
/// it needn't know whether it came from a `Change`, a `ChangeNode`, or a test.
pub type Tree = BTreeMap<PathBuf, (Oid, Visibility)>;

/// The classifier's only window into the repo's content. `open` returns the
/// plaintext if this identity may read it *now*, else `None`. A `None` answer
/// is exactly the relay role: we hold ciphertext we can't merge.
pub trait KeyOracle {
    fn open(&self, oid: &Oid, now: u64) -> Option<Vec<u8>>;
}

/// Classify every path an incoming tree touches against the local tree.
///
/// `local` is the repo's current view; `incoming` is the tree of the change
/// being applied. Returns one outcome per touched path. Pure: the only repo
/// access is through `oracle`.
pub fn classify(
    local: &Tree,
    incoming: &Tree,
    oracle: &dyn KeyOracle,
    now: u64,
) -> BTreeMap<PathBuf, MergeOutcome> {
    let mut outcomes: BTreeMap<PathBuf, MergeOutcome> = BTreeMap::new();
    for (path, (their_oid, _vis)) in incoming {
        // The same per-path rule `merge_trees` builds on — here we keep only the
        // label and discard the tree action.
        let outcome = reconcile_path(local.get(path), their_oid, oracle, now).outcome();
        let slot = outcomes.entry(path.clone()).or_insert(MergeOutcome::Converged);
        *slot = worst(slot.clone(), outcome);
    }
    outcomes
}

/// One path's reconciliation under the ADR 0001 rule — the single decision both
/// [`classify`] (which only labels paths) and [`merge_trees`] (which also builds
/// the merged tree) act on, so the label and the tree action can never drift.
/// [`MergeDecision::outcome`] projects it to the public [`MergeOutcome`].
enum MergeDecision {
    /// Same content address on both sides — keep ours, nothing to do.
    Converged,
    /// A path only `theirs` has — adopt it wholesale. Reported as `Converged`:
    /// there is no divergence to resolve.
    AdoptTheirs,
    /// One side's line set subsumes the other; `winner` is that superset side's
    /// content address, which a tree-building merge adopts. Reported as `Merged`.
    Merged { winner: Oid },
    /// Genuinely divergent line sets — keep ours, record the conflict for human
    /// resolution (the `theirs` side is never dropped: it stays reachable through
    /// the merge change's second parent).
    Conflict { ours: Oid, theirs: Oid },
    /// At least one side is sealed to us — keep ours, defer to a keyholder (relay
    /// role).
    Relayed,
}

impl MergeDecision {
    /// Project down to the public per-path [`MergeOutcome`] label.
    fn outcome(&self) -> MergeOutcome {
        match self {
            MergeDecision::Converged | MergeDecision::AdoptTheirs => MergeOutcome::Converged,
            MergeDecision::Merged { .. } => MergeOutcome::Merged,
            MergeDecision::Conflict { ours, theirs } => MergeOutcome::Conflict {
                ours: ours.clone(),
                theirs: theirs.clone(),
            },
            MergeDecision::Relayed => MergeOutcome::RelayedUnmerged,
        }
    }
}

/// The ADR 0001 rule for one path: reconcile what `ours` holds (if anything)
/// against `their_oid`. The single source of truth both `classify` and
/// `merge_trees` consume.
fn reconcile_path(
    ours: Option<&(Oid, Visibility)>,
    their_oid: &Oid,
    oracle: &dyn KeyOracle,
    now: u64,
) -> MergeDecision {
    match ours {
        None => MergeDecision::AdoptTheirs,
        Some((our_oid, _)) if our_oid == their_oid => MergeDecision::Converged,
        Some((our_oid, _)) => merge_pair(our_oid, their_oid, oracle, now),
    }
}

/// Decide a concurrent same-path edit where the two sides differ. Opening both
/// is the merger role; failing to open either is the relay role.
fn merge_pair(ours: &Oid, theirs: &Oid, oracle: &dyn KeyOracle, now: u64) -> MergeDecision {
    match (oracle.open(ours, now), oracle.open(theirs, now)) {
        (Some(a), Some(b)) => line_set_merge(ours, theirs, &a, &b),
        // Can't open at least one side -> relay, defer to a keyholder.
        _ => MergeDecision::Relayed,
    }
}

/// Spike merge of two plaintexts a keyholder can read. Without a stored common
/// base we approximate: identical converges as a merge; if one side's line set
/// subsumes the other it merges cleanly toward the superset; otherwise it's a
/// genuine `Conflict`. Crude on purpose — the point is that merging *requires
/// plaintext access*, the thesis tension. A real 3-way merge is a later seam.
fn line_set_merge(ours: &Oid, theirs: &Oid, a: &[u8], b: &[u8]) -> MergeDecision {
    if a == b {
        // Identical content (distinct addresses only via nonce) — adopt theirs.
        return MergeDecision::Merged { winner: theirs.clone() };
    }
    let al: std::collections::BTreeSet<&[u8]> = a.split(|&c| c == b'\n').collect();
    let bl: std::collections::BTreeSet<&[u8]> = b.split(|&c| c == b'\n').collect();
    if al.is_subset(&bl) {
        MergeDecision::Merged { winner: theirs.clone() } // theirs is the superset
    } else if bl.is_subset(&al) {
        MergeDecision::Merged { winner: ours.clone() } // ours is the superset
    } else {
        MergeDecision::Conflict { ours: ours.clone(), theirs: theirs.clone() }
    }
}

/// The reconciliation of two lines into one, for a caller that must *build* the
/// merged change (unlike [`classify`], which only labels paths). Same ADR 0001
/// rule; this additionally assembles the tree the merge change should carry:
///
///   - a path only `theirs` has, or one that converges/merges cleanly -> adopt
///     theirs (or the superset side) — no divergence to resolve;
///   - a genuine `Conflict` -> keep *ours* in the tree and record it in
///     `conflicts` (the `theirs` side is never dropped: it stays reachable
///     through the merge change's second parent, for `loot resolve`);
///   - a sealed path we cannot open (`RelayedUnmerged`) -> keep ours untouched.
///
/// `ours` is the base; `theirs` is the line being merged in.
pub struct Merge {
    /// The tree the merge change carries.
    pub tree: Tree,
    /// Paths needing human resolution: `path -> (ours, theirs)` addresses.
    pub conflicts: BTreeMap<PathBuf, (Oid, Oid)>,
    /// Per-path outcome, for reporting (same labels as [`classify`]).
    pub outcomes: BTreeMap<PathBuf, MergeOutcome>,
}

pub fn merge_trees(ours: &Tree, theirs: &Tree, oracle: &dyn KeyOracle, now: u64) -> Merge {
    let mut tree = ours.clone();
    let mut conflicts: BTreeMap<PathBuf, (Oid, Oid)> = BTreeMap::new();
    let mut outcomes: BTreeMap<PathBuf, MergeOutcome> = BTreeMap::new();
    for (path, their_entry) in theirs {
        // `tree` starts as ours, so "keep ours" cases need no write — only the
        // adopt/conflict actions touch the tree.
        let decision = reconcile_path(ours.get(path), &their_entry.0, oracle, now);
        match &decision {
            MergeDecision::Converged | MergeDecision::Relayed => {} // keep ours untouched
            MergeDecision::AdoptTheirs => {
                tree.insert(path.clone(), their_entry.clone());
            }
            MergeDecision::Merged { winner } => {
                // Adopt only when theirs is the superset; ours is already in `tree`.
                if *winner == their_entry.0 {
                    tree.insert(path.clone(), their_entry.clone());
                }
            }
            MergeDecision::Conflict { ours: o, theirs: t } => {
                // Keep ours in the tree; theirs survives via the merge's 2nd parent.
                conflicts.insert(path.clone(), (o.clone(), t.clone()));
            }
        }
        outcomes.insert(path.clone(), decision.outcome());
    }
    Merge { tree, conflicts, outcomes }
}

/// Order outcomes by "how much human attention is needed" so a path touched by
/// several incoming changes keeps its worst result.
pub fn worst(a: MergeOutcome, b: MergeOutcome) -> MergeOutcome {
    fn rank(o: &MergeOutcome) -> u8 {
        match o {
            MergeOutcome::Converged => 0,
            MergeOutcome::Merged => 1,
            MergeOutcome::RelayedUnmerged => 2,
            MergeOutcome::Conflict { .. } => 3,
        }
    }
    if rank(&a) >= rank(&b) {
        a
    } else {
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fake oracle: a fixed map of oid -> plaintext for openable content;
    /// anything absent is treated as un-openable (relay).
    struct FakeOracle(BTreeMap<Oid, Vec<u8>>);
    impl KeyOracle for FakeOracle {
        fn open(&self, oid: &Oid, _now: u64) -> Option<Vec<u8>> {
            self.0.get(oid).cloned()
        }
    }

    fn oid(n: u8) -> Oid {
        Oid([n; 32])
    }
    fn tree(entries: &[(&str, Oid)]) -> Tree {
        entries
            .iter()
            .map(|(p, o)| (PathBuf::from(p), (o.clone(), Visibility::Public)))
            .collect()
    }

    #[test]
    fn absent_path_converges() {
        let local = BTreeMap::new();
        let inc = tree(&[("a.txt", oid(1))]);
        let out = classify(&local, &inc, &FakeOracle(BTreeMap::new()), 0);
        assert_eq!(out[&PathBuf::from("a.txt")], MergeOutcome::Converged);
    }

    #[test]
    fn identical_address_converges() {
        let mut local = BTreeMap::new();
        local.insert(PathBuf::from("a.txt"), (oid(1), Visibility::Public));
        let inc = tree(&[("a.txt", oid(1))]);
        let out = classify(&local, &inc, &FakeOracle(BTreeMap::new()), 0);
        assert_eq!(out[&PathBuf::from("a.txt")], MergeOutcome::Converged);
    }

    #[test]
    fn concurrent_without_key_relays() {
        let mut local = BTreeMap::new();
        local.insert(PathBuf::from("a.txt"), (oid(1), Visibility::Public));
        let inc = tree(&[("a.txt", oid(2))]);
        // Oracle opens neither -> relay.
        let out = classify(&local, &inc, &FakeOracle(BTreeMap::new()), 0);
        assert_eq!(out[&PathBuf::from("a.txt")], MergeOutcome::RelayedUnmerged);
    }

    #[test]
    fn concurrent_with_keys_subset_merges() {
        let mut local = BTreeMap::new();
        local.insert(PathBuf::from("a.txt"), (oid(1), Visibility::Public));
        let inc = tree(&[("a.txt", oid(2))]);
        let mut plain = BTreeMap::new();
        plain.insert(oid(1), b"x\n".to_vec());
        plain.insert(oid(2), b"x\ny\n".to_vec()); // superset
        let out = classify(&local, &inc, &FakeOracle(plain), 0);
        assert_eq!(out[&PathBuf::from("a.txt")], MergeOutcome::Merged);
    }

    #[test]
    fn concurrent_with_keys_divergent_conflicts() {
        let mut local = BTreeMap::new();
        local.insert(PathBuf::from("a.txt"), (oid(1), Visibility::Public));
        let inc = tree(&[("a.txt", oid(2))]);
        let mut plain = BTreeMap::new();
        plain.insert(oid(1), b"left\n".to_vec());
        plain.insert(oid(2), b"right\n".to_vec());
        let out = classify(&local, &inc, &FakeOracle(plain), 0);
        assert_eq!(
            out[&PathBuf::from("a.txt")],
            MergeOutcome::Conflict { ours: oid(1), theirs: oid(2) }
        );
    }

    // --- merge_trees (CA2): assembles the reconciled tree, not just labels ---

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn merge_disjoint_paths_takes_the_union() {
        // ours has a.txt, theirs adds b.txt — a clean disjoint merge.
        let ours = tree(&[("a.txt", oid(1))]);
        let theirs = tree(&[("b.txt", oid(2))]);
        let m = merge_trees(&ours, &theirs, &FakeOracle(BTreeMap::new()), 0);
        assert_eq!(m.tree[&p("a.txt")].0, oid(1), "ours kept");
        assert_eq!(m.tree[&p("b.txt")].0, oid(2), "theirs adopted");
        assert!(m.conflicts.is_empty());
        assert_eq!(m.outcomes[&p("b.txt")], MergeOutcome::Converged);
    }

    #[test]
    fn merge_clean_line_superset_adopts_theirs() {
        let ours = tree(&[("a.txt", oid(1))]);
        let theirs = tree(&[("a.txt", oid(2))]);
        let mut plain = BTreeMap::new();
        plain.insert(oid(1), b"x\n".to_vec());
        plain.insert(oid(2), b"x\ny\n".to_vec()); // theirs is the superset
        let m = merge_trees(&ours, &theirs, &FakeOracle(plain), 0);
        assert_eq!(m.tree[&p("a.txt")].0, oid(2), "superset (theirs) wins");
        assert_eq!(m.outcomes[&p("a.txt")], MergeOutcome::Merged);
        assert!(m.conflicts.is_empty());
    }

    #[test]
    fn merge_clean_line_superset_keeps_ours_when_ours_is_bigger() {
        let ours = tree(&[("a.txt", oid(1))]);
        let theirs = tree(&[("a.txt", oid(2))]);
        let mut plain = BTreeMap::new();
        plain.insert(oid(1), b"x\ny\n".to_vec()); // ours is the superset
        plain.insert(oid(2), b"x\n".to_vec());
        let m = merge_trees(&ours, &theirs, &FakeOracle(plain), 0);
        assert_eq!(m.tree[&p("a.txt")].0, oid(1), "superset (ours) wins");
        assert_eq!(m.outcomes[&p("a.txt")], MergeOutcome::Merged);
    }

    #[test]
    fn merge_conflict_keeps_ours_and_records_it() {
        let ours = tree(&[("a.txt", oid(1))]);
        let theirs = tree(&[("a.txt", oid(2))]);
        let mut plain = BTreeMap::new();
        plain.insert(oid(1), b"left\n".to_vec());
        plain.insert(oid(2), b"right\n".to_vec());
        let m = merge_trees(&ours, &theirs, &FakeOracle(plain), 0);
        // Ours stays in the tree; theirs is recorded for resolution, not dropped.
        assert_eq!(m.tree[&p("a.txt")].0, oid(1));
        assert_eq!(m.conflicts[&p("a.txt")], (oid(1), oid(2)));
        assert_eq!(
            m.outcomes[&p("a.txt")],
            MergeOutcome::Conflict { ours: oid(1), theirs: oid(2) }
        );
    }

    #[test]
    fn merge_sealed_path_relays_and_keeps_ours() {
        // We can't open either side (no keys) -> relay role, ours carried forward.
        let ours = tree(&[("a.txt", oid(1))]);
        let theirs = tree(&[("a.txt", oid(2))]);
        let m = merge_trees(&ours, &theirs, &FakeOracle(BTreeMap::new()), 0);
        assert_eq!(m.tree[&p("a.txt")].0, oid(1), "ours carried forward");
        assert_eq!(m.outcomes[&p("a.txt")], MergeOutcome::RelayedUnmerged);
        assert!(m.conflicts.is_empty(), "relay is not a conflict");
    }

    #[test]
    fn merge_identical_address_is_converged_noop() {
        let ours = tree(&[("a.txt", oid(1))]);
        let theirs = tree(&[("a.txt", oid(1))]);
        let m = merge_trees(&ours, &theirs, &FakeOracle(BTreeMap::new()), 0);
        assert_eq!(m.tree[&p("a.txt")].0, oid(1));
        assert_eq!(m.outcomes[&p("a.txt")], MergeOutcome::Converged);
    }
}
