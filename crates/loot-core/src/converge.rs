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
/// being applied; `base` is the merge-base tree (the nearest common ancestor's
/// full tree) when the caller's history knows one — see [`merge_pair`] for how
/// it prevents spurious conflicts. Returns one outcome per touched path. Pure:
/// the only repo access is through `oracle`.
pub fn classify(
    local: &Tree,
    incoming: &Tree,
    base: Option<&Tree>,
    oracle: &dyn KeyOracle,
    now: u64,
) -> BTreeMap<PathBuf, MergeOutcome> {
    let mut outcomes: BTreeMap<PathBuf, MergeOutcome> = BTreeMap::new();
    for (path, (their_oid, _vis)) in incoming {
        // The same per-path rule `merge_trees` builds on — here we keep only the
        // label and discard the tree action.
        let base_oid = base.and_then(|b| b.get(path)).map(|(o, _)| o);
        let outcome = reconcile_path(local.get(path), their_oid, base_oid, oracle, now).outcome();
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
    /// A path one side deleted since the fork, the other side left untouched
    /// from the base — the deletion wins over the stale copy (standard 3-way).
    /// The merged tree omits the path; reported as `Converged` (no human needed).
    DeleteWins,
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
            MergeDecision::Converged
            | MergeDecision::AdoptTheirs
            | MergeDecision::DeleteWins => MergeOutcome::Converged,
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
    base_oid: Option<&Oid>,
    oracle: &dyn KeyOracle,
    now: u64,
) -> MergeDecision {
    match ours {
        // A path `theirs` holds that `ours` lacks. With no base entry it is a
        // genuine add — adopt it. When the base *does* hold it, `ours` deleted
        // it since the fork (#295): a full manifest's absence is a deletion, so
        // apply the standard 3-way deletion-vs-base rule rather than blindly
        // re-adopting the stale copy.
        None => match base_oid {
            None => MergeDecision::AdoptTheirs,
            Some(base) => match same_content(their_oid, base, oracle, now) {
                // Theirs is the base untouched — our deletion wins.
                Some(true) => MergeDecision::DeleteWins,
                // Theirs edited it since the fork — delete/edit conflict. There
                // is no `ours` oid (we deleted it), so the base content stands
                // in for the deleted side in the recorded conflict.
                Some(false) => MergeDecision::Conflict {
                    ours: base.clone(),
                    theirs: their_oid.clone(),
                },
                // Can't open a side — cannot tell untouched from edited, so keep
                // the content conservatively (never delete or conflict blind).
                None => MergeDecision::AdoptTheirs,
            },
        },
        Some((our_oid, _)) if our_oid == their_oid => MergeDecision::Converged,
        Some((our_oid, _)) => merge_pair(our_oid, their_oid, base_oid, oracle, now),
    }
}

/// Are two content addresses the same content? Address equality first (the
/// #98 unchanged-path fast path), then plaintext equality via the oracle —
/// a re-seal mints a fresh address for identical bytes (#65). `None` when a
/// side cannot be opened: the caller cannot decide untouched-vs-edited and
/// must fall back to conservative behavior.
fn same_content(a: &Oid, b: &Oid, oracle: &dyn KeyOracle, now: u64) -> Option<bool> {
    if a == b {
        return Some(true);
    }
    match (oracle.open(a, now), oracle.open(b, now)) {
        (Some(x), Some(y)) => Some(x == y),
        _ => None,
    }
}

/// Decide a concurrent same-path edit where the two sides differ. Opening both
/// is the merger role; failing to open either is the relay role.
///
/// `base_oid` is the path's content at the merge base, when the caller's
/// history knows one. Every change carries a *full* tree and re-seals mint
/// fresh addresses, so address inequality does NOT mean both sides edited —
/// a pulled chain re-raises paths its author never touched (#65, pilot
/// finding 6). A side whose bytes equal the base is untouched since the
/// fork: the other side simply wins, and only genuinely double-edited
/// content proceeds to the line-set heuristic.
fn merge_pair(
    ours: &Oid,
    theirs: &Oid,
    base_oid: Option<&Oid>,
    oracle: &dyn KeyOracle,
    now: u64,
) -> MergeDecision {
    match (oracle.open(ours, now), oracle.open(theirs, now)) {
        (Some(a), Some(b)) => {
            if let Some(base) = base_oid.and_then(|o| oracle.open(o, now)) {
                if base == b && base != a {
                    // Theirs is untouched since the base — ours is the only edit.
                    return MergeDecision::Merged { winner: ours.clone() };
                }
                if base == a && base != b {
                    // Ours is untouched since the base — adopt their edit.
                    return MergeDecision::Merged { winner: theirs.clone() };
                }
            }
            line_set_merge(ours, theirs, &a, &b)
        }
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
///   - a sealed path we cannot open (`RelayedUnmerged`) -> keep ours untouched;
///   - a **since-fork deletion** judged against the `base` (#295): when one
///     side deleted a path (a full manifest's absence is a deletion) and the
///     other left it untouched from the base, the deletion wins and the path
///     is dropped from the tree; when the other side *edited* it since the
///     fork, that is a delete/edit conflict, recorded like any other. Without a
///     base, or when a side can't be opened, the pre-#295 keep/adopt stands.
///
/// The theirs-only walk cannot see a path *`ours` still holds but `theirs`
/// deleted*, so a symmetric second pass covers that direction. `ours` is the
/// base; `theirs` is the line being merged in.
pub struct Merge {
    /// The tree the merge change carries.
    pub tree: Tree,
    /// Paths needing human resolution: `path -> (ours, theirs)` addresses.
    pub conflicts: BTreeMap<PathBuf, (Oid, Oid)>,
    /// Per-path outcome, for reporting (same labels as [`classify`]).
    pub outcomes: BTreeMap<PathBuf, MergeOutcome>,
}

pub fn merge_trees(
    ours: &Tree,
    theirs: &Tree,
    base: Option<&Tree>,
    oracle: &dyn KeyOracle,
    now: u64,
) -> Merge {
    let mut tree = ours.clone();
    let mut conflicts: BTreeMap<PathBuf, (Oid, Oid)> = BTreeMap::new();
    let mut outcomes: BTreeMap<PathBuf, MergeOutcome> = BTreeMap::new();
    for (path, their_entry) in theirs {
        // `tree` starts as ours, so "keep ours" cases need no write — only the
        // adopt/conflict actions touch the tree.
        let base_oid = base.and_then(|b| b.get(path)).map(|(o, _)| o);
        let decision = reconcile_path(ours.get(path), &their_entry.0, base_oid, oracle, now);
        match &decision {
            MergeDecision::Converged | MergeDecision::Relayed => {} // keep ours untouched
            MergeDecision::DeleteWins => {
                // Ours deleted a path theirs left untouched from the base — the
                // deletion wins. Ours already lacks it, so the path is absent
                // from `tree`; keep it that way (don't re-adopt theirs).
            }
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
                // Keep ours in the tree (a deletion stays deleted); theirs
                // survives via the merge's 2nd parent, for `loot resolve`.
                conflicts.insert(path.clone(), (o.clone(), t.clone()));
            }
        }
        outcomes.insert(path.clone(), decision.outcome());
    }

    // Symmetric pass for paths `ours` still holds but `theirs` deleted since the
    // fork (#295) — the theirs-only walk above cannot see them. Only paths the
    // base holds are deletions here; a path base lacks is a genuine ours-only
    // add and stays. Address equality first, then the oracle (a re-seal mints a
    // fresh address, #65/#98); an unopenable side keeps ours conservatively.
    if let Some(base) = base {
        for (path, (our_oid, _vis)) in ours {
            if theirs.contains_key(path) {
                continue; // already reconciled in the theirs walk
            }
            let Some((base_oid, _)) = base.get(path) else {
                continue; // base lacks it -> a genuine ours-only add, keep it
            };
            match same_content(our_oid, base_oid, oracle, now) {
                // Ours is the base untouched -> theirs' deletion wins.
                Some(true) => {
                    tree.remove(path);
                    outcomes.insert(path.clone(), MergeOutcome::Converged);
                }
                // Ours edited it since the fork -> delete/edit conflict. There is
                // no `theirs` oid (they deleted it), so the base content stands
                // in for the deleted side. Keep ours' edit in the tree; theirs'
                // deletion is the merge's 2nd parent.
                Some(false) => {
                    conflicts.insert(path.clone(), (our_oid.clone(), base_oid.clone()));
                    outcomes.insert(
                        path.clone(),
                        MergeOutcome::Conflict { ours: our_oid.clone(), theirs: base_oid.clone() },
                    );
                }
                // Can't open a side — keep ours conservatively, no verdict.
                None => {}
            }
        }
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
        let out = classify(&local, &inc, None, &FakeOracle(BTreeMap::new()), 0);
        assert_eq!(out[&PathBuf::from("a.txt")], MergeOutcome::Converged);
    }

    #[test]
    fn identical_address_converges() {
        let mut local = BTreeMap::new();
        local.insert(PathBuf::from("a.txt"), (oid(1), Visibility::Public));
        let inc = tree(&[("a.txt", oid(1))]);
        let out = classify(&local, &inc, None, &FakeOracle(BTreeMap::new()), 0);
        assert_eq!(out[&PathBuf::from("a.txt")], MergeOutcome::Converged);
    }

    #[test]
    fn concurrent_without_key_relays() {
        let mut local = BTreeMap::new();
        local.insert(PathBuf::from("a.txt"), (oid(1), Visibility::Public));
        let inc = tree(&[("a.txt", oid(2))]);
        // Oracle opens neither -> relay.
        let out = classify(&local, &inc, None, &FakeOracle(BTreeMap::new()), 0);
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
        let out = classify(&local, &inc, None, &FakeOracle(plain), 0);
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
        let out = classify(&local, &inc, None, &FakeOracle(plain), 0);
        assert_eq!(
            out[&PathBuf::from("a.txt")],
            MergeOutcome::Conflict { ours: oid(1), theirs: oid(2) }
        );
    }

    // --- base-aware downgrade (#65): untouched-since-fork must not conflict ---

    #[test]
    fn theirs_untouched_since_base_keeps_ours_not_conflict() {
        // Pilot finding 6: our line edited the path, theirs still carries the
        // base bytes under a fresh re-seal address. Two-way this line-conflicts
        // (modified line = no subset); with the base it is ours-wins Merged.
        let mut local = BTreeMap::new();
        local.insert(PathBuf::from("ctx.md"), (oid(1), Visibility::Public));
        let inc = tree(&[("ctx.md", oid(2))]);
        let base = tree(&[("ctx.md", oid(3))]);
        let mut plain = BTreeMap::new();
        plain.insert(oid(1), b"alpha\nbeta EDITED\n".to_vec()); // our edit
        plain.insert(oid(2), b"alpha\nbeta\n".to_vec()); // their re-seal of base
        plain.insert(oid(3), b"alpha\nbeta\n".to_vec()); // the base
        let out = classify(&local, &inc, Some(&base), &FakeOracle(plain.clone()), 0);
        assert_eq!(out[&PathBuf::from("ctx.md")], MergeOutcome::Merged);

        // And merge_trees keeps ours in the assembled tree.
        let ours = tree(&[("ctx.md", oid(1))]);
        let m = merge_trees(&ours, &inc, Some(&base), &FakeOracle(plain), 0);
        assert_eq!(m.tree[&p("ctx.md")].0, oid(1), "our edit wins");
        assert!(m.conflicts.is_empty());
    }

    #[test]
    fn ours_untouched_since_base_adopts_theirs() {
        let mut local = BTreeMap::new();
        local.insert(PathBuf::from("ctx.md"), (oid(1), Visibility::Public));
        let inc = tree(&[("ctx.md", oid(2))]);
        let base = tree(&[("ctx.md", oid(3))]);
        let mut plain = BTreeMap::new();
        plain.insert(oid(1), b"alpha\nbeta\n".to_vec()); // ours == base
        plain.insert(oid(2), b"alpha\nbeta EDITED\n".to_vec()); // their edit
        plain.insert(oid(3), b"alpha\nbeta\n".to_vec());
        let ours = tree(&[("ctx.md", oid(1))]);
        let m = merge_trees(&ours, &inc, Some(&base), &FakeOracle(plain), 0);
        assert_eq!(m.tree[&p("ctx.md")].0, oid(2), "their edit adopted");
        assert_eq!(m.outcomes[&p("ctx.md")], MergeOutcome::Merged);
    }

    #[test]
    fn both_edited_since_base_still_conflicts() {
        // The base only rescues an untouched side — a genuine double edit is
        // still a conflict for a human.
        let mut local = BTreeMap::new();
        local.insert(PathBuf::from("ctx.md"), (oid(1), Visibility::Public));
        let inc = tree(&[("ctx.md", oid(2))]);
        let base = tree(&[("ctx.md", oid(3))]);
        let mut plain = BTreeMap::new();
        plain.insert(oid(1), b"left\n".to_vec());
        plain.insert(oid(2), b"right\n".to_vec());
        plain.insert(oid(3), b"original\n".to_vec());
        let out = classify(&local, &inc, Some(&base), &FakeOracle(plain), 0);
        assert_eq!(
            out[&PathBuf::from("ctx.md")],
            MergeOutcome::Conflict { ours: oid(1), theirs: oid(2) }
        );
    }

    #[test]
    fn unopenable_base_falls_back_to_two_way() {
        // The base path exists but we can't open it (sealed to us) — behave
        // exactly as if no base were known.
        let mut local = BTreeMap::new();
        local.insert(PathBuf::from("ctx.md"), (oid(1), Visibility::Public));
        let inc = tree(&[("ctx.md", oid(2))]);
        let base = tree(&[("ctx.md", oid(9))]); // oid(9) not in the oracle
        let mut plain = BTreeMap::new();
        plain.insert(oid(1), b"left\n".to_vec());
        plain.insert(oid(2), b"right\n".to_vec());
        let out = classify(&local, &inc, Some(&base), &FakeOracle(plain), 0);
        assert_eq!(
            out[&PathBuf::from("ctx.md")],
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
        let m = merge_trees(&ours, &theirs, None, &FakeOracle(BTreeMap::new()), 0);
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
        let m = merge_trees(&ours, &theirs, None, &FakeOracle(plain), 0);
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
        let m = merge_trees(&ours, &theirs, None, &FakeOracle(plain), 0);
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
        let m = merge_trees(&ours, &theirs, None, &FakeOracle(plain), 0);
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
        let m = merge_trees(&ours, &theirs, None, &FakeOracle(BTreeMap::new()), 0);
        assert_eq!(m.tree[&p("a.txt")].0, oid(1), "ours carried forward");
        assert_eq!(m.outcomes[&p("a.txt")], MergeOutcome::RelayedUnmerged);
        assert!(m.conflicts.is_empty(), "relay is not a conflict");
    }

    #[test]
    fn merge_identical_address_is_converged_noop() {
        let ours = tree(&[("a.txt", oid(1))]);
        let theirs = tree(&[("a.txt", oid(1))]);
        let m = merge_trees(&ours, &theirs, None, &FakeOracle(BTreeMap::new()), 0);
        assert_eq!(m.tree[&p("a.txt")].0, oid(1));
        assert_eq!(m.outcomes[&p("a.txt")], MergeOutcome::Converged);
    }

    // --- three-way deletion rule (#295): a since-fork deletion vs. the base ---

    #[test]
    fn delete_vs_untouched_ours_deleted_theirs_kept_deletion_wins() {
        // OURS deleted del.txt since the fork; THEIRS carries the base bytes
        // untouched (same address). The deletion must win — theirs must not
        // silently re-adopt it.
        let base = tree(&[("keep.txt", oid(1)), ("del.txt", oid(2))]);
        let ours = tree(&[("keep.txt", oid(1))]); // ours deleted del.txt
        let theirs = tree(&[("keep.txt", oid(1)), ("del.txt", oid(2))]); // untouched
        let m = merge_trees(&ours, &theirs, Some(&base), &FakeOracle(BTreeMap::new()), 0);
        assert!(!m.tree.contains_key(&p("del.txt")), "ours' deletion of an untouched path wins");
        assert!(m.conflicts.is_empty(), "a clean deletion is not a conflict");
        assert_eq!(m.outcomes[&p("del.txt")], MergeOutcome::Converged);
    }

    #[test]
    fn delete_vs_untouched_survives_a_reseal_address_via_the_oracle() {
        // THEIRS re-sealed the base bytes to a fresh address (#65/#98), so
        // address equality can't see "untouched" — the oracle's plaintext
        // equality must. Deletion still wins.
        let base = tree(&[("keep.txt", oid(1)), ("del.txt", oid(2))]);
        let ours = tree(&[("keep.txt", oid(1))]); // deleted del.txt
        let theirs = tree(&[("keep.txt", oid(1)), ("del.txt", oid(3))]); // reseal, addr differs
        let mut plain = BTreeMap::new();
        plain.insert(oid(2), b"content\n".to_vec()); // base bytes
        plain.insert(oid(3), b"content\n".to_vec()); // theirs = same bytes, fresh seal
        let m = merge_trees(&ours, &theirs, Some(&base), &FakeOracle(plain), 0);
        assert!(!m.tree.contains_key(&p("del.txt")), "reseal of untouched base still deletes");
        assert!(m.conflicts.is_empty());
    }

    #[test]
    fn delete_vs_untouched_theirs_deleted_ours_kept_deletion_wins() {
        // Mirror: THEIRS deleted del.txt; OURS carries the base bytes untouched.
        // The ours-only pass must drop it from the merged tree.
        let base = tree(&[("keep.txt", oid(1)), ("del.txt", oid(2))]);
        let ours = tree(&[("keep.txt", oid(1)), ("del.txt", oid(2))]); // untouched
        let theirs = tree(&[("keep.txt", oid(1))]); // theirs deleted del.txt
        let m = merge_trees(&ours, &theirs, Some(&base), &FakeOracle(BTreeMap::new()), 0);
        assert!(!m.tree.contains_key(&p("del.txt")), "theirs' deletion of an untouched path wins");
        assert!(m.conflicts.is_empty());
        assert_eq!(m.outcomes[&p("del.txt")], MergeOutcome::Converged);
    }

    #[test]
    fn delete_vs_modified_ours_deleted_theirs_edited_conflicts() {
        // OURS deleted del.txt; THEIRS edited it since the fork. A genuine
        // delete/edit conflict — surface it, never silently resurrect. The
        // deleted side is represented by the base content (there is no ours oid).
        let base = tree(&[("del.txt", oid(2))]);
        let ours = tree(&[("keep.txt", oid(1))]); // del.txt deleted
        let theirs = tree(&[("keep.txt", oid(1)), ("del.txt", oid(3))]); // edited
        let mut plain = BTreeMap::new();
        plain.insert(oid(2), b"orig\n".to_vec());
        plain.insert(oid(3), b"edited\n".to_vec());
        let m = merge_trees(&ours, &theirs, Some(&base), &FakeOracle(plain), 0);
        assert!(!m.tree.contains_key(&p("del.txt")), "ours' deletion kept in the tree; theirs via 2nd parent");
        assert_eq!(m.conflicts[&p("del.txt")], (oid(2), oid(3)), "base stands in for the deleted side");
        assert_eq!(
            m.outcomes[&p("del.txt")],
            MergeOutcome::Conflict { ours: oid(2), theirs: oid(3) }
        );
    }

    #[test]
    fn delete_vs_modified_theirs_deleted_ours_edited_conflicts() {
        // Mirror: THEIRS deleted del.txt; OURS edited it. Conflict; ours' edit
        // stays in the tree, theirs' deletion is the second parent.
        let base = tree(&[("del.txt", oid(2))]);
        let ours = tree(&[("keep.txt", oid(1)), ("del.txt", oid(4))]); // edited
        let theirs = tree(&[("keep.txt", oid(1))]); // del.txt deleted
        let mut plain = BTreeMap::new();
        plain.insert(oid(2), b"orig\n".to_vec());
        plain.insert(oid(4), b"edited\n".to_vec());
        let m = merge_trees(&ours, &theirs, Some(&base), &FakeOracle(plain), 0);
        assert_eq!(m.tree[&p("del.txt")].0, oid(4), "our edit kept in the tree");
        assert_eq!(m.conflicts[&p("del.txt")], (oid(4), oid(2)), "base stands in for the deleted side");
        assert_eq!(
            m.outcomes[&p("del.txt")],
            MergeOutcome::Conflict { ours: oid(4), theirs: oid(2) }
        );
    }

    #[test]
    fn delete_vs_delete_is_clean() {
        // Both sides deleted del.txt since the fork — no resurrection, no
        // conflict. (Neither loop visits the path; it stays absent.)
        let base = tree(&[("keep.txt", oid(1)), ("del.txt", oid(2))]);
        let ours = tree(&[("keep.txt", oid(1))]);
        let theirs = tree(&[("keep.txt", oid(1))]);
        let m = merge_trees(&ours, &theirs, Some(&base), &FakeOracle(BTreeMap::new()), 0);
        assert!(!m.tree.contains_key(&p("del.txt")), "delete-vs-delete stays deleted");
        assert!(m.conflicts.is_empty());
    }

    #[test]
    fn add_when_base_lacks_the_path_is_still_adopted() {
        // Base-present rules must not swallow a genuine add: base lacks new.txt,
        // theirs adds it → adopt (today's correct behavior, unchanged).
        let base = tree(&[("keep.txt", oid(1))]);
        let ours = tree(&[("keep.txt", oid(1))]);
        let theirs = tree(&[("keep.txt", oid(1)), ("new.txt", oid(5))]);
        let m = merge_trees(&ours, &theirs, Some(&base), &FakeOracle(BTreeMap::new()), 0);
        assert_eq!(m.tree[&p("new.txt")].0, oid(5), "a genuine add is adopted");
        assert!(m.conflicts.is_empty());
        assert_eq!(m.outcomes[&p("new.txt")], MergeOutcome::Converged);
    }

    #[test]
    fn delete_vs_unopenable_side_keeps_conservatively() {
        // OURS deleted del.txt, but neither the base nor theirs can be opened
        // (sealed to us) — we cannot judge untouched-vs-edited, so keep the
        // content conservatively rather than delete or conflict.
        let base = tree(&[("del.txt", oid(9))]); // oid(9) not in the oracle
        let ours = tree(&[("keep.txt", oid(1))]); // deleted del.txt
        let theirs = tree(&[("keep.txt", oid(1)), ("del.txt", oid(3))]); // oid(3) also sealed
        let m = merge_trees(&ours, &theirs, Some(&base), &FakeOracle(BTreeMap::new()), 0);
        assert_eq!(m.tree[&p("del.txt")].0, oid(3), "unopenable → conservative keep/adopt");
        assert!(m.conflicts.is_empty(), "an unopenable side never manufactures a conflict");
    }

    #[test]
    fn classify_reports_theirs_side_deletion_cases() {
        // classify shares the per-path rule: a path theirs kept but ours
        // deleted (theirs untouched) is Converged; if theirs edited it, Conflict.
        let base = tree(&[("del.txt", oid(2))]);
        let local = tree(&[("keep.txt", oid(1))]); // ours deleted del.txt

        // untouched theirs → deletion wins → Converged
        let inc_untouched = tree(&[("del.txt", oid(2))]);
        let out = classify(&local, &inc_untouched, Some(&base), &FakeOracle(BTreeMap::new()), 0);
        assert_eq!(out[&p("del.txt")], MergeOutcome::Converged);

        // edited theirs → delete/edit → Conflict
        let inc_edited = tree(&[("del.txt", oid(3))]);
        let mut plain = BTreeMap::new();
        plain.insert(oid(2), b"orig\n".to_vec());
        plain.insert(oid(3), b"edited\n".to_vec());
        let out = classify(&local, &inc_edited, Some(&base), &FakeOracle(plain), 0);
        assert_eq!(
            out[&p("del.txt")],
            MergeOutcome::Conflict { ours: oid(2), theirs: oid(3) }
        );
    }
}
