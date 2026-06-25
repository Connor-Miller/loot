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
        let outcome = match local.get(path) {
            None => MergeOutcome::Converged,
            Some((our_oid, _)) if our_oid == their_oid => MergeOutcome::Converged,
            Some((our_oid, _)) => merge_pair(our_oid, their_oid, oracle, now),
        };
        let slot = outcomes.entry(path.clone()).or_insert(MergeOutcome::Converged);
        *slot = worst(slot.clone(), outcome);
    }
    outcomes
}

/// Decide a single concurrent same-path edit. Opening both sides is the
/// merger role; failing to open either is the relay role.
fn merge_pair(ours: &Oid, theirs: &Oid, oracle: &dyn KeyOracle, now: u64) -> MergeOutcome {
    match (oracle.open(ours, now), oracle.open(theirs, now)) {
        (Some(a), Some(b)) => line_set_merge(ours, theirs, &a, &b),
        // Can't open at least one side -> relay, defer to a keyholder.
        _ => MergeOutcome::RelayedUnmerged,
    }
}

/// Spike merge of two plaintexts a keyholder can read. Without a stored common
/// base we approximate: identical converges as `Merged`; if one side's line set
/// subsumes the other it merges cleanly; otherwise it's a genuine `Conflict`.
/// Crude on purpose — the point is that merging *requires plaintext access*,
/// which is the thesis tension. A real 3-way merge is a later internal seam.
fn line_set_merge(ours: &Oid, theirs: &Oid, a: &[u8], b: &[u8]) -> MergeOutcome {
    if a == b {
        return MergeOutcome::Merged;
    }
    let al: std::collections::BTreeSet<&[u8]> = a.split(|&c| c == b'\n').collect();
    let bl: std::collections::BTreeSet<&[u8]> = b.split(|&c| c == b'\n').collect();
    if al.is_subset(&bl) || bl.is_subset(&al) {
        MergeOutcome::Merged
    } else {
        MergeOutcome::Conflict {
            ours: ours.clone(),
            theirs: theirs.clone(),
        }
    }
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
}
