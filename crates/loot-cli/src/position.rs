//! Position — one home for the place a [`Workspace`](crate::workspace::Workspace)
//! sits: the dock, the lane id (if any), and the pinned tip a tracked position
//! must always advance. This is ADR 0034's "position is place, not state" as a
//! module (#324).
//!
//! Before this module the rule was re-derived at every call site: `dock`,
//! `lane_id`, and `tip` were three loose `Workspace` fields, `current_dock`/
//! `dock_opt`/`tracks_tip`/`anchor` were predicates scattered through
//! `workspace.rs`, and ten separate sites hand-wrote `self.tip = ...` followed by
//! `store.write_tip(...)`. The invariant those ten sites all owed -- *every*
//! finalize/adopt/resolve path advances a tracked position's tip -- broke three
//! separate times in three different places because nothing forced them to
//! agree: #195's guard fired live twice, #229/#234/#265 each rediscovered the
//! same stuck-tip bug class independently, and #293/#303 hardened the store
//! side of it. That is the definition of missing locality this module fixes.
//!
//! `Workspace` keeps every field's old public accessor (`current_dock`,
//! `lane_id`, `dock_name`, `finalized_anchor`, ...) -- they now delegate here, so
//! nothing outside `workspace.rs` needs to know `Position` exists.

use loot_core::{DagRepo, Oid, Repo, RepoStore, HOME_DOCK};

/// The three fields that name where a [`Workspace`](crate::workspace::Workspace)
/// sits: the dock, the lane id, and the pinned tip. Nothing else -- deliberately
/// small (ADR 0034/0035): "position is place, not state."
pub struct Position {
    /// The dock this position is on -- always `HOME_DOCK` now that named docks
    /// are retired (#253/ADR 0034): the primary and every lane use the root
    /// `.loot/` process files of their own store instance. Kept as the seam
    /// loot-first's land gate reads via [`current_dock`](Self::current_dock).
    dock: String,
    /// The registry id of the spawned lane this position is, or `None` on the
    /// primary directory (lane #0). A lane's `.loot` is a directory carrying a
    /// `store` pointer plus every lane-owned file (ADR 0034); store-mutating
    /// verbs with one owner (`gc`, remotes, the dock family, lane spawn/reap)
    /// refuse from a lane ([`Workspace::ensure_primary`](crate::workspace::Workspace::ensure_primary)).
    lane_id: Option<String>,
    /// The finalized change this position forks from, once pinned. `None` on a
    /// fresh primary that never pinned a tip (ADR 0022) selects the pre-dock
    /// behavior (fork from all heads) and keeps existing repos byte-for-byte
    /// unchanged; a lane, or a primary an `adopt`/`lane merge` seeded, tracks
    /// it (see [`tracks_tip`](Self::tracks_tip)).
    tip: Option<Oid>,
}

impl Position {
    /// Load a position's state for the open path (`open_at`/`open_lane`): the
    /// dock name and lane id are already known, and the tip is read from the
    /// store's dock-selected slot.
    pub(crate) fn load(store: &RepoStore, dock: String, lane_id: Option<String>) -> Self {
        let tip = store.read_tip(Self::selector(&dock));
        Position { dock, lane_id, tip }
    }

    /// A brand-new position -- `init_at`'s home dock, nothing pinned yet.
    pub(crate) fn fresh(dock: String) -> Self {
        Position {
            dock,
            lane_id: None,
            tip: None,
        }
    }

    /// The store selector for a dock name: `HOME_DOCK` maps to the root files
    /// (`None`), matching loot-core's own dock convention.
    fn selector(dock: &str) -> Option<&str> {
        if dock == HOME_DOCK {
            None
        } else {
            Some(dock)
        }
    }

    // --- predicates ---

    /// The ambient dock name, or `None` on the primary (which the CLI displays
    /// as `main`). Named docks are retired (#253/ADR 0034) and in-place
    /// switching died in layer 1, so a lane opens as the home dock too -- this
    /// is `None` everywhere now, kept as the seam loot-first's land gate reads.
    pub(crate) fn current_dock(&self) -> Option<&str> {
        Self::selector(&self.dock)
    }

    /// The store selector for this position's process files.
    pub(crate) fn dock_opt(&self) -> Option<&str> {
        Self::selector(&self.dock)
    }

    /// The ambient dock's raw display name (`main` for home).
    pub(crate) fn dock_name(&self) -> &str {
        &self.dock
    }

    /// The registry id of this lane, or `None` on the primary.
    pub(crate) fn lane_id(&self) -> Option<&str> {
        self.lane_id.as_deref()
    }

    /// The pinned tip, if this position has one.
    pub(crate) fn tip(&self) -> Option<&Oid> {
        self.tip.as_ref()
    }

    /// Whether this position tracks a pinned tip that every tip-moving verb
    /// must advance: a lane (born with a spawn-seeded tip), or a primary that
    /// `adopt`/`lane merge` seeded. Leaving a seeded tip behind is the
    /// stuck-tip bug class -- [`anchor`](Self::anchor) stays at the seed while
    /// the graph's heads move on, so the next ferry aims git-main backward and
    /// the #195/#201 guards refuse (#229, #234, #265: three verbs hit this
    /// independently before this predicate was extracted). `tip.is_some()`
    /// subsumes the lane case; both are kept explicit for the reader.
    pub(crate) fn tracks_tip(&self) -> bool {
        self.lane_id.is_some() || self.tip.is_some()
    }

    /// The finalized change this position currently sits on -- a new dock/lane
    /// forks from here. Uses the pinned tip when present, else derives it from
    /// the graph: the working change's finalized parent, or the sole head (the
    /// pre-dock home case). `repo` and `working` are borrowed from the caller
    /// rather than owned here -- Position only names *place*, never the graph or
    /// the in-progress change.
    pub(crate) fn anchor(&self, repo: &DagRepo, working: Option<&Oid>) -> Option<Oid> {
        if let Some(t) = &self.tip {
            return Some(t.clone());
        }
        match working {
            Some(w) => repo.parents_of(w).into_iter().next(),
            None => repo.heads().into_iter().next(),
        }
    }

    // --- the one tip-writing dance ---

    /// Advance the tracked tip to `new_tip` -- the guarded set+persist dance
    /// every finalize-shaped call used to hand-write (#195/#229/#234/#265/
    /// #293). A no-op on an untracked pristine-home position, so its on-disk
    /// shape -- and its fork-from-all-heads behavior -- stays byte-for-byte
    /// unchanged (ADR 0022). This is the single place the invariant "a tracked
    /// position always advances" is enforced; every finalize/adopt/resolve
    /// path in `workspace.rs` calls this instead of re-deriving the guard.
    pub(crate) fn advance(&mut self, store: &RepoStore, new_tip: Option<Oid>) {
        if self.tracks_tip() {
            self.tip = new_tip;
            let _ = store.write_tip(self.dock_opt(), self.tip.as_ref());
        }
    }

    /// Unconditionally pin the tip at `new_tip`, bypassing the
    /// [`tracks_tip`](Self::tracks_tip) guard -- for the handful of call sites
    /// whose whole point is to (re)seed the position at a specific anchor
    /// rather than to *advance* an already-tracked one: settling a dock
    /// wholesale onto an `adopt <version>` target, fast-forwarding onto a
    /// merge target, and (test-only) pinning at the current finalized anchor.
    pub(crate) fn seed(&mut self, store: &RepoStore, new_tip: Option<Oid>) {
        self.tip = new_tip;
        let _ = store.write_tip(self.dock_opt(), self.tip.as_ref());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_store(name: &str) -> (PathBuf, RepoStore) {
        let dir = std::env::temp_dir().join(format!("loot-position-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = RepoStore::new(&dir);
        (dir, store)
    }

    // --- tracks_tip truth table ---

    #[test]
    fn tracks_tip_truth_table() {
        let none = Position {
            dock: HOME_DOCK.to_string(),
            lane_id: None,
            tip: None,
        };
        assert!(
            !none.tracks_tip(),
            "a pristine home position tracks nothing"
        );

        let lane_only = Position {
            dock: HOME_DOCK.to_string(),
            lane_id: Some("t1".into()),
            tip: None,
        };
        assert!(
            lane_only.tracks_tip(),
            "a lane always tracks, even before its first tip write"
        );

        let seeded_home = Position {
            dock: HOME_DOCK.to_string(),
            lane_id: None,
            tip: Some(Oid([1; 32])),
        };
        assert!(
            seeded_home.tracks_tip(),
            "an adopt/merge-seeded home dock tracks too"
        );

        let both = Position {
            dock: HOME_DOCK.to_string(),
            lane_id: Some("t1".into()),
            tip: Some(Oid([1; 32])),
        };
        assert!(both.tracks_tip());
    }

    // --- anchor precedence ---

    #[test]
    fn anchor_precedence_pinned_tip_then_working_parent_then_head() {
        let mut repo = DagRepo::init(PathBuf::from("loot-position-anchor-test"), "tester").unwrap();
        let root = repo
            .snapshot_assigning(None, None, &[], "root", 0, &[], None)
            .unwrap();
        let child = repo
            .snapshot_assigning(Some(&root), None, &[], "child", 0, &[], None)
            .unwrap();

        let untracked = Position {
            dock: HOME_DOCK.to_string(),
            lane_id: None,
            tip: None,
        };

        // No pinned tip, no working change: falls back to the sole head.
        assert_eq!(
            untracked.anchor(&repo, None),
            Some(child.clone()),
            "falls back to the head with nothing else to go on"
        );

        // No pinned tip, a working change in progress: its finalized parent.
        assert_eq!(
            untracked.anchor(&repo, Some(&child)),
            Some(root.clone()),
            "falls back to the working change's parent"
        );

        // A pinned tip wins over everything, even a working change that
        // disagrees -- the whole point of pinning one.
        let pinned = Oid([9; 32]);
        let tracked = Position {
            dock: HOME_DOCK.to_string(),
            lane_id: None,
            tip: Some(pinned.clone()),
        };
        assert_eq!(
            tracked.anchor(&repo, Some(&child)),
            Some(pinned),
            "a pinned tip wins over the working change's parent"
        );
    }

    // --- the invariant: a tracked position always advances ---

    #[test]
    fn advance_always_moves_a_tracked_tip() {
        let (dir, store) = temp_store("advance-tracked");
        let new_tip = Oid([7; 32]);

        let mut lane = Position {
            dock: HOME_DOCK.to_string(),
            lane_id: Some("t1".into()),
            tip: None,
        };
        lane.advance(&store, Some(new_tip.clone()));
        assert_eq!(lane.tip(), Some(&new_tip), "a lane always advances");
        assert_eq!(
            store.read_tip(None),
            Some(new_tip.clone()),
            "the advance persists to disk"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn advance_is_a_noop_on_an_untracked_pristine_home_position() {
        let (dir, store) = temp_store("advance-untracked");

        let mut untracked = Position {
            dock: HOME_DOCK.to_string(),
            lane_id: None,
            tip: None,
        };
        untracked.advance(&store, Some(Oid([3; 32])));
        assert!(
            untracked.tip().is_none(),
            "an untracked position never advances"
        );
        assert!(
            store.read_tip(None).is_none(),
            "its on-disk shape must not change (ADR 0022) — no tip file is written"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seed_pins_the_tip_even_on_an_untracked_position() {
        let (dir, store) = temp_store("seed");

        let mut untracked = Position {
            dock: HOME_DOCK.to_string(),
            lane_id: None,
            tip: None,
        };
        let target = Oid([5; 32]);
        untracked.seed(&store, Some(target.clone()));
        assert_eq!(
            untracked.tip(),
            Some(&target),
            "seed bypasses the tracks_tip guard by design"
        );
        assert_eq!(store.read_tip(None), Some(target));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
