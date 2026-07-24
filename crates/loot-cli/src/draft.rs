//! Draft — the CLI's local state of the [working change](crate::workspace):
//! the working-change pointer and the eagerly-minted next-change handle, held as
//! **one** state machine. Sibling of [`Position`](crate::position::Position),
//! which names *place* (the dock, lane, and pinned tip): Draft names the *state*
//! you build on that place (ADR 0034's "position is place, not state" — Draft is
//! the state half).
//!
//! Before this module the two facts were loose `Workspace` fields —
//! `working: Option<Oid>` and `next_change_id: Option<[u8; 16]>` — hand-mutated
//! at ~19 sites, each site owing the invariant that they move together. Their
//! legal combinations are a **3-state machine**:
//!
//! | `working` | pending handle | meaning                                   |
//! |-----------|----------------|-------------------------------------------|
//! | None      | None           | [`Clean`](Draft::Clean) — no WIP, nothing pending |
//! | None      | Some           | [`Fresh`](Draft::Fresh) — armed, pre-snapshot     |
//! | Some      | None           | [`Active`](Draft::Active) — a change in progress   |
//!
//! The fourth combination — a working change *and* a pending handle — is never
//! valid: once a change is in progress the handle to print is the change's *own*
//! id (ADR 0029/0030), so the pre-minted one is dead. Two `Option`s made that
//! fourth state *representable* (and `edit` from a [`Fresh`](Draft::Fresh) state
//! transiently built it, leaking the dead handle until the next finalize
//! overwrote it); this enum makes it *unconstructable*. Every transition into
//! [`Active`](Draft::Active) drops the pending handle by construction.
//!
//! Draft owns *only* these two fields. The composite dances that also move the
//! [`Position`](crate::position::Position) tip (restart-on-anchor, the finalize
//! hand-off) stay as named coordinators on `Workspace`, which owns both modules.
//! Minting is the caller's job too: [`arm`](Draft::arm) takes the freshly minted
//! id as a value, so Draft needs no [`DagRepo`](loot_core::DagRepo) — its whole
//! dependency surface is [`RepoStore`](loot_core::RepoStore), exactly like
//! `Position`.

use loot_core::{Oid, RepoStore};

/// The working-change state (see the [module docs](self)). `pub(crate)` like
/// [`Position`](crate::position::Position); `Workspace` keeps every old public
/// accessor, delegating here.
pub(crate) enum Draft {
    /// No working change and no pending handle — a clean tip. Post-finalize with
    /// nothing armed, a redundant capture that was dropped, or a keyless repo
    /// (which mints no durable handles, ADR 0029).
    Clean,
    /// A durable change id minted eagerly for the *next* change (ADR 0029/0030),
    /// armed before any snapshot has recorded it. `loot init` and `loot new`
    /// land here so the fresh change has a name from birth.
    Fresh {
        /// The pending handle the first snapshot will assign onto the change.
        next: [u8; 16],
    },
    /// A working change is being rewritten in place. Its own change id is the
    /// handle now, so no pending one exists.
    Active {
        /// The working change's version id.
        working: Oid,
    },
}

impl Draft {
    // --- load / flush: the two on-disk slots this state serializes to ---

    /// Reconstruct the state from the store's `working` and `next-change` slots
    /// for `sel` (the [`Position`](crate::position::Position) dock selector).
    /// The two files are independent on disk, so this is defensive: a working id
    /// wins (→ [`Active`](Draft::Active)) and any stray pending handle beside it
    /// is dropped — self-healing any pre-module `(Some, Some)` a legacy write
    /// left behind, honoring the "pending handle is dead once a change exists"
    /// rule at load time.
    pub(crate) fn load(store: &RepoStore, sel: Option<&str>) -> Self {
        match store.read_working(sel) {
            Some(working) => Draft::Active { working },
            None => match store.read_next_change(sel) {
                Some(next) => Draft::Fresh { next },
                None => Draft::Clean,
            },
        }
    }

    /// Write both slots to match the current variant — the single place the two
    /// files are kept consistent. Called by `Workspace::persist`.
    pub(crate) fn flush(&self, store: &RepoStore, sel: Option<&str>) -> std::io::Result<()> {
        store.write_working(sel, self.working())?;
        store.write_next_change(sel, self.next().as_ref())?;
        Ok(())
    }

    // --- accessors ---

    /// The working change's id, if one is in progress ([`Active`](Draft::Active)).
    pub(crate) fn working(&self) -> Option<&Oid> {
        match self {
            Draft::Active { working } => Some(working),
            _ => None,
        }
    }

    /// The pending next-change handle, if one is armed ([`Fresh`](Draft::Fresh)).
    /// `None` in every state with a working change — which is exactly the
    /// "assign the durable handle only when starting a fresh change" rule the
    /// first snapshot needs (it assigns this, or nothing).
    pub(crate) fn next(&self) -> Option<[u8; 16]> {
        match self {
            Draft::Fresh { next } => Some(*next),
            _ => None,
        }
    }

    /// Whether nothing is in progress and nothing is armed — the guard
    /// `start_fresh_change` reads before minting the first handle.
    pub(crate) fn is_clean(&self) -> bool {
        matches!(self, Draft::Clean)
    }

    // --- transitions ---

    /// Arm the next-change handle on a state with no working change — the
    /// eager mint of `loot new`/`loot init`/the finalize hand-off. `None` (a
    /// keyless mint) leaves the state [`Clean`](Draft::Clean). Panics in debug
    /// if a working change is in progress: arming over one would build the
    /// illegal `(Some, Some)` state this module exists to forbid — the caller
    /// must [`take`](Draft::take) or [`clear`](Draft::clear) it first.
    pub(crate) fn arm(&mut self, next: Option<[u8; 16]>) {
        debug_assert!(
            self.working().is_none(),
            "arm() over a working change would build the illegal (Some, Some) state"
        );
        *self = match next {
            Some(next) => Draft::Fresh { next },
            None => Draft::Clean,
        };
    }

    /// Point the working change at `id` — the snapshot that records a change
    /// (the pending handle becomes that change's id) and the reopen/split/merge
    /// verbs that set the working change to an existing or freshly built one.
    /// Any pending handle is dropped: once a change is in progress it is the
    /// handle. This is the sole transition into [`Active`](Draft::Active).
    pub(crate) fn activate(&mut self, id: Oid) {
        *self = Draft::Active { working: id };
    }

    /// Remove the working change and return its id, leaving [`Clean`](Draft::Clean)
    /// — the finalize hand-off (`position.advance(draft.take())`). A no-op
    /// returning `None` when no change is in progress: a [`Fresh`](Draft::Fresh)
    /// state keeps its armed handle (nothing to hand off), matching
    /// `Option::take` on an absent working field.
    pub(crate) fn take(&mut self) -> Option<Oid> {
        match std::mem::replace(self, Draft::Clean) {
            Draft::Active { working } => Some(working),
            // Restore a Fresh handle we did not mean to drop.
            Draft::Fresh { next } => {
                *self = Draft::Fresh { next };
                None
            }
            Draft::Clean => None,
        }
    }

    /// Drop both the working change and any pending handle, leaving
    /// [`Clean`](Draft::Clean) — the "discard the working change" sites (a
    /// redundant capture, an abandoned WIP). Total: valid from any state.
    pub(crate) fn clear(&mut self) {
        *self = Draft::Clean;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_store(name: &str) -> (PathBuf, RepoStore) {
        let dir = std::env::temp_dir().join(format!("loot-draft-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = RepoStore::new(&dir);
        (dir, store)
    }

    // --- the accessor truth table across the three states ---

    #[test]
    fn accessors_map_each_state() {
        let clean = Draft::Clean;
        assert!(clean.working().is_none());
        assert!(clean.next().is_none());
        assert!(clean.is_clean());

        let fresh = Draft::Fresh { next: [7; 16] };
        assert!(fresh.working().is_none());
        assert_eq!(fresh.next(), Some([7; 16]));
        assert!(!fresh.is_clean());

        let active = Draft::Active { working: Oid([3; 32]) };
        assert_eq!(active.working(), Some(&Oid([3; 32])));
        assert!(
            active.next().is_none(),
            "an in-progress change has no pending handle — it IS the handle"
        );
        assert!(!active.is_clean());
    }

    // --- transitions ---

    #[test]
    fn arm_moves_clean_to_fresh_and_none_stays_clean() {
        let mut d = Draft::Clean;
        d.arm(Some([1; 16]));
        assert_eq!(d.next(), Some([1; 16]), "a keyed mint arms Fresh");

        let mut keyless = Draft::Clean;
        keyless.arm(None);
        assert!(keyless.is_clean(), "a keyless (None) mint stays Clean");
    }

    #[test]
    fn arm_replaces_a_fresh_handle() {
        // Finalizing from Fresh (nothing to hand off) re-mints the handle.
        let mut d = Draft::Fresh { next: [1; 16] };
        d.arm(Some([2; 16]));
        assert_eq!(d.next(), Some([2; 16]));
    }

    #[test]
    fn activate_enters_active_and_drops_the_pending_handle() {
        // The snapshot case: a Fresh handle becomes the recorded change's id.
        let mut d = Draft::Fresh { next: [9; 16] };
        d.activate(Oid([4; 32]));
        assert_eq!(d.working(), Some(&Oid([4; 32])));
        assert!(
            d.next().is_none(),
            "the pending handle is consumed onto the change — never left dangling beside a working change"
        );
    }

    #[test]
    fn activate_from_active_replaces_the_working_change() {
        // The merge/split case: point the working change at a freshly built one.
        let mut d = Draft::Active { working: Oid([1; 32]) };
        d.activate(Oid([2; 32]));
        assert_eq!(d.working(), Some(&Oid([2; 32])));
    }

    #[test]
    fn take_hands_off_the_working_id_and_leaves_clean() {
        let mut d = Draft::Active { working: Oid([5; 32]) };
        assert_eq!(d.take(), Some(Oid([5; 32])), "take returns the finished id");
        assert!(d.is_clean(), "and leaves the state clean for the next arm");
    }

    #[test]
    fn take_is_a_noop_that_preserves_a_fresh_handle() {
        // finalize's guard only calls take on Active, but faithfulness matters:
        // taking a working field that is None must not drop an armed handle.
        let mut d = Draft::Fresh { next: [8; 16] };
        assert_eq!(d.take(), None);
        assert_eq!(d.next(), Some([8; 16]), "the armed handle survives a no-op take");
    }

    #[test]
    fn clear_drops_everything_from_any_state() {
        let mut fresh = Draft::Fresh { next: [1; 16] };
        fresh.clear();
        assert!(fresh.is_clean());

        let mut active = Draft::Active { working: Oid([1; 32]) };
        active.clear();
        assert!(active.is_clean());
    }

    // --- load / flush round-trips through the two store slots ---

    #[test]
    fn flush_then_load_round_trips_each_state() {
        let (dir, store) = temp_store("roundtrip");

        Draft::Clean.flush(&store, None).unwrap();
        assert!(Draft::load(&store, None).is_clean());

        Draft::Fresh { next: [6; 16] }.flush(&store, None).unwrap();
        assert_eq!(Draft::load(&store, None).next(), Some([6; 16]));

        Draft::Active { working: Oid([2; 32]) }.flush(&store, None).unwrap();
        let loaded = Draft::load(&store, None);
        assert_eq!(loaded.working(), Some(&Oid([2; 32])));
        assert!(loaded.next().is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_self_heals_a_legacy_working_plus_pending_pair() {
        // A pre-module buggy write could leave BOTH slots populated. Load must
        // resolve it to Active (the working id wins) and drop the dead handle,
        // never surfacing the illegal fourth state.
        let (dir, store) = temp_store("self-heal");
        store.write_working(None, Some(&Oid([1; 32]))).unwrap();
        store.write_next_change(None, Some(&[2; 16])).unwrap();

        let loaded = Draft::load(&store, None);
        assert_eq!(loaded.working(), Some(&Oid([1; 32])));
        assert!(loaded.next().is_none(), "the stray pending handle is dropped");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
