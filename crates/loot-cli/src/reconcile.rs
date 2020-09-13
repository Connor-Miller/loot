//! Reconcile plan — the pure decision half of `Workspace::reconcile_onto`
//! (#325), split out of the executor that used to interleave deciding with
//! mutating (mint, sign, materialize, persist — see `workspace.rs`'s
//! `reconcile_onto`/`reconcile_capture`/`reconcile_merge`). R2/#178's
//! consolidation ("THE home for advance-a-tip") is preserved, not undone: the
//! home stays, it just splits into a pure brain (this module) and a small
//! pair of hands (the executor, still in `workspace.rs`, still the only place
//! a tip advances — through the Position module, #324).
//!
//! [`decide`] takes a [`View`] — everything the decision needs, already
//! computed by the caller — and returns a [`Plan`]: what to do, never how.
//! Nothing here touches a `Workspace`, a `DagRepo`, or disk, so the whole
//! table is unit-testable without either (see this module's `#[cfg(test)]`).
//!
//! `reconcile_onto`'s bug history is the reason this split exists: #280 (a
//! data-loss bug from gating capture on the wrong signal — fixed by making
//! capture unconditional on every materializing arm, mechanics untouched
//! here), #275 (a merge silently sealing an un-described working change as
//! its parent), and #292 (a review catch-up finalizing described WIP it was
//! supposed to leave reviewable). #275 and #292 were refusal *policy* buried
//! in the mutating `reconcile_capture` helper, reachable only through a full
//! `Workspace` — they are [`Refusal`] variants here instead, table-tested
//! directly.

use loot_core::Oid;

/// Everything [`decide`] needs to know about the reconcile state, already
/// computed by the caller (`Workspace::reconcile_onto`, which owns the graph
/// queries `is_ancestor`/`supersedes` this data comes from). Deliberately
/// data-only — no `&Workspace`, no `&DagRepo` — so a table test builds one by
/// hand.
#[derive(Debug, Clone)]
pub struct View {
    /// Our line already covers `target` (on it, ahead of it, or supersedes
    /// it) — the no-op fast path. The executor checks this itself, before
    /// capture, and returns early on `true` (capturing here would ask an
    /// un-described WIP for a name it is not owed — see `reconcile_onto`'s
    /// doc). Kept on `View` so the arm is still part of the one decision
    /// table and table-testable, even though production `decide` calls never
    /// carry it `true`.
    pub covered: bool,
    /// The change just captured off disk (mint + drop-if-redundant, #219
    /// semantics — see `reconcile_capture`), if capture found real work.
    /// `None` means the disk added nothing over the anchor/target.
    pub wip: Option<Oid>,
    /// The caller's pre-ingest anchor — the dock's tip before this reconcile
    /// pulled `target`'s lineage in. `None` on a fresh dock with no local
    /// line yet.
    pub pinned: Option<Oid>,
    /// Whether `pinned` is an ancestor of `target` — we are strictly behind,
    /// so a fast-forward loses nothing. Only consulted when `wip` is `None`
    /// (no captured tip means `pinned` decides the shape).
    pub pinned_is_ancestor_of_target: bool,
    /// Set only by the review projection (`loot ferry --with-wip`): forbids
    /// folding a live working change into the reconcile merge, because that
    /// would finalize WIP a review is entitled to show unsigned (#292).
    pub preserve_wip: bool,
    /// Whether the captured `wip` carries a real name — not empty, not the
    /// `(working change)` placeholder. Only meaningful when `wip` is `Some`.
    pub described: bool,
}

/// What `reconcile_onto` should do, decided but not yet done. The executor
/// matches on this and calls the corresponding hand: [`Plan::Adopt`] ->
/// `reconcile_adopt`, [`Plan::Merge`] -> (finalize the captured wip if that is
/// its source, then) `reconcile_merge`, [`Plan::Refuse`] -> return the
/// refusal's message, [`Plan::NoOp`] -> touch nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// Our line already covers `target` — nothing materializes.
    NoOp,
    /// No local line to fold, or one strictly behind `target`: fast-forward.
    Adopt,
    /// Fold `ours` (either the just-captured wip, or a pinned tip that
    /// diverged from `target`) into `target` via the converge classifier.
    Merge { ours: Oid },
    /// Refuse rather than mutate — see [`Refusal`].
    Refuse(Refusal),
}

/// Why [`decide`] refused, carrying the exact wording the operator sees.
/// Both variants preserve edits that are already captured on disk — a
/// refusal only withholds the signature, never the work (see each
/// constant's own doc for the full guarantee).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// #275: a merge is about to seal an un-described working change as its
    /// parent — its message becomes the permanent subject on git `main`.
    UndescribedParent,
    /// #292: a review catch-up caught up over a git `main` that moved while
    /// live, described WIP sat on the tree — folding it in would finalize
    /// the WIP a review is supposed to show unsigned.
    ReviewStaleAnchor,
}

impl Refusal {
    /// The exact refusal text the operator sees — byte-identical to the
    /// pre-#325 constants (agents and docs reference the wording).
    pub fn message(&self) -> &'static str {
        match self {
            Refusal::UndescribedParent => REFUSE_UNDESCRIBED_PARENT,
            Refusal::ReviewStaleAnchor => REFUSE_REVIEW_STALE_ANCHOR,
        }
    }
}

/// The whole `reconcile_onto` decision, transplanted faithfully from the
/// arms it used to be smeared across (#325). Order matters and mirrors the
/// original exactly: `covered` short-circuits before anything else; past
/// that, a real captured `wip` always outranks `pinned` (the disk holds real
/// work, so it decides); and within the `wip` arm, `preserve_wip` outranks
/// `described` (#292's refusal fires even over named work — it is about
/// *when*, not *whether named*, review may fold).
pub fn decide(view: &View) -> Plan {
    if view.covered {
        return Plan::NoOp;
    }
    if let Some(w) = &view.wip {
        return if view.preserve_wip {
            Plan::Refuse(Refusal::ReviewStaleAnchor)
        } else if !view.described {
            Plan::Refuse(Refusal::UndescribedParent)
        } else {
            Plan::Merge { ours: w.clone() }
        };
    }
    match &view.pinned {
        None => Plan::Adopt,
        Some(_) if view.pinned_is_ancestor_of_target => Plan::Adopt,
        Some(o) => Plan::Merge { ours: o.clone() },
    }
}

/// The [`Refusal::UndescribedParent`] twin for the merges that seal the
/// operator's work as a parent in passing (#275): same rule as
/// [`crate::workspace::REFUSE_UNDESCRIBED`], but it must say *why a sync verb
/// is suddenly asking for a name*, or it reads as a non-sequitur.
///
/// It promises the capture survives, and nothing more. That is the one thing
/// verified to outlive the erroring process (`snapshot_from` persists; loot is
/// process-per-command, so an in-memory guarantee would be a lie). A refused
/// pass's *ingest* does not persist — it is simply redone on the re-run, which
/// is why the whole pass is safe to abandon here.
pub(crate) const REFUSE_UNDESCRIBED_PARENT: &str =
    "refusing to sign your un-described working change as a merge parent — this merge seals \
     your local work into signed history, and its message becomes the permanent subject on \
     git `main`\n  name it:  loot describe -m \"<subject>\"\n  then re-run the same command\n  \
     (your edits are captured and safe — only the merge waits for the name)";

/// The review-only refusal (#292): `loot-first review` / `loot ferry --with-wip`
/// caught up over a git `main` that moved *under this lane* while a live working
/// change carried real work. Folding it into the catch-up merge would finalize
/// the WIP and leave the empty minted change as the thing to review — the silent
/// dead end #257 hit (unreviewable, unlandable, no op to undo). We refuse before
/// the fold, so the described WIP stays a live, unfinalized working change.
///
/// Like [`REFUSE_UNDESCRIBED_PARENT`], it promises only that the capture
/// survives the erroring process (`snapshot_from` persists; the refused pass's
/// ingest does not, so it is simply redone on the re-run). The root cause is a
/// lane spawned from an anchor already behind git `main`.
pub(crate) const REFUSE_REVIEW_STALE_ANCHOR: &str =
    "git `main` moved under this lane while your work is described but unfinalized, so \
     `loot-first review` would have to fold your WIP into a reconcile merge to catch up — \
     which finalizes it and leaves nothing to review (issue #292). Refusing so your work is \
     never silently stranded.\n  Nothing was finalized; your working change is intact on \
     disk.\n  This lane was spawned from an anchor already behind git `main`. To land this \
     work, re-spawn a lane from current main and re-apply it there (`loot lane new` from the \
     primary once it has caught up), or reconcile deliberately with `loot adopt` — aware that \
     the adopt signs your WIP into a merge (it stops being a reviewable working change).";

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(byte: u8) -> Oid {
        Oid([byte; 32])
    }

    fn base_view() -> View {
        View {
            covered: false,
            wip: None,
            pinned: None,
            pinned_is_ancestor_of_target: false,
            preserve_wip: false,
            described: false,
        }
    }

    // --- the decision table, one test per arm ---

    #[test]
    fn covered_is_a_noop_regardless_of_everything_else() {
        let view = View {
            covered: true,
            wip: Some(oid(1)),
            pinned: Some(oid(2)),
            pinned_is_ancestor_of_target: true,
            preserve_wip: true,
            described: true,
        };
        assert_eq!(decide(&view), Plan::NoOp, "covered outranks every other field");
    }

    #[test]
    fn real_captured_wip_with_preserve_wip_refuses_review_stale_anchor() {
        let view = View {
            wip: Some(oid(1)),
            preserve_wip: true,
            described: true, // named, and still refused — #292 is about *when*
            ..base_view()
        };
        assert_eq!(
            decide(&view),
            Plan::Refuse(Refusal::ReviewStaleAnchor),
            "preserve_wip refuses even a described wip"
        );
    }

    #[test]
    fn real_captured_wip_undescribed_refuses_undescribed_parent() {
        let view = View {
            wip: Some(oid(1)),
            preserve_wip: false,
            described: false,
            ..base_view()
        };
        assert_eq!(decide(&view), Plan::Refuse(Refusal::UndescribedParent));
    }

    #[test]
    fn real_captured_wip_described_merges_it_as_ours() {
        let w = oid(7);
        let view = View {
            wip: Some(w.clone()),
            preserve_wip: false,
            described: true,
            ..base_view()
        };
        assert_eq!(decide(&view), Plan::Merge { ours: w });
    }

    #[test]
    fn no_wip_no_pinned_adopts() {
        let view = View { wip: None, pinned: None, ..base_view() };
        assert_eq!(decide(&view), Plan::Adopt);
    }

    #[test]
    fn no_wip_pinned_ancestor_of_target_adopts() {
        let view = View {
            wip: None,
            pinned: Some(oid(3)),
            pinned_is_ancestor_of_target: true,
            ..base_view()
        };
        assert_eq!(decide(&view), Plan::Adopt, "strictly behind target — fast-forward");
    }

    #[test]
    fn no_wip_pinned_not_ancestor_merges_pinned_as_ours() {
        let p = oid(4);
        let view = View {
            wip: None,
            pinned: Some(p.clone()),
            pinned_is_ancestor_of_target: false,
            ..base_view()
        };
        assert_eq!(decide(&view), Plan::Merge { ours: p }, "diverged — merge via the classifier");
    }

    // --- precedence: wip always outranks pinned when both are present ---

    #[test]
    fn real_captured_wip_outranks_a_present_pinned() {
        let w = oid(9);
        let view = View {
            wip: Some(w.clone()),
            pinned: Some(oid(10)),
            pinned_is_ancestor_of_target: true,
            preserve_wip: false,
            described: true,
            ..base_view()
        };
        assert_eq!(
            decide(&view),
            Plan::Merge { ours: w },
            "real captured work decides over a stale pinned tip"
        );
    }

    // --- refusal wording stays exact (agents/docs reference it) ---

    #[test]
    fn refusal_messages_are_the_pinned_constants() {
        assert_eq!(Refusal::UndescribedParent.message(), REFUSE_UNDESCRIBED_PARENT);
        assert_eq!(Refusal::ReviewStaleAnchor.message(), REFUSE_REVIEW_STALE_ANCHOR);
        assert!(REFUSE_REVIEW_STALE_ANCHOR.contains("#292"), "docs point at the ticket by number");
    }
}
