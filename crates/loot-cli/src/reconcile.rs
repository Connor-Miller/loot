//! Reconcile plan — the pure decision half of `Workspace::reconcile_onto`
//! (#325), split out of the executor that used to interleave deciding with
//! mutating (mint, sign, materialize, persist — see `workspace.rs`'s
//! `reconcile_onto`/`reconcile_capture`/`reconcile_carry`). R2/#178's
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
//! supposed to leave reviewable). #275 remains a [`Refusal`] variant here,
//! table-tested directly. #292's refusal (`REFUSE_REVIEW_STALE_ANCHOR`) is
//! **gone with its trigger**: review mode is a pure projection since ADR 0039
//! — it performs no reconcile at all, so the fold that refusal guarded
//! against is unrepresentable and reconciling is again exclusively the
//! signing verbs' business (`ferry`, `adopt`, `loot-first land`).

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
    /// Whether the captured `wip` carries a real name — not empty, not the
    /// `(working change)` placeholder. Only meaningful when `wip` is `Some`.
    pub described: bool,
}

/// What `reconcile_onto` should do, decided but not yet done. The executor
/// matches on this and calls the corresponding hand: [`Plan::Adopt`] ->
/// `reconcile_adopt`, [`Plan::Merge`] -> (finalize the captured wip if that is
/// its source, then) `reconcile_carry` — the ADR 0039 carry, with the merge
/// shape as its foreign-work fallback — [`Plan::Refuse`] -> return the
/// refusal's message, [`Plan::NoOp`] -> touch nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// Our line already covers `target` — nothing materializes.
    NoOp,
    /// No local line to fold, or one strictly behind `target`: fast-forward.
    Adopt,
    /// Reconcile `ours` (either the just-captured wip, or a pinned tip that
    /// diverged from `target`) with `target` via the converge classifier —
    /// executed as a carry (ADR 0039), one commit per change.
    Merge { ours: Oid },
    /// Refuse rather than mutate — see [`Refusal`].
    Refuse(Refusal),
}

/// Why [`decide`] refused, carrying the exact wording the operator sees.
/// The refusal preserves edits that are already captured on disk — it only
/// withholds the signature, never the work (see the constant's doc for the
/// full guarantee).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// #275: a reconcile is about to seal an un-described working change into
    /// signed history — its message becomes the permanent subject on git
    /// `main`.
    UndescribedParent,
}

impl Refusal {
    /// The exact refusal text the operator sees — byte-identical to the
    /// pre-#325 constant (agents and docs reference the wording).
    pub fn message(&self) -> &'static str {
        match self {
            Refusal::UndescribedParent => REFUSE_UNDESCRIBED_PARENT,
        }
    }
}

/// The whole `reconcile_onto` decision, transplanted faithfully from the
/// arms it used to be smeared across (#325). Order matters and mirrors the
/// original exactly: `covered` short-circuits before anything else; past
/// that, a real captured `wip` always outranks `pinned` (the disk holds real
/// work, so it decides), and an un-described `wip` refuses (#275) before
/// anything is signed.
pub fn decide(view: &View) -> Plan {
    if view.covered {
        return Plan::NoOp;
    }
    if let Some(w) = &view.wip {
        return if !view.described {
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

/// The [`Refusal::UndescribedParent`] twin for the reconciles that seal the
/// operator's work in passing (#275): same rule as
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
            described: true,
        };
        assert_eq!(decide(&view), Plan::NoOp, "covered outranks every other field");
    }

    #[test]
    fn real_captured_wip_undescribed_refuses_undescribed_parent() {
        let view = View {
            wip: Some(oid(1)),
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
        assert_eq!(decide(&view), Plan::Merge { ours: p }, "diverged — carry via the classifier");
    }

    // --- precedence: wip always outranks pinned when both are present ---

    #[test]
    fn real_captured_wip_outranks_a_present_pinned() {
        let w = oid(9);
        let view = View {
            wip: Some(w.clone()),
            pinned: Some(oid(10)),
            pinned_is_ancestor_of_target: true,
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
    }
}
