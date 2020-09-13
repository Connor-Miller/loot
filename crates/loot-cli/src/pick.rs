//! `loot cherry-pick` / `loot revert` — apply (or invert) a single change's
//! delta onto the current line (#392/#393).
//!
//! `git cherry-pick` re-applies one commit's diff as a new commit; `git revert`
//! applies its *inverse*. loot has neither, and `loot adopt` is adjacent but the
//! wrong shape — it discards the local line rather than adding to it. Both verbs
//! here share ONE core, [`Workspace::apply_change_delta`], which computes the
//! target change's parent-delta and 3-way merges it onto the current working
//! change via the exact `apply`/`merge_tips` classifier — forward for
//! cherry-pick, inverted (additions<->deletions) for revert.
//!
//! Three loot-specific rules the shared core enforces (the tickets' notes):
//!
//! * **Re-sealed under the current policy.** The delta is written to the working
//!   tree and snapshotted, so it re-seals under the current `.lootattributes` —
//!   the source change's visibility does not travel with a cherry-pick.
//! * **Key-oracle gate, not fatal.** A delta path whose content this identity
//!   cannot open is skipped and named, never thrown — you cannot re-seal
//!   plaintext you cannot read.
//! * **Conflicts stop, exactly like `apply`.** A genuine same-path divergence is
//!   recorded in the conflicts map and the working tree is left untouched;
//!   nothing is minted, and `loot resolve` takes it from there.
//!
//! The predecessor graph is not touched: the result is a new change (new
//! change-id/version-id, current identity as author), not a superseding version
//! of the source.

use crate::emit::{self, Emit};
use crate::error::CliError;
use crate::render::{outcome_rows, short};
use crate::workspace::{DeltaReport, Workspace};
use loot_core::{verdict::PathVerdict, Oid};
use std::fmt::Write as _;

/// `loot cherry-pick <selector>` — re-apply the target change's delta forward.
pub fn cmd_cherry_pick(args: &[String]) -> Result<Box<dyn Emit>, CliError> {
    run(args, false, "cherry-pick")
}

/// `loot revert <selector>` — apply the inverse of the target change's delta.
pub fn cmd_revert(args: &[String]) -> Result<Box<dyn Emit>, CliError> {
    run(args, true, "revert")
}

fn run(args: &[String], invert: bool, verb: &str) -> Result<Box<dyn Emit>, CliError> {
    let selector = args
        .iter()
        .map(String::as_str)
        .find(|a| !a.starts_with('-'))
        .ok_or_else(|| format!("usage: loot {verb} <selector>"))?;

    let mut ws = Workspace::open().map_err(CliError::no_repo)?;
    let target = ws.resolve_selector(selector)?;

    // The new change's subject: cherry-pick keeps the original message; revert
    // announces itself over the original's first line (git's convention).
    let original = ws.graph().message(&target).unwrap_or_default();
    let subject = if invert {
        let first = original.lines().next().unwrap_or("").trim();
        if first.is_empty() {
            format!("revert: {}", short(&target))
        } else {
            format!("revert: {first}")
        }
    } else if original.trim().is_empty() {
        format!("cherry-pick {}", short(&target))
    } else {
        original
    };

    let report = ws.apply_change_delta(&target, invert, &subject)?;
    let human = render_human(verb, selector, &target, &subject, &report);
    let verdicts: Vec<PathVerdict> = report
        .outcomes
        .iter()
        .map(|(p, o)| PathVerdict::new(p.clone(), o.clone()))
        .collect();

    // Record the view change for `loot undo` — but a pure no-op (nothing applied,
    // nothing skipped, no conflict) records nothing, like the other verbs.
    if report.change.is_some() || report.conflicted || !report.skipped.is_empty() {
        ws.record_op(verb, &format!("{verb} {}", short(&target)), false);
    }

    Ok(Box::new(emit::Reconciliation { verdicts, human }))
}

fn render_human(verb: &str, selector: &str, target: &Oid, subject: &str, report: &DeltaReport) -> String {
    let mut out = String::new();
    // Sealed paths are surfaced whichever way the delta went — the operator must
    // know the result omits them.
    for path in &report.skipped {
        let _ = writeln!(
            out,
            "warning: skipped {} — sealed to you, cannot {verb} (no key)",
            path.display()
        );
    }

    if report.conflicted {
        let _ = writeln!(
            out,
            "{verb} {} ({}) conflicts with the current line — recorded, nothing applied:",
            short(target),
            selector
        );
        out.push_str(&outcome_rows(&report.outcomes));
        let _ = writeln!(out, "resolve them (`loot resolve <path> <file>`), then retry");
        return out;
    }

    match &report.change {
        Some(id) => {
            let _ = writeln!(out, "{verb} {} as {} \"{subject}\"", short(target), short(id));
            if !report.outcomes.is_empty() {
                out.push_str(&outcome_rows(&report.outcomes));
            }
        }
        None => {
            let _ = writeln!(out, "{verb} {} ({}): nothing to apply", short(target), selector);
        }
    }
    out
}
