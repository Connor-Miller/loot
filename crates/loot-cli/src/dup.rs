//! `loot duplicate` — copy a change as a fresh, independent node (#398).
//!
//! `jj duplicate` makes an exact copy of a change under a new change id for
//! cherry-pick-style workflows that want the same content at a different point
//! in history *without* the predecessor link. loot has `edit` (supersede, which
//! carries the change id and records the source as a predecessor) and
//! `cherry-pick` (re-apply a delta, re-sealed under the current
//! `.lootattributes`), but neither is a copy: they either rewrite the source or
//! transform it. Duplicate copies the *whole tree* address-for-address into a
//! brand-new change.
//!
//! The engine work is one call — [`Workspace::duplicate`] — because ADR 0004's
//! content-address dedup means the source's sealed objects are already stored:
//! reusing their addresses reuses the objects and their keys, so nothing is
//! re-encrypted (the per-path visibility travels unchanged with the copied
//! entry). The copy mints a fresh change id + version id, carries no
//! predecessor, and is signed so it travels like any finalized change.

use crate::emit::{self, Emit};
use crate::error::CliError;
use crate::render::short;
use crate::workspace::Workspace;

/// `loot duplicate <selector> [--after <selector>]` — mint a NEW change id and
/// version id reproducing the target change's tree, with no predecessor link.
/// The copy parents on `--after` when given, else on the current working
/// change (its default insertion point on top of the working line).
pub fn cmd_duplicate(args: &[String]) -> Result<Box<dyn Emit>, CliError> {
    // `--after <selector>` (optional) is the explicit insertion point. Its
    // value is a positional-shaped token, so remember its index and skip it
    // when picking the source selector — either order parses the same.
    let after = flag(args, "--after");
    let after_value_idx = args.iter().position(|a| a == "--after").map(|i| i + 1);
    let selector = args
        .iter()
        .enumerate()
        .find(|(i, a)| !a.starts_with('-') && Some(*i) != after_value_idx)
        .map(|(_, a)| a.as_str())
        .ok_or("usage: loot duplicate <selector> [--after <selector>]")?;

    let mut ws = Workspace::open().map_err(CliError::no_repo)?;
    let report = ws.duplicate(selector, after)?;

    let mut human = format!("duplicate {} as {}", short(&report.source), short(&report.version));
    if let Some(parent) = &report.parent {
        human.push_str(&format!(" (on {})", short(parent)));
    }
    Ok(Box::new(emit::Message::new(human)))
}

/// The value following `name`, if present — a local twin of main.rs's private
/// `flag` helper so this module parses `--after` without reaching across it.
fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}
