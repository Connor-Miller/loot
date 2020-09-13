//! `loot split` (#395) and `loot squash` (#396) — the two history-editing verbs
//! that move change content along the graph.
//!
//! They share one primitive ([`Workspace::supersede_with_tree`](crate::workspace::Workspace)):
//! re-finalize a change with a replaced tree, recorded as an ADR-0032
//! superseding version. `split` moves a subset of paths DOWN into a new lower
//! change; `squash` moves the working change's delta UP into an ancestor. Both
//! reuse the same `reopen`/`record_superseding`/`sign` machinery `loot edit`
//! uses, so neither reinvents superseding.
//!
//! These handlers are thin: they parse arguments and render the report the
//! Workspace verb returns. The engine work — predecessor/parent wiring, the
//! undescribed-change guard, the intervening-change conflict check — lives in
//! [`Workspace::split`]/[`Workspace::squash`].

use crate::emit::{self, Emit};
use crate::error::CliError;
use crate::render::short;
use crate::workspace::Workspace;
use std::fmt::Write as _;

/// `loot split -m <subject> <path...>` — cut the named paths out of the working
/// change into a NEW finalized change below it, leaving the rest as the working
/// change on top (#395).
pub fn cmd_split(args: &[String]) -> Result<Box<dyn Emit>, CliError> {
    let subject = message_flag(args)
        .ok_or("loot split needs a subject for the finalized first change: -m \"<subject>\"")?;
    let paths = positionals_skipping_message(args);
    if paths.is_empty() {
        return Err("usage: loot split -m <subject> <path...>".into());
    }

    let mut ws = Workspace::open().map_err(CliError::no_repo)?;
    let report = ws.split(&paths, subject)?;

    let mut out = String::new();
    let _ = writeln!(
        out,
        "split {} path(s) into finalized {} (below); remainder is the working change {}",
        report.moved.len(),
        short(&report.first),
        short(&report.remainder),
    );
    for path in &report.moved {
        let _ = writeln!(out, "  moved {}", path.display());
    }
    Ok(Box::new(emit::Message::new(out)))
}

/// `loot squash [--into <selector>] [-m <subject>]` — fold the working change's
/// delta up into its immediate parent, or into an arbitrary ancestor with
/// `--into` (#396). A conflict with an intervening change stops the fold and
/// records the clash for `loot resolve`.
pub fn cmd_squash(args: &[String]) -> Result<Box<dyn Emit>, CliError> {
    let into = flag(args, "--into");
    let message = message_flag(args);

    let mut ws = Workspace::open().map_err(CliError::no_repo)?;
    let report = ws.squash(into, message)?;

    let mut out = String::new();
    match &report.folded_into {
        Some(target) => {
            let _ = writeln!(out, "squashed the working change into {}", short(target));
            if report.rebased > 0 {
                let _ = writeln!(
                    out,
                    "  re-anchored {} intervening change(s) onto it",
                    report.rebased
                );
            }
        }
        None => {
            let _ = writeln!(
                out,
                "squash stopped — {} path(s) clash with an intervening change:",
                report.conflicts.len()
            );
            for path in &report.conflicts {
                let _ = writeln!(out, "  {}", path.display());
            }
            let _ = writeln!(out, "resolve them (`loot resolve <path> <file>`), then retry");
        }
    }
    Ok(Box::new(emit::Message::new(out)))
}

/// The value following `name`, if present — a local twin of main.rs's private
/// `flag` helper so this module parses its flags without reaching across it.
fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// `-m`/`--message`, the subject flag (mirrors main.rs's `message_flag`).
fn message_flag(args: &[String]) -> Option<&str> {
    flag(args, "-m").or_else(|| flag(args, "--message"))
}

/// The positional arguments (`split`'s paths), skipping the flags and the value
/// of the one value-taking flag `-m`/`--message` so a subject like `-m "fix"` is
/// never mistaken for a path.
fn positionals_skipping_message(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "-m" || a == "--message" {
            i += 2; // skip the flag and its value
        } else if a.starts_with('-') {
            i += 1; // skip a bare flag
        } else {
            out.push(args[i].clone());
            i += 1;
        }
    }
    out
}
