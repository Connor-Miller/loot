//! `loot` — a CLI over the canonical engine (ADR 0005, 0006).
//!
//! JJ-style: the working tree *is* the current change. `status` snapshots it,
//! `describe` names it, `new` finalizes it and starts fresh. No commit ceremony.
//! All ambient state (`.loot/` home, identity, clock, persistence, working-change
//! id) is owned by the [`Workspace`]; commands are thin verbs over it.

mod workspace;

use loot_core::{MergeOutcome, Oid, Repo, SyncBundle};
use std::process::ExitCode;
use workspace::Workspace;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    let rest = &args[args.len().min(1)..];

    let result = match cmd {
        "init" => cmd_init(rest),
        "status" => cmd_status(rest),
        "describe" => cmd_describe(rest),
        "new" => cmd_new(),
        "checkout" => cmd_checkout(),
        "log" => cmd_log(),
        "bundle" => cmd_bundle(rest),
        "apply" => cmd_apply(rest),
        "help" | "-h" | "--help" => {
            print_help();
            Ok(())
        }
        other => Err(format!("unknown command '{other}'\n\n{USAGE}")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("loot: {e}");
            ExitCode::FAILURE
        }
    }
}

const USAGE: &str = "\
usage:
  loot init --identity <name>   initialize a repo here, owned by <name>
  loot status [-m <message>]    snapshot the working tree into the working change
  loot describe -m <message>    name the working change
  loot new                      finalize the working change; start a fresh one
  loot checkout                 materialize what the current identity may see
  loot log                      show change history
  loot bundle <file>            write a sync bundle (ciphertext, no private keys)
  loot apply <file>             merge a peer's bundle (idempotent)";

fn print_help() {
    println!("loot — source control where privacy is per-content, not per-repo\n\n{USAGE}");
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn message_flag(args: &[String]) -> Option<&str> {
    flag(args, "-m").or_else(|| flag(args, "--message"))
}

// --- commands ---

fn cmd_init(args: &[String]) -> Result<(), String> {
    let identity = flag(args, "--identity").ok_or("init requires --identity <name>")?;
    Workspace::init(identity)?;
    println!("initialized empty loot repo, identity = {identity}");
    println!("tip: declare per-file privacy in .lootattributes, e.g. `.env restricted={identity}`");
    Ok(())
}

fn cmd_status(args: &[String]) -> Result<(), String> {
    let mut ws = Workspace::open()?;
    // Snapshot first (JJ: the tree IS the change), then report it.
    let message = message_flag(args).unwrap_or("(working change)");
    let (id, entries) = ws.snapshot(message)?;
    if entries.is_empty() {
        println!("working change {} is empty", short(&id));
        return Ok(());
    }
    println!("working change {} — \"{message}\"", short(&id));
    for (path, vis) in &entries {
        println!("  {:<24} {}", path.display(), mark(vis));
    }
    Ok(())
}

fn cmd_describe(args: &[String]) -> Result<(), String> {
    let message = message_flag(args).ok_or("describe requires -m <message>")?;
    let mut ws = Workspace::open()?;
    let (id, _) = ws.snapshot(message)?;
    println!("described working change {} as \"{message}\"", short(&id));
    Ok(())
}

fn cmd_new() -> Result<(), String> {
    let mut ws = Workspace::open()?;
    ws.finalize_working()?;
    println!("finalized working change; the next `status` starts a fresh one");
    Ok(())
}

fn cmd_checkout() -> Result<(), String> {
    let ws = Workspace::open()?;
    let head = ws.checkout()?;
    println!(
        "checked out {} as {} (content you may not see was skipped)",
        short(&head),
        ws.identity()
    );
    Ok(())
}

fn cmd_log() -> Result<(), String> {
    let ws = Workspace::open()?;
    let entries = ws.repo().log();
    if entries.is_empty() {
        println!("no changes yet");
        return Ok(());
    }
    for (id, message) in entries.into_iter().rev() {
        println!("{}  {}", short(&id), message);
    }
    Ok(())
}

fn cmd_bundle(args: &[String]) -> Result<(), String> {
    let out = args.first().ok_or("bundle requires <file>")?;
    let ws = Workspace::open()?;
    // Full bundle (have = []); apply is idempotent. Ships ciphertext + ANYONE-
    // granted keys only — restricted keys never travel (ADR 0003).
    let bundle = ws.repo().bundle(&[]).map_err(|e| e.to_string())?;
    std::fs::write(out, &bundle.0).map_err(|e| format!("write {out}: {e}"))?;
    println!("wrote {} ({} bytes) — copy it to a peer and `loot apply`", out, bundle.0.len());
    Ok(())
}

fn cmd_apply(args: &[String]) -> Result<(), String> {
    let infile = args.first().ok_or("apply requires <file>")?;
    let bytes = std::fs::read(infile).map_err(|e| format!("read {infile}: {e}"))?;
    let mut ws = Workspace::open()?;
    let now = ws.now();
    let identity = ws.identity().to_string();
    let outcomes = ws.with_repo(|repo| {
        repo.apply(&SyncBundle(bytes), now).map_err(|e| e.to_string())
    })?;

    if outcomes.is_empty() {
        println!("applied {infile}: nothing new (already up to date)");
    } else {
        println!("applied {infile} as {identity}:");
        for (path, outcome) in &outcomes {
            println!("  {:<24} {}", path.display(), describe(outcome));
        }
        println!("run `loot checkout` to materialize what you may see");
    }
    Ok(())
}

// --- formatting ---

fn mark(vis: &loot_core::Visibility) -> String {
    use loot_core::Visibility::*;
    match vis {
        Public => "public".to_string(),
        Restricted(ids) => format!("restricted={}", ids.join(",")),
        Embargoed { reveal_at } => format!("embargoed@{reveal_at}"),
    }
}

/// Human phrasing for a merge outcome, naming the relay role explicitly.
fn describe(o: &MergeOutcome) -> &'static str {
    match o {
        MergeOutcome::Converged => "converged",
        MergeOutcome::Merged => "merged",
        MergeOutcome::Conflict => "conflict (needs resolution)",
        MergeOutcome::RelayedUnmerged => "relayed (sealed — you lack the key)",
    }
}

fn short(oid: &Oid) -> String {
    oid.0[..4].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use loot_core::Visibility;

    #[test]
    fn describe_names_the_relay_role() {
        assert_eq!(describe(&MergeOutcome::Converged), "converged");
        assert_eq!(describe(&MergeOutcome::Merged), "merged");
        assert!(describe(&MergeOutcome::RelayedUnmerged).contains("sealed"));
        assert!(describe(&MergeOutcome::Conflict).contains("conflict"));
    }

    #[test]
    fn mark_renders_visibility() {
        assert_eq!(mark(&Visibility::Public), "public");
        assert_eq!(mark(&Visibility::Restricted(vec!["a".into(), "b".into()])), "restricted=a,b");
        assert_eq!(mark(&Visibility::Embargoed { reveal_at: 5 }), "embargoed@5");
    }
}
