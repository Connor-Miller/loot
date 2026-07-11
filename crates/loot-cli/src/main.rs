//! `loot` — a CLI over the canonical engine (ADR 0005, 0006).
//!
//! JJ-style: the working tree *is* the current change. `status` snapshots it,
//! `describe` names it, `new` finalizes it and starts fresh. No commit ceremony.
//! All ambient state (`.loot/` home, identity, clock, persistence, working-change
//! id) is owned by the [`Workspace`]; commands are thin verbs over it.

mod ferry;
mod workspace;

use loot_core::{
    verdict, MaroonResult, MergeOutcome, MigrateResult, Oid, PathVerdict, Repo, SyncBundle,
    Visibility,
};
use loot_identity as identity;
use std::process::ExitCode;
use workspace::{GlobalConfig, StepReport, Workspace};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    let rest = &args[args.len().min(1)..];

    // `buoy` returns its own ExitCode (0/2/3/1) rather than the generic Ok/Err.
    if cmd == "buoy" {
        return cmd_buoy(rest);
    }

    let result = match cmd {
        "help" | "-h" | "--help" => {
            print_help();
            Ok(())
        }
        other => match COMMANDS.iter().find(|(name, _)| *name == other) {
            Some((_, run)) => run(rest),
            None => Err(format!("unknown command '{other}'\n\n{USAGE}")),
        },
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("loot: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Every dispatchable verb in one table the dispatcher and the usage test
/// share, so a verb cannot silently vanish from the CLI while its usage line
/// survives — the #66 regression class (`loot gc` dropped in a merge).
/// `buoy` is dispatched separately (it returns its own ExitCode) and `help`
/// is a match arm; everything else lives here.
const COMMANDS: &[(&str, fn(&[String]) -> Result<(), String>)] = &[
    ("init", cmd_init),
    ("status", cmd_status),
    ("describe", cmd_describe),
    ("new", cmd_new),
    ("undo", |_| cmd_undo()),
    ("op", cmd_op),
    ("surface", |_| cmd_surface()),
    ("dock", cmd_dock),
    ("docks", |_| cmd_docks()),
    ("log", |_| cmd_log()),
    ("gc", cmd_gc),
    ("bundle", cmd_bundle),
    ("apply", cmd_apply),
    ("grant", cmd_grant),
    ("maroon", cmd_maroon),
    ("migrate", cmd_migrate),
    ("manifest", |_| cmd_manifest()),
    ("attest", cmd_attest),
    ("conflicts", cmd_conflicts),
    ("resolve", cmd_resolve),
    ("remote", cmd_remote),
    ("keygen", |_| cmd_keygen()),
    ("whoami", |_| cmd_whoami()),
    ("peer", cmd_peer),
    ("serve", cmd_serve),
    ("push", cmd_push),
    ("pull", cmd_pull),
    ("pull-grants", cmd_pull_grants),
    ("grants", cmd_grants),
    ("clone", cmd_clone),
    ("config", cmd_config),
    ("id", cmd_id),
    ("ferry", cmd_ferry),
];

const USAGE: &str = "\
usage:
  loot init [--identity <name>]             initialize a repo here (identity from global config if omitted)
  loot clone <url> <dir> [--identity <name>]  clone a relay into <dir>
  loot config [set <key> <val>] [unset <key>] [list]  manage global config (~/.config/loot/config)
  loot status [--porcelain|--json]          show the working change read-only (live version id + durable change id; no snapshot)
  loot describe -m <message> [--allow-demote <path>]...  record the tree and name the working change
  loot new [-m <message>] [--no-snapshot]   finalize the working change (sign) and start a fresh one; prints the next change id
  loot undo                                 step the view back one operation (refuses across a push/grant/maroon barrier)
  loot op log                               list the operation log (newest first; barriers flagged)
  loot op restore <n>                       jump the view to operation <n> (redo lands here after an undo)
  loot surface                              materialize what the current identity may see
  loot dock <name>                          create a dock (isolated working tree + tip), or switch to one
  loot docks                                list docks with their tip and visibility
  loot log                                  show change history
  loot gc [--dry-run]                       prune loose objects no change references (--dry-run reports only)
  loot bundle <file>                        write a sync bundle (ciphertext, no private keys)
  loot apply <file> [--porcelain|--json]    merge a peer's bundle (idempotent; machine output for agents)
  loot grant <path> <identity> <file>       write a targeted grant bundle for <identity> (file delivery)
  loot grant --relay <name> <path> <identity>  seal and deliver a grant via relay mailbox
  loot grants [<url>] [--remote <name>]     peek pending grant count (no download)
  loot pull-grants [<url>] [--remote <name>]   fetch, verify, and apply sealed grants from relay
  loot maroon [--hard] <path> <identity> [dir]  cut off <identity> from future access; --hard adds a purge event
  loot migrate <path> <vis-spec> [dir]      change a path's visibility (public | restricted=a,b | embargoed=<ts>)
  loot dock <name> [--at <dir>]             create/switch a dock (isolated tree over the shared store, ADR 0022)
  loot dock merge <name> [--porcelain|--json]  merge another dock's finalized tip into the current dock (local, CA2)
  loot docks                                list docks with their working tip
                                            (convention: a dock named `harbor` is the shared integration dock)
  loot manifest                             show the grant audit trail (and attestations)
  loot attest <change-id> [role]            attest a change (advisory sign-off, ADR 0018)
  loot buoy [role] [--verbose] [--porcelain|--json]  resolve the newest trusted role-attested change (CA4, ADR 0025)
  loot conflicts [--porcelain|--json]       list paths that need human resolution
  loot resolve <path> <file>                resolve a conflict at <path> using the content of <file>
  loot remote add <name> <url>              register a relay URL under a name
  loot remote remove <name>                 forget a named relay
  loot remote list                          show all named relays
  loot keygen                               generate an identity keypair (backfills existing repos)
  loot whoami                               show this repo's public key
  loot id export <file>                     export keypair to <file>, passphrase-encrypted
  loot id import <file>                     import keypair from passphrase-encrypted <file>
  loot peer add <name> <pubkey>             register a peer's public key
  loot peer remove <name>                   forget a peer
  loot peer list                            show all known peers
  loot serve [--dir <path>] [--addr <host:port>] [--allow <pubkey>]...  run a relay
  loot push [<url>] [--remote <name>]       publish changes to a relay (uses 'origin' if no url given)
  loot pull [<url>] [--remote <name>] [--porcelain|--json]  fetch, merge, and converge changes from a relay
  loot ferry [--git-dir <path>] [--dock <name>] [--porcelain|--json]  one bidirectional loot <-> git mirror pass (GB1, ADR 0028)

mutating verbs (new, describe, grant, maroon, migrate) snapshot the working tree
first (ADR 0030) — no manual `loot status` needed. Two globals ride any of them:
  --allow-demote <path>   permit this snapshot to re-seal <path> more readably (repeatable)
  --no-snapshot           act on the last recorded working change; skip the implicit capture";

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

/// Every value following an occurrence of `name` — for repeatable flags like
/// `--allow-demote a.txt --allow-demote b.txt`.
fn flag_values(args: &[String], name: &str) -> Vec<String> {
    args.windows(2)
        .filter(|w| w[0] == name)
        .map(|w| w[1].clone())
        .collect()
}

/// Machine-output selector for the reconciliation verbs (CA3, ADR 0023).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutFmt {
    Human,
    Porcelain,
    Json,
}

/// True if `name` appears as a bare flag anywhere in `args`.
fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// Which output format the verb should emit. `--json` wins over `--porcelain`;
/// with neither flag the default is human text (unchanged for existing callers).
fn out_fmt(args: &[String]) -> OutFmt {
    if has_flag(args, "--json") {
        OutFmt::Json
    } else if has_flag(args, "--porcelain") {
        OutFmt::Porcelain
    } else {
        OutFmt::Human
    }
}

/// First positional (non-`-`) argument. Lets `--porcelain`/`--json` sit on
/// either side of the filename for the reconciliation verbs, which take at
/// most one positional.
fn first_positional(args: &[String]) -> Option<&str> {
    args.iter().map(String::as_str).find(|a| !a.starts_with('-'))
}

/// The two global controls every snapshotting (mutating) verb honors under
/// implicit auto-snapshot (ADR 0030): the demotion allowlist and the
/// skip-the-snapshot escape hatch.
struct SnapshotOpts {
    /// `--allow-demote <path>` (repeatable): paths permitted to re-seal more
    /// readably on this snapshot (#62). The demotion guard aborts on any other.
    allow_demote: Vec<std::path::PathBuf>,
    /// `--no-snapshot` / `--ignore-working-copy`: skip the implicit capture for
    /// this one invocation, acting on the last recorded working change as-is.
    skip: bool,
}

impl SnapshotOpts {
    fn parse(args: &[String]) -> Self {
        Self {
            allow_demote: flag_values(args, "--allow-demote").into_iter().map(Into::into).collect(),
            skip: has_flag(args, "--no-snapshot") || has_flag(args, "--ignore-working-copy"),
        }
    }
}

/// A verb's positional arguments with flags removed — including the *value* of
/// the one value-taking global, `--allow-demote <path>`, so a demotion
/// allowlist entry is never mistaken for the verb's own positional (a path,
/// identity, or file). Bare flags (`--no-snapshot`, `--hard`, …) are dropped
/// too. Used by the snapshotting verbs that index positionals by position.
fn positionals(args: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--allow-demote" {
            i += 2; // skip the flag and its value
        } else if a.starts_with('-') {
            i += 1; // skip a bare flag
        } else {
            out.push(a);
            i += 1;
        }
    }
    out
}

/// The implicit snapshot that precedes a mutating verb (ADR 0030): capture the
/// working tree into the working change so the verb acts on what is on disk,
/// without a manual `loot status` first. Preserves the working change's name
/// (an implicit capture must not clobber a message a prior `describe` set), and
/// carries the demotion guard via `--allow-demote`. `--no-snapshot` /
/// `--ignore-working-copy` skips it. Read-only verbs never call this.
fn implicit_snapshot(ws: &mut Workspace, opts: &SnapshotOpts) -> Result<(), String> {
    if opts.skip {
        return Ok(());
    }
    let msg = ws.working_message().unwrap_or_else(|| "(working change)".to_string());
    ws.snapshot_allowing(&msg, &opts.allow_demote)?;
    Ok(())
}

/// Lift an apply/pull outcome map into the serializable verdict rows.
fn verdicts_of(
    outcomes: &std::collections::BTreeMap<std::path::PathBuf, MergeOutcome>,
) -> Vec<PathVerdict> {
    outcomes
        .iter()
        .map(|(p, o)| PathVerdict::new(p.clone(), o.clone()))
        .collect()
}

/// Lift the recorded conflict set (path -> ours/theirs) into verdict rows.
fn conflict_verdicts(
    conflicts: &std::collections::BTreeMap<std::path::PathBuf, (Oid, Oid)>,
) -> Vec<PathVerdict> {
    conflicts
        .iter()
        .map(|(p, (ours, theirs))| {
            PathVerdict::new(
                p.clone(),
                MergeOutcome::Conflict { ours: ours.clone(), theirs: theirs.clone() },
            )
        })
        .collect()
}

// --- commands ---

fn cmd_init(args: &[String]) -> Result<(), String> {
    let id_name = flag(args, "--identity")
        .map(String::from)
        .or_else(|| GlobalConfig::load().get("identity").map(String::from))
        .ok_or("init requires --identity <name> (or set `identity` in `loot config`)")?;
    init_repo(std::path::Path::new("."), &id_name)
}

/// Shared init logic: initialize a repo at `dir`, generate keypair, print summary.
fn init_repo(dir: &std::path::Path, id_name: &str) -> Result<(), String> {
    let ws = Workspace::init_at(dir, id_name)?;
    let dot = ws.dot().to_path_buf();
    let keypair = identity::generate_and_save(&dot, &format!("{id_name}@loot"))
        .map_err(|e| e.to_string())?;
    let pub_line = std::fs::read_to_string(dot.join("id.pub"))
        .map_err(|e| format!("read id.pub: {e}"))?;
    // Re-open now that the keypair exists so the repo is authored, then mint the
    // first change's durable handle (ADR 0029/0030) — the repo's first change,
    // like every later one, has a name from birth that `status`/`log` can show.
    let mut ws = Workspace::open_at(dir)?;
    ws.start_fresh_change()?;
    // Genesis operation: the floor of the op log, so `undo` always has an
    // initial view to walk back to and never below (ADR 0031).
    ws.record_op("init", "initialized repo", false);
    println!("initialized empty loot repo at {}, identity = {id_name}", dir.display());
    println!("public key: {}", pub_line.trim());
    println!("tip: share your public key with peers via `loot whoami`");
    println!("tip: declare per-file privacy in .lootattributes, e.g. `.env restricted={id_name}`");
    let _ = keypair;
    Ok(())
}

fn cmd_status(args: &[String]) -> Result<(), String> {
    let fmt = out_fmt(args);
    let mut ws = Workspace::open()?;
    // status is READ-ONLY (ADR 0030): it recomputes the pending delta live and
    // never persists a snapshot, so scripts and parallel agents can call it
    // freely. The version id it shows is live-computed and non-durable — the
    // durable handle a caller holds is the change id. `-m` is gone (naming is
    // `describe`'s job); a demotion can't happen without a mutating snapshot, so
    // there is no `--allow-demote` here either.
    let Some(row) = ws.live_working_row()? else {
        // No in-progress change and no eagerly-minted handle (a keyless/legacy
        // or freshly-initialized repo). Nothing pending to report.
        match fmt {
            OutFmt::Human => println!("no working change (run `loot new` to start one)"),
            OutFmt::Porcelain => print!("{}", verdict::status_porcelain(None, None, &[])),
            OutFmt::Json => println!("{}", verdict::status_json(None, None, &[])),
        }
        return Ok(());
    };

    // An empty working change (no delta over the tip) has no meaningful version
    // id or pending path listing — the durable change id is the only holdable
    // handle, so machine output emits just the `@` header, no `~` rows.
    let version = if row.empty { None } else { Some(&row.version) };
    let entries: &[(std::path::PathBuf, loot_core::Visibility)] =
        if row.empty { &[] } else { &row.entries };
    match fmt {
        OutFmt::Human => {
            let change = row.change_id.map(|c| short_change(&c)).unwrap_or_else(|| NO_ID.into());
            if row.empty {
                println!("working change {change} is empty (no changes since the last `new`)");
                return Ok(());
            }
            println!(
                "working change {change}  {}  \"{}\"",
                short(&row.version),
                row.message
            );
            for (path, vis) in &row.entries {
                println!("  {:<24} {}", path.display(), mark(vis));
            }
        }
        // status is not a merge: its own working-change shape (ADR 0023/0029).
        OutFmt::Porcelain => {
            print!("{}", verdict::status_porcelain(row.change_id, version, entries))
        }
        OutFmt::Json => {
            println!("{}", verdict::status_json(row.change_id, version, entries))
        }
    }
    Ok(())
}

fn cmd_describe(args: &[String]) -> Result<(), String> {
    let message = message_flag(args).ok_or("describe requires -m <message>")?;
    let allow_demote: Vec<std::path::PathBuf> =
        flag_values(args, "--allow-demote").into_iter().map(Into::into).collect();
    let mut ws = Workspace::open()?;
    // describe is the namer: it always records the tree (its whole job), so it
    // snapshots-and-names in one step — `--no-snapshot` does not apply. The
    // demotion guard still rides it via `--allow-demote`.
    let (id, _) = ws.snapshot_allowing(message, &allow_demote)?;
    println!("described working change {} as \"{message}\"", short(&id));
    ws.record_op("describe", &format!("named \"{message}\""), false);
    Ok(())
}

fn cmd_new(args: &[String]) -> Result<(), String> {
    let opts = SnapshotOpts::parse(args);
    let mut ws = Workspace::open()?;
    // Convenience `new -m <msg>`: name the working change before finalizing, so
    // finalize-and-name is one step (ADR 0030). It is a mutating snapshot, so it
    // honors the demotion guard via `--allow-demote`.
    if let Some(message) = message_flag(args) {
        ws.snapshot_allowing(message, &opts.allow_demote)?;
    }
    // Capture edits made since the last command before finalizing (ADR 0030),
    // so `edit; loot new` cannot lose work — no manual `loot status` needed.
    let finalized = ws.finalize_capturing(&opts.allow_demote, opts.skip)?;
    // `new` is the finalize/sign boundary and eagerly mints the *next* change's
    // durable handle (ADR 0029/0030), so the fresh change has a name from birth.
    let next = ws
        .next_change_id()
        .map(|c| short_change(&c))
        .unwrap_or_else(|| "a fresh change".to_string());
    let desc = match &finalized {
        Some(id) => format!("finalize {}", short(id)),
        None => "new (nothing to finalize)".to_string(),
    };
    match finalized {
        Some(id) => println!("finalized working change {}; started fresh change {next}", short(&id)),
        None => println!("nothing to finalize; started fresh change {next}"),
    }
    ws.record_op("new", &desc, false);
    Ok(())
}

/// `loot undo` — step the view back one operation (ADR 0031). Refuses across a
/// one-way barrier (push/grant/maroon/pull-grants) with the remedy to use instead.
fn cmd_undo() -> Result<(), String> {
    let mut ws = Workspace::open()?;
    let report = ws.undo()?;
    print_step(&report);
    Ok(())
}

/// `loot op log` | `loot op restore <n>` — inspect and jump the operation log.
fn cmd_op(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        None | Some("log") => cmd_op_log(),
        Some("restore") => {
            let target = args.get(1).ok_or("usage: loot op restore <op-number>")?;
            let n: u32 = target
                .parse()
                .map_err(|_| format!("op restore expects an operation number, got '{target}'"))?;
            let mut ws = Workspace::open()?;
            let report = ws.restore_op(n)?;
            print_step(&report);
            Ok(())
        }
        Some(other) => Err(format!(
            "unknown op subcommand '{other}' — use `loot op log` or `loot op restore <n>`"
        )),
    }
}

/// `loot op log` — the append-only operation history, newest first. Barrier ops
/// (one-way disclosures undo won't cross) are flagged.
fn cmd_op_log() -> Result<(), String> {
    let ws = Workspace::open()?;
    let ops = ws.op_log()?;
    if ops.is_empty() {
        println!("no operations recorded yet");
        return Ok(());
    }
    for op in ops.iter().rev() {
        let heads = op.heads();
        let head_col = if heads.is_empty() {
            String::new()
        } else {
            format!("  heads {{{}}}", heads.iter().map(short).collect::<Vec<_>>().join(", "))
        };
        let barrier = if op.barrier { "  ⚠ barrier" } else { "" };
        println!(
            "op {:<4} {:<11} {}{}{}",
            op.index, op.command, op.description, head_col, barrier
        );
    }
    Ok(())
}

/// Report what an `undo`/`op restore` did: which op the view now sits on, its
/// heads, and the working change (if any).
fn print_step(r: &StepReport) {
    let heads = if r.heads.is_empty() {
        "∅".to_string()
    } else {
        r.heads.iter().map(short).collect::<Vec<_>>().join(", ")
    };
    println!("{} — now at op {}, head {heads}", r.description, r.restored_to);
    if let Some(w) = &r.working {
        println!("  working change {}", short(w));
    }
}

fn cmd_surface() -> Result<(), String> {
    let mut ws = Workspace::open()?;
    let (head, written, skipped) = ws.surface_with_report()?;
    if written.is_empty() && skipped == 0 {
        println!("nothing to surface (no changes recorded)");
        return Ok(());
    }
    for (path, vis) in &written {
        println!("  {:<32} {}", path.display(), mark(vis));
    }
    if skipped > 0 {
        println!("  ({skipped} sealed path(s) skipped — request a grant to access them)");
    }
    println!("surfaced {} as {}", short(&head), ws.identity());
    Ok(())
}

fn cmd_docks() -> Result<(), String> {
    let ws = Workspace::open()?;
    for d in ws.dock_list() {
        let marker = if d.current { "*" } else { " " };
        let head = d.head.as_ref().map(short).unwrap_or_else(|| "(empty)".to_string());
        let vis = match d.visibility {
            Some((total, restricted, embargoed)) => seal_hint(total, restricted, embargoed),
            None => String::new(),
        };
        println!("{marker} {:<20} {}{}", d.name, head, vis);
    }
    Ok(())
}

fn cmd_gc(args: &[String]) -> Result<(), String> {
    let dry_run = args.iter().any(|a| a == "--dry-run" || a == "-n");
    let mut ws = Workspace::open()?;
    let report = ws.gc(dry_run)?;

    if report.pruned == 0 {
        println!("nothing to prune — every stored object is referenced by a change");
        return Ok(());
    }

    let human = human_bytes(report.bytes);
    if dry_run {
        println!(
            "would prune {} object(s), freeing {human} ({} bytes)",
            report.pruned, report.bytes
        );
        println!("  run `loot gc` (without --dry-run) to delete them");
    } else {
        println!(
            "pruned {} object(s), freed {human} ({} bytes)",
            report.pruned, report.bytes
        );
    }
    Ok(())
}

/// Render a byte count as a compact human-readable size (B / KiB / MiB / GiB).
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[0])
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

fn cmd_log() -> Result<(), String> {
    let mut ws = Workspace::open()?;
    // The live working row (ADR 0030): read-only, never persists — same figure
    // `status` shows, so the two agree on the working change. Computed first,
    // while the `&mut` borrow is free, then rendered last.
    let working = ws.live_working_row()?;
    // The in-progress working change is a graph head, so it appears in
    // `log_detailed`; render it *once*, as the live working row below, not also
    // as a finalized row (its persisted and live version ids differ, ADR 0030,
    // and two rows under one change id would misread as divergence).
    let working_node = ws.working_id().cloned();
    let identity = ws.identity().to_string();

    let detailed = ws.repo().log_detailed();
    if detailed.is_empty() && working.is_none() {
        println!("no changes yet");
        return Ok(());
    }

    // Resolve each change's author pubkey to a peer name (short-hex fallback),
    // reusing the peer registry (S3, ADR 0018). Author trust stays advisory —
    // this is display only. The change id (durable handle) rides its own column
    // as reverse-hex letters; the version id is the hex short (ADR 0029).
    let reg = identity::PeerRegistry::load(ws.dot());
    let own = ws.identity_pubkey();
    let change_of = |id: &Oid| match ws.repo().change_change_id(id) {
        Some(cid) => short_change(&cid),
        None => NO_ID.to_string(),
    };
    let author_of = |id: &Oid| match ws.repo().change_author(id) {
        // A change this identity authored resolves to its own name — the peer
        // registry holds peers, not self, so it would otherwise show hex.
        Some(pk) if own == Some(pk) => identity.clone(),
        Some(pk) => resolve_pubkey_name(&reg, &pk),
        None => String::new(),
    };
    let print_attestations = |id: &Oid| {
        for a in ws.repo().attestations_for(id) {
            println!("    + attested by {} ({})", resolve_pubkey_name(&reg, &a.attester), a.role);
        }
    };
    let row_of = |id: &Oid, message: &str, total: usize, restricted: usize, embargoed: usize| {
        log_row(
            &change_of(id),
            &short(id),
            message,
            &vis_col(total, restricted, embargoed),
            &author_of(id),
        )
    };

    // A single head keeps the flat, newest-first listing. Only a diverged graph
    // (2+ heads, e.g. after a pull) switches to a branch view.
    if ws.repo().heads().len() <= 1 {
        println!("{}", log_header());
        for (id, message, total, restricted, embargoed) in detailed.into_iter().rev() {
            if Some(&id) == working_node.as_ref() {
                continue; // shown once, as the live working row below
            }
            println!("{}", row_of(&id, &message, total, restricted, embargoed));
            print_attestations(&id);
        }
        if let Some(row) = &working {
            print_working_row(&identity, row);
        }
        return Ok(());
    }

    // Multi-head: show each head's own lineage indented under a label, then the
    // shared ancestry once. Makes the divergence visible before `loot apply`.
    // Per-change counts + message, keyed by version id, for the columnar rows.
    let meta: std::collections::BTreeMap<Oid, (String, usize, usize, usize)> = detailed
        .into_iter()
        .map(|(id, m, total, restricted, embargoed)| (id, (m, total, restricted, embargoed)))
        .collect();
    let node_row = |id: &Oid| match meta.get(id) {
        Some((m, total, restricted, embargoed)) => row_of(id, m, *total, *restricted, *embargoed),
        None => row_of(id, "", 0, 0, 0),
    };

    let g = ws.repo().log_graph();
    println!("{} heads — diverged; run `loot apply` to converge", g.heads.len());
    for (hi, head) in g.heads.iter().enumerate() {
        println!();
        println!("head {} — {}", hi + 1, short(head));
        println!("{}", log_header());
        for node in g.changes.iter().filter(|n| n.reachable_from == [hi]) {
            println!("{}", node_row(&node.id));
            print_attestations(&node.id);
        }
    }

    let shared: Vec<&loot_core::LogNode> =
        g.changes.iter().filter(|n| n.reachable_from.len() > 1).collect();
    if !shared.is_empty() {
        println!();
        println!("shared history");
        println!("{}", log_header());
        for node in shared {
            println!("{}", node_row(&node.id));
            print_attestations(&node.id);
        }
    }
    Ok(())
}

/// Render the working-change row for `log` (ADR 0030): the durable change id
/// (letters) + the live version id (hex, `—` when the change is empty), the
/// message, and the current identity as author. Shares the columnar shape with
/// the finalized rows so the two ids line up.
fn print_working_row(identity: &str, row: &workspace::WorkingRow) {
    let change = row.change_id.map(|c| short_change(&c)).unwrap_or_else(|| NO_ID.into());
    let (version, message) = if row.empty {
        (NO_ID.to_string(), "(working change, empty)".to_string())
    } else {
        (short(&row.version), row.message.clone())
    };
    println!("{}", log_row(&change, &version, &message, "", identity));
}

/// Annotate a change with its sealed/embargoed file counts, or "" if all public.
fn seal_hint(total: usize, restricted: usize, embargoed: usize) -> String {
    match (restricted, embargoed) {
        (0, 0) => String::new(),
        (r, 0) => format!("  [{r}/{total} sealed]"),
        (0, e) => format!("  [{e}/{total} embargoed]"),
        (r, e) => format!("  [{r} sealed, {e} embargoed / {total}]"),
    }
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
    let fmt = out_fmt(args);
    let infile = first_positional(args).ok_or("apply requires <file>")?;
    let bytes = std::fs::read(infile).map_err(|e| format!("read {infile}: {e}"))?;
    let mut ws = Workspace::open()?;
    let now = ws.now();
    let identity = ws.identity().to_string();
    let outcomes = ws.with_repo(|repo| {
        repo.apply(&SyncBundle(bytes), now).map_err(|e| e.to_string())
    })?;

    match fmt {
        OutFmt::Human => {
            if outcomes.is_empty() {
                println!("applied {infile}: nothing new (already up to date)");
            } else {
                println!("applied {infile} as {identity}:");
                for (path, outcome) in &outcomes {
                    println!("  {:<24} {}", path.display(), describe(outcome));
                }
                println!("run `loot surface` to materialize what you may see");
            }
        }
        // Machine output: just the verdict rows, no prose (empty -> no lines).
        OutFmt::Porcelain => print!("{}", verdict::porcelain(&verdicts_of(&outcomes))),
        OutFmt::Json => println!("{}", verdict::json(&verdicts_of(&outcomes))),
    }
    if !outcomes.is_empty() {
        ws.record_op("apply", &format!("apply {infile} ({} path(s))", outcomes.len()), false);
    }
    Ok(())
}

/// `loot ferry` — one bidirectional loot ↔ git mirror pass (GB1, ADR 0028).
/// A reconciliation verb, so it emits the shared verdict rows for the merge
/// outcomes when the two sides had diverged (CA3, ADR 0023).
fn cmd_ferry(args: &[String]) -> Result<(), String> {
    let fmt = out_fmt(args);
    let git_dir = flag(args, "--git-dir");
    let dock = flag(args, "--dock");
    let mut ws = Workspace::open()?;
    let report = ferry::run(&mut ws, git_dir, dock)?;

    match fmt {
        OutFmt::Human => {
            for note in &report.notes {
                println!("note: {note}");
            }
            if report.ingested == 0 && report.projected == 0 && report.outcomes.is_empty() {
                println!("ferry: up to date (nothing to ingest or project)");
            } else {
                println!(
                    "ferry: ingested {} git commit(s), projected {} loot change(s)",
                    report.ingested, report.projected
                );
                for (path, outcome) in &report.outcomes {
                    println!("  {:<24} {}", path.display(), describe(outcome));
                }
            }
        }
        // Machine output: the merge verdict rows only (empty -> no lines).
        OutFmt::Porcelain => print!("{}", verdict::porcelain(&verdicts_of(&report.outcomes))),
        OutFmt::Json => println!("{}", verdict::json(&verdicts_of(&report.outcomes))),
    }
    if report.ingested > 0 || report.projected > 0 || !report.outcomes.is_empty() {
        ws.record_op(
            "ferry",
            &format!("ferry (+{} ingested, +{} projected)", report.ingested, report.projected),
            false,
        );
    }
    Ok(())
}

fn cmd_grant(args: &[String]) -> Result<(), String> {
    if args.iter().any(|a| a == "--relay") {
        return cmd_grant_relay(args);
    }
    let pos = positionals(args);
    if pos.len() < 3 {
        return Err("grant requires <path> <identity> <file>\n  or: grant --relay <remote> <path> <identity>".into());
    }
    let path = pos[0];
    let grantee = pos[1];
    let out = pos[2];

    let opts = SnapshotOpts::parse(args);
    let mut ws = Workspace::open()?;
    // Capture the working tree first (ADR 0030) so the grant seals what is on
    // disk now, not a stale last-`status` snapshot.
    implicit_snapshot(&mut ws, &opts)?;
    let now = ws.now();

    let oid = ws
        .repo()
        .current_tree_oid(std::path::Path::new(path))
        .map_err(|_| format!("path '{path}' not found in current change"))?;

    let bundle = ws.with_repo(|repo| {
        repo.grant(&oid, grantee, now).map_err(|e| e.to_string())
    })?;
    std::fs::write(out, &bundle.0).map_err(|e| format!("write {out}: {e}"))?;
    println!(
        "wrote grant bundle {} ({} bytes) — send it to {grantee}",
        out,
        bundle.0.len()
    );
    println!("  {path} → {grantee} (recorded in manifest)");
    // A grant hands a content key to a peer — one-way (ADR 0031). Barrier.
    ws.record_op("grant", &format!("grant {path} → {grantee}"), true);
    Ok(())
}

fn cmd_grant_relay(args: &[String]) -> Result<(), String> {
    // Usage: grant --relay <remote-name-or-url> <path> <identity>
    let relay_target = flag(args, "--relay")
        .ok_or("grant --relay requires a relay name or URL after --relay")?;
    // Drop flags (and `--allow-demote`'s value) and the `--relay` target, leaving
    // the verb's own positionals.
    let positional: Vec<&str> = positionals(args)
        .into_iter()
        .filter(|a| *a != relay_target)
        .collect();
    if positional.len() < 2 {
        return Err("grant --relay <remote> <path> <identity>".into());
    }
    let path = positional[0];
    let grantee = positional[1];

    let opts = SnapshotOpts::parse(args);
    let mut ws = Workspace::open()?;
    // Capture the working tree first (ADR 0030) so the sealed grant covers the
    // path's current on-disk content.
    implicit_snapshot(&mut ws, &opts)?;
    let dot = ws.dot().to_owned();

    // Resolve the relay URL via the shared helper (consistent with push/pull).
    let url = resolve_remote(args, &ws)
        .unwrap_or_else(|_| relay_target.to_string());

    // Load our signing identity (grantor).
    let id = identity::load_or_missing(&dot).map_err(|e| e.to_string())?;
    let grantor_pubkey = id.public_key_bytes();

    // Look up recipient's ed25519 pubkey; derive x25519 for ECIES sealing.
    let reg = identity::PeerRegistry::load(&dot);
    let grantee_ed_pubkey = reg.pubkey_bytes(grantee)
        .map_err(|e| format!("peer '{grantee}': {e}"))?
        .ok_or_else(|| format!("peer '{grantee}' not found — run `loot peer add {grantee} <pubkey>` first"))?;
    let recipient_x25519 = identity::x25519_pubkey_from_ed25519_bytes(&grantee_ed_pubkey)
        .map_err(|e| format!("could not derive x25519 key for '{grantee}': {e}"))?;

    let now = ws.now();
    let oid = ws
        .repo()
        .current_tree_oid(std::path::Path::new(path))
        .map_err(|_| format!("path '{path}' not found in current change"))?;

    // An embargoed seal's grant inherits its reveal_at (ADR 0027): a late-added
    // recipient gets a timed grant the relay withholds like the push-time
    // deposits — never an immediately-delivered key. Everything else is an
    // ordinary untimed grant (reveal_at = 0).
    let reveal_at = match ws.repo().visibility_of(&oid) {
        Some(Visibility::Embargoed { reveal_at }) => reveal_at,
        _ => 0,
    };

    let bundle = ws.with_repo(|repo| {
        repo.grant_sealed(&oid, grantee, grantee_ed_pubkey, grantor_pubkey, reveal_at, now, |content_key| {
            identity::seal_key(content_key, &recipient_x25519)
                .map_err(|e| loot_core::RepoError::Backend(e.to_string()))
        }).map_err(|e| e.to_string())
    })?;

    // Wrap in a push envelope so the recipient can verify the grantor (ADR 0015).
    let envelope = id.wrap_envelope(&bundle.0);

    // Address the mailbox by grantee pubkey (loot-net hexes it; relay learns no names, ADR 0015).
    loot_net::deliver_grant(&url, &grantee_ed_pubkey, &envelope).map_err(|e| e.to_string())?;
    println!("delivered sealed grant for '{grantee}' via relay {url}");
    println!("  {path} → {grantee} (sealed, signed, recorded in manifest)");
    if reveal_at > 0 {
        println!("  timed: the relay withholds the key until {reveal_at} (hard embargo, ADR 0027)");
    }
    println!("  recipient runs `loot pull-grants` to receive it");
    // Sealed grant delivered to the relay — a one-way disclosure (ADR 0031).
    ws.record_op("grant", &format!("grant {path} → {grantee} (sealed)"), true);
    Ok(())
}

fn cmd_clone(args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err("clone requires <url> <dir>".into());
    }
    let url = &args[0];
    let dir = std::path::Path::new(args[1].as_str());

    let id_name = flag(args, "--identity")
        .map(String::from)
        .or_else(|| GlobalConfig::load().get("identity").map(String::from))
        .ok_or("clone requires --identity <name> (or set `identity` in `loot config`)")?;

    // Init repo at the target directory.
    init_repo(dir, &id_name)?;

    // Register origin so subsequent push/pull work out-of-the-box.
    let mut ws = Workspace::open_at(dir)?;
    ws.remote_add("origin", url)?;

    // Pull from the relay and surface what this identity can see.
    let now = ws.now();
    let have = ws.repo().heads();
    let bytes = loot_net::pull(url, &have).map_err(|e| e.to_string())?;
    if !bytes.is_empty() {
        let outcomes = ws.with_repo(|repo| {
            repo.apply(&SyncBundle(bytes), now).map_err(|e| e.to_string())
        })?;
        if !outcomes.is_empty() {
            println!("pulled {} change(s) from {url}", outcomes.len());
        }
    }
    ws.surface().map_err(|e| e.to_string())?;
    println!("cloned {url} → {}", dir.display());
    println!("run `loot status` to see the working tree");
    Ok(())
}

fn cmd_config(args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("list");
    match sub {
        "set" => {
            if args.len() < 3 {
                return Err("config set requires <key> <value>".into());
            }
            let key = &args[1];
            let val = &args[2];
            GlobalConfig::load().set(key, val)?;
            println!("set {key} = {val}");
            Ok(())
        }
        "unset" => {
            let key = args.get(1).ok_or("config unset requires <key>")?;
            GlobalConfig::load().unset(key)?;
            println!("unset {key}");
            Ok(())
        }
        "list" | "ls" => {
            let cfg = GlobalConfig::load();
            let pairs = cfg.list();
            if pairs.is_empty() {
                println!("global config is empty  (~/.config/loot/config)");
            } else {
                for (k, v) in pairs {
                    println!("{k} = {v}");
                }
            }
            Ok(())
        }
        other => Err(format!("unknown config subcommand '{other}': use set | unset | list")),
    }
}

fn cmd_maroon(args: &[String]) -> Result<(), String> {
    let hard = args.iter().any(|a| a == "--hard");
    let positional = positionals(args);
    if positional.len() < 2 {
        return Err("maroon requires <path> <identity> [dir]".into());
    }
    let path = std::path::Path::new(positional[0]);
    let marooned = positional[1];
    let out_dir = positional
        .get(2)
        .map(|s| std::path::Path::new(*s))
        .unwrap_or(std::path::Path::new("."));

    let opts = SnapshotOpts::parse(args);
    let mut ws = Workspace::open()?;
    // Re-seal against the working tree as it is now (ADR 0030).
    implicit_snapshot(&mut ws, &opts)?;
    let now = ws.now();
    let result: MaroonResult = ws.with_repo(|repo| {
        if hard {
            repo.maroon_hard(path, marooned, now).map_err(|e| e.to_string())
        } else {
            repo.maroon(path, marooned, now).map_err(|e| e.to_string())
        }
    })?;

    // Finalize (sign) the re-seal change so it propagates: the engine records it
    // authored-but-unsigned, and unsigned authored changes never travel via
    // push/bundle (ADR 0018). Without this, a maroon's re-seal is stranded on
    // the originator and peers keep reading the old content.
    ws.sign_change(&result.change_id)?;

    let level = if hard { "hard-marooned" } else { "marooned" };
    println!(
        "{} {} from {} (new oid: {})",
        level,
        marooned,
        path.display(),
        short(&result.new_oid)
    );
    if hard {
        println!("  purge event recorded — cooperating peers will remove {marooned}'s old key on next bundle apply");
    }
    println!("  {} no longer has future access", marooned);

    if result.grants.is_empty() {
        println!("  (no remaining grantees — content is now accessible only to you)");
    } else {
        std::fs::create_dir_all(out_dir)
            .map_err(|e| format!("create {}: {e}", out_dir.display()))?;
        for (grantee, bundle) in &result.grants {
            let filename = format!("grant-{grantee}.bundle");
            let dest = out_dir.join(&filename);
            std::fs::write(&dest, &bundle.0)
                .map_err(|e| format!("write {}: {e}", dest.display()))?;
            println!(
                "  grant bundle for {grantee}: {} ({} bytes) — send to {grantee} then `loot apply`",
                dest.display(),
                bundle.0.len()
            );
        }
        println!("  also run `loot bundle` to ship the re-sealed object to all peers");
    }
    // A maroon is an audited, one-way revocation of a restricted key (ADR 0031).
    ws.record_op("maroon", &format!("maroon {} ⁄ {marooned}", path.display()), true);
    Ok(())
}

fn parse_vis_spec(spec: &str) -> Result<Visibility, String> {
    if spec == "public" {
        Ok(Visibility::Public)
    } else if let Some(ids) = spec.strip_prefix("restricted=") {
        let ids: Vec<String> = ids.split(',').filter(|s| !s.is_empty()).map(String::from).collect();
        if ids.is_empty() {
            Err("restricted= requires at least one identity".into())
        } else {
            Ok(Visibility::Restricted(ids))
        }
    } else if let Some(reveal) = spec.strip_prefix("embargoed=") {
        let reveal_at: u64 = reveal.parse().map_err(|_| format!("embargoed= requires a unix timestamp, got '{reveal}'"))?;
        Ok(Visibility::Embargoed { reveal_at })
    } else {
        Err(format!("unknown vis-spec '{spec}': use public | restricted=a,b | embargoed=<unix_seconds>"))
    }
}

fn cmd_migrate(args: &[String]) -> Result<(), String> {
    let positional = positionals(args);
    if positional.len() < 2 {
        return Err("migrate requires <path> <vis-spec> [dir]".into());
    }
    let path = std::path::Path::new(positional[0]);
    let new_vis = parse_vis_spec(positional[1])?;
    let out_dir = positional
        .get(2)
        .map(|s| std::path::Path::new(*s))
        .unwrap_or(std::path::Path::new("."));

    let opts = SnapshotOpts::parse(args);
    let mut ws = Workspace::open()?;
    // Re-classify against the current on-disk tree (ADR 0030).
    implicit_snapshot(&mut ws, &opts)?;
    let now = ws.now();
    let result: MigrateResult = ws.with_repo(|repo| {
        repo.migrate(path, new_vis.clone(), now).map_err(|e| e.to_string())
    })?;

    let vis_label = verdict::visibility_token(&new_vis);
    println!(
        "migrated {} -> {} (new oid: {})",
        path.display(),
        vis_label,
        short(&result.new_oid)
    );

    if result.grants.is_empty() {
        println!("  run `loot bundle` to ship the re-sealed object to all peers");
    } else {
        std::fs::create_dir_all(out_dir)
            .map_err(|e| format!("create {}: {e}", out_dir.display()))?;
        for (grantee, bundle) in &result.grants {
            let filename = format!("grant-{grantee}.bundle");
            let dest = out_dir.join(&filename);
            std::fs::write(&dest, &bundle.0)
                .map_err(|e| format!("write {}: {e}", dest.display()))?;
            println!(
                "  grant bundle for {grantee}: {} ({} bytes) — send to {grantee} then `loot apply`",
                dest.display(),
                bundle.0.len()
            );
        }
        println!("  run `loot bundle` to ship the re-sealed object to all peers");
    }
    ws.record_op("migrate", &format!("migrate {} → {vis_label}", path.display()), false);
    Ok(())
}

fn cmd_dock(args: &[String]) -> Result<(), String> {
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    // Subcommand form: `loot dock merge <name>` collapses another dock's tip
    // into this one locally (CA2). Everything else is create/switch.
    if positional.first().map(|s| s.as_str()) == Some("merge") {
        let name = positional
            .get(1)
            .ok_or("usage: loot dock merge <name>")?;
        return cmd_dock_merge(name, args);
    }
    let name = positional
        .first()
        .ok_or("usage: loot dock <name> [--at <dir>]  |  loot dock merge <name>")?;
    let at = flag(args, "--at").map(std::path::PathBuf::from);
    let mut ws = Workspace::open()?;
    ws.create_dock(name, at.as_deref())?;
    match &at {
        Some(dir) => println!(
            "created dock '{name}' at {} — a separate working tree over this repo's shared store",
            dir.display()
        ),
        None => println!("on dock '{name}' — re-materialized its working tree here"),
    }
    ws.record_op("dock", &format!("dock {name}"), false);
    Ok(())
}

/// `loot dock merge <name> [--porcelain|--json]` — collapse another dock's tip
/// into this one (CA2). A reconciliation verb, so it emits the shared verdict
/// rows for the merge outcomes in machine formats (CA3, ADR 0023) — dropping the
/// typed outcomes at the `println!` boundary was the exact anti-pattern CA3
/// removed everywhere else (#126).
fn cmd_dock_merge(name: &str, args: &[String]) -> Result<(), String> {
    let fmt = out_fmt(args);
    let mut ws = Workspace::open()?;
    let current = ws.current_dock().unwrap_or("main").to_string();
    let (_source, outcomes) = ws.merge_dock(name)?;
    if !outcomes.is_empty() {
        ws.record_op("dock merge", &format!("merge {name} → {current}"), false);
    }

    match fmt {
        OutFmt::Human => {
            if outcomes.is_empty() {
                println!("merge '{name}' → '{current}': already up to date");
                return Ok(());
            }
            println!("merged dock '{name}' into '{current}':");
            for (path, outcome) in &outcomes {
                println!("  {:<24} {}", path.display(), describe(outcome));
            }
            let conflicts = outcomes
                .values()
                .filter(|o| matches!(o, MergeOutcome::Conflict { .. }))
                .count();
            if conflicts > 0 {
                println!("resolve {conflicts} conflict(s) with `loot resolve <path> <file>` — each advances this dock's tip");
            } else {
                println!("merge committed as this dock's tip; run `loot log` to see it");
            }
        }
        // Machine output: the merge verdict rows only, no prose (empty -> no lines).
        OutFmt::Porcelain => print!("{}", verdict::porcelain(&verdicts_of(&outcomes))),
        OutFmt::Json => println!("{}", verdict::json(&verdicts_of(&outcomes))),
    }
    Ok(())
}

fn cmd_manifest() -> Result<(), String> {
    let ws = Workspace::open()?;
    let dot = ws.dot().to_owned();
    let reg = identity::PeerRegistry::load(&dot);
    let entries: Vec<_> = ws.repo().manifest().iter().collect();
    if entries.is_empty() {
        println!("no grants recorded");
        return Ok(());
    }
    println!("{:<12} {:<16} {:<16} oid", "granted_at", "grantee", "grantor");
    println!("{}", "-".repeat(72));
    let mut sorted = entries;
    sorted.sort_by_key(|e| e.granted_at);
    for e in sorted {
        let grantor = if e.has_grantor() {
            resolve_pubkey_name(&reg, &e.grantor_pubkey)
        } else {
            "(file)".to_string()
        };
        println!("{:<12} {:<16} {:<16} {}", e.granted_at, e.grantee, grantor, short_oid(&e.oid));
    }

    // Attestations (S4, ADR 0018): advisory sign-offs over changes, by pubkey.
    let attestations = ws.repo().all_attestations();
    if !attestations.is_empty() {
        println!();
        println!("attestations:");
        for a in attestations {
            println!(
                "  {}  {} ({})",
                short_oid(&a.change_id),
                resolve_pubkey_name(&reg, &a.attester),
                a.role
            );
        }
    }
    Ok(())
}

/// Resolve a change-id hex prefix (as shown by `loot log`) to a full change id.
/// The ephemeral working change is excluded: its id is rewritten on every
/// snapshot, so an attestation over it would be orphaned the next time the tree
/// changes — finalize it with `loot new` first (S4, ADR 0018).
fn resolve_change(ws: &Workspace, prefix: &str) -> Result<loot_core::Oid, String> {
    let working = ws.working_id().cloned();
    if let Some(w) = &working {
        if loot_core::hex::encode(&w.0).starts_with(prefix) {
            return Err(
                "cannot attest the working change — its id is still changing; finalize it with `loot new` first"
                    .into(),
            );
        }
    }
    let matches: Vec<loot_core::Oid> = ws
        .repo()
        .log()
        .into_iter()
        .map(|(id, _)| id)
        .filter(|id| Some(id) != working.as_ref())
        .filter(|id| loot_core::hex::encode(&id.0).starts_with(prefix))
        .collect();
    match matches.len() {
        0 => Err(format!("no change matching '{prefix}'")),
        1 => Ok(matches.into_iter().next().unwrap()),
        n => Err(format!("ambiguous change prefix '{prefix}' — matches {n} changes")),
    }
}

fn cmd_attest(args: &[String]) -> Result<(), String> {
    let change_ref = args
        .first()
        .ok_or("usage: loot attest <change-id> [role]")?;
    let role = args.get(1).map(String::as_str).unwrap_or("reviewed");
    let mut ws = Workspace::open()?;
    let change_id = resolve_change(&ws, change_ref)?;
    ws.attest(&change_id, role)?;
    println!("attested {} as \"{}\"", short(&change_id), role);
    Ok(())
}

/// `loot buoy [role] [--verbose] [--porcelain|--json]`
///
/// Resolve the newest trusted role-attested change — the buoy (CA4, ADR 0025).
/// Returns its own ExitCode: 0 = resolved, 2 = no buoy, 3 = ambiguous, 1 = error.
fn cmd_buoy(args: &[String]) -> ExitCode {
    match cmd_buoy_inner(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("loot: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_buoy_inner(args: &[String]) -> Result<ExitCode, String> {
    // `--verbose`, `--porcelain`, `--json` are flags; the first non-flag arg is the role.
    let verbose = has_flag(args, "--verbose");
    let fmt = out_fmt(args);
    let role = first_positional(args).unwrap_or("reviewed");

    let ws = Workspace::open()?;
    let dot = ws.dot().to_owned();
    let reg = identity::PeerRegistry::load(&dot);

    // The local identity's own pubkey enables self-trust.
    let my_pubkey: Option<[u8; 32]> = if identity::keypair_exists(&dot) {
        let id = identity::load_or_missing(&dot).map_err(|e| e.to_string())?;
        Some(id.public_key_bytes())
    } else {
        None
    };

    // Build the trusted predicate: peer registry OR self.
    let trusted = |pk: &[u8; 32]| -> bool {
        if my_pubkey.as_ref() == Some(pk) {
            return true;
        }
        for (_name, pubkey_line) in reg.list() {
            if identity::PeerRegistry::parse_pubkey_bytes_from_line(pubkey_line)
                .map_or(false, |p| &p == pk)
            {
                return true;
            }
        }
        false
    };

    // Build the present-changes set and parent-lookup from the engine.
    use std::collections::BTreeSet;
    let present: BTreeSet<loot_core::Oid> = ws.repo().log().into_iter().map(|(id, _)| id).collect();
    let parents_fn = |id: &loot_core::Oid| ws.repo().parents_of(id);

    let all_attestations = ws.repo().all_attestations();

    // Collect verbose exclusions: trusted attestations naming absent changes.
    let excluded: Vec<&&loot_core::attestation::Attestation> = if verbose {
        all_attestations
            .iter()
            .filter(|a| a.role == role && a.verify() && trusted(&a.attester) && !present.contains(&a.change_id))
            .collect()
    } else {
        vec![]
    };

    let result = loot_core::buoy::resolve(
        &present,
        &parents_fn,
        all_attestations.iter().copied(),
        &trusted,
        role,
    );

    if verbose && !excluded.is_empty() {
        eprintln!("buoy: trusted attestations for changes absent locally:");
        for a in &excluded {
            eprintln!("  {} ({})", loot_core::hex::encode(&a.change_id.0), a.role);
        }
    }

    match result {
        loot_core::buoy::BuoyResult::Resolved { change, attesters } => {
            match fmt {
                OutFmt::Porcelain => {
                    print!("B\t{}\t{role}\n", loot_core::hex::encode(&change.0));
                }
                OutFmt::Json => {
                    let attesters_json: Vec<String> =
                        attesters.iter().map(|pk| loot_core::hex::encode(pk)).collect();
                    println!(
                        "{{\"contract\":{},\"role\":{role_json},\"status\":\"resolved\",\"buoy\":\"{hex}\",\"attesters\":[{atts}]}}",
                        loot_core::format::FORMAT_MAJOR,
                        role_json = json_str(role),
                        hex = loot_core::hex::encode(&change.0),
                        atts = attesters_json.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(","),
                    );
                }
                OutFmt::Human => {
                    let attester_names: Vec<String> =
                        attesters.iter().map(|pk| resolve_pubkey_name(&reg, pk)).collect();
                    println!(
                        "buoy ({}): {} — attested by {}",
                        role,
                        short(&change),
                        attester_names.join(", "),
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        loot_core::buoy::BuoyResult::Ambiguous { candidates } => {
            match fmt {
                OutFmt::Porcelain => {
                    for c in &candidates {
                        print!("A\t{}\t{role}\n", loot_core::hex::encode(&c.change.0));
                    }
                }
                OutFmt::Json => {
                    let cands_json: Vec<String> = candidates
                        .iter()
                        .map(|c| {
                            let atts: Vec<String> =
                                c.attesters.iter().map(|pk| format!("\"{}\"", loot_core::hex::encode(pk))).collect();
                            format!(
                                "{{\"change\":\"{}\",\"attesters\":[{}]}}",
                                loot_core::hex::encode(&c.change.0),
                                atts.join(","),
                            )
                        })
                        .collect();
                    println!(
                        "{{\"contract\":{},\"role\":{role_json},\"status\":\"ambiguous\",\"candidates\":[{cands}]}}",
                        loot_core::format::FORMAT_MAJOR,
                        role_json = json_str(role),
                        cands = cands_json.join(","),
                    );
                }
                OutFmt::Human => {
                    println!("ambiguous: {role} is attested on {} concurrent changes — attest one to resolve:", candidates.len());
                    for c in &candidates {
                        let names: Vec<String> =
                            c.attesters.iter().map(|pk| resolve_pubkey_name(&reg, pk)).collect();
                        println!("  {} (attested by {})", short(&c.change), names.join(", "));
                    }
                    println!("  run `loot attest <id> {role}` to pin one as the buoy");
                }
            }
            Ok(ExitCode::from(3))
        }
        loot_core::buoy::BuoyResult::None => {
            match fmt {
                OutFmt::Porcelain => {
                    // No lines — the exit code carries the signal.
                }
                OutFmt::Json => {
                    println!(
                        "{{\"contract\":{},\"role\":{role_json},\"status\":\"none\"}}",
                        loot_core::format::FORMAT_MAJOR,
                        role_json = json_str(role),
                    );
                }
                OutFmt::Human => {
                    println!("no buoy for role '{role}'");
                }
            }
            Ok(ExitCode::from(2))
        }
    }
}

/// Minimal JSON string escaping for role values (role is a free-form String).
fn json_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn resolve_pubkey_name(reg: &identity::PeerRegistry, pubkey: &[u8; 32]) -> String {
    for (name, pubkey_line) in reg.list() {
        if identity::PeerRegistry::parse_pubkey_bytes_from_line(pubkey_line)
            .map_or(false, |pk| &pk == pubkey)
        {
            return name.to_string();
        }
    }
    hex_short(pubkey)
}

fn cmd_conflicts(args: &[String]) -> Result<(), String> {
    let fmt = out_fmt(args);
    let ws = Workspace::open()?;
    let conflicts = ws.repo().conflicts();
    match fmt {
        OutFmt::Human => {
            if conflicts.is_empty() {
                println!("no conflicts");
                return Ok(());
            }
            for (path, (our_oid, their_oid)) in conflicts {
                println!("conflict at {}", path.display());
                println!("  ours:   {}", short(our_oid));
                println!("  theirs: {}", short(their_oid));
            }
        }
        // Every recorded conflict is a `C` row (ADR 0023); empty -> no lines.
        OutFmt::Porcelain => print!("{}", verdict::porcelain(&conflict_verdicts(conflicts))),
        OutFmt::Json => println!("{}", verdict::json(&conflict_verdicts(conflicts))),
    }
    Ok(())
}

fn cmd_resolve(args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err("resolve requires <path> <file>".into());
    }
    let path = std::path::Path::new(args[0].as_str());
    let infile = &args[1];

    let bytes = std::fs::read(infile).map_err(|e| format!("read {infile}: {e}"))?;

    let mut ws = Workspace::open()?;

    // Determine the visibility for this path from .lootattributes (same logic
    // snapshot uses). Unrecognized paths default to Public.
    let vis = ws.visibility_for(&path.to_string_lossy());

    let new_oid = ws.resolve_conflict(path, &bytes, vis)?;

    println!("resolved {} (new oid: {})", path.display(), short(&new_oid));
    ws.record_op("resolve", &format!("resolve {}", path.display()), false);

    // The resolution is signed on the spot; on a dock it also advanced the tip.
    if ws.repo().conflicts().is_empty() {
        if ws.current_dock().is_none() {
            println!("all conflicts resolved");
        } else {
            println!("all conflicts resolved — dock tip advanced");
        }
    }
    Ok(())
}

fn cmd_grants(args: &[String]) -> Result<(), String> {
    let ws = Workspace::open()?;
    let dot = ws.dot().to_owned();
    let url = resolve_remote(args, &ws)?;
    let id = identity::load_or_missing(&dot).map_err(|e| e.to_string())?;
    let count = loot_net::peek_grants(&url, &id.public_key_bytes()).map_err(|e| e.to_string())?;
    if count == 0 {
        println!("no pending grants at {url}");
    } else {
        println!("{count} grant(s) pending at {url} — run `loot pull-grants` to receive");
    }
    Ok(())
}

fn cmd_pull_grants(args: &[String]) -> Result<(), String> {
    let mut ws = Workspace::open()?;
    let dot = ws.dot().to_owned();
    let url = resolve_remote(args, &ws)?;

    let id = identity::load_or_missing(&dot).map_err(|e| e.to_string())?;
    let my_pubkey = id.public_key_bytes();
    let now = ws.now();

    // Fetch by pubkey — loot-net hexes it; relay addresses mailbox by pubkey, not name (ADR 0015).
    let envelopes = loot_net::fetch_grants(&url, &my_pubkey).map_err(|e| e.to_string())?;
    if envelopes.is_empty() {
        println!("no pending grants at {url}");
        return Ok(());
    }

    let reg = identity::PeerRegistry::load(&dot);
    let mut applied = 0usize;
    let mut quarantined = 0usize;

    for envelope_bytes in &envelopes {
        // Unwrap the push envelope: verifies grantor signature (ADR 0015).
        let (grantor_pubkey, bundle_bytes) =
            match identity::unwrap_envelope(envelope_bytes, &[]) {
                Ok(pair) => pair,
                Err(e) => {
                    eprintln!("loot: skipping grant (bad envelope): {e}");
                    continue;
                }
            };

        // Peer-registry gate: only accept grants from registered peers (ADR 0015).
        let grantor_known = reg.list()
            .iter()
            .any(|(_, pubkey_line)| {
                identity::PeerRegistry::parse_pubkey_bytes_from_line(pubkey_line)
                    .map_or(false, |pk| pk == grantor_pubkey)
            });
        if !grantor_known {
            eprintln!(
                "loot: quarantined grant from unknown key {} — run `loot peer add <name> <pubkey>` to trust",
                hex_short(&grantor_pubkey)
            );
            quarantined += 1;
            continue;
        }

        let bundle = loot_core::SyncBundle(bundle_bytes.to_vec());
        let result = ws.with_repo(|repo| {
            repo.apply_sealed_grant(&bundle, grantor_pubkey, now, |wrapped| {
                id.unseal_key(wrapped)
                    .map_err(|e| loot_core::RepoError::Backend(e.to_string()))
            }).map_err(|e| e.to_string())
        });
        match result {
            Ok(()) => applied += 1,
            Err(e) => eprintln!("loot: skipping grant (could not apply): {e}"),
        }
    }

    println!("applied {applied}/{n} grant(s) from {url}", n = envelopes.len());
    if quarantined > 0 {
        println!("  {quarantined} quarantined (unknown grantor) — register the sender as a peer to trust them");
    }
    if applied > 0 {
        println!("run `loot surface` to materialize newly-accessible content");
    }
    if applied > 0 {
        // pull-grants files keys into the keyring — key state undo never touches
        // (ADR 0031). Record as a barrier so `undo` refuses to sit "before" it.
        ws.record_op("pull-grants", &format!("pull-grants ({applied} applied)"), true);
    }
    Ok(())
}

// --- identity keypairs (ADR 0014, 0016) ---

fn cmd_id(args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("help");
    match sub {
        "export" => {
            let file = args.get(1).ok_or("id export requires <file>")?;
            let ws = Workspace::open()?;
            let dot = ws.dot();
            if !identity::keypair_exists(dot) {
                return Err("no identity keypair — run `loot keygen` to generate one".into());
            }
            let id = identity::load_or_missing(dot).map_err(|e| e.to_string())?;
            let passphrase = identity::prompt_new_passphrase().map_err(|e| e.to_string())?;
            id.export_encrypted(std::path::Path::new(file.as_str()), &passphrase, &format!("{}@loot", ws.identity()))
                .map_err(|e| e.to_string())?;
            println!("exported identity to {file} (passphrase-encrypted)");
            println!("  move this file to your other machine and run `loot id import {file}`");
            Ok(())
        }
        "import" => {
            let file = args.get(1).ok_or("id import requires <file>")?;
            let ws = Workspace::open()?;
            let dot = ws.dot();
            if identity::keypair_exists(dot) {
                return Err(
                    "a keypair already exists at .loot/id — remove it first if you want to replace it".into()
                );
            }
            let passphrase = identity::prompt_passphrase().map_err(|e| e.to_string())?;
            let id = identity::Identity::import_encrypted(std::path::Path::new(file.as_str()), &passphrase)
                .map_err(|e| e.to_string())?;
            id.save(dot, &format!("{}@loot", ws.identity()))
                .map_err(|e| e.to_string())?;
            let pub_line = std::fs::read_to_string(dot.join("id.pub"))
                .map_err(|e| format!("read id.pub: {e}"))?;
            println!("imported identity keypair");
            println!("public key: {}", pub_line.trim());
            Ok(())
        }
        _ => Err("id subcommands: export <file> | import <file>".into()),
    }
}

fn cmd_keygen() -> Result<(), String> {
    let ws = Workspace::open()?;
    let dot = ws.dot();
    if identity::keypair_exists(dot) {
        return Err("keypair already exists at .loot/id — remove it first if you want to regenerate".into());
    }
    let keypair = identity::generate_and_save(dot, &format!("{}@loot", ws.identity()))
        .map_err(|e| e.to_string())?;
    let pub_line = std::fs::read_to_string(dot.join("id.pub"))
        .map_err(|e| format!("read id.pub: {e}"))?;
    println!("generated keypair at .loot/id (private) and .loot/id.pub (public)");
    println!("public key: {}", pub_line.trim());
    let _ = keypair;
    Ok(())
}

fn cmd_whoami() -> Result<(), String> {
    let ws = Workspace::open()?;
    let dot = ws.dot();
    if !identity::keypair_exists(dot) {
        return Err("no identity keypair — run `loot keygen` to generate one".into());
    }
    let pub_line = std::fs::read_to_string(dot.join("id.pub"))
        .map_err(|e| format!("read id.pub: {e}"))?;
    let pub_line = pub_line.trim();
    println!("identity: {}", ws.identity());
    println!("pubkey:   {pub_line}");
    println!();
    println!("share with peers:  loot peer add {} {pub_line}", ws.identity());
    Ok(())
}

fn cmd_peer(args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("list");
    match sub {
        "add" => {
            if args.len() < 3 {
                return Err("peer add requires <name> <pubkey>".into());
            }
            let name = &args[1];
            let pubkey = &args[2];
            let ws = Workspace::open()?;
            let mut reg = identity::PeerRegistry::load(ws.dot());
            reg.add(name, pubkey);
            reg.save().map_err(|e| e.to_string())?;
            println!("registered peer '{name}'");
            Ok(())
        }
        "remove" | "rm" => {
            let name = args.get(1).ok_or("peer remove requires <name>")?;
            let ws = Workspace::open()?;
            let mut reg = identity::PeerRegistry::load(ws.dot());
            reg.remove(name);
            reg.save().map_err(|e| e.to_string())?;
            println!("removed peer '{name}'");
            Ok(())
        }
        "list" | "ls" => {
            let ws = Workspace::open()?;
            let reg = identity::PeerRegistry::load(ws.dot());
            let peers = reg.list();
            if peers.is_empty() {
                println!("no peers registered  (use `loot peer add <name> <pubkey>`)");
            } else {
                for (name, pubkey) in peers {
                    println!("{:<16} {pubkey}", name);
                }
            }
            Ok(())
        }
        other => Err(format!("unknown peer subcommand '{other}': use add | remove | list")),
    }
}

// --- named remotes (ADR 0013) ---

fn cmd_remote(args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("list");
    match sub {
        "add" => {
            if args.len() < 3 {
                return Err("remote add requires <name> <url>".into());
            }
            let name = &args[1];
            let url = &args[2];
            let ws = Workspace::open()?;
            ws.remote_add(name, url)?;
            println!("remote '{name}' → {url}");
            Ok(())
        }
        "remove" | "rm" => {
            let name = args.get(1).ok_or("remote remove requires <name>")?;
            let ws = Workspace::open()?;
            ws.remote_remove(name)?;
            println!("removed remote '{name}'");
            Ok(())
        }
        "list" | "ls" => {
            let ws = Workspace::open()?;
            let remotes = ws.remote_list();
            if remotes.is_empty() {
                println!("no remotes configured  (use `loot remote add origin <url>`)");
            } else {
                for (name, url) in remotes {
                    println!("{:<16} {url}", name);
                }
            }
            Ok(())
        }
        other => Err(format!("unknown remote subcommand '{other}': use add | remove | list")),
    }
}

// --- network sync (ADR 0011) ---

fn cmd_serve(args: &[String]) -> Result<(), String> {
    let dir = flag(args, "--dir").unwrap_or(".loot-relay");
    let addr = flag(args, "--addr").unwrap_or("127.0.0.1:4000");

    // Collect zero or more --allow <pubkey-hex> arguments.
    let allowed_keys: Vec<[u8; 32]> = {
        let mut keys = Vec::new();
        let mut i = 0;
        while i < args.len() {
            if args[i] == "--allow" {
                if let Some(hex) = args.get(i + 1) {
                    let bytes = parse_pubkey_hex(hex)?;
                    keys.push(bytes);
                    i += 2;
                    continue;
                }
            }
            i += 1;
        }
        keys
    };

    if allowed_keys.is_empty() {
        println!("starting open loot relay (dir = {dir}, addr = {addr}) — any signed push accepted");
    } else {
        println!("starting loot relay (dir = {dir}, addr = {addr}) — {n} key(s) allowed", n = allowed_keys.len());
    }
    println!("  a relay holds ciphertext and forwards it — it holds no keys and reads nothing");
    loot_net::serve(std::path::PathBuf::from(dir), addr, allowed_keys).map_err(|e| e.to_string())
}

fn parse_pubkey_hex(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err(format!("public key must be 64 hex chars (32 bytes), got {} chars", hex.len()));
    }
    loot_core::hex::decode_array::<32>(hex)
        .ok_or_else(|| format!("invalid hex in public key '{hex}'"))
}

fn resolve_remote(args: &[String], ws: &Workspace) -> Result<String, String> {
    // Explicit positional URL wins; then --remote <name>; then "origin" default.
    let positional = args.iter().find(|a| !a.starts_with('-')).map(String::as_str);
    if let Some(url) = positional {
        return Ok(url.to_string());
    }
    let name = flag(args, "--remote").unwrap_or("origin");
    ws.remote_url(name)
        .ok_or_else(|| format!("no remote '{name}' configured — use `loot remote add {name} <url>` or pass a URL directly"))
}

// 32 objects per batch: coarse enough for low round-trip count on typical
// pushes, fine enough that an interrupted transfer loses at most ~32 objects
// before the next re-negotiate checkpoint (ADR 0024).
const OBJECTS_PER_BATCH: usize = 32;

fn cmd_push(args: &[String]) -> Result<(), String> {
    let mut ws = Workspace::open()?;
    let url = resolve_remote(args, &ws)?;
    let id = identity::load_or_missing(ws.dot()).map_err(|e| e.to_string())?;
    // S5: offer our object addresses; the relay replies with the subset it is
    // missing, so we ship only new object bytes (re-push transfers ~0 objects).
    //
    // `have` is what the *relay* already holds — and a relay we push to may hold
    // none of our history (a first push to a fresh relay), so we cannot assume it
    // has our heads. Offer everything and let the object-level `wants` negotiation
    // dedup what it already has; change metadata is small and `stow` is idempotent,
    // so re-pushes stay cheap even though they re-send the change delta.
    let have: Vec<Oid> = Vec::new();
    let offered = ws.repo().offered_objects(&have);
    if offered.is_empty() && ws.repo().has_unsigned_tip() {
        return Err(
            "nothing to push: your working change has not been signed yet.\n\
             Run `loot new` (or sign the current change) before pushing."
                .into(),
        );
    }
    let wants = loot_net::wants(&url, &offered).map_err(|e| e.to_string())?;
    // S6: bundle_wanted_batched computes the shared change delta / keys /
    // attestations once and produces one SyncBundle per object batch. Each
    // bundle is stowed independently on the relay (stow is append-only +
    // idempotent), so an interrupted push resumes by re-negotiating and sending
    // only the objects not yet stowed. The empty-wants case always produces one
    // bundle so the change delta and attestations propagate even when no new
    // objects are needed.
    let bundles = ws
        .repo()
        .bundle_wanted_batched(&have, &wants, OBJECTS_PER_BATCH)
        .map_err(|e| e.to_string())?;
    let batch_count = bundles.len();
    for bundle in bundles {
        loot_net::push(&url, bundle.0, &id).map_err(|e| e.to_string())?;
    }
    println!(
        "pushed {} new object(s) to {url} in {batch_count} batch(es) — resumable (re-run to continue if interrupted)",
        wants.len(),
    );
    println!("  this published your sealed content to the relay (it still cannot read it)");

    // Hard embargo (ADR 0027): push is also when embargoed keys are deposited,
    // one timed SealedGrant per registered peer, withheld by the relay until
    // its clock passes reveal_at. Ciphertext traveled in the bundles above;
    // keys only ever travel wrapped, here.
    deposit_embargo_grants(&mut ws, &url, &id)?;
    // A push discloses to a relay — a one-way act undo cannot retract (ADR 0031).
    // Record it as a barrier so `undo` refuses to step across it.
    ws.record_op("push", &format!("push → {url}"), true);
    Ok(())
}

/// One planned hard-embargo deposit: a timed grant for `oid` to `peer`.
struct EmbargoDeposit {
    path: std::path::PathBuf,
    oid: Oid,
    peer: String,
    peer_pubkey: [u8; 32],
    reveal_at: u64,
}

/// Which (embargoed oid × registered peer) pairs still need a timed grant
/// deposited (ADR 0027: Embargoed means "everyone reads after reveal", so the
/// default recipient set is every registered peer). The manifest is the dedupe
/// ledger — a recorded (oid → peer) grant is never re-deposited, which is also
/// what makes an interrupted deposit loop resumable by re-running `loot push`.
fn plan_embargo_deposits(
    repo: &loot_core::DagRepo,
    peers: &[(String, [u8; 32])],
    own_pubkey: [u8; 32],
) -> Vec<EmbargoDeposit> {
    let mut plan = Vec::new();
    for (path, oid, reveal_at) in repo.embargoed_paths() {
        for (peer, peer_pubkey) in peers {
            if *peer_pubkey == own_pubkey {
                continue; // the originator already holds the key
            }
            let already_granted = repo
                .manifest()
                .grants_for(&oid)
                .iter()
                .any(|e| e.grantee_pubkey == *peer_pubkey);
            if !already_granted {
                plan.push(EmbargoDeposit {
                    path: path.clone(),
                    oid: oid.clone(),
                    peer: peer.clone(),
                    peer_pubkey: *peer_pubkey,
                    reveal_at,
                });
            }
        }
    }
    plan
}

/// Deposit a timed SealedGrant at the relay mailbox for every planned
/// (embargoed oid × peer) pair. Each deposit seals + delivers inside one
/// `with_repo` closure so a failed delivery never persists its manifest
/// record — the next push retries it instead of skipping it forever.
fn deposit_embargo_grants(
    ws: &mut Workspace,
    url: &str,
    id: &identity::Identity,
) -> Result<(), String> {
    let embargoed = ws.repo().embargoed_paths();
    if embargoed.is_empty() {
        return Ok(());
    }
    let reg = identity::PeerRegistry::load(ws.dot());
    let peers: Vec<(String, [u8; 32])> = reg
        .list()
        .iter()
        .filter_map(|(name, line)| {
            identity::PeerRegistry::parse_pubkey_bytes_from_line(line)
                .ok()
                .map(|pk| (name.to_string(), pk))
        })
        .collect();
    if peers.is_empty() {
        println!(
            "note: {} embargoed path(s) but no registered peers — no timed grants deposited.\n\
             \x20 Their keys stay on this machine; run `loot peer add <name> <pubkey>` and push again.",
            embargoed.len()
        );
        return Ok(());
    }

    let my_pubkey = id.public_key_bytes();
    let plan = plan_embargo_deposits(ws.repo(), &peers, my_pubkey);
    if plan.is_empty() {
        return Ok(());
    }
    let now = ws.now();
    for d in &plan {
        let recipient_x25519 = identity::x25519_pubkey_from_ed25519_bytes(&d.peer_pubkey)
            .map_err(|e| format!("could not derive x25519 key for '{}': {e}", d.peer))?;
        ws.with_repo(|repo| {
            let bundle = repo
                .grant_sealed(&d.oid, &d.peer, d.peer_pubkey, my_pubkey, d.reveal_at, now, |key| {
                    identity::seal_key(key, &recipient_x25519)
                        .map_err(|e| loot_core::RepoError::Backend(e.to_string()))
                })
                .map_err(|e| e.to_string())?;
            let envelope = id.wrap_envelope(&bundle.0);
            loot_net::deliver_grant(url, &d.peer_pubkey, &envelope).map_err(|e| e.to_string())
        })?;
        println!("  {} → {} (embargoed until {})", d.path.display(), d.peer, d.reveal_at);
    }
    println!(
        "deposited {} timed grant(s) — the relay withholds each key until its reveal time (ADR 0027)",
        plan.len()
    );
    Ok(())
}

fn cmd_pull(args: &[String]) -> Result<(), String> {
    let fmt = out_fmt(args);
    let mut ws = Workspace::open()?;
    let url = resolve_remote(args, &ws)?;
    let now = ws.now();
    let identity = ws.identity().to_string();
    let have = ws.repo().heads();
    // Our side before the pull — the tip the working directory reflects. After
    // ingesting a peer's divergent tip we collapse onto this (#128).
    let ours_before = have.first().cloned();
    // S5: negotiate object addresses before any object bytes move. The relay
    // offers the closure it would send; we reply with only the addresses we
    // lack; fetch returns a bundle limited to those. A re-pull with nothing new
    // transfers ~0 object bytes.
    let offered = loot_net::offer(&url, &have).map_err(|e| e.to_string())?;
    let wants = ws.repo().missing_objects(&offered);
    // S6: fetch objects in batches. Each applied batch is persisted (with_repo
    // saves), so an interrupted pull resumes by re-negotiating and fetching
    // only what's left.
    //
    // Two correctness points:
    //   - `have` is re-read after each batch so the relay's change-delta
    //     computation stays relative to our current heads, not the pre-pull
    //     snapshot. This keeps bandwidth proportional to actual progress.
    //   - outcomes are merged with converge::worst so a Conflict from one
    //     batch cannot be silently overwritten by a later Converged for the
    //     same path (apply_sync uses worst internally per call; we must honour
    //     the same rule across calls).
    //
    // Atomicity note (ADR 0024): if a batch fetch fails mid-pull the repo holds
    // change nodes referencing objects that have not yet arrived. Re-pulling
    // resolves this, but loot surface / loot log may error on those nodes until
    // the pull completes.
    let mut outcomes: std::collections::BTreeMap<std::path::PathBuf, MergeOutcome> =
        std::collections::BTreeMap::new();
    for batch in wants.chunks(OBJECTS_PER_BATCH) {
        let current_have = ws.repo().heads();
        let bytes = loot_net::fetch(&url, &current_have, batch).map_err(|e| e.to_string())?;
        let batch_outcomes = ws.with_repo(|repo| {
            repo.apply(&SyncBundle(bytes), now).map_err(|e| e.to_string())
        })?;
        for (path, outcome) in batch_outcomes {
            let slot = outcomes
                .entry(path)
                .or_insert(MergeOutcome::Converged);
            *slot = loot_core::converge::worst(slot.clone(), outcome);
        }
    }

    // Collapse any fork this pull (or a prior one) left us on into a single
    // materialized tip — the keyholder fork-collapse of ADR 0011 (#128). apply
    // only ingests + classifies; without this the peer sits on diverged heads
    // and its working tree shows only its own side. Merge outcomes fold in with
    // `worst`, so a relayed/conflicted path can't be masked by an earlier row.
    let converged = ws.converge_heads(ours_before.as_ref())?;
    for (path, outcome) in converged {
        let slot = outcomes.entry(path).or_insert(MergeOutcome::Converged);
        *slot = loot_core::converge::worst(slot.clone(), outcome);
    }

    match fmt {
        OutFmt::Human => {
            if outcomes.is_empty() {
                println!("pulled from {url}: nothing new (already up to date)");
            } else {
                println!("pulled from {url} as {identity}:");
                for (path, outcome) in &outcomes {
                    println!("  {:<24} {}", path.display(), describe(outcome));
                }
                println!("converged onto one line; run `loot surface` to materialize what you may see");
            }
        }
        // Machine output: the merge verdict rows only, no prose (empty -> no lines).
        OutFmt::Porcelain => print!("{}", verdict::porcelain(&verdicts_of(&outcomes))),
        OutFmt::Json => println!("{}", verdict::json(&verdicts_of(&outcomes))),
    }
    if !outcomes.is_empty() {
        ws.record_op("pull", &format!("pull from {url} ({} path(s))", outcomes.len()), false);
    }
    Ok(())
}

// --- formatting ---

fn mark(vis: &loot_core::Visibility) -> String {
    // One home for the visibility token, shared with the machine `status`
    // output (CA3). Human phrasing is unchanged: public / restricted=a,b /
    // embargoed@<ts>.
    verdict::visibility_token(vis)
}

/// Human phrasing for a merge outcome, naming the relay role explicitly.
fn describe(o: &MergeOutcome) -> &'static str {
    match o {
        MergeOutcome::Converged => "converged",
        MergeOutcome::Merged => "merged",
        MergeOutcome::Conflict { .. } => "conflict (needs resolution)",
        MergeOutcome::RelayedUnmerged => "relayed (sealed — you lack the key)",
    }
}

fn short(oid: &Oid) -> String {
    oid.0[..4].iter().map(|b| format!("{b:02x}")).collect()
}

fn short_oid(oid: &Oid) -> String {
    short(oid)
}

/// A change id's short display: the first 4 bytes as reverse-hex **letters**
/// (ADR 0029), e.g. `qsouzmpr` — the durable-handle twin of [`short`]'s hex
/// **digits**. The two alphabets disambiguate the ids at a glance.
fn short_change(cid: &[u8; 16]) -> String {
    loot_core::hex::short_letters(cid, 4)
}

/// The em dash shown where an id is absent — a legacy change with no change id,
/// or the empty working change's not-yet-computed version (ADR 0029/0030).
const NO_ID: &str = "—";

/// Header + one row of the columnar `log`/`status` display (ADR 0030): the two
/// ids ride their own columns so a change can carry both legibly. Column order
/// is **change · version · message · vis · author**.
fn log_header() -> String {
    log_row("change", "version", "message", "vis", "author")
}

fn log_row(change: &str, version: &str, message: &str, vis: &str, author: &str) -> String {
    // Trailing whitespace trimmed so empty tail columns don't dangle.
    format!("{change:<10} {version:<9} {message:<30} {vis:<12} {author}")
        .trim_end()
        .to_string()
}

/// The compact `vis` column for a finalized change: the count of sealed and/or
/// embargoed paths, or empty when the change is fully public.
fn vis_col(_total: usize, restricted: usize, embargoed: usize) -> String {
    match (restricted, embargoed) {
        (0, 0) => String::new(),
        (r, 0) => format!("{r} sealed"),
        (0, e) => format!("{e} embargoed"),
        (r, e) => format!("{r} sealed, {e} emb"),
    }
}

/// A pubkey prefix for display: first 4 bytes as hex, plus an ellipsis.
fn hex_short(bytes: &[u8]) -> String {
    format!("{}…", loot_core::hex::short(bytes, 4))
}

#[cfg(test)]
mod tests {
    use super::*;
    use loot_core::Visibility;

    /// #66 regression class: `loot gc` vanished from the CLI in a merge while
    /// its documentation survived. The usage text and the dispatch table must
    /// name exactly the same verbs — a documented verb that doesn't dispatch
    /// (or a dispatched verb that isn't documented) fails here.
    #[test]
    fn every_documented_verb_is_dispatched_and_vice_versa() {
        use std::collections::BTreeSet;
        let documented: BTreeSet<&str> = USAGE
            .lines()
            .filter_map(|l| l.trim_start().strip_prefix("loot "))
            .filter_map(|rest| rest.split_whitespace().next())
            .filter(|v| v.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
            .collect();
        let mut dispatched: BTreeSet<&str> = COMMANDS.iter().map(|(n, _)| *n).collect();
        dispatched.insert("buoy"); // dispatched before the table (own ExitCode)
        assert_eq!(
            documented, dispatched,
            "usage text and the COMMANDS dispatch table disagree on the verb set"
        );
    }

    #[test]
    fn describe_names_the_relay_role() {
        assert_eq!(describe(&MergeOutcome::Converged), "converged");
        assert_eq!(describe(&MergeOutcome::Merged), "merged");
        assert!(describe(&MergeOutcome::RelayedUnmerged).contains("sealed"));
        assert!(describe(&MergeOutcome::Conflict { ours: loot_core::Oid([0; 32]), theirs: loot_core::Oid([1; 32]) }).contains("conflict"));
    }

    #[test]
    fn mark_renders_visibility() {
        assert_eq!(mark(&Visibility::Public), "public");
        assert_eq!(mark(&Visibility::Restricted(vec!["a".into(), "b".into()])), "restricted=a,b");
        assert_eq!(mark(&Visibility::Embargoed { reveal_at: 5 }), "embargoed@5");
    }

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn out_fmt_selects_format_json_wins() {
        assert_eq!(out_fmt(&args(&["file"])), OutFmt::Human);
        assert_eq!(out_fmt(&args(&["file", "--porcelain"])), OutFmt::Porcelain);
        assert_eq!(out_fmt(&args(&["file", "--json"])), OutFmt::Json);
        // Explicit precedence: --json wins over --porcelain if both appear.
        assert_eq!(out_fmt(&args(&["--porcelain", "--json"])), OutFmt::Json);
    }

    #[test]
    fn first_positional_skips_flags_either_side() {
        assert_eq!(first_positional(&args(&["--porcelain", "b.bundle"])), Some("b.bundle"));
        assert_eq!(first_positional(&args(&["b.bundle", "--json"])), Some("b.bundle"));
        assert_eq!(first_positional(&args(&["--json"])), None);
    }

    #[test]
    fn verdicts_of_preserves_outcomes_in_path_order() {
        let mut m: std::collections::BTreeMap<std::path::PathBuf, MergeOutcome> =
            std::collections::BTreeMap::new();
        m.insert("b.rs".into(), MergeOutcome::Merged);
        m.insert("a.rs".into(), MergeOutcome::Converged);
        let v = verdicts_of(&m);
        // BTreeMap iteration is sorted, so rows are deterministic.
        assert_eq!(v[0].path, std::path::PathBuf::from("a.rs"));
        assert_eq!(v[0].outcome, MergeOutcome::Converged);
        assert_eq!(v[1].outcome, MergeOutcome::Merged);
    }

    #[test]
    fn conflict_verdicts_builds_conflict_rows() {
        let mut c: std::collections::BTreeMap<std::path::PathBuf, (Oid, Oid)> =
            std::collections::BTreeMap::new();
        c.insert("x".into(), (Oid([7; 32]), Oid([9; 32])));
        let v = conflict_verdicts(&c);
        assert_eq!(v[0].status_char(), 'C');
        assert_eq!(v[0].addrs(), (Some(Oid([7; 32])), Some(Oid([9; 32]))));
    }

    // --- hard-embargo CLI slice (#88, ADR 0027) ---

    use loot_core::{Change, DagRepo};

    fn tmp(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("loot-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// An alice repo holding one embargoed path; the minted key sits in her
    /// Escrow (originator staging, ADR 0007) until `reveal_at`.
    fn embargoed_repo(tag: &str, reveal_at: u64) -> (DagRepo, Oid) {
        let dir = tmp(tag);
        let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
        let vis = Visibility::Embargoed { reveal_at };
        let oid = repo.put(b"embargoed plans\n", vis.clone()).unwrap();
        let mut tree = std::collections::BTreeMap::new();
        tree.insert(std::path::PathBuf::from("plans.md"), (oid.clone(), vis));
        repo.record(Change { id: Oid([0; 32]), parents: vec![], message: "init".into(), tree })
            .unwrap();
        (repo, oid)
    }

    fn peer(name: &str, byte: u8) -> (String, [u8; 32]) {
        (name.to_string(), [byte; 32])
    }

    #[test]
    fn plan_deposits_one_timed_grant_per_registered_peer() {
        let (repo, oid) = embargoed_repo("plan-fanout", 9_999);
        let peers = vec![peer("bob", 0xbb), peer("carol", 0xcc)];
        let plan = plan_embargo_deposits(&repo, &peers, [0xaa; 32]);
        assert_eq!(plan.len(), 2, "one deposit per registered peer");
        assert!(plan.iter().all(|d| d.oid == oid && d.reveal_at == 9_999));
        assert!(plan.iter().all(|d| d.path == std::path::PathBuf::from("plans.md")));
    }

    #[test]
    fn plan_skips_already_granted_peers_and_the_originator() {
        let (mut repo, oid) = embargoed_repo("plan-dedupe", 9_999);
        // bob already got his timed grant on an earlier push (manifest records it).
        repo.grant_sealed(&oid, "bob", [0xbb; 32], [0xaa; 32], 9_999, 0, |_| Ok([0u8; 80]))
            .unwrap();
        // alice's own key is registered as a peer too (e.g. a second machine).
        let peers = vec![peer("alice", 0xaa), peer("bob", 0xbb), peer("carol", 0xcc)];
        let plan = plan_embargo_deposits(&repo, &peers, [0xaa; 32]);
        assert_eq!(plan.len(), 1, "only the late-added peer still needs a deposit");
        assert_eq!(plan[0].peer, "carol");
    }

    #[test]
    fn plan_ignores_non_embargoed_paths() {
        let dir = tmp("plan-public");
        let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
        let oid = repo.put(b"open\n", Visibility::Public).unwrap();
        let mut tree = std::collections::BTreeMap::new();
        tree.insert(std::path::PathBuf::from("open.md"), (oid, Visibility::Public));
        repo.record(Change { id: Oid([0; 32]), parents: vec![], message: "init".into(), tree })
            .unwrap();
        assert!(plan_embargo_deposits(&repo, &[peer("bob", 0xbb)], [0xaa; 32]).is_empty());
    }

    #[test]
    fn plan_is_empty_for_a_non_keyholder() {
        // bob applied alice's bundle: he holds the embargoed ciphertext and the
        // tree, but no key (v5 bundles have no embargoed-key lane, ADR 0027) —
        // so he has nothing to deposit for anyone.
        let (mut alice, _) = embargoed_repo("plan-nonkey", 9_999);
        let bundle = alice.bundle(&[]).unwrap();
        let mut bob = DagRepo::init(tmp("plan-nonkey-bob").join("work"), "bob").unwrap();
        bob.apply(&bundle, 0).unwrap();
        assert!(plan_embargo_deposits(&bob, &[peer("carol", 0xcc)], [0xbb; 32]).is_empty());
    }

    fn contains_key(hay: &[u8], key: &[u8; 32]) -> bool {
        hay.windows(32).any(|w| w == key)
    }

    /// AC (#88): no plaintext embargoed key ever leaves the originator machine.
    /// The raw key surfaces exactly once — inside `grant_sealed`'s seal closure —
    /// so capture it there and assert it appears in no outbound bytes: not in
    /// the SealedGrant frame (only the ECIES-wrapped form travels) and not in
    /// any push bundle (v5 removed the plaintext escrow lane).
    #[test]
    fn no_plaintext_embargoed_key_in_grant_frames_or_push_bundles() {
        let (mut alice, oid) = embargoed_repo("leak", 9_999_999);
        let bob = identity::Identity::generate();
        let bob_x25519 = bob.x25519_pubkey_bytes();

        let mut raw_key = [0u8; 32];
        let grant = alice
            .grant_sealed(&oid, "bob", bob.public_key_bytes(), [0xaa; 32], 9_999_999, 0, |k| {
                raw_key = *k;
                identity::seal_key(k, &bob_x25519)
                    .map_err(|e| loot_core::RepoError::Backend(e.to_string()))
            })
            .unwrap();
        assert_ne!(raw_key, [0u8; 32], "the seal closure must have seen the key");
        assert!(!contains_key(&grant.0, &raw_key), "grant frame must carry only the wrapped key");

        let offered = alice.offered_objects(&[]);
        let bundles = alice.bundle_wanted_batched(&[], &offered, 8).unwrap();
        assert!(!bundles.is_empty());
        for b in &bundles {
            assert!(!contains_key(&b.0, &raw_key), "push bundles must never carry the raw key");
        }
    }

    /// AC (#88) end-to-end over a real relay: push-time deposits fan out one
    /// timed grant per registered peer; the relay withholds a not-yet-due key
    /// and releases a due one; re-running deposits nothing new (manifest
    /// dedupe); a late-added peer gets grants from the next pass; the delivered
    /// grant files the key so the recipient can read.
    #[test]
    fn push_deposit_flow_delivers_embargoed_keys_only_when_due() {
        let relay_dir = tmp("relay-deposit");
        let addr = "127.0.0.1:47301";
        let base = format!("http://{addr}");
        std::thread::spawn(move || {
            let _ = loot_net::serve(relay_dir, addr, vec![]);
        });
        for _ in 0..50 {
            if loot_net::pull(&base, &[]).is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let alice_dir = tmp("alice-deposit");
        init_repo(&alice_dir, "alice").unwrap();
        let mut ws = Workspace::open_at(&alice_dir).unwrap();
        let id = identity::load_or_missing(ws.dot()).map_err(|e| e.to_string()).unwrap();

        // One embargo already due (reveal passed) and one far in the future.
        let due_vis = Visibility::Embargoed { reveal_at: wall.saturating_sub(60) };
        let future_vis = Visibility::Embargoed { reveal_at: wall + 3600 };
        let due_oid = ws
            .with_repo(|repo| {
                let a = repo.put(b"due\n", due_vis.clone()).map_err(|e| e.to_string())?;
                let b = repo.put(b"future\n", future_vis.clone()).map_err(|e| e.to_string())?;
                let mut tree = std::collections::BTreeMap::new();
                tree.insert(std::path::PathBuf::from("due.md"), (a.clone(), due_vis.clone()));
                tree.insert(std::path::PathBuf::from("future.md"), (b, future_vis.clone()));
                repo.record(Change { id: Oid([0; 32]), parents: vec![], message: "init".into(), tree })
                    .map_err(|e| e.to_string())?;
                Ok(a)
            })
            .unwrap();

        let bob = identity::Identity::generate();
        let mut reg = identity::PeerRegistry::load(ws.dot());
        reg.add("bob", &bob.public_key_openssh("bob@loot").unwrap());
        reg.save().unwrap();

        deposit_embargo_grants(&mut ws, &base, &id).unwrap();

        // Two grants deposited for bob; the relay releases only the due one.
        assert_eq!(loot_net::peek_grants(&base, &bob.public_key_bytes()).unwrap(), 1);

        // Idempotent: a second pass finds everything already granted.
        deposit_embargo_grants(&mut ws, &base, &id).unwrap();
        assert_eq!(loot_net::peek_grants(&base, &bob.public_key_bytes()).unwrap(), 1);

        // Late recipient: carol registers after the first push and still gets hers.
        let carol = identity::Identity::generate();
        reg.add("carol", &carol.public_key_openssh("carol@loot").unwrap());
        reg.save().unwrap();
        deposit_embargo_grants(&mut ws, &base, &id).unwrap();
        assert_eq!(loot_net::peek_grants(&base, &carol.public_key_bytes()).unwrap(), 1);

        // Bob pulls: the due grant verifies, files the key, and the content reads.
        let envelopes = loot_net::fetch_grants(&base, &bob.public_key_bytes()).unwrap();
        assert_eq!(envelopes.len(), 1, "the future-dated grant stays withheld");
        let (grantor, bundle_bytes) = identity::unwrap_envelope(&envelopes[0], &[]).unwrap();
        assert_eq!(grantor, id.public_key_bytes());
        let mut bob_repo = DagRepo::init(tmp("bob-deposit").join("work"), "bob").unwrap();
        bob_repo
            .apply_sealed_grant(&SyncBundle(bundle_bytes.to_vec()), grantor, wall, |w| {
                bob.unseal_key(w).map_err(|e| loot_core::RepoError::Backend(e.to_string()))
            })
            .unwrap();
        assert_eq!(bob_repo.get(&due_oid, "bob", wall).unwrap(), b"due\n");
    }

    // --- S1: implicit auto-snapshot on mutating verbs (#144, ADR 0030) ---

    fn no_opts() -> SnapshotOpts {
        SnapshotOpts { allow_demote: vec![], skip: false }
    }

    /// `--allow-demote` is repeatable; either skip flag sets `skip`.
    #[test]
    fn snapshot_opts_parse_globals() {
        let o = SnapshotOpts::parse(&args(&["--allow-demote", "a.txt", "--allow-demote", "b.txt"]));
        assert_eq!(o.allow_demote, vec![std::path::PathBuf::from("a.txt"), std::path::PathBuf::from("b.txt")]);
        assert!(!o.skip);
        assert!(SnapshotOpts::parse(&args(&["--no-snapshot"])).skip);
        assert!(SnapshotOpts::parse(&args(&["--ignore-working-copy"])).skip);
        assert!(!SnapshotOpts::parse(&args(&["x"])).skip);
    }

    /// The verb's own positionals survive with the `--allow-demote <path>` pair
    /// (flag *and* value) and bare flags stripped — so a demotion path is never
    /// read as a positional, wherever the flag sits.
    #[test]
    fn positionals_strip_allow_demote_value_and_bare_flags() {
        assert_eq!(positionals(&args(&["p", "id", "f", "--no-snapshot"])), vec!["p", "id", "f"]);
        assert_eq!(
            positionals(&args(&["--allow-demote", "secret.txt", "p", "id", "f"])),
            vec!["p", "id", "f"]
        );
        assert_eq!(
            positionals(&args(&["p", "--hard", "id", "--allow-demote", "x", "dir"])),
            vec!["p", "id", "dir"]
        );
    }

    /// A file written but never `status`-ed is captured by `loot new` and lands
    /// in finalized history — the headline of the trigger moving to implicit.
    #[test]
    fn new_captures_pending_edits_without_a_manual_status() {
        let dir = tmp("s1-new-capture");
        init_repo(&dir, "alice").unwrap();
        std::fs::write(dir.join("a.txt"), b"hello\n").unwrap();

        let mut ws = Workspace::open_at(&dir).unwrap();
        ws.finalize_capturing(&[], false).unwrap();

        // Finalized: no working change left, one change carrying a.txt.
        assert!(ws.working_id().is_none());
        let log = ws.repo().log();
        assert_eq!(log.len(), 1, "exactly one finalized change");
        let tree = ws.repo().change_tree(&log[0].0).unwrap();
        assert!(tree.contains_key(std::path::Path::new("a.txt")), "a.txt captured: {tree:?}");
    }

    /// A bare `loot new` with nothing pending must not mint an empty signed
    /// change — the duplicate/empty capture is dropped before finalize.
    #[test]
    fn bare_new_mints_no_empty_change() {
        let dir = tmp("s1-new-empty");
        init_repo(&dir, "alice").unwrap();
        let mut ws = Workspace::open_at(&dir).unwrap();
        ws.finalize_capturing(&[], false).unwrap();
        assert!(ws.repo().log().is_empty(), "no spurious empty change: {:?}", ws.repo().log());
    }

    /// An implicit capture re-records the tree without clobbering a name a
    /// prior `describe` set (working_message is preserved).
    #[test]
    fn implicit_snapshot_preserves_describe_name() {
        let dir = tmp("s1-preserve-name");
        init_repo(&dir, "alice").unwrap();
        let mut ws = Workspace::open_at(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"v1\n").unwrap();
        ws.snapshot_allowing("the intro", &[]).unwrap(); // like `describe -m`
        assert_eq!(ws.working_message().as_deref(), Some("the intro"));

        std::fs::write(dir.join("a.txt"), b"v2\n").unwrap();
        implicit_snapshot(&mut ws, &no_opts()).unwrap();
        assert_eq!(ws.working_message().as_deref(), Some("the intro"), "name survives implicit capture");
    }

    /// `--no-snapshot` acts on the last recorded working change: a later edit is
    /// not captured, so the working change id is unchanged; without the flag the
    /// same edit is captured and the id moves.
    #[test]
    fn no_snapshot_skips_the_implicit_capture() {
        let dir = tmp("s1-skip");
        init_repo(&dir, "alice").unwrap();
        let mut ws = Workspace::open_at(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"v1\n").unwrap();
        ws.snapshot_allowing("(working change)", &[]).unwrap();
        let before = ws.working_id().cloned();

        std::fs::write(dir.join("a.txt"), b"v2\n").unwrap();
        implicit_snapshot(&mut ws, &SnapshotOpts { allow_demote: vec![], skip: true }).unwrap();
        assert_eq!(ws.working_id(), before.as_ref(), "skip leaves the working change untouched");

        implicit_snapshot(&mut ws, &no_opts()).unwrap();
        assert_ne!(ws.working_id(), before.as_ref(), "a real capture moves the working change");
    }
}
