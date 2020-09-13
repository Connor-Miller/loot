//! `loot` — a CLI over the canonical engine (ADR 0005, 0006).
//!
//! JJ-style: the working tree *is* the current change. `status` snapshots it,
//! `describe` names it, `new` finalizes it and starts fresh. No commit ceremony.
//! All ambient state (`.loot/` home, identity, clock, persistence, working-change
//! id) is owned by the [`Workspace`]; commands are thin verbs over it.

use loot_cli::emit::{self, Emit, OutFmt};
use loot_cli::flags::{FlagCheck, FlagSpec};
use loot_cli::{ferry, render, workspace};
use loot_core::{
    verdict, MaroonResult, MergeOutcome, MigrateResult, Oid, PathVerdict, Visibility,
};
use loot_identity as identity;
use render::{
    change_col, delta_line, outcome_rows, render_buoy_human, render_grant_status, render_history,
    short, short_change,
};
use std::fmt::Write as _;
use std::process::ExitCode;
use workspace::{
    GlobalConfig, LaneStatus, SnapshotOpts, StepReport, SweepOutcome, Workspace, LANE_STALE_SECS,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    let rest = &args[args.len().min(1)..];

    // `buoy` returns its own ExitCode (0/2/3/1) rather than the generic Ok/Err.
    if cmd == "buoy" {
        return match BUOY_FLAGS.check(rest) {
            Ok(FlagCheck::Help) => {
                print_help();
                ExitCode::SUCCESS
            }
            Ok(FlagCheck::Proceed) => cmd_buoy(rest),
            Err(e) => {
                eprintln!("loot: {e}");
                ExitCode::FAILURE
            }
        };
    }

    let result = match cmd {
        "help" | "-h" | "--help" => {
            print_help();
            Ok(())
        }
        "-V" | "--version" => {
            println!("{}", version_line());
            Ok(())
        }
        other => match COMMANDS.iter().find(|v| v.spec.name == other) {
            // The flag gate runs *before* the verb (#67): a verb never sees an
            // argument list holding a flag it does not understand, so a typo
            // can't read as "no filter requested" and quietly do something else.
            Some(v) => match v.spec.check(rest) {
                Ok(FlagCheck::Help) => {
                    print_help();
                    Ok(())
                }
                Ok(FlagCheck::Proceed) => (v.run)(rest),
                Err(e) => Err(e),
            },
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

/// A dispatchable verb: what it is called, which flags it accepts (#67, gated
/// by [`FlagSpec::check`] before the verb runs), and how to run it.
struct Verb {
    spec: FlagSpec,
    run: fn(&[String]) -> Result<(), String>,
}

const fn verb(
    name: &'static str,
    valued: &'static [&'static str],
    bare: &'static [&'static str],
    run: fn(&[String]) -> Result<(), String>,
) -> Verb {
    Verb { spec: FlagSpec { bin: "loot", name, valued, bare }, run }
}

/// The two globals every snapshotting verb carries (ADR 0030): `--allow-demote
/// <path>` (repeatable) and the two spellings of the capture skip.
const DEMOTE: &[&str] = &["--allow-demote"];
const SKIP: &[&str] = &["--no-snapshot", "--ignore-working-copy"];
/// The machine-output selectors (CA3, ADR 0023).
const OUT: &[&str] = &["--porcelain", "--json"];

/// Every dispatchable verb in one table the dispatcher and the usage test
/// share, so a verb cannot silently vanish from the CLI while its usage line
/// survives — the #66 regression class (`loot gc` dropped in a merge).
/// `buoy` is dispatched separately (it returns its own ExitCode) and `help`
/// is a match arm; everything else lives here.
const COMMANDS: &[Verb] = &[
    verb("init", &["--identity"], &[], cmd_init),
    verb("status", &[], OUT, cmd_status),
    verb("diff", &["--conflict"], &[], cmd_diff),
    verb("describe", &["-m", "--message", "--allow-demote"], &[], cmd_describe),
    verb("new", &["-m", "--message", "--allow-demote"], SKIP, cmd_new),
    verb("edit", &[], &[], cmd_edit),
    verb("abandon", &[], &["--head"], cmd_abandon),
    verb("adopt", &[], &["--discard-wip"], cmd_adopt),
    verb("undo", &[], &[], |_| cmd_undo()),
    verb("op", &[], &[], cmd_op),
    verb("surface", &[], &[], |_| cmd_surface()),
    verb("lane", &["--ticket", "--name", "--at", "--stale-hours"], OUT, cmd_lane),
    verb("lanes", &[], OUT, cmd_lane_list),
    verb("log", &["--path"], &[], cmd_log),
    verb("gc", &[], &["--dry-run", "-n"], cmd_gc),
    verb("verify", &[], &["--accept-loss"], cmd_verify),
    verb("bundle", &[], &[], cmd_bundle),
    verb("apply", &[], OUT, cmd_apply),
    verb("grant", &["--relay", "--allow-demote"], SKIP, cmd_grant),
    verb("grant-status", &[], &[], cmd_grant_status),
    verb("maroon", DEMOTE, &["--hard", "--no-snapshot", "--ignore-working-copy"], cmd_maroon),
    verb("migrate", DEMOTE, SKIP, cmd_migrate),
    verb("manifest", &[], &[], |_| cmd_manifest()),
    verb("attest", &[], &[], cmd_attest),
    verb("conflicts", &[], OUT, cmd_conflicts),
    verb("resolve", &[], &[], cmd_resolve),
    verb("remote", &[], &[], cmd_remote),
    verb("keygen", &[], &[], |_| cmd_keygen()),
    verb("whoami", &[], &["--pubkey"], cmd_whoami),
    verb("peer", &[], &[], cmd_peer),
    verb("serve", &["--dir", "--addr", "--allow"], &[], cmd_serve),
    verb("push", &["--remote"], &[], cmd_push),
    verb("pull", &["--remote"], &["--no-surface", "--porcelain", "--json"], cmd_pull),
    verb("pull-grants", &["--remote"], &[], cmd_pull_grants),
    verb("grants", &["--remote"], &[], cmd_grants),
    verb("clone", &["--identity"], &[], cmd_clone),
    verb("config", &[], &[], cmd_config),
    verb("id", &[], &[], cmd_id),
    verb("ferry", &["--git-dir", "--dock"], &["--with-wip", "--porcelain", "--json"], cmd_ferry),
    verb("completions", &[], &[], cmd_completions),
];

/// `buoy`'s flag spec. It dispatches ahead of [`COMMANDS`] (it returns its own
/// ExitCode), so its flags are declared here rather than in the table.
const BUOY_FLAGS: FlagSpec = FlagSpec {
    bin: "loot",
    name: "buoy",
    valued: &[],
    bare: &["--verbose", "--porcelain", "--json"],
};

const USAGE: &str = "\
usage:
  loot init [--identity <name>]             initialize a repo here (identity from global config if omitted)
  loot clone <url> <dir> [--identity <name>]  clone a relay into <dir>
  loot config [set <key> <val>] [unset <key>] [list]  manage global config (~/.config/loot/config)
  loot status [--porcelain|--json]          show the working change read-only (live version id + durable change id; no snapshot)
  loot diff [<from>] [<to>]                 show which paths changed between two changes (defaults: HEAD vs @ working); selectors: @, HEAD, HEAD~<n>, id prefix
  loot diff --conflict <path>               inspect both sides (ours/theirs) of a recorded conflict; decrypts when the key is held, else shows the OIDs
  loot describe -m <message> [--allow-demote <path>]...  record the tree and name the working change
  loot new [-m <message>] [--no-snapshot]   finalize the working change (sign) and start a fresh one; prints the next change id
  loot edit <change-id>                     reopen a finalized tip change as the working change, superseding it on finalize (amend, ADR 0032); refuses on uncaptured edits
  loot abandon <selector>                   drop a version from a divergent change (marked `!` in log), leaving one; undoable; selectors: @, HEAD, HEAD~<n>, id prefix
  loot abandon --head <selector>            drop an independent live head (a whole fork tip); undoable
  loot adopt                                catch this position up to landed main by merging it in (keeps the local line); undoable
  loot adopt <version-id> [--discard-wip]   settle this position onto a landed change, discarding the divergent line (no merge); undoable
  loot undo                                 step the view back one operation (refuses across a push/grant/maroon barrier)
  loot op log                               list the operation log (newest first; barriers flagged)
  loot op restore <n>                       jump the view to operation <n> (redo lands here after an undo)
  loot surface                              materialize what the current identity may see
  loot log [<selector>] [--path <path>]     show change history, or the ancestry of one point in it; selectors: @, HEAD, HEAD~<n>, id prefix; --path filters to changes whose recorded tree includes <path> (#6) — combine both to intersect (the selector's ancestry AND the path)
  loot gc [--dry-run]                       prune loose objects no change references (--dry-run reports only)
  loot verify [--accept-loss]               integrity-check the object store: rehash every object, find missing ones with their referencing changes (exits 1 on problems); --accept-loss records current losses as acknowledged
  loot bundle <file>                        write a sync bundle (ciphertext, no private keys)
  loot apply <file> [--porcelain|--json]    merge a peer's bundle (idempotent; machine output for agents)
  loot grant <path> <identity> <file>       write a targeted grant bundle for <identity> (file delivery)
  loot grant --relay <name> <path> <identity>  seal and deliver a grant via relay mailbox
  loot grant-status <path>                  list current grantees for <path> — grantor, delivery method, granted_at (sanity check before `loot maroon`, #5)
  loot grants [<url>] [--remote <name>]     peek pending grant count (no download)
  loot pull-grants [<url>] [--remote <name>]   fetch, verify, and apply sealed grants from relay
  loot maroon [--hard] <path> <identity> [dir]  cut off <identity> from future access; --hard adds a purge event
  loot migrate <path> <vis-spec> [dir]      change a path's visibility (public | restricted=a,b | embargoed=<ts>)
  loot lane new [--ticket <n>] [--name <n>] [--at <dir>] [--porcelain|--json]  spawn a sealed ephemeral lane over the shared store (primary-only, keyed repos; ADR 0034); --ticket derives the handle (t<n>) for the claim-to-lane flow (#232)
  loot lanes [--porcelain|--json]           lane observability: id, name, path, tip, in-flight PR, dirty/clean, heartbeat, landed/stale — check before acting on shared state (alias: loot lane list)
  loot lane merge <id-or-name> [--porcelain|--json]  fold a named lane's finalized line into the primary (local, CA2; ADR 0034 — a dock is a named lane)
  loot lane name <n>                        (inside a lane) promote it to a dock — persists until removed
  loot lane rm <id-or-name>                 reap a lane: delete its directory + registry entry (NOT undoable)
  loot lane gc [--stale-hours <h>]          sweep unnamed lanes that landed or went stale (default 24h)
  loot manifest                             show the grant audit trail (and attestations)
  loot attest <change-id> [role]            attest a change (advisory sign-off, ADR 0018); selectors: @ (refused — finalize first), HEAD, HEAD~<n>, id prefix
  loot buoy [role] [--verbose] [--porcelain|--json]  resolve the newest trusted role-attested change (CA4, ADR 0025)
  loot conflicts [--porcelain|--json]       list paths that need human resolution
  loot resolve <path> <file>                resolve a conflict at <path> using the content of <file>
  loot remote add <name> <url>              register a relay URL under a name
  loot remote remove <name>                 forget a named relay
  loot remote list                          show all named relays
  loot keygen                               generate an identity keypair (backfills existing repos)
  loot whoami [--pubkey]                    show this repo's public key (with the flag: bare OpenSSH line only, for scripting)
  loot id export <file>                     export keypair to <file>, passphrase-encrypted
  loot id import <file>                     import keypair from passphrase-encrypted <file>
  loot peer add <name> <pubkey>             register a peer's public key (<pubkey> of `-` reads the key from stdin)
  loot peer remove <name>                   forget a peer
  loot peer list                            show all known peers
  loot serve [--dir <path>] [--addr <host:port>] [--allow <pubkey>]...  run a relay
  loot push [<url>] [--remote <name>]       publish changes to a relay (uses 'origin' if no url given)
  loot pull [<url>] [--remote <name>] [--no-surface] [--porcelain|--json]  fetch, merge, converge, and surface changes from a relay
  loot ferry [--git-dir <path>] [--dock <name>] [--with-wip] [--porcelain|--json]  one bidirectional loot <-> git mirror pass (GB1, ADR 0028); --with-wip also projects the ambient dock's unfinalized WIP to review/<lane-id> (review/<dock> on the primary; map #148, #281)
  loot completions <bash|zsh|fish>          print a shell completion script to stdout (no repo needed) — pipe it into your shell config, e.g. loot completions zsh > ~/.zsh/completions/_loot

mutating verbs (new, describe, grant, maroon, migrate) snapshot the working tree
first (ADR 0030) — no manual `loot status` needed. Two globals ride them:
  --allow-demote <path>   permit this snapshot to re-seal <path> more readably (repeatable)
  --no-snapshot           act on the last recorded working change; skip the implicit capture
                          (not on `describe` — recording the tree is its whole job)

info flags (no repo needed):
  -h, --help              show this usage — rides any verb, and explains rather
                          than runs it (`loot new --help` never finalizes)
  -V, --version           print the loot version and exit

a flag a verb does not accept is an error, never ignored (#67) — a typo like
  `loot log --verbose` refuses instead of printing the unfiltered log as if the
  filter had run. That holds within a verb too (#278): `loot lane new
  --stale-hours 12` refuses (`--stale-hours` belongs to `lane gc`) rather than
  reading as accepted and doing nothing.";

fn print_help() {
    println!("loot — source control where privacy is per-content, not per-repo\n\n{USAGE}");
}

/// The `loot X.Y.Z` line printed by `loot --version` / `-V` (#237). The version
/// is the loot-cli crate version — the shipped binary — read straight from Cargo
/// at compile time, so a cargo-dist release tag and the binary's self-report
/// cannot drift.
fn version_line() -> String {
    format!("loot {}", env!("CARGO_PKG_VERSION"))
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

/// `loot log`'s selector positional (#6): like [`first_positional`], but
/// skips `--path`'s own value, so `loot log --path a.txt HEAD` and `loot log
/// HEAD --path a.txt` both resolve the selector to `HEAD` — never mistaking
/// the path filter's argument for the selector (mirrors `positionals()`'s
/// treatment of `--allow-demote <path>`).
fn log_selector(args: &[String]) -> Option<&str> {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--path" {
            i += 2; // skip the flag and its value
        } else if a.starts_with('-') {
            i += 1;
        } else {
            return Some(a);
        }
    }
    None
}

/// Parse the two snapshotting-verb globals (ADR 0030) — `--allow-demote <path>`
/// (repeatable, #62) and `--no-snapshot`/`--ignore-working-copy` — into the
/// [`SnapshotOpts`] the Workspace's proof-of-capture door consumes.
fn parse_snapshot_opts(args: &[String]) -> SnapshotOpts {
    SnapshotOpts {
        allow_demote: flag_values(args, "--allow-demote").into_iter().map(Into::into).collect(),
        skip: has_flag(args, "--no-snapshot") || has_flag(args, "--ignore-working-copy"),
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
    // Quickstart (#21): teach the three visibility modes right at init, on
    // stdout so CI logs carry it too. Print-only — pasting it is the user's call.
    println!("\nquickstart — paste this into a .lootattributes file to control visibility:\n");
    println!("{}", lootattributes_quickstart());
    let _ = keypair;
    Ok(())
}

/// The commented `.lootattributes` example `init` prints (#21): one comment per
/// visibility mode and one concrete line exercising each. Never written to disk.
fn lootattributes_quickstart() -> &'static str {
    "\
# .lootattributes — control per-path visibility
# public      — everyone can read
# restricted  — only named identities
# embargoed   — sealed until unix timestamp

*.md          public
.env          restricted=alice
RELEASE.md    embargoed=1800000000"
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
        //
        // The hint names `describe -m` — capture *without* finalize — because
        // `new` is capture-then-finalize, so on a dirty tree the old hint signed
        // the edits in one stroke, skipping the review lane (#174). `describe` is
        // the first verb on dirty work; `new` is step 6 (docs/agents/workflow.md).
        let human = "no working change (run `loot describe -m \"<subject>\"` to start one)\n".to_string();
        print!("{}", emit::Status { change_id: None, version: None, entries: &[], human }.render(fmt));
        return Ok(());
    };

    // An empty working change (no delta over the tip) has no meaningful version
    // id or pending path listing — the durable change id is the only holdable
    // handle, so machine output emits just the `@` header, no `~` rows.
    let version = if row.empty { None } else { Some(&row.version) };
    let entries: &[(std::path::PathBuf, loot_core::Visibility)] =
        if row.empty { &[] } else { &row.entries };

    // Only the human text re-reads the working tree (`working_delta`, a disk
    // I/O porcelain/json never paid for pre-#321) — so it is built lazily,
    // gated on the format that will actually print it (emit.rs's module doc).
    let human = if matches!(fmt, OutFmt::Human) {
        // A working change whose change id has another live version renders
        // with a trailing `!` here too (S3, ADR 0030).
        let change = change_col(row.change_id, &ws.divergent_change_ids());
        if row.empty {
            format!("working change {change} is empty (no changes since the last `new`)\n")
        } else {
            let mut out =
                format!("working change {change}  {}  \"{}\"\n", short(&row.version), row.message);
            // The per-path listing is the delta vs the previous finalized
            // change (#7), rendered through the shared #306 line: `+` new,
            // `M` modified, `-` deleted, visibility token trailing. The base
            // is implicit (the working change's anchor) — no selector here.
            for d in &ws.working_delta()? {
                let _ = writeln!(out, "{}", delta_line(d));
            }
            out
        }
    } else {
        String::new()
    };
    // status is not a merge: its own working-change shape (ADR 0023/0029).
    print!("{}", emit::Status { change_id: row.change_id, version, entries, human }.render(fmt));
    Ok(())
}

/// `loot diff [<from>] [<to>]` (#1): the path-level delta between two changes.
/// Selectors are the #305 grammar (`@`, `HEAD`, `HEAD~n`, an id prefix); the
/// defaults are command-specific — no arg diffs HEAD vs the working change, one
/// arg diffs that change vs the working change, two diffs the pair. Output is
/// the #306 shared path-delta line, one row per changed path.
fn cmd_diff(args: &[String]) -> Result<(), String> {
    // `--conflict <path>` is a distinct mode (#13): inspect both sides of a
    // recorded conflict rather than diff two changes. It takes no from/to.
    if has_flag(args, "--conflict") {
        let path = flag(args, "--conflict").ok_or("usage: loot diff --conflict <path>")?;
        let ws = Workspace::open()?;
        let view = ws.graph().conflict_at(std::path::Path::new(path))?;
        print!("{}", render::conflict_sides(&view));
        return Ok(());
    }
    let pos = positionals(args);
    let (from, to) = match pos.as_slice() {
        [] => ("HEAD", "@"),
        [a] => (*a, "@"),
        [a, b] => (*a, *b),
        _ => return Err("usage: loot diff [<from>] [<to>]".into()),
    };
    let ws = Workspace::open()?;
    let from_oid = ws.resolve_selector(from)?;
    let to_oid = ws.resolve_selector(to)?;
    let deltas = ws.diff(&from_oid, &to_oid)?;
    if deltas.is_empty() {
        println!("no changes");
        return Ok(());
    }
    for d in &deltas {
        println!("{}", delta_line(d));
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
    let opts = parse_snapshot_opts(args);
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

/// `loot edit <change-id>` — reopen a finalized change as the working change,
/// superseding it (ADR 0032): jj-parity `jj edit`. The reopened change keeps its
/// durable handle; finalizing (`loot new`) signs a new version whose
/// `predecessors` names the old one, so the replacement travels. Refuses on an
/// in-progress working change or uncaptured edits (edit *replaces* the working
/// change — it never implicit-captures), on a divergent handle, and on a change
/// with descendants. One undoable operation (ADR 0031).
fn cmd_edit(args: &[String]) -> Result<(), String> {
    let prefix = first_positional(args).ok_or("usage: loot edit <change-id>")?;
    let mut ws = Workspace::open()?;
    let report = ws.edit(prefix)?;
    print!("{}", render::edit_done(&report));
    Ok(())
}

/// `loot abandon <selector>` — drop a version from a **divergent** change (S3,
/// ADR 0029/0030): jj-parity `jj abandon`. Leaves the other live version(s) under
/// the change id; nothing is deleted from the object store — the version stops
/// being a live head — and the step is one undoable operation (ADR 0031). The
/// target is the #305/#315 selector grammar (`@`, `HEAD`, `HEAD~<n>`, a version
/// or change-id prefix — see [`Workspace::resolve_selector`]), the same one
/// `loot diff`/`loot log`/`loot attest` speak.
///
/// `loot abandon --head <selector>` drops an independent live **head** (a whole
/// fork tip), the non-divergent counterpart used to walk a drifted dock off a
/// stale line before a re-ferry (#243). Same undoable machinery; refuses a
/// non-head and refuses emptying the dock of its last live head.
fn cmd_abandon(args: &[String]) -> Result<(), String> {
    let head_mode = has_flag(args, "--head");
    let selector = first_positional(args).ok_or(if head_mode {
        "usage: loot abandon --head <selector>"
    } else {
        "usage: loot abandon <selector>"
    })?;
    let mut ws = Workspace::open()?;
    // Route through the one #305 selector grammar (@ / HEAD / HEAD~n /
    // hex-or-change prefix, #315) rather than the bare live-version-prefix
    // match this used to hand-roll — `loot abandon @` and `loot abandon
    // HEAD~2` now resolve the same way `loot diff` already does.
    let version = ws.resolve_selector(selector)?;
    if head_mode {
        ws.abandon_fork(&version)?;
        println!("abandoned fork head {} — the dock keeps its other live line(s)", short(&version));
    } else {
        ws.abandon(&version)?;
        println!(
            "abandoned version {} — its change id keeps the remaining live version(s)",
            short(&version)
        );
    }
    println!("  nothing was deleted; `loot undo` brings it back (see `loot op log`)");
    Ok(())
}

/// `loot adopt <version-id> [--discard-wip]` — settle this dock **wholesale**
/// onto a landed change, discarding its divergent local line with no merge
/// (#244, amends ADR 0034). The re-baseline primitive #243 needs: `apply` /
/// converge would *merge* a stale fork and resurrect files deleted upstream;
/// adopt abandons every competing head down to the shared anchor and
/// materializes the target's tree. One undoable op — `loot undo` restores the
/// pre-adopt view. `--discard-wip` drops a dirty working tree (the sanctioned
/// override of the #219 tree-write chokepoint).
fn cmd_adopt(args: &[String]) -> Result<(), String> {
    let discard_wip = has_flag(args, "--discard-wip");
    let mut ws = Workspace::open()?;

    // No target → the harbor catch-up **merge** arm (ADR 0034): fold the landed
    // main line into this dock/lane, keeping the local line. `<version>` below is
    // the take-wholesale arm that discards it.
    let Some(prefix) = first_positional(args) else {
        if discard_wip {
            return Err(
                "`--discard-wip` applies only to `loot adopt <version-id>`; the no-arg catch-up \
                 merge folds your working change in rather than dropping it"
                    .into(),
            );
        }
        let report = ws.adopt_harbor()?;
        if report.already_current {
            println!("already caught up to landed main ({}) — nothing to merge", short(&report.harbor));
            return Ok(());
        }
        println!("caught up to landed main ({}) — folded the local line in", short(&report.harbor));
        let conflicts = report
            .outcomes
            .values()
            .filter(|o| matches!(o, MergeOutcome::Conflict { .. }))
            .count();
        if conflicts > 0 {
            println!(
                "  {conflicts} path(s) need resolution — `loot resolve <path> <file>`, then re-land"
            );
        }
        println!("  `loot undo` steps back before the catch-up (see `loot op log`)");
        return Ok(());
    };

    let report = ws.adopt(prefix, discard_wip)?;
    if report.already_there {
        println!("already on {} — nothing to settle", short(&report.target));
        return Ok(());
    }
    println!(
        "adopted {} — the dock now sits on it, no merge",
        short(&report.target)
    );
    if !report.abandoned.is_empty() {
        println!(
            "  discarded the divergent line ({} head(s) abandoned)",
            report.abandoned.len()
        );
    }
    if report.discarded_wip {
        println!("  dropped the dock's working-tree changes (`--discard-wip`)");
    }
    println!("  nothing was deleted; `loot undo` brings the line back (see `loot op log`)");
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
    print_surface_listing(&head, &written, skipped, ws.identity());
    Ok(())
}

/// The `loot surface` listing — written paths with visibility marks, the
/// sealed-skip count, and the surfaced-as line — shared with `pull`'s
/// auto-surface (#3) so the two verbs cannot drift apart.
fn print_surface_listing(
    head: &Oid,
    written: &[(std::path::PathBuf, Visibility)],
    skipped: usize,
    identity: &str,
) {
    for (path, vis) in written {
        println!("  {:<32} {}", path.display(), mark(vis));
    }
    if skipped > 0 {
        println!("  ({skipped} sealed path(s) skipped — request a grant to access them)");
    }
    println!("surfaced {} as {identity}", short(head));
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

/// `loot verify [--accept-loss]` — integrity-check the loose object store
/// (#19). Read-only: every object file is decoded and re-hashed against its
/// filename (the content address), and every address a change references must
/// have a file. A clean store exits 0; any corrupt or missing object is
/// reported by full address — with the referencing change and path (#335) —
/// and the command errors (exit 1), so CI can gate on it. Deliberately never
/// opens the Workspace: a corrupt store fails to load, and the store that
/// fails to load is the one this command exists to diagnose.
///
/// `--accept-loss` records the currently-missing addresses in the store's
/// acknowledged-lost ledger (`.loot/lost`, #335): an unrecoverable loss —
/// the address hashes nonce+ciphertext, and the nonce died with the file —
/// stops failing every future verify, while NEW damage still fails. Primary
/// only: the ledger is a shared-store file with one writer (ADR 0034).
fn cmd_verify(args: &[String]) -> Result<(), String> {
    let accept = args.iter().any(|a| a == "--accept-loss");
    let dot = workspace::resolve_store_dot(std::path::Path::new("."))?;
    if accept && loot_core::RepoStore::read_store_pointer(std::path::Path::new(".loot")).is_some()
    {
        return Err(
            "`loot verify --accept-loss` writes the shared store's loss ledger — run it \
             from the primary, not a lane (ADR 0034 single-writer)"
                .into(),
        );
    }

    let report = if accept {
        let report = loot_core::DagRepo::accept_loss(&dot).map_err(|e| e.to_string())?;
        if report.missing.is_empty() {
            println!("nothing missing — loss ledger unchanged");
        } else {
            println!(
                "accepted {} missing object(s) as lost — recorded in .loot/lost:",
                report.missing.len()
            );
            for m in &report.missing {
                print_missing(m);
            }
        }
        // Re-read so the exit reflects the post-acknowledgment state: the
        // accepted addresses moved to `lost`; anything still failing is
        // corruption (or a race), which acknowledgment must not mask.
        loot_core::DagRepo::verify(&dot).map_err(|e| e.to_string())?
    } else {
        loot_core::DagRepo::verify(&dot).map_err(|e| e.to_string())?
    };

    if !report.lost.is_empty() {
        println!(
            "lost (acknowledged): {} object(s) — unrecoverable, recorded in .loot/lost",
            report.lost.len()
        );
    }
    if report.is_clean() {
        println!("all objects OK — {} object(s) verified", report.ok);
        return Ok(());
    }
    for addr in &report.corrupt {
        println!("corrupt: {}", loot_core::hex::encode(&addr.0));
    }
    for m in &report.missing {
        print_missing(m);
    }
    Err(format!(
        "object store failed verification: {} corrupt, {} missing ({} OK)",
        report.corrupt.len(),
        report.missing.len(),
        report.ok
    ))
}

/// One missing address with its referencing sites (#335); a long-lived path
/// can be referenced by many changes — show a few.
fn print_missing(m: &loot_core::MissingObject) {
    println!("missing: {}", loot_core::hex::encode(&m.addr.0));
    const SHOWN: usize = 3;
    for site in m.referenced_by.iter().take(SHOWN) {
        let subject = site.message.lines().next().unwrap_or("");
        println!(
            "    referenced by {} \"{}\" at {}",
            short(&site.change),
            subject,
            site.path.display()
        );
    }
    if m.referenced_by.len() > SHOWN {
        println!("    ... and {} more reference(s)", m.referenced_by.len() - SHOWN);
    }
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

/// `loot log [<selector>] [--path <path>]` — with no argument, unchanged: the
/// full history (rows newest-first, abandoned versions dropped, the working
/// node rendered once as the live row, routed flat-vs-branch by distinct
/// change lines, ADR 0029). With a selector (#305/#315 — `@`, `HEAD`,
/// `HEAD~<n>`, a version or change-id prefix, the same grammar `loot
/// diff`/`loot attest`/`loot abandon` speak), the view scopes to that
/// version's **ancestry** ([`Workspace::ancestors_of`], a full multi-parent
/// walk): rows and, in the diverged case, each head's lane and the shared
/// section are filtered down to ids reachable from the selector. The live
/// working row only survives the filter when the selector names it directly
/// (`loot log @`) — otherwise it is "now", not history up to the selector,
/// and is dropped.
///
/// This is deliberately the minimal honest scoping, not a general revision-walk
/// subsystem (#315 scope note): a selector picks the *point*, ancestry answers
/// "what came before it", and nothing here re-derives divergence or head
/// membership — `g.heads` still lists every live head exactly as the unscoped
/// view would, even if a head's own lane renders empty because none of its
/// rows are in the requested ancestry.
///
/// `--path <path>` (#6) narrows independently: a change survives only if its
/// own recorded tree includes `path` ([`Workspace::filter_history_to_path`]).
/// It composes with a selector as an intersection — `loot log <selector>
/// --path <path>` shows the ancestry of `<selector>` filtered to changes that
/// also touched `<path>` — applied here as two sequential retains, in either
/// order, over the same view.
fn cmd_log(args: &[String]) -> Result<(), String> {
    let mut ws = Workspace::open()?;
    let identity = ws.identity().to_string();
    // The whole read lives behind the Workspace (R1, #177): rows newest-first
    // with abandoned versions dropped and the working node excluded (rendered
    // once, as the live row), routed flat-vs-branch by distinct change lines
    // (ADR 0029). This function only renders.
    let mut view = ws.history()?;
    // `--path`'s own value is skipped when hunting the selector positional,
    // so `loot log --path a.txt HEAD` and `loot log HEAD --path a.txt` both
    // resolve the selector to `HEAD`, not `a.txt` (mirrors `positionals()`'s
    // treatment of `--allow-demote <path>`).
    if let Some(sel) = log_selector(args) {
        let target = ws.resolve_selector(sel)?;
        let ancestry = ws.ancestors_of(&target);
        view.rows.retain(|r| ancestry.contains(&r.version));
        if let Some(g) = &mut view.graph {
            for lane in &mut g.per_head {
                lane.retain(|r| ancestry.contains(&r.version));
            }
            g.shared.retain(|r| ancestry.contains(&r.version));
        }
        if view.working.as_ref().map(|w| &w.version) != Some(&target) {
            view.working = None;
        }
    }
    if let Some(p) = flag(args, "--path") {
        ws.filter_history_to_path(&mut view, std::path::Path::new(p));
    }
    if view.is_empty() {
        println!("no changes yet");
        return Ok(());
    }

    // Resolve author pubkeys to display names (peer registry + self); the
    // rendering itself lives in render.rs and is tested there (R5, #181).
    let reg = identity::PeerRegistry::load(ws.dot());
    let own = ws.author_pubkey();
    let name_of = |author: Option<&[u8; 32]>| match author {
        Some(pk) if own.as_ref() == Some(pk) => identity.clone(),
        Some(pk) => resolve_pubkey_name(&reg, pk),
        None => String::new(),
    };
    print!("{}", render_history(&view, &identity, &name_of));
    Ok(())
}

fn cmd_bundle(args: &[String]) -> Result<(), String> {
    let out = args.first().ok_or("bundle requires <file>")?;
    let ws = Workspace::open()?;
    // Full bundle (have = []); apply is idempotent. Ships ciphertext + ANYONE-
    // granted keys only — restricted keys never travel (ADR 0003).
    let bundle = ws.bundle_full()?;
    std::fs::write(out, &bundle.0).map_err(|e| format!("write {out}: {e}"))?;
    println!("wrote {} ({} bytes) — copy it to a peer and `loot apply`", out, bundle.0.len());
    Ok(())
}

fn cmd_apply(args: &[String]) -> Result<(), String> {
    let fmt = out_fmt(args);
    let infile = first_positional(args).ok_or("apply requires <file>")?;
    let bytes = std::fs::read(infile).map_err(|e| format!("read {infile}: {e}"))?;
    let mut ws = Workspace::open()?;
    let identity = ws.identity().to_string();
    // Capture-first (#219, ADR 0030 amendment): fold uncaptured disk edits into
    // the working change before ingest, like every other mutating verb — so a
    // later `loot surface` can never silently overwrite them.
    let had_working = ws.working_id().is_some();
    let captured = ws.capture_uncaptured_edits()?;
    let newly_captured = captured.filter(|_| !had_working);
    let outcomes = ws.apply_bundle(bytes)?;

    let mut human = String::new();
    if let Some(id) = &newly_captured {
        let _ = writeln!(
            human,
            "captured working change {} (uncaptured edits) before applying",
            loot_core::hex::short(&id.0, 4)
        );
    }
    if outcomes.is_empty() {
        let _ = writeln!(human, "applied {infile}: nothing new (already up to date)");
    } else {
        let _ = writeln!(human, "applied {infile} as {identity}:");
        human.push_str(&outcome_rows(&outcomes));
        let _ = writeln!(human, "run `loot surface` to materialize what you may see");
    }
    print!("{}", emit::Reconciliation { verdicts: verdicts_of(&outcomes), human }.render(fmt));
    // Capture-first can create a working change even when the bundle brought
    // nothing new (#219); record the op so that view change is undoable too.
    if !outcomes.is_empty() || newly_captured.is_some() {
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
    let with_wip = args.iter().any(|a| a == "--with-wip");
    let mut ws = Workspace::open()?;
    let report = ferry::run(&mut ws, git_dir, dock, with_wip)?;

    let mut human = String::new();
    for note in &report.notes {
        let _ = writeln!(human, "note: {note}");
    }
    if report.ingested == 0 && report.projected == 0 && report.outcomes.is_empty() {
        let _ = writeln!(human, "ferry: up to date (nothing to ingest or project)");
    } else {
        let _ = writeln!(
            human,
            "ferry: ingested {} git commit(s), projected {} loot change(s)",
            report.ingested, report.projected
        );
        human.push_str(&outcome_rows(&report.outcomes));
    }
    if let Some(line) = &report.review {
        let _ = writeln!(human, "{line}");
    }
    print!("{}", emit::Reconciliation { verdicts: verdicts_of(&report.outcomes), human }.render(fmt));
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

    let opts = parse_snapshot_opts(args);
    let mut ws = Workspace::open()?;
    // Capture the working tree first (ADR 0030) so the grant seals what is on
    // disk now, not a stale last-`status` snapshot — the handle is the proof.
    let mut snap = ws.snapshotted(&opts)?;
    let now = snap.ws().now();

    let oid = snap
        .ws()
        .current_tree_oid(std::path::Path::new(path))
        .map_err(|_| format!("path '{path}' not found in current change"))?;

    let bundle = snap.mutate(|repo| {
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
    snap.record_op("grant", &format!("grant {path} → {grantee}"), true);
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

    let opts = parse_snapshot_opts(args);
    let mut ws = Workspace::open()?;
    // Capture the working tree first (ADR 0030) so the sealed grant covers the
    // path's current on-disk content — the handle is the proof.
    let mut snap = ws.snapshotted(&opts)?;
    let dot = snap.ws().dot().to_owned();

    // Resolve the relay URL via the shared helper (consistent with push/pull).
    let url = resolve_remote(args, snap.ws())
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

    let now = snap.ws().now();
    let oid = snap
        .ws()
        .current_tree_oid(std::path::Path::new(path))
        .map_err(|_| format!("path '{path}' not found in current change"))?;

    // An embargoed seal's grant inherits its reveal_at (ADR 0027): a late-added
    // recipient gets a timed grant the relay withholds like the push-time
    // deposits — never an immediately-delivered key. Everything else is an
    // ordinary untimed grant (reveal_at = 0).
    let reveal_at = match snap.ws().visibility_of(&oid) {
        Some(Visibility::Embargoed { reveal_at }) => reveal_at,
        _ => 0,
    };

    let bundle = snap.mutate(|repo| {
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
    snap.record_op("grant", &format!("grant {path} → {grantee} (sealed)"), true);
    Ok(())
}

/// `loot grant-status <path>` (#5): who currently holds a grant for `path`,
/// read straight from the Manifest — a sanity check before `loot maroon`.
/// Read-only (no snapshot, ADR 0030 — this inspects existing history, it
/// doesn't record any).
fn cmd_grant_status(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or("grant-status requires <path>")?;
    let ws = Workspace::open()?;
    let reg = identity::PeerRegistry::load(ws.dot());

    let oid = ws
        .current_tree_oid(std::path::Path::new(path))
        .map_err(|_| format!("path '{path}' not found in current change"))?;

    let entries = ws.manifest().grants_for(&oid);
    let name_of = |pk: &[u8; 32]| resolve_pubkey_name(&reg, pk);
    print!("{}", render_grant_status(std::path::Path::new(path), &entries, &name_of));
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
    ws.remotes().add("origin", url)?;

    // Pull from the relay and surface what this identity can see.
    let have = ws.heads();
    let bytes = loot_net::pull(url, &have).map_err(|e| e.to_string())?;
    if !bytes.is_empty() {
        let outcomes = ws.apply_bundle(bytes)?;
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

    let opts = parse_snapshot_opts(args);
    let mut ws = Workspace::open()?;
    // Re-seal against the working tree as it is now (ADR 0030) — the handle is
    // the proof of capture.
    let mut snap = ws.snapshotted(&opts)?;
    let now = snap.ws().now();
    let result: MaroonResult = snap.mutate(|repo| {
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
    snap.sign_change(&result.change_id)?;

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
    snap.record_op("maroon", &format!("maroon {} ⁄ {marooned}", path.display()), true);
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

    let opts = parse_snapshot_opts(args);
    let mut ws = Workspace::open()?;
    // Re-classify against the current on-disk tree (ADR 0030) — the handle is
    // the proof of capture.
    let mut snap = ws.snapshotted(&opts)?;
    let now = snap.ws().now();
    let result: MigrateResult = snap.mutate(|repo| {
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
    snap.record_op("migrate", &format!("migrate {} → {vis_label}", path.display()), false);
    Ok(())
}

/// A subcommand's own flag spec (#278): `name` is the resolved form the
/// refusal shows (`lane new`), checked with [`FlagSpec::check_sub`] where the
/// verb resolves its subcommand. The verb's [`COMMANDS`] entry stays the union
/// of these (a test pins that), so a flag that exists nowhere is still caught
/// — and `--help` still honoured — before dispatch.
const fn subspec(
    name: &'static str,
    valued: &'static [&'static str],
    bare: &'static [&'static str],
) -> FlagSpec {
    FlagSpec { bin: "loot", name, valued, bare }
}

/// `loot lane`'s subcommand specs (#278).
const LANE_NEW: FlagSpec = subspec("lane new", &["--ticket", "--name", "--at"], OUT);
const LANE_LIST: FlagSpec = subspec("lane list", &[], OUT);
const LANE_MERGE: FlagSpec = subspec("lane merge", &[], OUT);
const LANE_NAME: FlagSpec = subspec("lane name", &[], &[]);
const LANE_RM: FlagSpec = subspec("lane rm", &[], &[]);
const LANE_GC: FlagSpec = subspec("lane gc", &["--stale-hours"], &[]);
#[cfg(test)]
const LANE_SUBS: &[&FlagSpec] =
    &[&LANE_NEW, &LANE_LIST, &LANE_MERGE, &LANE_NAME, &LANE_RM, &LANE_GC];

/// `loot lane <new|list|merge|name|rm|gc>` — the sealed-lane lifecycle (ADR
/// 0034, #231). A lane is an ephemeral working directory over this repo's shared
/// store, born at the finalized tip; naming it makes it a dock (persisted).
/// Unnamed lanes are reaped by `lane gc` once their change lands or their
/// heartbeat goes stale; `merge` folds a lane's finalized line into the primary
/// (#253, the former `loot dock merge`).
/// Resolve `loot lane <sub>` and run the resolved subcommand's own flag gate
/// (#278): the table's `lane` entry is the union over the subcommands, so
/// `main`'s gate alone would let a sibling's flag (`lane new --stale-hours`)
/// ride through ignored. Pure — no workspace opens here — so the gate's tests
/// exercise every refusal without ever walking the test runner's cwd into a
/// real `.loot` store (#322). Returns the resolved subcommand (`ls`
/// normalizes to `list`; bare `loot lane` defaults to it).
fn lane_gate(args: &[String]) -> Result<&'static str, String> {
    let (sub, spec) = match args.first().map(String::as_str).unwrap_or("list") {
        "new" => ("new", &LANE_NEW),
        "list" | "ls" => ("list", &LANE_LIST),
        "merge" => ("merge", &LANE_MERGE),
        "name" => ("name", &LANE_NAME),
        "rm" => ("rm", &LANE_RM),
        "gc" => ("gc", &LANE_GC),
        other => {
            return Err(format!(
                "unknown lane subcommand '{other}'\n\nusage: loot lane new [--ticket <n>] \
                 [--name <n>] [--at <dir>] | list | merge <id-or-name> | name <n> | \
                 rm <id-or-name> | gc [--stale-hours <h>]"
            ))
        }
    };
    spec.check_sub(args)?;
    Ok(sub)
}

fn cmd_lane(args: &[String]) -> Result<(), String> {
    match lane_gate(args)? {
        "new" => {
            let fmt = out_fmt(args);
            let name = flag(args, "--name");
            let at = flag(args, "--at").map(std::path::PathBuf::from);
            // The ticket-derived handle (#232): `--ticket 232` spawns lane
            // `t232` (a bare number is prefixed; anything else is the handle
            // itself), so `loot lanes` reads as a claim board.
            let handle = flag(args, "--ticket").map(|t| {
                let t = t.trim_start_matches('#');
                if t.chars().all(|c| c.is_ascii_digit()) { format!("t{t}") } else { t.to_string() }
            });
            let mut ws = Workspace::open()?;
            let spawned = ws.spawn_lane_as(name, at.as_deref(), handle.as_deref())?;
            ws.record_op("lane new", &format!("spawn lane {}", spawned.id), false);
            // One row, the `loot lanes` shape — an agent wrapper parses the same
            // columns whether it spawned or listed. Computed unconditionally
            // (like `cmd_lane_list`'s own rows): it's a cheap, side-effect-free
            // registry read, so there is no format-gated cost to avoid here the
            // way `status`'s disk re-read has one.
            let rows = lane_rows(&ws, |s| s.entry.id == spawned.id);
            let mut human = format!(
                "lane '{}' at {} — sealed over this repo's store, born at the finalized tip\n",
                spawned.id,
                spawned.dir.display()
            );
            match name {
                Some(n) => {
                    let _ = writeln!(human, "  named '{n}' — persists until `loot lane rm {n}`");
                }
                None => {
                    let _ = writeln!(
                        human,
                        "  ephemeral — `loot lane gc` reaps it once it lands or goes stale; \
                         `loot lane name <n>` (inside it) keeps it"
                    );
                }
            }
            print!("{}", emit::Lanes { rows, human }.render(fmt));
            Ok(())
        }
        // Full `args` (not `args[1..]`): `out_fmt` only reads flags, and bare
        // `loot lane` used to panic slicing an empty argv here.
        "list" => cmd_lane_list(args),
        "merge" => {
            let key = args.get(1).ok_or("usage: loot lane merge <id-or-name>")?;
            cmd_lane_merge(key, args)
        }
        "name" => {
            let name = args.get(1).ok_or("usage: loot lane name <name>  (inside the lane)")?;
            let ws = Workspace::open()?;
            ws.name_lane(name)?;
            println!(
                "lane '{}' named '{name}' — now a dock; persists until `loot lane rm {name}`",
                ws.lane_id().unwrap_or("?")
            );
            Ok(())
        }
        "rm" => {
            let key = args.get(1).ok_or("usage: loot lane rm <id-or-name>")?;
            let mut ws = Workspace::open()?;
            let e = ws.remove_lane(key)?;
            println!(
                "reaped lane '{}' ({}) — unsigned WIP died with the directory; \
                 signed changes stay in the store",
                e.id,
                e.path.display()
            );
            Ok(())
        }
        "gc" => {
            let stale_secs: u64 = match flag(args, "--stale-hours") {
                Some(v) => {
                    let hours: u64 =
                        v.parse().map_err(|_| format!("--stale-hours: not a number: {v}"))?;
                    hours * 3600
                }
                None => LANE_STALE_SECS,
            };
            let mut ws = Workspace::open()?;
            let outcomes = ws.lane_gc(stale_secs)?;
            if outcomes.is_empty() {
                println!("no lanes to sweep");
                return Ok(());
            }
            for (e, o) in outcomes {
                match o {
                    SweepOutcome::Reaped(why) => println!("reaped {:<16} ({why})", e.id),
                    SweepOutcome::Kept(why) => println!("kept   {:<16} ({why})", e.id),
                    SweepOutcome::Failed(why) => println!("FAILED {:<16} — {why}", e.id),
                }
            }
            Ok(())
        }
        // `lane_gate` refuses anything it doesn't resolve to one of the above.
        _ => unreachable!("lane_gate returns only resolved subcommands"),
    }
}

/// `loot lanes [--porcelain|--json]` (also `loot lane list`) — the lane
/// observability report (#232): each registered lane's id, name, path, tip,
/// in-flight PR, dirty/clean, heartbeat age, and landed/stale markers. The
/// check an agent (or the human) runs before acting on shared state — and it
/// is read-only: no heartbeat refreshes, no capture, no op recorded.
fn cmd_lane_list(args: &[String]) -> Result<(), String> {
    let fmt = out_fmt(args);
    let ws = Workspace::open()?;
    let rows = lane_rows(&ws, |_| true);
    let mut human = String::new();
    if rows.is_empty() {
        let _ = writeln!(human, "no lanes  (spawn one with `loot lane new`)");
    } else {
        for r in &rows {
            let name = r.name.clone().unwrap_or_else(|| "(unnamed)".to_string());
            let tip = r.tip.as_ref().map(short).unwrap_or_else(|| "-".to_string());
            let mut notes = Vec::new();
            let pr_note;
            if let Some(pr) = r.pr {
                pr_note = format!("PR #{pr}");
                notes.push(pr_note.as_str());
            }
            match r.dirty {
                Some(true) => notes.push("dirty"),
                Some(false) => {}
                None => notes.push("unreadable"),
            }
            if r.landed {
                notes.push("landed");
            }
            if r.stale {
                notes.push("stale");
            }
            let notes = if notes.is_empty() {
                String::new()
            } else {
                format!("  [{}]", notes.join(", "))
            };
            let _ = writeln!(
                human,
                "{:<16} {:<16} {}  tip {tip}  (heartbeat {}){notes}",
                r.id,
                name,
                r.path.display(),
                fmt_age(r.heartbeat_age)
            );
        }
    }
    print!("{}", emit::Lanes { rows, human }.render(fmt));
    Ok(())
}

/// [`LaneStatus`] → the encoder rows, deriving the presentation-side facts
/// (heartbeat age from the clock, staleness from the gc threshold — named
/// lanes never read stale because they never sweep).
fn lane_rows(ws: &Workspace, keep: impl Fn(&LaneStatus) -> bool) -> Vec<verdict::LaneRow> {
    let now = ws.now();
    ws.lane_statuses()
        .into_iter()
        .filter(keep)
        .map(|s| verdict::LaneRow {
            id: s.entry.id.clone(),
            name: s.entry.name.clone(),
            path: s.entry.path.clone(),
            tip: s.tip,
            change: s.change,
            pr: s.pr,
            dirty: s.dirty,
            heartbeat_age: now.saturating_sub(s.entry.heartbeat),
            stale: s.entry.name.is_none() && s.entry.stale(now, LANE_STALE_SECS),
            landed: s.entry.landed,
        })
        .collect()
}

/// Rough age for `lane list` heartbeats — humans triage staleness in units,
/// not seconds.
fn fmt_age(secs: u64) -> String {
    match secs {
        s if s < 60 => format!("{s}s ago"),
        s if s < 3_600 => format!("{}m ago", s / 60),
        s if s < 86_400 => format!("{}h ago", s / 3_600),
        s => format!("{}d ago", s / 86_400),
    }
}

/// `loot lane merge <id-or-name> [--porcelain|--json]` — fold a named lane's
/// finalized line into the primary (CA2; ADR 0034 — a dock is a named lane). A
/// reconciliation verb, so it emits the shared verdict rows for the merge
/// outcomes in machine formats (CA3, ADR 0023) — dropping the typed outcomes at
/// the `println!` boundary was the exact anti-pattern CA3 removed everywhere
/// else (#126).
fn cmd_lane_merge(key: &str, args: &[String]) -> Result<(), String> {
    let fmt = out_fmt(args);
    let mut ws = Workspace::open()?;
    let current = ws.current_dock().unwrap_or("main").to_string();
    let (source, outcomes) = ws.merge_lane(key)?;
    if !outcomes.is_empty() {
        ws.record_op("lane merge", &format!("merge {source} → {current}"), false);
    }

    let human = if outcomes.is_empty() {
        format!("merge lane '{source}' → '{current}': already up to date\n")
    } else {
        let mut out = format!("merged lane '{source}' into '{current}':\n");
        out.push_str(&outcome_rows(&outcomes));
        let conflicts =
            outcomes.values().filter(|o| matches!(o, MergeOutcome::Conflict { .. })).count();
        if conflicts > 0 {
            let _ = writeln!(
                out,
                "resolve {conflicts} conflict(s) with `loot resolve <path> <file>` — each advances the primary's tip"
            );
        } else {
            let _ = writeln!(out, "merge committed as the primary's tip; run `loot log` to see it");
        }
        out
    };
    print!("{}", emit::Reconciliation { verdicts: verdicts_of(&outcomes), human }.render(fmt));
    Ok(())
}

fn cmd_manifest() -> Result<(), String> {
    let ws = Workspace::open()?;
    let dot = ws.dot().to_owned();
    let reg = identity::PeerRegistry::load(&dot);
    let entries: Vec<_> = ws.manifest().iter().collect();
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
        println!("{:<12} {:<16} {:<16} {}", e.granted_at, e.grantee, grantor, short(&e.oid));
    }

    // Attestations (S4, ADR 0018): advisory sign-offs over changes, by pubkey.
    let attestations = ws.all_attestations();
    if !attestations.is_empty() {
        println!();
        println!("attestations:");
        for a in attestations {
            println!(
                "  {}  {} ({})",
                short(&a.change_id),
                resolve_pubkey_name(&reg, &a.attester),
                a.role
            );
        }
    }
    Ok(())
}

fn cmd_attest(args: &[String]) -> Result<(), String> {
    // `args[0]` is always the selector and `args[1]` (if present) the role —
    // both read by fixed position, not `first_positional`'s flag-skipping
    // scan, so a selector like `HEAD~1` in `args[0]` is never mistaken for a
    // role and vice versa.
    let change_ref = args
        .first()
        .ok_or("usage: loot attest <change-id> [role]")?;
    let role = args.get(1).map(String::as_str).unwrap_or("reviewed");
    let mut ws = Workspace::open()?;
    // Route through the one #305 selector grammar (@ / HEAD / HEAD~n / prefix,
    // #315) rather than the verb's own hand-rolled version-prefix match. The
    // id `resolve_selector` returns is a version's `Oid` — exactly what
    // `Attestation` records under its `change_id` field throughout the engine
    // (see `attestations_for`/`buoy_resolution`, both keyed by version id, and
    // this verb's own former body, which matched hex prefixes against
    // `version_ids()`). So no separate version->change-id remap is needed —
    // and `Workspace::change_id` (`Option<[u8; 16]>`, the *durable* handle)
    // would be the wrong type to feed `attest` even if one were attempted.
    let version = ws.resolve_selector(change_ref)?;
    // `@` legitimately resolves (it is the working change, and `diff` wants
    // exactly that) — but attest still must refuse it: the working change's
    // id is rewritten on every snapshot, so an attestation over it would be
    // orphaned the moment the tree changes again (S4, ADR 0018).
    if Some(&version) == ws.working_id() {
        return Err(
            "cannot attest the working change — its id is still changing; finalize it with `loot new` first"
                .into(),
        );
    }
    ws.attest(&version, role)?;
    println!("attested {} as \"{}\"", short(&version), role);
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
    let reg = identity::PeerRegistry::load(ws.dot());

    // The whole read — present set, parent lookup, attestation stream, trust
    // predicate (peer registry ∪ self) — lives behind the Workspace (R1, #177).
    let resolution = ws.buoy_resolution(role);
    let result = resolution.result;

    if verbose && !resolution.excluded.is_empty() {
        eprintln!("buoy: trusted attestations for changes absent locally:");
        for change in &resolution.excluded {
            eprintln!("  {} ({role})", loot_core::hex::encode(&change.0));
        }
    }

    // The machine shapes (porcelain/JSON) are the frozen ADR 0025 contract and
    // encode via `emit::Buoy` (which wraps loot_core::verdict::BuoyVerdict) —
    // one tested home beside the reconciliation shapes. Human rendering is
    // built here (it needs the peer registry for attester names, kept out of
    // `emit`/`verdict` by design, R5 #181) and handed in pre-rendered, same as
    // every other shape's `human` field. `None`'s porcelain is deliberately
    // empty: the exit code carries that outcome.
    let exit = match &result {
        loot_core::buoy::BuoyResult::Resolved { .. } => ExitCode::SUCCESS,
        loot_core::buoy::BuoyResult::Ambiguous { .. } => ExitCode::from(3),
        loot_core::buoy::BuoyResult::None => ExitCode::from(2),
    };
    let name_of = |pk: &[u8; 32]| resolve_pubkey_name(&reg, pk);
    let human = render_buoy_human(&result, role, &name_of);
    print!("{}", emit::Buoy::new(result, role, human).render(fmt));
    Ok(exit)
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
    let conflicts = ws.conflicts();
    let mut human = String::new();
    if conflicts.is_empty() {
        let _ = writeln!(human, "no conflicts");
    } else {
        for (path, (our_oid, their_oid)) in conflicts {
            let _ = writeln!(human, "conflict at {}", path.display());
            let _ = writeln!(human, "  ours:   {}", short(our_oid));
            let _ = writeln!(human, "  theirs: {}", short(their_oid));
        }
    }
    // Every recorded conflict is a `C` row (ADR 0023); empty -> no lines.
    print!("{}", emit::Reconciliation { verdicts: conflict_verdicts(conflicts), human }.render(fmt));
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

    let (new_oid, message) = ws.resolve_conflict(path, &bytes, vis)?;

    println!("resolved {} (new oid: {})", path.display(), short(&new_oid));
    // The minted subject (#337): the ours-line subject suffixed with
    // "(conflict resolution: <path>)", or the bare placeholder when none was
    // derivable — showing it here is what tells the operator whether a
    // `loot describe` rescue is still needed before landing (#316).
    println!("recorded as \"{message}\"");
    ws.record_op("resolve", &format!("resolve {}", path.display()), false);

    // The resolution is signed on the spot; on a dock it also advanced the tip.
    if ws.conflicts().is_empty() {
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

        match ws.apply_sealed_grant(bundle_bytes.to_vec(), grantor_pubkey) {
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

fn cmd_whoami(args: &[String]) -> Result<(), String> {
    let ws = Workspace::open()?;
    let dot = ws.dot();
    if !identity::keypair_exists(dot) {
        return Err("no identity keypair — run `loot keygen` to generate one".into());
    }
    let pub_line = std::fs::read_to_string(dot.join("id.pub"))
        .map_err(|e| format!("read id.pub: {e}"))?;
    let pub_line = pub_line.trim();
    // `--pubkey`: emit only the bare OpenSSH line so it pipes cleanly into
    // `loot peer add <name> -` on another box (#4). No labels, no trailer.
    let pubkey_only = args.iter().any(|a| a == "--pubkey");
    print!("{}", render_whoami(&ws.identity(), pub_line, pubkey_only));
    Ok(())
}

/// The `loot whoami` output. `--pubkey` (`pubkey_only`) yields the bare
/// OpenSSH line and nothing else, so a pipe into `loot peer add <name> -`
/// sees exactly one line; the default is the labelled human block (#4).
fn render_whoami(identity: &str, pub_line: &str, pubkey_only: bool) -> String {
    if pubkey_only {
        format!("{pub_line}\n")
    } else {
        format!(
            "identity: {identity}\npubkey:   {pub_line}\n\n\
             share with peers:  loot peer add {identity} {pub_line}\n"
        )
    }
}

/// Resolve a `peer add` pubkey argument: a literal key passes through, while
/// `-` means "read it from `read`" — stdin in production (#4), a fixture in
/// tests. The reader is only touched for `-`, so a literal never blocks on it.
fn resolve_pubkey_arg(
    arg: &str,
    read: impl FnOnce() -> Result<String, String>,
) -> Result<String, String> {
    if arg == "-" { read() } else { Ok(arg.to_string()) }
}

/// Read a pubkey from stdin (the whole stream, trimmed), the production reader
/// for a `-` argument, so `loot whoami --pubkey | loot peer add <name> -` feeds
/// directly.
fn read_stdin_key() -> Result<String, String> {
    use std::io::Read;
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf).map_err(|e| format!("read stdin: {e}"))?;
    let key = buf.trim().to_string();
    if key.is_empty() {
        return Err("peer add: `-` given but stdin was empty".into());
    }
    Ok(key)
}

fn cmd_peer(args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("list");
    match sub {
        "add" => {
            if args.len() < 3 {
                return Err("peer add requires <name> <pubkey>".into());
            }
            let name = &args[1];
            // `<pubkey>` of `-` reads the key from stdin, so a piped
            // `loot whoami --pubkey | loot peer add alice -` works (#4).
            let pubkey = resolve_pubkey_arg(&args[2], read_stdin_key)?;
            let ws = Workspace::open()?;
            let mut reg = identity::PeerRegistry::load(ws.dot());
            reg.add(name, &pubkey);
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
            ws.remotes().add(name, url)?;
            println!("remote '{name}' → {url}");
            Ok(())
        }
        "remove" | "rm" => {
            let name = args.get(1).ok_or("remote remove requires <name>")?;
            let ws = Workspace::open()?;
            ws.remotes().remove(name)?;
            println!("removed remote '{name}'");
            Ok(())
        }
        "list" | "ls" => {
            let ws = Workspace::open()?;
            let remotes = ws.remotes().list();
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

// --- shell completions (#23) ---
//
// Generated, not hand-maintained: the verb list comes straight off
// [`COMMANDS`] (plus `buoy`/`help`, dispatched outside the table), so a new
// top-level verb is picked up the moment it's added there — no second list to
// keep in sync (the #66 failure class this whole table exists to avoid).
// A handful of verbs dispatch multi-word leaves by hand (`peer add`, `lane
// gc`, …) rather than through a `FlagSpec`, so those live in the small
// [`SUBCOMMANDS`] map below instead of being re-derived from parsing.

/// Multi-word subcommands the flag-spec table doesn't carry on its own — the
/// `cmd_*` handlers dispatch these by matching `args.first()` directly (only
/// `loot lane`'s leaves are declared as their own [`FlagSpec`]s, see
/// [`LANE_SUBS`]). Add a leaf here once and every generated shell offers it.
const SUBCOMMANDS: &[(&str, &[&str])] = &[
    ("lane", &["new", "list", "merge", "name", "rm", "gc"]),
    ("peer", &["add", "remove", "list"]),
    ("remote", &["add", "remove", "list"]),
    ("id", &["export", "import"]),
    ("config", &["set", "unset", "list"]),
    ("op", &["log", "restore"]),
];

/// Every top-level verb name completions should offer: [`COMMANDS`] plus
/// `buoy` (dispatched ahead of the table — its own `ExitCode`) and `help`.
/// Sorted so the generated scripts — and the tests pinning their shape — are
/// deterministic.
fn completion_verb_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = COMMANDS.iter().map(|v| v.spec.name).collect();
    names.push("buoy");
    names.push("help");
    names.sort_unstable();
    names
}

/// `loot completions bash` — a `_loot_completions` function registered with
/// `complete -F`. Verb names complete at word 1; [`SUBCOMMANDS`] completes
/// each multi-word verb's leaves at word 2. Built with plain string literals
/// (not `format!`) wherever the text is literal shell syntax like `${cur}`,
/// so nothing needs brace-escaping.
fn bash_completions() -> String {
    let verbs = completion_verb_names().join(" ");
    let mut s = String::new();
    s.push_str("# loot shell completion (bash) — generated by `loot completions bash`; do not edit by hand\n");
    s.push_str("_loot_completions() {\n");
    s.push_str("    local cur\n");
    s.push_str("    cur=\"${COMP_WORDS[COMP_CWORD]}\"\n");
    s.push('\n');
    s.push_str("    if [[ ${COMP_CWORD} -eq 1 ]]; then\n");
    s.push_str("        COMPREPLY=( $(compgen -W \"");
    s.push_str(&verbs);
    s.push_str("\" -- \"${cur}\") )\n");
    s.push_str("        return 0\n");
    s.push_str("    fi\n");
    s.push('\n');
    s.push_str("    case \"${COMP_WORDS[1]}\" in\n");
    for (verb, subs) in SUBCOMMANDS {
        // The leading `(` before the pattern is POSIX-legal (optional on
        // every case arm) — used here so each arm's label parenthesizes
        // itself instead of leaving its label `)` unmatched.
        s.push_str("        (");
        s.push_str(verb);
        s.push_str(") COMPREPLY=( $(compgen -W \"");
        s.push_str(&subs.join(" "));
        s.push_str("\" -- \"${cur}\") ) ;;\n");
    }
    s.push_str("    esac\n");
    s.push_str("}\n");
    s.push_str("complete -F _loot_completions loot\n");
    s
}

/// `loot completions zsh` — a `#compdef loot` function. Verb names complete
/// at word 2 (`$CURRENT == 2`); [`SUBCOMMANDS`] completes leaves at word 3
/// once the verb is known.
fn zsh_completions() -> String {
    let verbs = completion_verb_names().join(" ");
    let mut s = String::new();
    s.push_str("#compdef loot\n");
    s.push_str("# loot shell completion (zsh) — generated by `loot completions zsh`; do not edit by hand\n");
    s.push('\n');
    s.push_str("_loot() {\n");
    s.push_str("    local -a verbs\n");
    s.push_str("    verbs=(");
    s.push_str(&verbs);
    s.push_str(")\n");
    s.push('\n');
    s.push_str("    if (( CURRENT == 2 )); then\n");
    s.push_str("        compadd -- \"${verbs[@]}\"\n");
    s.push_str("        return\n");
    s.push_str("    fi\n");
    s.push('\n');
    s.push_str("    local verb=\"${words[2]}\"\n");
    s.push_str("    case \"$verb\" in\n");
    for (verb, subs) in SUBCOMMANDS {
        // Same leading-`(` trick as the bash generator (POSIX-legal, avoids
        // an unmatched case-label `)`).
        s.push_str("        (");
        s.push_str(verb);
        s.push_str(") compadd -- ");
        s.push_str(&subs.join(" "));
        s.push_str(" ;;\n");
    }
    s.push_str("    esac\n");
    s.push_str("}\n");
    s.push('\n');
    s.push_str("_loot \"$@\"\n");
    s
}

/// `loot completions fish` — `complete -c loot` lines. Verb names complete
/// when no subcommand has been seen yet; [`SUBCOMMANDS`] adds one
/// `__fish_seen_subcommand_from <verb>`-gated line per multi-word verb.
fn fish_completions() -> String {
    let verbs = completion_verb_names().join(" ");
    let mut s = String::new();
    s.push_str("# loot shell completion (fish) — generated by `loot completions fish`; do not edit by hand\n");
    s.push('\n');
    s.push_str("complete -c loot -f\n");
    s.push_str("complete -c loot -n '__fish_use_subcommand' -a '");
    s.push_str(&verbs);
    s.push_str("'\n");
    s.push('\n');
    for (verb, subs) in SUBCOMMANDS {
        s.push_str("complete -c loot -n '__fish_seen_subcommand_from ");
        s.push_str(verb);
        s.push_str("' -a '");
        s.push_str(&subs.join(" "));
        s.push_str("'\n");
    }
    s
}

/// `loot completions <bash|zsh|fish>` (#23) — print a shell completion script
/// to stdout for the caller to pipe into their shell config. No repo needed
/// (like `--help`/`--version`); an unknown or missing shell name is a clear
/// usage error rather than a silent no-op.
fn cmd_completions(args: &[String]) -> Result<(), String> {
    let script = match args.first().map(String::as_str) {
        Some("bash") => bash_completions(),
        Some("zsh") => zsh_completions(),
        Some("fish") => fish_completions(),
        Some(other) => {
            return Err(format!("unknown shell '{other}' — usage: loot completions <bash|zsh|fish>"))
        }
        None => return Err("usage: loot completions <bash|zsh|fish>".into()),
    };
    print!("{script}");
    Ok(())
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
    ws.remotes().url(name)
        .ok_or_else(|| format!("no remote '{name}' configured — use `loot remote add {name} <url>` or pass a URL directly"))
}

// 32 objects per batch: coarse enough for low round-trip count on typical
// pushes, fine enough that an interrupted transfer loses at most ~32 objects
// before the next re-negotiate checkpoint (ADR 0024).
const OBJECTS_PER_BATCH: usize = 32;

// Byte cap per push batch (#309): the relay buffers each request body whole
// and refuses one over loot_net::MAX_BODY_BYTES, so batches stay well under it
// — the 8× headroom absorbs the change delta, keys, and envelope that ride on
// top of the counted object ciphertext. A single object larger than this still
// ships alone (only the relay's hard limit can refuse it).
const BYTES_PER_BATCH: usize = loot_net::MAX_BODY_BYTES / 8;

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
    let offered = ws.offered_objects(&have);
    if offered.is_empty() && ws.has_unsigned_tip() {
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
    let bundles = ws.bundle_wanted_batched(&have, &wants, OBJECTS_PER_BATCH, BYTES_PER_BATCH)?;
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
    embargoed: &[(std::path::PathBuf, Oid, u64)],
    manifest: &loot_core::manifest::Manifest,
    peers: &[(String, [u8; 32])],
    own_pubkey: [u8; 32],
) -> Vec<EmbargoDeposit> {
    let mut plan = Vec::new();
    for (path, oid, reveal_at) in embargoed {
        for (peer, peer_pubkey) in peers {
            if *peer_pubkey == own_pubkey {
                continue; // the originator already holds the key
            }
            let already_granted = manifest
                .grants_for(oid)
                .iter()
                .any(|e| e.grantee_pubkey == *peer_pubkey);
            if !already_granted {
                plan.push(EmbargoDeposit {
                    path: path.clone(),
                    oid: oid.clone(),
                    peer: peer.clone(),
                    peer_pubkey: *peer_pubkey,
                    reveal_at: *reveal_at,
                });
            }
        }
    }
    plan
}

/// Deposit a timed SealedGrant at the relay mailbox for every planned
/// (embargoed oid × peer) pair. Each deposit seals + delivers atomically
/// (`Workspace::deposit_sealed_grant`) so a failed delivery never persists its
/// manifest record — the next push retries it instead of skipping it forever.
fn deposit_embargo_grants(
    ws: &mut Workspace,
    url: &str,
    id: &identity::Identity,
) -> Result<(), String> {
    let embargoed = ws.embargoed_paths();
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
    let plan = plan_embargo_deposits(&embargoed, ws.manifest(), &peers, my_pubkey);
    if plan.is_empty() {
        return Ok(());
    }
    for d in &plan {
        let recipient_x25519 = identity::x25519_pubkey_from_ed25519_bytes(&d.peer_pubkey)
            .map_err(|e| format!("could not derive x25519 key for '{}': {e}", d.peer))?;
        ws.deposit_sealed_grant(
            &d.oid,
            &d.peer,
            d.peer_pubkey,
            my_pubkey,
            d.reveal_at,
            |key| {
                identity::seal_key(key, &recipient_x25519)
                    .map_err(|e| loot_core::RepoError::Backend(e.to_string()))
            },
            |bundle| {
                let envelope = id.wrap_envelope(&bundle);
                loot_net::deliver_grant(url, &d.peer_pubkey, &envelope).map_err(|e| e.to_string())
            },
        )?;
        println!("  {} → {} (embargoed until {})", d.path.display(), d.peer, d.reveal_at);
    }
    println!(
        "deposited {} timed grant(s) — the relay withholds each key until its reveal time (ADR 0027)",
        plan.len()
    );
    Ok(())
}

/// The production adapter at the [`workspace::SyncTransport`] seam (#217):
/// today's loot-net client functions, bound to the resolved relay URL. The
/// pipeline itself lives behind `Workspace::pull_via`.
struct HttpTransport {
    url: String,
}
impl workspace::SyncTransport for HttpTransport {
    fn offer(&self, have: &[Oid]) -> Result<Vec<Oid>, String> {
        loot_net::offer(&self.url, have).map_err(|e| e.to_string())
    }
    fn fetch(&self, have: &[Oid], wants: &[Oid]) -> Result<Vec<u8>, String> {
        loot_net::fetch(&self.url, have, wants).map_err(|e| e.to_string())
    }
}

fn cmd_pull(args: &[String]) -> Result<(), String> {
    let fmt = out_fmt(args);
    let no_surface = has_flag(args, "--no-surface");
    let mut ws = Workspace::open()?;
    let url = resolve_remote(args, &ws)?;
    run_pull(&mut ws, &HttpTransport { url: url.clone() }, &url, fmt, no_surface)
}

/// The verb behind the transport seam, so tests drive it in-process (#3).
/// The whole pipeline — negotiate, batched fetch with per-batch persist,
/// apply, post-pull converge, worst-folding — is `Workspace::pull_via`
/// (#217); this renders, then auto-surfaces after a non-empty converged
/// apply, exactly as `loot clone` does — users ran `loot surface` by hand
/// after nearly every pull. `--no-surface` opts out, and a deferred pull
/// (capture-first left heads unconverged, #219) keeps the
/// finalize-then-re-pull instruction instead: surfacing there would only
/// rewrite the operator's own captured tree, not the pulled content.
fn run_pull(
    ws: &mut Workspace,
    transport: &impl workspace::SyncTransport,
    url: &str,
    fmt: OutFmt,
    no_surface: bool,
) -> Result<(), String> {
    let identity = ws.identity().to_string();
    let report = ws.pull_via(transport)?;
    let outcomes = &report.outcomes;

    let human = if outcomes.is_empty() && report.deferred.is_none() {
        format!("pulled from {url}: nothing new (already up to date)\n")
    } else {
        let mut out = format!("pulled from {url} as {identity}:\n");
        out.push_str(&outcome_rows(outcomes));
        match &report.deferred {
            // Capture-first (#219): a dirty tree was captured, so the
            // freshly ingested heads are left flat this pass.
            Some(id) => {
                let _ = writeln!(
                    out,
                    "captured working change {}; heads left unconverged — finalize \
                     (`loot new`) then re-run `loot pull` to converge",
                    loot_core::hex::short(&id.0, 4)
                );
            }
            None if no_surface => {
                let _ = writeln!(
                    out,
                    "converged onto one line; run `loot surface` to materialize what you may see"
                );
            }
            None => {
                let _ = writeln!(out, "converged onto one line:");
            }
        }
        out
    };
    // Machine output: the merge verdict rows only, no prose (empty -> no lines).
    print!("{}", emit::Reconciliation { verdicts: verdicts_of(outcomes), human }.render(fmt));
    if !outcomes.is_empty() || report.deferred.is_some() {
        ws.record_op("pull", &format!("pull from {url} ({} path(s))", outcomes.len()), false);
    }
    // Auto-surface (#3): a non-empty converged apply materializes the tree.
    // Machine output still materializes — the working tree is behavior, not
    // rendering — but stays verdict-rows-only; a no-op pull stays quiet.
    if !no_surface && !outcomes.is_empty() && report.deferred.is_none() {
        let (head, written, skipped) = ws.surface_with_report()?;
        if matches!(fmt, OutFmt::Human) {
            print_surface_listing(&head, &written, skipped, ws.identity());
        }
    }
    Ok(())
}

// --- formatting (the log/outcome family lives in render.rs, R5 #181) ---

fn mark(vis: &loot_core::Visibility) -> String {
    // One home for the visibility token, shared with the machine `status`
    // output (CA3). Human phrasing is unchanged: public / restricted=a,b /
    // embargoed@<ts>.
    verdict::visibility_token(vis)
}

/// A pubkey prefix for display: first 4 bytes as hex, plus an ellipsis.
fn hex_short(bytes: &[u8]) -> String {
    format!("{}…", loot_core::hex::short(bytes, 4))
}

#[cfg(test)]
mod tests {
    use super::*;
    use render::{describe, NO_ID};
    use loot_core::{Repo, SyncBundle, Visibility};

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
        let mut dispatched: BTreeSet<&str> = COMMANDS.iter().map(|v| v.spec.name).collect();
        dispatched.insert("buoy"); // dispatched before the table (own ExitCode)
        assert_eq!(
            documented, dispatched,
            "usage text and the COMMANDS dispatch table disagree on the verb set"
        );
    }

    /// #237: the shipped `loot` binary must report its own version so a
    /// cargo-dist release tag and the one-liner-installed binary can't drift.
    /// The line is wired straight from the crate version, not a hand-kept string.
    #[test]
    fn version_line_reports_the_crate_version() {
        // `loot <semver>` — a bin name and a dotted, non-empty version tail so the
        // Install page's post-install check has something to match. We assert the
        // shape, not the literal number, so a version bump doesn't break the test.
        let line = version_line();
        assert!(line.starts_with("loot "));
        let ver = line.split(' ').nth(1).unwrap();
        assert!(!ver.is_empty() && ver.contains('.'), "expected a semver tail, got {ver:?}");
        assert!(ver.chars().next().is_some_and(|c| c.is_ascii_digit()), "semver starts with a digit");
    }

    // --- #67: the dispatch table's flag specs ---
    // The gate's own behavior is tested in `flags.rs`; these pin *this* table's
    // wiring — the specs real verbs declare.

    fn check(verb: &str, argv: &[&str]) -> Result<FlagCheck, String> {
        let v = COMMANDS.iter().find(|v| v.spec.name == verb).expect("a dispatched verb");
        v.spec.check(&args(argv))
    }

    // --- #4: `loot whoami --pubkey` + `loot peer add <name> -` (stdin) ---

    /// `--pubkey` must be a declared flag on `whoami` (else the #67 gate would
    /// reject it), and no stray flag sneaks through.
    #[test]
    fn whoami_pubkey_flag_is_wired() {
        assert_eq!(check("whoami", &["--pubkey"]), Ok(FlagCheck::Proceed));
        assert!(check("whoami", &["--bogus"]).is_err());
    }

    /// `--pubkey` prints the bare OpenSSH line and *nothing else* — exactly one
    /// line, so it pipes into `loot peer add <name> -` without a label to strip.
    #[test]
    fn whoami_pubkey_prints_only_the_key_line() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyBytesHere connor@loot";
        let out = render_whoami("connor", key, true);
        assert_eq!(out, format!("{key}\n"));
        // The default block still labels and coaches — unchanged behavior.
        let full = render_whoami("connor", key, false);
        assert!(full.contains("identity: connor") && full.contains("pubkey:   "));
        assert!(full.contains("loot peer add connor "));
    }

    /// `peer add <name> -` reads the key from the reader; a literal key never
    /// touches it (so a normal add never blocks on stdin).
    #[test]
    fn peer_add_dash_reads_from_the_reader() {
        let piped = resolve_pubkey_arg("-", || Ok("ssh-ed25519 PIPED connor@loot".into())).unwrap();
        assert_eq!(piped, "ssh-ed25519 PIPED connor@loot");

        let literal =
            resolve_pubkey_arg("ssh-ed25519 LITERAL a@b", || panic!("reader must not run for a literal"))
                .unwrap();
        assert_eq!(literal, "ssh-ed25519 LITERAL a@b");

        // An empty pipe is a loud error, not a silent empty registration.
        let err = resolve_pubkey_arg("-", || Err("peer add: `-` given but stdin was empty".into()));
        assert!(err.unwrap_err().contains("stdin was empty"));
    }

    /// The finding itself (pilot finding 11): a flag loot does not implement
    /// must fail loudly instead of silently reading as "the filter ran and
    /// matched everything". `--path` used to be exactly this trap on `log`
    /// (it now IS implemented, #6 — see `log_path_flag_is_wired` below) but
    /// the regression class it guards against is general, so this keeps
    /// proving it on a flag `log` still does not have.
    #[test]
    fn unknown_flag_is_rejected_not_ignored() {
        let err = check("log", &["--verbose", "x"]).unwrap_err();
        assert!(err.contains("--verbose"), "the error names the offending flag: {err}");
        assert!(err.contains("accepts: --path"), "`loot log` names --path as its one flag: {err}");
        // A flag that is real elsewhere in the CLI is still unknown here.
        assert!(check("log", &["--porcelain"]).is_err());
    }

    /// #6: `--path` must be a declared flag on `log` (else the #67 gate would
    /// reject it, like `--path` itself used to before this ticket), and it
    /// composes with the existing selector positional (#315) without either
    /// swallowing the other's argument.
    #[test]
    fn log_path_flag_is_wired() {
        assert_eq!(check("log", &["--path", "README.md"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("log", &["--path", "README.md", "HEAD"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("log", &["HEAD", "--path", "README.md"]), Ok(FlagCheck::Proceed));
        assert_eq!(log_selector(&args(&["--path", "README.md", "HEAD"])), Some("HEAD"));
        assert_eq!(log_selector(&args(&["HEAD", "--path", "README.md"])), Some("HEAD"));
        assert_eq!(log_selector(&args(&["--path", "README.md"])), None, "no selector, just a path filter");
    }

    /// The #66 guard, extended from verbs to their flags (#67): every flag the
    /// usage text shows on a verb's line must be one that verb accepts. The
    /// specs are hand-declared beside the table, so without this a documented
    /// flag could silently become a refusal — the mirror image of the bug #67
    /// fixed, and worse, because it breaks a flag that used to work.
    #[test]
    fn every_documented_flag_is_accepted_by_its_verb() {
        for line in USAGE.lines() {
            let Some(rest) = line.trim_start().strip_prefix("loot ") else { continue };
            let Some(name) = rest.split_whitespace().next() else { continue };
            let spec = match COMMANDS.iter().find(|v| v.spec.name == name) {
                Some(v) => &v.spec,
                None if name == "buoy" => &BUOY_FLAGS,
                None => continue, // not a verb line (prose that mentions `loot`)
            };
            // #278: a line that documents a subcommand (`loot lane gc …`,
            // `loot lane merge …`) must also pass that subcommand's own
            // gate — the verb's union alone would hide a flag documented on
            // the wrong sibling.
            let subhead = rest.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
            let subspec = LANE_SUBS.iter().find(|s| s.name == subhead);
            // Usage decorates flags with brackets and alternation:
            // `[--porcelain|--json]`, `[-m <message>]`.
            for token in rest.split(|c: char| c.is_whitespace() || "[]|()".contains(c)) {
                if !token.starts_with('-') || token == "-" {
                    continue;
                }
                assert!(
                    spec.check(&args(&[token])).is_ok(),
                    "usage documents `{token}` on `loot {name}`, but its spec rejects it"
                );
                if let Some(s) = subspec {
                    assert!(
                        s.check(&args(&[token])).is_ok(),
                        "usage documents `{token}` on `loot {subhead}`, but its subcommand spec rejects it"
                    );
                }
            }
        }
    }

    /// Every flag the verbs actually read still passes its own gate — the
    /// specs are hand-declared beside the table, so a missing entry would turn
    /// a working flag into a refusal.
    #[test]
    fn every_declared_flag_passes_its_verbs_gate() {
        assert_eq!(check("init", &["--identity", "alice"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("clone", &["url", "dir", "--identity", "alice"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("status", &["--porcelain"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("diff", &["--conflict", "a.txt"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("describe", &["-m", "subject", "--allow-demote", "a"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("new", &["--message", "s", "--no-snapshot"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("new", &["--ignore-working-copy"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("abandon", &["--head", "a3f9"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("adopt", &["a3f9", "--discard-wip"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("lane", &["merge", "x", "--json"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("lane", &["new", "--ticket", "67", "--name", "n", "--at", "d", "--json"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("lane", &["gc", "--stale-hours", "12"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("lanes", &["--porcelain"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("gc", &["--dry-run"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("gc", &["-n"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("log", &["--path", "a.txt"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("apply", &["b.bundle", "--json"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("grant", &["--relay", "origin", "p", "bob"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("maroon", &["p", "bob", "--hard", "--allow-demote", "a"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("migrate", &["p", "public", "--no-snapshot"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("conflicts", &["--json"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("serve", &["--dir", "d", "--addr", "a", "--allow", "k"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("push", &["--remote", "origin"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("pull", &["--remote", "origin", "--porcelain"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("pull", &["--no-surface"]), Ok(FlagCheck::Proceed));
        // #3: registering `--no-surface` must not loosen the gate — a typo'd
        // spelling is still refused, not read as "surface as usual".
        assert!(check("pull", &["--no-surfac"]).is_err());
        assert_eq!(check("pull-grants", &["--remote", "origin"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("grants", &["--remote", "origin"]), Ok(FlagCheck::Proceed));
        assert_eq!(check("ferry", &["--git-dir", "g", "--dock", "main", "--with-wip", "--json"]), Ok(FlagCheck::Proceed));
        assert_eq!(BUOY_FLAGS.check(&args(&["release", "--verbose", "--json"])), Ok(FlagCheck::Proceed));
    }

    /// The ADR 0030 globals ride exactly the verbs whose `cmd_*` reads them:
    /// `--allow-demote` every snapshotting verb, the capture skip all but
    /// `describe` (recording the tree is its whole job). `maroon` spells the
    /// skip out rather than reusing `SKIP` (it adds `--hard`), so this is what
    /// keeps the two in step.
    #[test]
    fn the_snapshot_globals_ride_their_verbs() {
        for v in ["new", "grant", "maroon", "migrate"] {
            for skip in SKIP {
                assert_eq!(check(v, &[skip]), Ok(FlagCheck::Proceed), "`loot {v} {skip}`");
            }
        }
        for v in ["new", "describe", "grant", "maroon", "migrate"] {
            assert_eq!(check(v, &["--allow-demote", "a"]), Ok(FlagCheck::Proceed), "`loot {v}`");
        }
        // `describe` always records the tree, so the skip is meaningless there,
        // and `status` is read-only — neither takes what it cannot honour.
        assert!(check("describe", &["--no-snapshot"]).is_err());
        assert!(check("status", &["--allow-demote", "a"]).is_err());
    }

    /// `buoy` dispatches ahead of the table; it is gated all the same.
    #[test]
    fn buoy_gates_its_flags_too() {
        assert!(BUOY_FLAGS.check(&args(&["--rolel", "release"])).is_err());
        assert_eq!(BUOY_FLAGS.check(&args(&["--help"])), Ok(FlagCheck::Help));
    }

    // --- #278: the subcommand gate ---
    // The table's `lane`/`dock` entry is the union over its subcommands, so a
    // flag real on a *sibling* subcommand passes `main`'s gate; the verb
    // re-checks the resolved subcommand's own spec before anything runs.

    /// The finding itself: `loot lane new --stale-hours 12` read as accepted
    /// (`--stale-hours` is `lane gc`'s flag) and did nothing. Each refusal
    /// fires at [`lane_gate`] — pure, so these tests never open a workspace:
    /// calling `cmd_lane` here walked the test runner's cwd into the
    /// developer's *real* `.loot` store whenever an arm got past the gate
    /// (#322).
    #[test]
    fn a_sibling_subcommands_flag_is_rejected_at_the_subcommand() {
        let err = lane_gate(&args(&["new", "--stale-hours", "12"])).unwrap_err();
        assert!(err.contains("--stale-hours"), "the error names the offending flag: {err}");
        assert!(err.contains("`loot lane new` accepts"), "{err}");

        let err = lane_gate(&args(&["gc", "--ticket", "67"])).unwrap_err();
        assert!(err.contains("--ticket"), "{err}");
        assert!(err.contains("`loot lane gc` accepts"), "{err}");

        // `lane name`/`lane rm` take no flags at all — even the union's
        // machine-output selectors refuse.
        let err = lane_gate(&args(&["name", "n", "--json"])).unwrap_err();
        assert!(err.contains("`loot lane name` takes no flags"), "{err}");
        let err = lane_gate(&args(&["rm", "t1", "--porcelain"])).unwrap_err();
        assert!(err.contains("`loot lane rm` takes no flags"), "{err}");

        // `lane merge` takes only the machine-output selectors — an unrelated
        // sibling flag (`--at`, the create form's) is refused, not ignored.
        let err = lane_gate(&args(&["merge", "x", "--at", "y"])).unwrap_err();
        assert!(err.contains("`loot lane merge` accepts"), "{err}");

        // An unknown subcommand refuses at the gate too, naming the usage.
        let err = lane_gate(&args(&["frobnicate"])).unwrap_err();
        assert!(err.contains("unknown lane subcommand 'frobnicate'"), "{err}");
    }

    /// Each subcommand's own flags still pass its gate — the narrowed specs
    /// must not turn a working flag into a refusal.
    #[test]
    fn each_subcommands_declared_flags_pass_its_own_gate() {
        let ok =
            |s: &FlagSpec, argv: &[&str]| assert_eq!(s.check(&args(argv)), Ok(FlagCheck::Proceed));
        ok(&LANE_NEW, &["new", "--ticket", "67", "--name", "n", "--at", "d", "--json"]);
        ok(&LANE_LIST, &["list", "--porcelain"]);
        ok(&LANE_NAME, &["name", "n"]);
        ok(&LANE_RM, &["rm", "t1"]);
        ok(&LANE_GC, &["gc", "--stale-hours", "12"]);
        ok(&LANE_MERGE, &["merge", "x", "--json"]);
    }

    /// The two gates must agree on which flags exist under the verb: the
    /// table's union is what catches a nowhere-flag (and honours `--help`)
    /// before dispatch, and the subcommand specs are what the verb re-checks.
    /// A flag added to one side only is either refused before its own gate
    /// can accept it, or slips back to silently-ignored — this is the "second
    /// dispatch table kept in step" #67 declined to hand-maintain, held by a
    /// test instead.
    #[test]
    fn the_verb_spec_is_the_union_of_its_subcommand_specs() {
        use std::collections::BTreeSet;
        let union = |subs: &[&FlagSpec]| -> (BTreeSet<&str>, BTreeSet<&str>) {
            (
                subs.iter().flat_map(|s| s.valued).copied().collect(),
                subs.iter().flat_map(|s| s.bare).copied().collect(),
            )
        };
        // `lane` is the only multi-subcommand verb now that `dock` is retired
        // (#253); its table entry must stay the union over `lane`'s subspecs.
        let table = &COMMANDS.iter().find(|v| v.spec.name == "lane").unwrap().spec;
        let (valued, bare) = union(LANE_SUBS);
        assert_eq!(table.valued.iter().copied().collect::<BTreeSet<_>>(), valued, "lane");
        assert_eq!(table.bare.iter().copied().collect::<BTreeSet<_>>(), bare, "lane");
    }

    /// Bare `loot lane` defaults to `list` — it must not panic slicing an
    /// empty argv (found wiring #278; `&args[1..]` on zero args). Asserted at
    /// the pure gate: the old form ran `cmd_lane(&[])`, which opened a
    /// workspace from the test runner's ambient cwd — the real `.loot` when
    /// run from the repo (#322). The end-to-end "returns a refusal, never
    /// panics" contract lives in `tests/cli_smoke.rs` with a controlled cwd.
    #[test]
    fn bare_lane_defaults_to_list_at_the_gate() {
        assert_eq!(lane_gate(&args(&[])), Ok("list"));
        assert_eq!(lane_gate(&args(&["ls"])), Ok("list"), "`ls` normalizes");
    }

    #[test]
    fn describe_names_the_relay_role() {
        assert_eq!(describe(&MergeOutcome::Converged), "converged");
        assert_eq!(describe(&MergeOutcome::Merged), "merged");
        assert!(describe(&MergeOutcome::RelayedUnmerged).contains("sealed"));
        assert!(describe(&MergeOutcome::Conflict { ours: loot_core::Oid([0; 32]), theirs: loot_core::Oid([1; 32]) }).contains("conflict"));
    }

    #[test]
    fn change_col_marks_divergence_with_a_bang() {
        use std::collections::BTreeSet;
        let cid = [7u8; 16];
        let plain: BTreeSet<[u8; 16]> = BTreeSet::new();
        let diverged: BTreeSet<[u8; 16]> = BTreeSet::from([cid]);

        // Non-divergent: bare letters. Divergent: same letters + trailing `!`.
        let base = change_col(Some(cid), &plain);
        assert!(!base.ends_with('!'), "a settled change carries no marker: {base}");
        assert_eq!(change_col(Some(cid), &diverged), format!("{base}!"));
        // A legacy/unsigned change (no change id) is the dash and never divergent.
        assert_eq!(change_col(None, &diverged), NO_ID);
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
        let plan = plan_embargo_deposits(&repo.embargoed_paths(), repo.manifest(), &peers, [0xaa; 32]);
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
        let plan = plan_embargo_deposits(&repo.embargoed_paths(), repo.manifest(), &peers, [0xaa; 32]);
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
        assert!(plan_embargo_deposits(&repo.embargoed_paths(), repo.manifest(), &[peer("bob", 0xbb)], [0xaa; 32])
            .is_empty());
    }

    #[test]
    fn plan_is_empty_for_a_non_keyholder() {
        // bob applied alice's bundle: he holds the embargoed ciphertext and the
        // tree, but no key (v5 bundles have no embargoed-key lane, ADR 0027) —
        // so he has nothing to deposit for anyone.
        let (alice, _) = embargoed_repo("plan-nonkey", 9_999);
        let bundle = alice.bundle(&[]).unwrap();
        let mut bob = DagRepo::init(tmp("plan-nonkey-bob").join("work"), "bob").unwrap();
        bob.apply(&bundle, 0).unwrap();
        assert!(plan_embargo_deposits(&bob.embargoed_paths(), bob.manifest(), &[peer("carol", 0xcc)], [0xbb; 32])
            .is_empty());
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
        let bundles = alice.bundle_wanted_batched(&[], &offered, 8, usize::MAX).unwrap();
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
            .with_repo_mut(|repo| {
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

    /// `--allow-demote` is repeatable; either skip flag sets `skip`.
    #[test]
    fn snapshot_opts_parse_globals() {
        let o = parse_snapshot_opts(&args(&["--allow-demote", "a.txt", "--allow-demote", "b.txt"]));
        assert_eq!(o.allow_demote, vec![std::path::PathBuf::from("a.txt"), std::path::PathBuf::from("b.txt")]);
        assert!(!o.skip);
        assert!(parse_snapshot_opts(&args(&["--no-snapshot"])).skip);
        assert!(parse_snapshot_opts(&args(&["--ignore-working-copy"])).skip);
        assert!(!parse_snapshot_opts(&args(&["x"])).skip);
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
    /// The name comes from `describe`/`new -m` (finalize refuses an un-described
    /// change, #174); the *capture* is still implicit, which is what this guards:
    /// `b.txt` is written after the name and never `status`-ed.
    #[test]
    fn new_captures_pending_edits_without_a_manual_status() {
        let dir = tmp("s1-new-capture");
        init_repo(&dir, "alice").unwrap();
        std::fs::write(dir.join("a.txt"), b"hello\n").unwrap();

        let mut ws = Workspace::open_at(&dir).unwrap();
        ws.snapshot_allowing("add the greeting files", &[]).unwrap();
        std::fs::write(dir.join("b.txt"), b"world\n").unwrap();
        ws.finalize_capturing(&[], false).unwrap();

        // Finalized: no working change left, one change carrying both files.
        assert!(ws.working_id().is_none());
        let log = ws.repo().log();
        assert_eq!(log.len(), 1, "exactly one finalized change");
        let tree = ws.repo().change_tree(&log[0].0).unwrap();
        assert!(tree.contains_key(std::path::Path::new("a.txt")), "a.txt captured: {tree:?}");
        assert!(tree.contains_key(std::path::Path::new("b.txt")), "b.txt captured: {tree:?}");
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

    // --- #21: `loot init` prints a `.lootattributes` quickstart ---

    /// The quickstart template printed after init must teach all three
    /// visibility modes — a comment explaining each, plus a concrete example
    /// line per mode — so a new user understands the model without the docs.
    #[test]
    fn lootattributes_quickstart_covers_all_three_modes() {
        let t = lootattributes_quickstart();
        // A comment line names and explains each mode.
        for mode in ["public", "restricted", "embargoed"] {
            assert!(
                t.lines().any(|l| l.starts_with('#') && l.contains(mode)),
                "no comment line explaining `{mode}`:\n{t}"
            );
        }
        // A concrete (non-comment) example line exercises each mode.
        let examples: Vec<&str> =
            t.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()).collect();
        assert!(examples.iter().any(|l| l.ends_with("public")), "no public example:\n{t}");
        assert!(examples.iter().any(|l| l.contains("restricted=")), "no restricted example:\n{t}");
        assert!(examples.iter().any(|l| l.contains("embargoed=")), "no embargoed example:\n{t}");
        // It names the file it's meant to be pasted into.
        assert!(t.contains(".lootattributes"), "template must name .lootattributes:\n{t}");
    }

    /// The quickstart is print-only: init must never materialize
    /// `.lootattributes` in the new repo — the user pastes it if they want it.
    #[test]
    fn init_never_writes_lootattributes_to_disk() {
        let dir = tmp("init-no-lootattributes");
        init_repo(&dir, "alice").unwrap();
        assert!(
            !dir.join(".lootattributes").exists(),
            ".lootattributes must not be written by init"
        );
    }

    /// An implicit capture (via the Snapshotted handle, #182) re-records the
    /// tree without clobbering a name a prior `describe` set.
    #[test]
    fn implicit_snapshot_preserves_describe_name() {
        let dir = tmp("s1-preserve-name");
        init_repo(&dir, "alice").unwrap();
        let mut ws = Workspace::open_at(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"v1\n").unwrap();
        ws.snapshot_allowing("the intro", &[]).unwrap(); // like `describe -m`
        assert_eq!(ws.working_message().as_deref(), Some("the intro"));

        std::fs::write(dir.join("a.txt"), b"v2\n").unwrap();
        let _ = ws.snapshotted(&SnapshotOpts::default()).unwrap();
        assert_eq!(ws.working_message().as_deref(), Some("the intro"), "name survives implicit capture");
    }

    /// `--no-snapshot` acts on the last recorded working change: a later edit is
    /// not captured, so the working change id is unchanged; without the flag the
    /// same edit is captured and the id moves. The skip rides the handle's
    /// constructor, so even a skipped verb holds the proof-of-capture type.
    #[test]
    fn no_snapshot_skips_the_implicit_capture() {
        let dir = tmp("s1-skip");
        init_repo(&dir, "alice").unwrap();
        let mut ws = Workspace::open_at(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"v1\n").unwrap();
        ws.snapshot_allowing(workspace::UNDESCRIBED_MESSAGE, &[]).unwrap();
        let before = ws.working_id().cloned();

        std::fs::write(dir.join("a.txt"), b"v2\n").unwrap();
        let _ = ws.snapshotted(&SnapshotOpts { allow_demote: vec![], skip: true }).unwrap();
        assert_eq!(ws.working_id(), before.as_ref(), "skip leaves the working change untouched");

        let _ = ws.snapshotted(&SnapshotOpts::default()).unwrap();
        assert_ne!(ws.working_id(), before.as_ref(), "a real capture moves the working change");
    }

    // --- #3: `loot pull` auto-surfaces after a non-empty apply ---

    /// The in-memory adapter at the SyncTransport seam, as workspace.rs's own
    /// pull tests build it (that module is private to the lib, so the bin's
    /// tests mirror it): a relay-role DagRepo answering offer/fetch with
    /// exactly the engine methods the HTTP relay's handlers call.
    struct InMemoryRelay(DagRepo);
    impl workspace::SyncTransport for InMemoryRelay {
        fn offer(&self, have: &[Oid]) -> Result<Vec<Oid>, String> {
            Ok(self.0.offered_objects(have))
        }
        fn fetch(&self, have: &[Oid], wants: &[Oid]) -> Result<Vec<u8>, String> {
            self.0.bundle_wanted(have, wants).map(|b| b.0).map_err(|e| e.to_string())
        }
    }

    /// An alice workspace with one finalized public `doc.txt` change, a relay
    /// stowing everything she published, and a fresh bob who has pulled
    /// nothing yet — the auto-surface scenario (#3).
    fn pull_fixture(
        tag: &str,
    ) -> (Workspace, InMemoryRelay, std::path::PathBuf, Workspace) {
        let dir_a = tmp(&format!("{tag}-a"));
        init_repo(&dir_a, "alice").unwrap();
        let mut alice = Workspace::open_at(&dir_a).unwrap();
        std::fs::write(dir_a.join("doc.txt"), b"v1").unwrap();
        alice.snapshot("doc").unwrap();
        alice.finalize_working().unwrap();
        let mut relay = DagRepo::init(tmp(&format!("{tag}-relay")), "relay").unwrap();
        relay.stow(&alice.repo().bundle(&[]).unwrap()).unwrap();
        let dir_b = tmp(&format!("{tag}-b"));
        init_repo(&dir_b, "bob").unwrap();
        let bob = Workspace::open_at(&dir_b).unwrap();
        (alice, InMemoryRelay(relay), dir_b, bob)
    }

    /// #3: a non-empty converged apply auto-surfaces — the pulled content
    /// lands on disk without a separate `loot surface`, as `loot clone` does.
    #[test]
    fn pull_materializes_the_tree_after_a_nonempty_apply() {
        let (_alice, relay, dir_b, mut bob) = pull_fixture("pull-surf");
        run_pull(&mut bob, &relay, "mem://relay", OutFmt::Human, false).unwrap();
        assert_eq!(
            std::fs::read(dir_b.join("doc.txt")).unwrap(),
            b"v1",
            "the pull surfaced what bob may see"
        );
    }

    /// #3: `--no-surface` opts out — the graph still converges onto the
    /// pulled line, but the tree stays untouched.
    #[test]
    fn pull_no_surface_skips_materialization() {
        let (alice, relay, dir_b, mut bob) = pull_fixture("pull-nosurf");
        run_pull(&mut bob, &relay, "mem://relay", OutFmt::Human, true).unwrap();
        assert!(!dir_b.join("doc.txt").exists(), "--no-surface leaves the tree alone");
        assert_eq!(bob.heads(), alice.heads(), "the pull itself still converged");
    }

    /// #3: a no-op pull stays quiet — nothing new to apply means no surface
    /// pass: the tree, the graph, and the working slot are all untouched.
    #[test]
    fn noop_pull_skips_surface() {
        let (_alice, relay, dir_b, mut bob) = pull_fixture("pull-noop");
        run_pull(&mut bob, &relay, "mem://relay", OutFmt::Human, false).unwrap();
        let heads = bob.heads();
        run_pull(&mut bob, &relay, "mem://relay", OutFmt::Human, false).unwrap();
        assert_eq!(bob.heads(), heads, "nothing new ingested");
        assert!(bob.working_id().is_none(), "a no-op pull mints no working change");
        assert_eq!(std::fs::read(dir_b.join("doc.txt")).unwrap(), b"v1");
    }

    // --- #23: `loot completions <bash|zsh|fish>` ---
    //
    // No shell to actually source on this machine, so these tests cover what's
    // checkable without one: every verb and multi-word subcommand shows up in
    // each generated script, basic structural validity (paired braces/parens/
    // quotes), and the overall shape of each script (snapshot-style anchors —
    // not the full text, so cosmetic rewording doesn't break the suite).

    /// A crude but real structural check: every opening brace/paren and every
    /// quote character has a matching close, counted over the whole script
    /// (not stack-based — "balanced where feasible", per the ticket, and the
    /// generators never nest unmatched delimiters inside a string literal).
    fn assert_balanced(shell: &str, s: &str) {
        let braces = s.chars().filter(|&c| c == '{').count() as i64
            - s.chars().filter(|&c| c == '}').count() as i64;
        let parens = s.chars().filter(|&c| c == '(').count() as i64
            - s.chars().filter(|&c| c == ')').count() as i64;
        let dquotes = s.chars().filter(|&c| c == '"').count();
        let squotes = s.chars().filter(|&c| c == '\'').count();
        assert_eq!(braces, 0, "{shell}: unbalanced braces:\n{s}");
        assert_eq!(parens, 0, "{shell}: unbalanced parens:\n{s}");
        assert_eq!(dquotes % 2, 0, "{shell}: unbalanced double quotes:\n{s}");
        assert_eq!(squotes % 2, 0, "{shell}: unbalanced single quotes:\n{s}");
    }

    /// Word-boundary containment — `contains` alone would let `"op"` match
    /// inside an unrelated word like `"stop"`; splitting on anything that
    /// isn't alphanumeric/hyphen and comparing whole tokens catches that.
    fn contains_word(haystack: &str, word: &str) -> bool {
        haystack.split(|c: char| !(c.is_alphanumeric() || c == '-')).any(|tok| tok == word)
    }

    fn all_scripts() -> [(&'static str, String); 3] {
        [("bash", bash_completions()), ("zsh", zsh_completions()), ("fish", fish_completions())]
    }

    /// The generation contract: every script is built from [`COMMANDS`], so a
    /// verb added to the dispatch table is offered by every shell without
    /// touching this file (the whole point of generating rather than
    /// hand-maintaining a second command list).
    #[test]
    fn every_script_covers_every_top_level_verb() {
        for (shell, script) in all_scripts() {
            for name in completion_verb_names() {
                assert!(
                    contains_word(&script, name),
                    "{shell} completion is missing top-level verb `{name}`"
                );
            }
        }
    }

    /// The [`SUBCOMMANDS`] supplement: multi-word leaves (`peer add`, `lane
    /// gc`, …) that the flag-spec table alone doesn't carry.
    #[test]
    fn every_script_covers_every_multi_word_subcommand() {
        for (shell, script) in all_scripts() {
            for (verb, subs) in SUBCOMMANDS {
                for sub in *subs {
                    assert!(
                        contains_word(&script, sub),
                        "{shell} completion for `{verb}` is missing subcommand `{sub}`"
                    );
                }
            }
        }
    }

    #[test]
    fn every_script_is_structurally_balanced() {
        for (shell, script) in all_scripts() {
            assert_balanced(shell, &script);
        }
    }

    /// Snapshot-style shape checks — the anchors a real completion file for
    /// each shell must carry, not the full text (so rewording a comment can't
    /// break the suite).
    #[test]
    fn bash_completion_has_the_expected_shape() {
        let s = bash_completions();
        assert!(s.starts_with("# loot shell completion (bash)"));
        assert!(s.contains("_loot_completions() {"));
        assert!(s.contains("complete -F _loot_completions loot"));
        assert!(s.contains("COMP_WORDS"));
    }

    #[test]
    fn zsh_completion_has_the_expected_shape() {
        let s = zsh_completions();
        assert!(s.starts_with("#compdef loot"));
        assert!(s.contains("_loot() {"));
        assert!(s.contains("compadd"));
        assert!(s.trim_end().ends_with("_loot \"$@\""));
    }

    #[test]
    fn fish_completion_has_the_expected_shape() {
        let s = fish_completions();
        assert!(s.starts_with("# loot shell completion (fish)"));
        assert!(s.contains("complete -c loot -f"));
        assert!(s.contains("__fish_use_subcommand"));
        assert!(s.contains("__fish_seen_subcommand_from lane"));
    }

    /// `loot completions` is a real dispatched verb, documented like every
    /// other (the #66 guard already asserts this generally; pinned here too
    /// so the intent is legible beside the rest of the completions tests).
    #[test]
    fn completions_verb_is_dispatched_and_documented() {
        assert!(COMMANDS.iter().any(|v| v.spec.name == "completions"));
        assert!(USAGE.contains("loot completions <bash|zsh|fish>"));
    }

    /// The acceptance bar: a bare or unknown shell name is a clear usage
    /// error, never a silent no-op or a panic.
    #[test]
    fn cmd_completions_rejects_missing_or_unknown_shell() {
        let err = cmd_completions(&args(&[])).unwrap_err();
        assert!(err.contains("usage: loot completions <bash|zsh|fish>"), "{err}");

        let err = cmd_completions(&args(&["powershell"])).unwrap_err();
        assert!(err.contains("unknown shell 'powershell'"), "{err}");
        assert!(err.contains("usage: loot completions <bash|zsh|fish>"), "{err}");
    }

    /// Each supported shell name is accepted and dispatch never opens a
    /// workspace — `completions` needs no repo, so this stays a plain
    /// in-process check (no controlled-cwd hazard, #322).
    #[test]
    fn cmd_completions_accepts_each_supported_shell() {
        for shell in ["bash", "zsh", "fish"] {
            assert!(cmd_completions(&args(&[shell])).is_ok(), "loot completions {shell}");
        }
    }

    /// The flag gate still applies: `completions` takes no flags, so a stray
    /// one is refused rather than silently accepted (#67).
    #[test]
    fn completions_takes_no_flags() {
        assert_eq!(check("completions", &["bash"]), Ok(FlagCheck::Proceed));
        assert!(check("completions", &["--bogus"]).is_err());
    }
}
