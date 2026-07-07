//! `loot` — a CLI over the canonical engine (ADR 0005, 0006).
//!
//! JJ-style: the working tree *is* the current change. `status` snapshots it,
//! `describe` names it, `new` finalizes it and starts fresh. No commit ceremony.
//! All ambient state (`.loot/` home, identity, clock, persistence, working-change
//! id) is owned by the [`Workspace`]; commands are thin verbs over it.

mod workspace;

use loot_core::{MaroonResult, MergeOutcome, MigrateResult, Oid, Repo, SyncBundle, Visibility};
use loot_identity as identity;
use std::process::ExitCode;
use workspace::{DockAction, GlobalConfig, Workspace};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    let rest = &args[args.len().min(1)..];

    let result = match cmd {
        "init" => cmd_init(rest),
        "status" => cmd_status(rest),
        "describe" => cmd_describe(rest),
        "new" => cmd_new(),
        "surface" => cmd_surface(),
        "dock" => cmd_dock(rest),
        "docks" => cmd_docks(),
        "log" => cmd_log(),
        "bundle" => cmd_bundle(rest),
        "apply" => cmd_apply(rest),
        "grant" => cmd_grant(rest),
        "maroon" => cmd_maroon(rest),
        "migrate" => cmd_migrate(rest),
        "manifest" => cmd_manifest(),
        "attest" => cmd_attest(rest),
        "conflicts" => cmd_conflicts(),
        "resolve" => cmd_resolve(rest),
        "remote" => cmd_remote(rest),
        "keygen" => cmd_keygen(),
        "whoami" => cmd_whoami(),
        "peer" => cmd_peer(rest),
        "serve" => cmd_serve(rest),
        "push" => cmd_push(rest),
        "pull" => cmd_pull(rest),
        "pull-grants" => cmd_pull_grants(rest),
        "grants" => cmd_grants(rest),
        "clone" => cmd_clone(rest),
        "config" => cmd_config(rest),
        "id" => cmd_id(rest),
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
  loot init [--identity <name>]             initialize a repo here (identity from global config if omitted)
  loot clone <url> <dir> [--identity <name>]  clone a relay into <dir>
  loot config [set <key> <val>] [unset <key>] [list]  manage global config (~/.config/loot/config)
  loot status [-m <message>]                snapshot the working tree into the working change
  loot describe -m <message>                name the working change
  loot new                                  finalize the working change; start a fresh one
  loot surface                              materialize what the current identity may see
  loot dock <name>                          create a dock (isolated working tree + tip), or switch to one
  loot docks                                list docks with their tip and visibility
  loot log                                  show change history
  loot bundle <file>                        write a sync bundle (ciphertext, no private keys)
  loot apply <file>                         merge a peer's bundle (idempotent)
  loot grant <path> <identity> <file>       write a targeted grant bundle for <identity> (file delivery)
  loot grant --relay <name> <path> <identity>  seal and deliver a grant via relay mailbox
  loot grants [<url>] [--remote <name>]     peek pending grant count (no download)
  loot pull-grants [<url>] [--remote <name>]   fetch, verify, and apply sealed grants from relay
  loot maroon [--hard] <path> <identity> [dir]  cut off <identity> from future access; --hard adds a purge event
  loot migrate <path> <vis-spec> [dir]      change a path's visibility (public | restricted=a,b | embargoed=<ts>)
  loot manifest                             show the grant audit trail (and attestations)
  loot attest <change-id> [role]            attest a change (advisory sign-off, ADR 0018)
  loot conflicts                            list paths that need human resolution
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
  loot pull [<url>] [--remote <name>]       fetch and merge changes from a relay";

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
    let id_name = flag(args, "--identity")
        .map(String::from)
        .or_else(|| GlobalConfig::load().get("identity").map(String::from))
        .ok_or("init requires --identity <name> (or set `identity` in `loot config`)")?;
    init_repo(std::path::Path::new("."), &id_name)
}

/// Shared init logic: initialize a repo at `dir`, generate keypair, print summary.
fn init_repo(dir: &std::path::Path, id_name: &str) -> Result<(), String> {
    let ws = Workspace::init_at(dir, id_name)?;
    let dot = ws.dot();
    let keypair = identity::generate_and_save(dot, &format!("{id_name}@loot"))
        .map_err(|e| e.to_string())?;
    let pub_line = std::fs::read_to_string(dot.join("id.pub"))
        .map_err(|e| format!("read id.pub: {e}"))?;
    println!("initialized empty loot repo at {}, identity = {id_name}", dir.display());
    println!("public key: {}", pub_line.trim());
    println!("tip: share your public key with peers via `loot whoami`");
    println!("tip: declare per-file privacy in .lootattributes, e.g. `.env restricted={id_name}`");
    let _ = keypair;
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

fn cmd_dock(args: &[String]) -> Result<(), String> {
    let name = args
        .first()
        .ok_or("dock requires <name>\n  loot dock <name>   create a dock, or switch to an existing one")?;
    let mut ws = Workspace::open()?;
    let from = ws.current_dock().to_string();
    match ws.dock_goto(name)? {
        DockAction::Already => println!("already on dock '{name}'"),
        DockAction::Switched => {
            println!("switched to dock '{name}' — working tree re-materialized (run `loot docks`)");
        }
        DockAction::Created => {
            println!("created dock '{name}' off '{from}' and switched to it");
        }
    }
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

fn cmd_log() -> Result<(), String> {
    let ws = Workspace::open()?;
    let detailed = ws.repo().log_detailed();
    if detailed.is_empty() {
        println!("no changes yet");
        return Ok(());
    }

    // Resolve each change's author pubkey to a peer name (short-hex fallback),
    // reusing the peer registry (S3, ADR 0018). Author trust stays advisory —
    // this is display only.
    let reg = identity::PeerRegistry::load(ws.dot());
    let author_of = |id: &loot_core::Oid| match ws.repo().change_author(id) {
        Some(pk) => format!("  [logged by {}]", resolve_pubkey_name(&reg, &pk)),
        None => String::new(),
    };
    let print_attestations = |id: &loot_core::Oid| {
        for a in ws.repo().attestations_for(id) {
            println!("      + attested by {} ({})", resolve_pubkey_name(&reg, &a.attester), a.role);
        }
    };

    // A single head keeps the flat, newest-first listing (unchanged). Only a
    // diverged graph (2+ heads, e.g. after a pull) switches to a branch view.
    if ws.repo().heads().len() <= 1 {
        for (id, message, total, restricted, embargoed) in detailed.into_iter().rev() {
            println!("{}  {}{}{}", short(&id), message, seal_hint(total, restricted, embargoed), author_of(&id));
            print_attestations(&id);
        }
        if let Some(working) = ws.working_id() {
            println!("{}  (working change)", short(&working));
        }
        return Ok(());
    }

    // Multi-head: show each head's own lineage indented under a label, then the
    // shared ancestry once. Makes the divergence visible before `loot apply`.
    let hints: std::collections::BTreeMap<Oid, String> = detailed
        .iter()
        .map(|(id, _m, total, restricted, embargoed)| {
            (id.clone(), seal_hint(*total, *restricted, *embargoed))
        })
        .collect();
    let hint_for = |id: &Oid| hints.get(id).map(String::as_str).unwrap_or("");

    let g = ws.repo().log_graph();
    println!("{} heads — diverged; run `loot apply` to converge", g.heads.len());
    for (hi, head) in g.heads.iter().enumerate() {
        println!();
        println!("head {} — {}", hi + 1, short(head));
        for node in g.changes.iter().filter(|n| n.reachable_from == [hi]) {
            println!("  {}  {}{}{}", short(&node.id), node.message, hint_for(&node.id), author_of(&node.id));
            print_attestations(&node.id);
        }
    }

    let shared: Vec<&loot_core::LogNode> =
        g.changes.iter().filter(|n| n.reachable_from.len() > 1).collect();
    if !shared.is_empty() {
        println!();
        println!("shared history");
        for node in shared {
            println!("  {}  {}{}{}", short(&node.id), node.message, hint_for(&node.id), author_of(&node.id));
            print_attestations(&node.id);
        }
    }
    Ok(())
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
        println!("run `loot surface` to materialize what you may see");
    }
    Ok(())
}

fn cmd_grant(args: &[String]) -> Result<(), String> {
    if args.iter().any(|a| a == "--relay") {
        return cmd_grant_relay(args);
    }
    if args.len() < 3 {
        return Err("grant requires <path> <identity> <file>\n  or: grant --relay <remote> <path> <identity>".into());
    }
    let path = &args[0];
    let grantee = &args[1];
    let out = &args[2];

    let mut ws = Workspace::open()?;
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
    Ok(())
}

fn cmd_grant_relay(args: &[String]) -> Result<(), String> {
    // Usage: grant --relay <remote-name-or-url> <path> <identity>
    let relay_target = flag(args, "--relay")
        .ok_or("grant --relay requires a relay name or URL after --relay")?;
    let positional: Vec<&str> = args.iter()
        .filter(|a| !a.starts_with('-') && a.as_str() != relay_target)
        .map(String::as_str)
        .collect();
    if positional.len() < 2 {
        return Err("grant --relay <remote> <path> <identity>".into());
    }
    let path = positional[0];
    let grantee = positional[1];

    let mut ws = Workspace::open()?;
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

    let bundle = ws.with_repo(|repo| {
        repo.grant_sealed(&oid, grantee, grantee_ed_pubkey, grantor_pubkey, now, |content_key| {
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
    println!("  recipient runs `loot pull-grants` to receive it");
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
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if positional.len() < 2 {
        return Err("maroon requires <path> <identity> [dir]".into());
    }
    let path = std::path::Path::new(positional[0].as_str());
    let marooned = positional[1].as_str();
    let out_dir = positional
        .get(2)
        .map(|s| std::path::Path::new(s.as_str()))
        .unwrap_or(std::path::Path::new("."));

    let mut ws = Workspace::open()?;
    let now = ws.now();
    let result: MaroonResult = ws.with_repo(|repo| {
        if hard {
            repo.maroon_hard(path, marooned, now).map_err(|e| e.to_string())
        } else {
            repo.maroon(path, marooned, now).map_err(|e| e.to_string())
        }
    })?;

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
    if args.len() < 2 {
        return Err("migrate requires <path> <vis-spec> [dir]".into());
    }
    let path = std::path::Path::new(args[0].as_str());
    let new_vis = parse_vis_spec(&args[1])?;
    let out_dir = args
        .get(2)
        .map(|s| std::path::Path::new(s.as_str()))
        .unwrap_or(std::path::Path::new("."));

    let mut ws = Workspace::open()?;
    let now = ws.now();
    let result: MigrateResult = ws.with_repo(|repo| {
        repo.migrate(path, new_vis.clone(), now).map_err(|e| e.to_string())
    })?;

    let vis_label = match &new_vis {
        Visibility::Public => "public".to_string(),
        Visibility::Restricted(ids) => format!("restricted={}", ids.join(",")),
        Visibility::Embargoed { reveal_at } => format!("embargoed@{reveal_at}"),
    };
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

fn cmd_conflicts() -> Result<(), String> {
    let ws = Workspace::open()?;
    let conflicts = ws.repo().conflicts();
    if conflicts.is_empty() {
        println!("no conflicts");
        return Ok(());
    }
    for (path, (our_oid, their_oid)) in conflicts {
        println!("conflict at {}", path.display());
        println!("  ours:   {}", short(our_oid));
        println!("  theirs: {}", short(their_oid));
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
    let now = ws.now();

    // Determine the visibility for this path from .lootattributes (same logic
    // snapshot uses). Unrecognized paths default to Public.
    let vis = ws.visibility_for(&path.to_string_lossy());

    let new_oid = ws.with_repo(|repo| {
        repo.resolve(path, &bytes, vis, now).map_err(|e| e.to_string())
    })?;

    println!("resolved {} (new oid: {})", path.display(), short(&new_oid));

    // Check if all conflicts are now clear.
    if ws.repo().conflicts().is_empty() {
        println!("all conflicts resolved — run `loot new` to finalize");
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

fn cmd_push(args: &[String]) -> Result<(), String> {
    let ws = Workspace::open()?;
    let url = resolve_remote(args, &ws)?;
    let id = identity::load_or_missing(ws.dot()).map_err(|e| e.to_string())?;
    let bundle = ws.repo().bundle(&[]).map_err(|e| e.to_string())?;
    let n = bundle.0.len();
    loot_net::push(&url, bundle.0, &id).map_err(|e| e.to_string())?;
    println!("pushed {n} bytes to {url}");
    println!("  this published your sealed content to the relay (it still cannot read it)");
    Ok(())
}

fn cmd_pull(args: &[String]) -> Result<(), String> {
    let mut ws = Workspace::open()?;
    let url = resolve_remote(args, &ws)?;
    let now = ws.now();
    let identity = ws.identity().to_string();
    let have = ws.repo().heads();
    let bytes = loot_net::pull(&url, &have).map_err(|e| e.to_string())?;
    if bytes.is_empty() {
        println!("pulled from {url}: nothing new (already up to date)");
        return Ok(());
    }
    let outcomes = ws.with_repo(|repo| {
        repo.apply(&SyncBundle(bytes), now).map_err(|e| e.to_string())
    })?;
    if outcomes.is_empty() {
        println!("pulled from {url}: nothing new (already up to date)");
    } else {
        println!("pulled from {url} as {identity}:");
        for (path, outcome) in &outcomes {
            println!("  {:<24} {}", path.display(), describe(outcome));
        }
        println!("run `loot surface` to materialize what you may see");
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

/// A pubkey prefix for display: first 4 bytes as hex, plus an ellipsis.
fn hex_short(bytes: &[u8]) -> String {
    format!("{}…", loot_core::hex::short(bytes, 4))
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
        assert!(describe(&MergeOutcome::Conflict { ours: loot_core::Oid([0; 32]), theirs: loot_core::Oid([1; 32]) }).contains("conflict"));
    }

    #[test]
    fn mark_renders_visibility() {
        assert_eq!(mark(&Visibility::Public), "public");
        assert_eq!(mark(&Visibility::Restricted(vec!["a".into(), "b".into()])), "restricted=a,b");
        assert_eq!(mark(&Visibility::Embargoed { reveal_at: 5 }), "embargoed@5");
    }
}
