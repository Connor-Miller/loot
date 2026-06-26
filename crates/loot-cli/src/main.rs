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
        "surface" => cmd_surface(),
        "log" => cmd_log(),
        "bundle" => cmd_bundle(rest),
        "apply" => cmd_apply(rest),
        "grant" => cmd_grant(rest),
        "maroon" => cmd_maroon(rest),
        "migrate" => cmd_migrate(rest),
        "manifest" => cmd_manifest(),
        "conflicts" => cmd_conflicts(),
        "resolve" => cmd_resolve(rest),
        "remote" => cmd_remote(rest),
        "keygen" => cmd_keygen(),
        "whoami" => cmd_whoami(),
        "peer" => cmd_peer(rest),
        "serve" => cmd_serve(rest),
        "push" => cmd_push(rest),
        "pull" => cmd_pull(rest),
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
  loot init --identity <name>               initialize a repo here, owned by <name>
  loot status [-m <message>]                snapshot the working tree into the working change
  loot describe -m <message>                name the working change
  loot new                                  finalize the working change; start a fresh one
  loot surface                              materialize what the current identity may see
  loot log                                  show change history
  loot bundle <file>                        write a sync bundle (ciphertext, no private keys)
  loot apply <file>                         merge a peer's bundle (idempotent)
  loot grant <path> <identity> <file>       write a targeted grant bundle for <identity>
  loot maroon [--hard] <path> <identity> [dir]  cut off <identity> from future access; --hard adds a purge event
  loot migrate <path> <vis-spec> [dir]      change a path's visibility (public | restricted=a,b | embargoed=<ts>)
  loot manifest                             show the grant audit trail
  loot conflicts                            list paths that need human resolution
  loot resolve <path> <file>                resolve a conflict at <path> using the content of <file>
  loot remote add <name> <url>              register a relay URL under a name
  loot remote remove <name>                 forget a named relay
  loot remote list                          show all named relays
  loot keygen                               generate an identity keypair (backfills existing repos)
  loot whoami                               show this repo's public key
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
    let id_name = flag(args, "--identity").ok_or("init requires --identity <name>")?;
    let ws = Workspace::init(id_name)?;
    let dot = ws.dot();
    let keypair = identity::generate_and_save(dot, &format!("{id_name}@loot"))
        .map_err(|e| e.to_string())?;
    let pub_line = std::fs::read_to_string(dot.join("id.pub"))
        .map_err(|e| format!("read id.pub: {e}"))?;
    println!("initialized empty loot repo, identity = {id_name}");
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
    let head = ws.surface()?;
    println!(
        "surfaced {} as {} (content you may not see was skipped)",
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
        println!("run `loot surface` to materialize what you may see");
    }
    Ok(())
}

fn cmd_grant(args: &[String]) -> Result<(), String> {
    if args.len() < 3 {
        return Err("grant requires <path> <identity> <file>".into());
    }
    let path = &args[0];
    let grantee = &args[1];
    let out = &args[2];

    let mut ws = Workspace::open()?;
    let now = ws.now();

    // Find the OID for this path in the current tree.
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
    let entries: Vec<_> = ws.repo().manifest().iter().collect();
    if entries.is_empty() {
        println!("no grants recorded");
        return Ok(());
    }
    println!("{:<12} {:<32} oid", "granted_at", "grantee");
    println!("{}", "-".repeat(72));
    let mut sorted = entries;
    sorted.sort_by_key(|e| e.granted_at);
    for e in sorted {
        println!("{:<12} {:<32} {}", e.granted_at, e.grantee, short_oid(&e.oid));
    }
    Ok(())
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

// --- identity keypairs (ADR 0014) ---

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
    println!("{} — {}", ws.identity(), pub_line.trim());
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
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|e| e.to_string())?;
        out[i] = u8::from_str_radix(s, 16)
            .map_err(|_| format!("invalid hex byte '{s}' in public key"))?;
    }
    Ok(out)
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
