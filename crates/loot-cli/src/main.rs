//! `loot` — a CLI over the canonical engine (ADR 0005).
//!
//! Commands: init, commit, checkout, log, bundle, apply. State persists under
//! `.loot/` between invocations (engine `save`/`load`). The current identity
//! comes from `.loot/identity`; the clock is real system time. Per-path
//! visibility is declared in `.lootattributes`. Sync is a one-way bundle file:
//! `bundle` writes a transport artifact, `apply` merges it (idempotently).

use loot_core::{Change, DagRepo, MergeOutcome, Oid, Repo, SyncBundle, Visibility};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

const DOT: &str = ".loot";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    let rest = &args[args.len().min(1)..];

    let result = match cmd {
        "init" => cmd_init(rest),
        "commit" => cmd_commit(rest),
        "checkout" => cmd_checkout(rest),
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
  loot commit -m <message>      seal + record the working tree per .lootattributes
  loot checkout                 materialize what the current identity may see
  loot log                      show change history
  loot bundle <file>            write a sync bundle (ciphertext, no private keys)
  loot apply <file>             merge a peer's bundle (idempotent)";

fn print_help() {
    println!("loot — source control where privacy is per-content, not per-repo\n\n{USAGE}");
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The repo root is the current directory; engine state lives in `<root>/.loot`.
fn dot_dir() -> PathBuf {
    PathBuf::from(DOT)
}

fn require_repo() -> Result<(), String> {
    if dot_dir().join("identity").exists() {
        Ok(())
    } else {
        Err("not a loot repo (no .loot/). Run `loot init --identity <name>` first.".into())
    }
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

// --- commands ---

fn cmd_init(args: &[String]) -> Result<(), String> {
    let identity = flag(args, "--identity")
        .ok_or("init requires --identity <name>")?;
    if dot_dir().join("identity").exists() {
        return Err("already a loot repo (.loot/ exists)".into());
    }
    let repo = DagRepo::init(PathBuf::from("."), identity)
        .map_err(|e| e.to_string())?;
    repo.save(&dot_dir()).map_err(|e| e.to_string())?;
    println!("initialized empty loot repo, identity = {identity}");
    println!("tip: declare per-file privacy in .lootattributes, e.g. `.env restricted={identity}`");
    Ok(())
}

fn cmd_commit(args: &[String]) -> Result<(), String> {
    require_repo()?;
    let message = flag(args, "-m")
        .or_else(|| flag(args, "--message"))
        .ok_or("commit requires -m <message>")?;

    let mut repo = DagRepo::load(&dot_dir(), PathBuf::from(".")).map_err(|e| e.to_string())?;
    let attrs = Attributes::load(Path::new(".lootattributes"));

    // Walk the working tree (excluding .loot and .lootattributes itself),
    // sealing each file under the visibility its path resolves to.
    let mut tree: BTreeMap<PathBuf, (Oid, Visibility)> = BTreeMap::new();
    let mut count = 0usize;
    for path in walk(Path::new("."))? {
        let rel = path.strip_prefix("./").unwrap_or(&path).to_path_buf();
        let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let vis = attrs.visibility_for(&rel.to_string_lossy());
        let oid = repo.put(&bytes, vis.clone()).map_err(|e| e.to_string())?;
        let mark = match &vis {
            Visibility::Public => "public".to_string(),
            Visibility::Restricted(ids) => format!("restricted={}", ids.join(",")),
            Visibility::Embargoed { reveal_at } => format!("embargoed@{reveal_at}"),
        };
        println!("  {:<24} {mark}", rel.display());
        tree.insert(rel, (oid, vis));
        count += 1;
    }
    if count == 0 {
        return Err("nothing to commit (no files in the working tree)".into());
    }

    let change = Change {
        id: Oid([0; 32]), // engine computes the real id
        parents: repo.heads(),
        message: message.to_string(),
        tree,
    };
    let id = repo.commit(change).map_err(|e| e.to_string())?;
    repo.save(&dot_dir()).map_err(|e| e.to_string())?;
    println!("committed {} file(s) as {}", count, short(&id));
    Ok(())
}

fn cmd_checkout(_args: &[String]) -> Result<(), String> {
    require_repo()?;
    let repo = DagRepo::load(&dot_dir(), PathBuf::from(".")).map_err(|e| e.to_string())?;
    let head = repo
        .heads()
        .into_iter()
        .next()
        .ok_or("nothing to check out (no commits yet)")?;
    let identity = read_identity()?;
    repo.checkout(&head, &identity, now()).map_err(|e| e.to_string())?;
    println!("checked out {} as {} (content you may not see was skipped)", short(&head), identity);
    Ok(())
}

fn cmd_log() -> Result<(), String> {
    require_repo()?;
    let repo = DagRepo::load(&dot_dir(), PathBuf::from(".")).map_err(|e| e.to_string())?;
    let entries = repo.log();
    if entries.is_empty() {
        println!("no commits yet");
        return Ok(());
    }
    // Most-recent first.
    for (id, message) in entries.into_iter().rev() {
        println!("{}  {}", short(&id), message);
    }
    Ok(())
}

fn cmd_bundle(args: &[String]) -> Result<(), String> {
    require_repo()?;
    let out = args.first().ok_or("bundle requires <file>")?;
    let repo = DagRepo::load(&dot_dir(), PathBuf::from(".")).map_err(|e| e.to_string())?;
    // Full bundle (have = []): apply is idempotent, so the recipient dedups
    // anything it already has. Ships ciphertext + ANYONE-granted keys only;
    // restricted keys never travel (ADR 0003).
    let bundle = repo.bundle(&[]).map_err(|e| e.to_string())?;
    std::fs::write(out, &bundle.0).map_err(|e| format!("write {out}: {e}"))?;
    println!("wrote {} ({} bytes) — copy it to a peer and `loot apply`", out, bundle.0.len());
    Ok(())
}

fn cmd_apply(args: &[String]) -> Result<(), String> {
    require_repo()?;
    let infile = args.first().ok_or("apply requires <file>")?;
    let bytes = std::fs::read(infile).map_err(|e| format!("read {infile}: {e}"))?;
    let mut repo = DagRepo::load(&dot_dir(), PathBuf::from(".")).map_err(|e| e.to_string())?;
    let outcomes = repo
        .apply(&SyncBundle(bytes), now())
        .map_err(|e| e.to_string())?;
    repo.save(&dot_dir()).map_err(|e| e.to_string())?;

    if outcomes.is_empty() {
        println!("applied {infile}: nothing new (already up to date)");
    } else {
        let identity = read_identity()?;
        println!("applied {infile} as {identity}:");
        for (path, outcome) in &outcomes {
            println!("  {:<24} {}", path.display(), describe(outcome));
        }
        println!("run `loot checkout` to materialize what you may see");
    }
    Ok(())
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

// --- helpers ---

fn read_identity() -> Result<String, String> {
    String::from_utf8(
        std::fs::read(dot_dir().join("identity")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

fn short(oid: &Oid) -> String {
    oid.0[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Recursively list files under `dir`, skipping `.loot/` and `.lootattributes`.
fn walk(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d).map_err(|e| format!("read_dir {}: {e}", d.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == DOT || name == ".lootattributes" || name == ".git" {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Parsed `.lootattributes`: ordered (glob, visibility) rules. First match wins;
/// unmatched paths default to Public.
struct Attributes {
    rules: Vec<(Glob, Visibility)>,
}

impl Attributes {
    fn load(path: &Path) -> Self {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let mut rules = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let (Some(pat), Some(spec)) = (parts.next(), parts.next()) else {
                continue;
            };
            if let Some(vis) = parse_visibility(spec) {
                rules.push((Glob::new(pat), vis));
            }
        }
        Attributes { rules }
    }

    fn visibility_for(&self, path: &str) -> Visibility {
        for (glob, vis) in &self.rules {
            if glob.matches(path) {
                return vis.clone();
            }
        }
        Visibility::Public
    }
}

fn parse_visibility(spec: &str) -> Option<Visibility> {
    if spec == "public" {
        Some(Visibility::Public)
    } else if let Some(ids) = spec.strip_prefix("restricted=") {
        let ids: Vec<String> = ids.split(',').filter(|s| !s.is_empty()).map(String::from).collect();
        if ids.is_empty() {
            None
        } else {
            Some(Visibility::Restricted(ids))
        }
    } else if let Some(reveal) = spec.strip_prefix("embargoed=") {
        reveal.parse().ok().map(|reveal_at| Visibility::Embargoed { reveal_at })
    } else {
        None
    }
}

/// Minimal glob: supports `*` (any run within a path segment-agnostic match)
/// and `**` (any run including separators). Exact match otherwise. Enough for
/// `.env`, `*.md`, `secrets/**`.
struct Glob {
    pattern: String,
}

impl Glob {
    fn new(pattern: &str) -> Self {
        Glob { pattern: pattern.to_string() }
    }

    fn matches(&self, path: &str) -> bool {
        glob_match(&self.pattern, path)
    }
}

/// Backtracking glob matcher. `*` matches any run of non-`/` chars; `**`
/// matches any run including `/`.
fn glob_match(pat: &str, text: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = text.chars().collect();
    fn go(p: &[char], t: &[char]) -> bool {
        if p.is_empty() {
            return t.is_empty();
        }
        if p[0] == '*' {
            // `**` matches across separators; single `*` stops at `/`.
            let double = p.len() >= 2 && p[1] == '*';
            let rest = if double { &p[2..] } else { &p[1..] };
            // zero-width match
            if go(rest, t) {
                return true;
            }
            let mut i = 0;
            while i < t.len() {
                if !double && t[i] == '/' {
                    break;
                }
                i += 1;
                if go(rest, &t[i..]) {
                    return true;
                }
            }
            false
        } else if !t.is_empty() && p[0] == t[0] {
            go(&p[1..], &t[1..])
        } else {
            false
        }
    }
    go(&p, &t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_basics() {
        assert!(glob_match(".env", ".env"));
        assert!(!glob_match(".env", ".envx"));
        assert!(glob_match("*.md", "README.md"));
        assert!(!glob_match("*.md", "src/x.md")); // single * stops at /
        assert!(glob_match("secrets/**", "secrets/a/b.txt"));
        assert!(glob_match("*", "anything"));
    }

    #[test]
    fn attributes_first_match_wins_else_public() {
        let text = "# comment\n.env restricted=alice\n*.md public\n";
        let dir = std::env::temp_dir().join(format!("loot-attrs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(".lootattributes");
        std::fs::write(&p, text).unwrap();
        let attrs = Attributes::load(&p);
        assert!(matches!(attrs.visibility_for(".env"), Visibility::Restricted(ids) if ids == ["alice"]));
        assert!(matches!(attrs.visibility_for("README.md"), Visibility::Public));
        assert!(matches!(attrs.visibility_for("main.rs"), Visibility::Public)); // default
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn describe_names_the_relay_role() {
        assert_eq!(describe(&MergeOutcome::Converged), "converged");
        assert_eq!(describe(&MergeOutcome::Merged), "merged");
        assert!(describe(&MergeOutcome::RelayedUnmerged).contains("sealed"));
        assert!(describe(&MergeOutcome::Conflict).contains("conflict"));
    }
}
