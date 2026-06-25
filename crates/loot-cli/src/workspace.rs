//! Workspace — the process-bound ambient repo (ADR 0006).
//!
//! Owns everything a command needs but shouldn't re-derive: where `.loot/` is,
//! the current identity, the clock, the loaded engine, and the id of the
//! *working change* being rewritten in place. Commands are thin verbs over it.
//!
//! The snapshot invariant itself lives in the engine (`DagRepo::snapshot`); the
//! Workspace only reads the working tree + `.lootattributes` into the entries
//! the engine reconciles, and persists state after a mutation.

use loot_core::{DagRepo, Oid, Repo, Visibility};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const DOT: &str = ".loot";
const ATTRS: &str = ".lootattributes";

pub struct Workspace {
    dot: PathBuf,
    root: PathBuf,
    identity: String,
    repo: DagRepo,
    /// The working change being rewritten in place, if one is in progress.
    /// `None` right after `init` or `apply` (finalized history, no WIP change).
    working: Option<Oid>,
    /// Injected clock — a value, not a call, so tests can drive embargo timing.
    now: u64,
}

impl Workspace {
    /// Discover `.loot/` from the current directory and load the repo.
    pub fn open() -> Result<Self, String> {
        let dot = PathBuf::from(DOT);
        if !dot.join("identity").exists() {
            return Err("not a loot repo (no .loot/). Run `loot init --identity <name>` first.".into());
        }
        let root = PathBuf::from(".");
        let repo = DagRepo::load(&dot, root.clone()).map_err(|e| e.to_string())?;
        let identity = read_to_string(&dot.join("identity"))?;
        let working = match std::fs::read(dot.join("working")) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&bytes);
                Some(Oid(a))
            }
            _ => None,
        };
        Ok(Workspace { dot, root, identity, repo, working, now: real_now() })
    }

    /// Create a fresh repo here, owned by `identity`.
    pub fn init(identity: &str) -> Result<Self, String> {
        let dot = PathBuf::from(DOT);
        if dot.join("identity").exists() {
            return Err("already a loot repo (.loot/ exists)".into());
        }
        let root = PathBuf::from(".");
        let repo = DagRepo::init(root.clone(), identity).map_err(|e| e.to_string())?;
        let ws = Workspace {
            dot,
            root,
            identity: identity.to_string(),
            repo,
            working: None,
            now: real_now(),
        };
        ws.persist()?;
        Ok(ws)
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }

    pub fn now(&self) -> u64 {
        self.now
    }

    pub fn repo(&self) -> &DagRepo {
        &self.repo
    }

    /// Snapshot the working tree into the working change (visibility-aware,
    /// engine-owned). Reads the tree + `.lootattributes`, hands entries to the
    /// engine, tracks the resulting working id, and persists. Returns the
    /// working-change id and the entries' resolved visibilities for reporting.
    pub fn snapshot(&mut self, message: &str) -> Result<(Oid, Vec<(PathBuf, Visibility)>), String> {
        // Promote any embargoed keys whose reveal time has passed before reading
        // content — `sealed::open` will then find them in the Keyring (ADR 0007).
        self.repo.flush_escrow(self.now);
        let attrs = Attributes::load(&self.root.join(ATTRS));
        let mut entries: Vec<(PathBuf, Vec<u8>, Visibility)> = Vec::new();
        let mut reported: Vec<(PathBuf, Visibility)> = Vec::new();
        for path in walk(&self.root)? {
            let rel = path.strip_prefix("./").unwrap_or(&path).to_path_buf();
            let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
            let vis = attrs.visibility_for(&rel.to_string_lossy());
            reported.push((rel.clone(), vis.clone()));
            entries.push((rel, bytes, vis));
        }
        let id = self
            .repo
            .snapshot(self.working.as_ref(), &entries, message, self.now)
            .map_err(|e| e.to_string())?;
        self.working = Some(id.clone());
        self.persist()?;
        reported.sort_by(|a, b| a.0.cmp(&b.0));
        Ok((id, reported))
    }

    /// Finalize the working change and start fresh: the next snapshot appends a
    /// new change rather than rewriting this one.
    pub fn finalize_working(&mut self) -> Result<(), String> {
        self.working = None;
        self.persist()
    }

    /// Materialize what the current identity may see from the tip change.
    pub fn checkout(&mut self) -> Result<Oid, String> {
        // Promote embargoed keys before materializing — same flush discipline as
        // snapshot (ADR 0007). Takes &mut self because flush mutates the escrow.
        self.repo.flush_escrow(self.now);
        let head = self
            .repo
            .heads()
            .into_iter()
            .next()
            .ok_or("nothing to check out (no commits yet)")?;
        self.repo
            .checkout(&head, &self.identity, self.now)
            .map_err(|e| e.to_string())?;
        self.persist()?;
        Ok(head)
    }

    /// Run a closure that mutates the repo, then persist. The single path for
    /// "mutation ⇒ save" — callers can't forget to persist (e.g. `apply`).
    pub fn with_repo<T>(
        &mut self,
        f: impl FnOnce(&mut DagRepo) -> Result<T, String>,
    ) -> Result<T, String> {
        let out = f(&mut self.repo)?;
        self.persist()?;
        Ok(out)
    }

    fn persist(&self) -> Result<(), String> {
        self.repo.save(&self.dot).map_err(|e| e.to_string())?;
        match &self.working {
            Some(oid) => std::fs::write(self.dot.join("working"), oid.0)
                .map_err(|e| format!("write working: {e}"))?,
            None => {
                let _ = std::fs::remove_file(self.dot.join("working"));
            }
        }
        Ok(())
    }
}

fn real_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn read_to_string(path: &Path) -> Result<String, String> {
    String::from_utf8(std::fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

/// Recursively list files under `dir`, skipping `.loot/`, `.lootattributes`, `.git`.
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
            if name == DOT || name == ATTRS || name == ".git" {
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

/// Minimal glob: `*` matches a run of non-`/`; `**` matches across separators.
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

fn glob_match(pat: &str, text: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = text.chars().collect();
    fn go(p: &[char], t: &[char]) -> bool {
        if p.is_empty() {
            return t.is_empty();
        }
        if p[0] == '*' {
            let double = p.len() >= 2 && p[1] == '*';
            let rest = if double { &p[2..] } else { &p[1..] };
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
        assert!(!glob_match("*.md", "src/x.md"));
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
        assert!(matches!(attrs.visibility_for("main.rs"), Visibility::Public));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
