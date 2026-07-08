//! Workspace — the process-bound ambient repo (ADR 0006).
//!
//! Owns everything a command needs but shouldn't re-derive: where `.loot/` is,
//! the current identity, the clock, the loaded engine, and the id of the
//! *working change* being rewritten in place. Commands are thin verbs over it.
//!
//! The snapshot invariant itself lives in the engine (`DagRepo::snapshot`); the
//! Workspace only reads the working tree + `.lootattributes` into the entries
//! the engine reconciles, and persists state after a mutation.

use loot_core::{valid_dock_name, DagRepo, Oid, Repo, RepoStore, Visibility, HOME_DOCK};
use loot_identity::Identity;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const DOT: &str = ".loot";
const ATTRS: &str = ".lootattributes";

pub struct Workspace {
    dot: PathBuf,
    store: RepoStore,
    root: PathBuf,
    identity: String,
    repo: DagRepo,
    /// The ambient dock this workspace is on (ADR 0022). `HOME_DOCK` uses the
    /// root `.loot/` process files, so a repo that never docks is unchanged on
    /// disk; named docks live under `.loot/docks/<name>/`.
    dock: String,
    /// The working change being rewritten in place, if one is in progress.
    /// `None` right after `init` or `apply` (finalized history, no WIP change).
    working: Option<Oid>,
    /// The finalized change the ambient dock forks from — new snapshots parent on
    /// it (ADR 0022). `None` on the home dock until a dock is created, which
    /// selects the pre-dock behavior (fork from all heads) and keeps existing
    /// repos byte-for-byte unchanged.
    tip: Option<Oid>,
    /// The loaded signing keypair, if this repo has one. Stamps the author on new
    /// changes and signs at finalization (S3, ADR 0018). `None` for a keyless
    /// repo, which then produces unauthored (legacy) changes.
    signer: Option<Identity>,
    /// Injected clock — a value, not a call, so tests can drive embargo timing.
    now: u64,
}

impl Workspace {
    /// Discover `.loot/` from the current directory and load the repo.
    pub fn open() -> Result<Self, String> {
        Self::open_at(Path::new("."))
    }

    /// Load a repo rooted at an explicit directory (used by `clone`).
    pub fn open_at(dir: &Path) -> Result<Self, String> {
        let dot = dir.join(DOT);
        let store = RepoStore::new(&dot);
        if !store.identity().exists() {
            return Err(format!(
                "not a loot repo at {} (no .loot/). Run `loot init` first.",
                dir.display()
            ));
        }
        let mut repo = DagRepo::load(&dot, dir.to_path_buf()).map_err(|e| e.to_string())?;
        let identity = read_to_string(&store.identity())?;
        let dock = store.read_dock();
        let dock_opt = opt(&dock);
        let working = store.read_working(dock_opt);
        let tip = store.read_tip(dock_opt);
        // Load the signing keypair if present and stamp its pubkey as the author,
        // so new changes are attributable and signable (S3, ADR 0018). A keyless
        // repo stays unauthored (legacy ids), which keeps older repos working.
        let signer = if loot_identity::keypair_exists(&dot) {
            let id = loot_identity::load_or_missing(&dot).map_err(|e| e.to_string())?;
            repo.set_author(id.public_key_bytes());
            Some(id)
        } else {
            None
        };
        Ok(Workspace { dot, store, root: dir.to_path_buf(), identity, repo, dock, working, tip, signer, now: real_now() })
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// The `.loot/` directory for this repo (used by identity keypair commands).
    pub fn dot(&self) -> &std::path::Path {
        &self.dot
    }

    /// Resolve the visibility for `path` according to `.lootattributes` — the
    /// same rule `snapshot` uses. Returns `Public` if no rule matches.
    pub fn visibility_for(&self, path: &str) -> Visibility {
        let attrs = Attributes::load(&self.root.join(ATTRS));
        attrs.visibility_for(path)
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
    ///
    /// Idempotent: if the working tree hash matches the last recorded hash AND
    /// the message matches, the engine call is skipped and the current working id
    /// is returned unchanged. This makes repeated `loot status` calls cheap.
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
        reported.sort_by(|a, b| a.0.cmp(&b.0));

        // Hash the current working tree content + message. Skip the engine
        // snapshot if nothing changed — running `loot status` repeatedly is safe.
        let tree_hash = hash_tree(&entries, message);
        let last_hash = self.store.read_tree_hash(self.dock_opt());
        if last_hash == tree_hash {
            if let Some(id) = &self.working {
                return Ok((id.clone(), reported));
            }
        }

        // Fork the working change from the ambient dock's tip (ADR 0022). `tip`
        // is `None` on the pre-dock home dock, which preserves the original
        // fork-from-all-heads behavior exactly.
        let id = self
            .repo
            .snapshot(self.tip.as_ref(), self.working.as_ref(), &entries, message, self.now)
            .map_err(|e| e.to_string())?;
        self.working = Some(id.clone());
        // Persist the new tree hash before persisting the rest of state.
        let _ = self.store.write_tree_hash(self.dock_opt(), &tree_hash);
        self.persist()?;
        Ok((id, reported))
    }

    /// Finalize the working change and start fresh: the next snapshot appends a
    /// new change rather than rewriting this one.
    pub fn finalize_working(&mut self) -> Result<(), String> {
        // Sign the finalized change id with our identity key (S3, ADR 0018). The
        // working change is ephemeral until now (rewritten on each `status`), so
        // we sign exactly once, here. A keyless repo finalizes unsigned (legacy).
        if let (Some(signer), Some(working)) = (&self.signer, self.working.clone()) {
            let sig = signer.sign(&working.0);
            self.repo
                .attach_signature(&working, sig)
                .map_err(|e| e.to_string())?;
        }
        // The finalized change becomes this dock's tip — the anchor the next
        // change forks from. Persist it only once docks are in play; the pristine
        // home dock keeps `tip` absent so its on-disk shape (and its
        // fork-from-all-heads behavior) is unchanged (ADR 0022).
        if self.docks_active() {
            self.tip = self.working.take();
            let _ = self.store.write_tip(self.dock_opt(), self.tip.as_ref());
        } else {
            self.working = None;
        }
        // Clear the tree-hash so the next snapshot always runs the engine.
        self.store.clear_tree_hash(self.dock_opt());
        self.persist()
    }

    /// Attest an existing change with this repo's identity (S4, ADR 0018): sign
    /// `change_id || attester || role` and record the attestation. Advisory — it
    /// never changes the change id. Errors if the repo has no keypair.
    pub fn attest(&mut self, change_id: &Oid, role: &str) -> Result<(), String> {
        let att = {
            let signer = self
                .signer
                .as_ref()
                .ok_or("no identity keypair — run `loot keygen` to generate one")?;
            let attester = signer.public_key_bytes();
            let signature =
                signer.sign(&loot_core::attestation::signing_bytes(change_id, &attester, role));
            loot_core::Attestation {
                change_id: change_id.clone(),
                attester,
                role: role.to_string(),
                signature,
            }
        };
        if !self.repo.add_attestation(att) {
            return Err("internal error: freshly-signed attestation failed to verify".into());
        }
        self.persist()
    }

    /// Materialize what the current identity may see from the tip change.
    pub fn surface(&mut self) -> Result<Oid, String> {
        let (head, _, _) = self.surface_with_report()?;
        Ok(head)
    }

    /// Like `surface`, but also returns the written paths+visibility and the
    /// count of skipped (sealed) paths for richer CLI output.
    pub fn surface_with_report(&mut self) -> Result<(Oid, Vec<(PathBuf, loot_core::Visibility)>, usize), String> {
        self.repo.flush_escrow(self.now);
        // Surface the ambient dock's own tip — its in-progress working change, or
        // its finalized tip, falling back to the graph head for the pre-dock home
        // dock. In a multi-dock (multi-head) graph `heads().next()` is arbitrary,
        // so a dock must name its own head (ADR 0022).
        let head = self
            .working
            .clone()
            .or_else(|| self.tip.clone())
            .or_else(|| self.repo.heads().into_iter().next())
            .ok_or("nothing to surface yet (no changes recorded)")?;
        let (written, skipped) = self.repo
            .surface_with_report(&head, &self.identity, self.now)
            .map_err(|e| e.to_string())?;
        self.persist()?;
        Ok((head, written, skipped))
    }

    /// The id of the current working change, if one is in progress.
    pub fn working_id(&self) -> Option<&Oid> {
        self.working.as_ref()
    }

    /// Prune orphaned loose objects from `.loot/objects/` (ADR 0012). Delegates
    /// to the engine, which owns the object store and the reachability walk over
    /// the change graph. `dry_run` reports what would be pruned without deleting.
    pub fn gc(&mut self, dry_run: bool) -> Result<loot_core::GcReport, String> {
        self.repo.gc(&self.dot, dry_run).map_err(|e| e.to_string())
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

    /// Read the URL for a named remote (e.g. "origin") from `.loot/config`.
    /// Returns `None` if the remote is not set.
    pub fn remote_url(&self, name: &str) -> Option<String> {
        Config::load(&self.store.config()).get(name)
    }

    /// Add or update a named remote in `.loot/config`.
    pub fn remote_add(&self, name: &str, url: &str) -> Result<(), String> {
        let path = self.store.config();
        let mut cfg = Config::load(&path);
        cfg.set(name, url);
        cfg.save(&path)
    }

    /// Remove a named remote from `.loot/config`. No-ops if not present.
    pub fn remote_remove(&self, name: &str) -> Result<(), String> {
        let path = self.store.config();
        let mut cfg = Config::load(&path);
        cfg.remove(name);
        cfg.save(&path)
    }

    /// List all named remotes from `.loot/config`.
    pub fn remote_list(&self) -> Vec<(String, String)> {
        Config::load(&self.store.config()).entries()
    }

    /// Create a fresh repo inside `dir`, owned by `identity`. `dir` is created if
    /// it doesn't exist. Unlike `init()` this targets an explicit path rather than
    /// the current directory, so `clone` can materialize the repo anywhere.
    pub fn init_at(dir: &Path, identity: &str) -> Result<Self, String> {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("create {}: {e}", dir.display()))?;
        let dot = dir.join(DOT);
        if RepoStore::new(&dot).identity().exists() {
            return Err(format!("already a loot repo at {}", dir.display()));
        }
        let store = RepoStore::new(&dot);
        let repo = DagRepo::init(dir.to_path_buf(), identity).map_err(|e| e.to_string())?;
        let ws = Workspace {
            dot,
            store,
            root: dir.to_path_buf(),
            identity: identity.to_string(),
            repo,
            // A fresh repo starts on the home dock with pre-dock semantics.
            dock: HOME_DOCK.to_string(),
            working: None,
            tip: None,
            // A freshly-initialized repo has no keypair yet (`loot keygen` adds one);
            // its early changes are unauthored until then (S3, ADR 0018).
            signer: None,
            now: real_now(),
        };
        ws.persist()?;
        Ok(ws)
    }

    // --- docks (ADR 0022) ---

    /// The ambient dock name (`home` for the default dock).
    pub fn current_dock(&self) -> &str {
        &self.dock
    }

    /// The store selector for the ambient dock: `None` for home (root files),
    /// `Some(name)` for a named dock under `.loot/docks/`.
    fn dock_opt(&self) -> Option<&str> {
        opt(&self.dock)
    }

    /// Whether docks are in play — either we're on a named dock, or named docks
    /// exist alongside home. Gates whether home persists an explicit tip, so a
    /// repo that never docks stays pristine on disk.
    fn docks_active(&self) -> bool {
        self.dock != HOME_DOCK || self.store.list_docks().len() > 1
    }

    /// The finalized change the ambient dock currently sits on — a new dock forks
    /// from here. Uses the pinned tip when present, else derives it from the
    /// graph (the pre-dock home case): the working change's parent, or the head.
    fn anchor(&self) -> Option<Oid> {
        if let Some(t) = &self.tip {
            return Some(t.clone());
        }
        match &self.working {
            Some(w) => self.repo.parents_of(w).into_iter().next(),
            None => self.repo.heads().into_iter().next(),
        }
    }

    /// `loot dock <name>`: switch to an existing dock, or create it (forking from
    /// the ambient dock's finalized tip) and switch to it. A no-op if already on
    /// `name`. The outgoing dock is auto-snapshotted first so no uncommitted work
    /// is lost — every pruned file is recoverable by switching back (ADR 0022).
    pub fn dock_goto(&mut self, name: &str) -> Result<DockAction, String> {
        if name == self.dock {
            return Ok(DockAction::Already);
        }
        let creating = !self.store.dock_exists(name);
        if creating {
            valid_dock_name(name)?;
        }

        // 1. Capture the outgoing dock's working tree, preserving its message.
        let msg = self
            .working
            .as_ref()
            .and_then(|w| self.repo.change_message(w))
            .unwrap_or_else(|| "(working change)".to_string());
        self.snapshot(&msg)?;
        let from = self.working.clone().or_else(|| self.tip.clone());

        // 2. Pin the outgoing home dock's tip before it stops being the lone dock,
        //    so a later `status` on home never merges the new fork.
        let anchor = self.anchor();
        if self.dock == HOME_DOCK && self.tip.is_none() {
            if let Some(a) = &anchor {
                let _ = self.store.write_tip(None, Some(a));
            }
        }

        // 3. Resolve the incoming dock's target head + working/tip state.
        let (target, incoming_working, incoming_tip) = if creating {
            let a = anchor
                .clone()
                .ok_or("nothing to fork yet — record a change first (`loot new`)")?;
            self.store.ensure_dock_dir(name).map_err(|e| e.to_string())?;
            self.store.write_tip(Some(name), Some(&a)).map_err(|e| e.to_string())?;
            (a.clone(), None, Some(a))
        } else {
            let o = opt(name);
            let w = self.store.read_working(o);
            let t = self.store.read_tip(o);
            let target = w
                .clone()
                .or_else(|| t.clone())
                .ok_or_else(|| format!("dock '{name}' has no content to materialize"))?;
            (target, w, t)
        };

        // 4. Switch the ambient pointer, then reconcile the working tree.
        self.store.write_dock(name).map_err(|e| e.to_string())?;
        self.repo
            .materialize(from.as_ref(), &target, &self.identity, self.now)
            .map_err(|e| e.to_string())?;
        self.dock = name.to_string();
        self.working = incoming_working;
        self.tip = incoming_tip;
        // The incoming dock re-derives its snapshot hash on the next `status`.
        self.store.clear_tree_hash(self.dock_opt());
        self.persist()?;
        Ok(if creating { DockAction::Created } else { DockAction::Switched })
    }

    /// Every dock with its head and visibility summary, for `loot docks`.
    pub fn dock_list(&self) -> Vec<DockInfo> {
        self.store
            .list_docks()
            .into_iter()
            .map(|name| {
                let current = name == self.dock;
                // For the ambient dock, in-memory state is authoritative and may
                // be ahead of disk; for others, read the persisted head.
                let head = if current {
                    self.working
                        .clone()
                        .or_else(|| self.tip.clone())
                        .or_else(|| self.repo.heads().into_iter().next())
                } else {
                    let o = opt(&name);
                    self.store.read_working(o).or_else(|| self.store.read_tip(o))
                };
                let visibility = head.as_ref().map(|h| self.repo.visibility_summary_at(h));
                DockInfo { name, head, current, visibility }
            })
            .collect()
    }

    fn persist(&self) -> Result<(), String> {
        self.repo.save(&self.dot).map_err(|e| e.to_string())?;
        self.store
            .write_working(self.dock_opt(), self.working.as_ref())
            .map_err(|e| format!("write working: {e}"))
    }
}

/// Store selector for a dock name: `home` maps to the root files (`None`).
fn opt(name: &str) -> Option<&str> {
    if name == HOME_DOCK {
        None
    } else {
        Some(name)
    }
}

/// What `dock_goto` did, for CLI reporting.
pub enum DockAction {
    Already,
    Switched,
    Created,
}

/// A dock's summary for `loot docks`: its head change, visibility counts
/// `(total, restricted, embargoed)`, and whether it's the ambient dock.
pub struct DockInfo {
    pub name: String,
    pub head: Option<Oid>,
    pub visibility: Option<(usize, usize, usize)>,
    pub current: bool,
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

fn parse_config_text(text: &str) -> BTreeMap<String, String> {
    let mut entries = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            entries.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    entries
}

/// Named remotes from `.loot/config`. Format: one `name = url` pair per line;
/// blank lines and `#` comments are ignored.
struct Config {
    entries: BTreeMap<String, String>,
}

impl Config {
    fn load(path: &Path) -> Self {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        Config { entries: parse_config_text(&text) }
    }

    fn get(&self, name: &str) -> Option<String> {
        self.entries.get(name).cloned()
    }

    fn set(&mut self, name: &str, url: &str) {
        self.entries.insert(name.to_string(), url.to_string());
    }

    fn remove(&mut self, name: &str) {
        self.entries.remove(name);
    }

    fn entries(&self) -> Vec<(String, String)> {
        self.entries.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    fn save(&self, path: &Path) -> Result<(), String> {
        let mut out = String::new();
        for (k, v) in &self.entries {
            out.push_str(&format!("{k} = {v}\n"));
        }
        std::fs::write(path, out).map_err(|e| format!("write {}: {e}", path.display()))
    }
}

/// Global user config at `~/.config/loot/config` (XDG base-dir convention).
///
/// Stores identity-scope settings only — keys like `identity = alice`.
/// Format is the same `key = value` text as the per-repo config.
pub struct GlobalConfig {
    entries: BTreeMap<String, String>,
    path: PathBuf,
}

impl GlobalConfig {
    /// Load from the XDG config path. Missing file = empty config.
    pub fn load() -> Self {
        let path = global_config_path();
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        GlobalConfig { entries: parse_config_text(&text), path }
    }

    /// Read a key. Returns `None` if not set.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(String::as_str)
    }

    /// Set a key and persist.
    pub fn set(&mut self, key: &str, value: &str) -> Result<(), String> {
        self.entries.insert(key.to_string(), value.to_string());
        self.save()
    }

    /// Remove a key and persist.
    pub fn unset(&mut self, key: &str) -> Result<(), String> {
        self.entries.remove(key);
        self.save()
    }

    /// All key/value pairs.
    pub fn list(&self) -> Vec<(&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
    }

    fn save(&self) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create config dir: {e}"))?;
        }
        let mut out = String::new();
        for (k, v) in &self.entries {
            out.push_str(&format!("{k} = {v}\n"));
        }
        std::fs::write(&self.path, out)
            .map_err(|e| format!("write {}: {e}", self.path.display()))
    }
}

/// Hash the working tree entries + message for idempotent snapshot detection.
/// Returns 32 raw bytes (blake3). Stable: same inputs always produce the same
/// hash regardless of platform or rust version.
fn hash_tree(entries: &[(PathBuf, Vec<u8>, Visibility)], message: &str) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(message.as_bytes());
    h.update(&[0]);
    // entries arrive pre-sorted from walk(); hash in that order for stability.
    // Visibility is included so a .lootattributes-only change (same content,
    // different access policy) triggers a new snapshot rather than being skipped.
    for (path, bytes, vis) in entries {
        h.update(path.to_string_lossy().as_bytes());
        h.update(&[0]);
        h.update(bytes);
        h.update(&[0]);
        // Stable encoding: Public=0, Restricted=1+names, Embargoed=2+timestamp.
        match vis {
            Visibility::Public => { h.update(&[0]); }
            Visibility::Restricted(ids) => {
                h.update(&[1]);
                for id in ids {
                    h.update(id.as_bytes());
                    h.update(&[0]);
                }
            }
            Visibility::Embargoed { reveal_at } => {
                h.update(&[2]);
                h.update(&reveal_at.to_le_bytes());
            }
        }
        h.update(&[0]);
    }
    h.finalize().as_bytes().to_vec()
}

fn global_config_path() -> PathBuf {
    // XDG_CONFIG_HOME takes precedence; fall back to $HOME/.config
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".config"))
                .unwrap_or_else(|_| PathBuf::from(".config"))
        });
    base.join("loot").join("config")
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
    fn config_round_trips_remotes() {
        let dir = std::env::temp_dir().join(format!("loot-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("config");

        let mut cfg = Config::load(&p);
        assert!(cfg.get("origin").is_none());

        cfg.set("origin", "http://localhost:4000");
        cfg.set("upstream", "http://relay.example.com");
        cfg.save(&p).unwrap();

        let loaded = Config::load(&p);
        assert_eq!(loaded.get("origin").as_deref(), Some("http://localhost:4000"));
        assert_eq!(loaded.get("upstream").as_deref(), Some("http://relay.example.com"));

        let mut loaded2 = Config::load(&p);
        loaded2.remove("upstream");
        loaded2.save(&p).unwrap();
        let loaded3 = Config::load(&p);
        assert!(loaded3.get("upstream").is_none());
        assert!(loaded3.get("origin").is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_ignores_comments_and_blanks() {
        let dir = std::env::temp_dir().join(format!("loot-config2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("config");
        std::fs::write(&p, "# a comment\n\norigin = http://localhost:4000\n").unwrap();
        let cfg = Config::load(&p);
        assert_eq!(cfg.get("origin").as_deref(), Some("http://localhost:4000"));
        assert_eq!(cfg.entries().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

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

    #[test]
    fn global_config_set_get_unset() {
        // Drive via XDG_CONFIG_HOME so we don't touch the real ~/.config
        let dir = std::env::temp_dir().join(format!("loot-gcfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("XDG_CONFIG_HOME", &dir);

        let mut cfg = GlobalConfig::load();
        assert!(cfg.get("identity").is_none());

        cfg.set("identity", "alice").unwrap();
        let cfg2 = GlobalConfig::load();
        assert_eq!(cfg2.get("identity"), Some("alice"));

        let mut cfg3 = GlobalConfig::load();
        cfg3.unset("identity").unwrap();
        let cfg4 = GlobalConfig::load();
        assert!(cfg4.get("identity").is_none());

        std::env::remove_var("XDG_CONFIG_HOME");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn init_at_and_open_at_round_trip() {
        let dir = std::env::temp_dir().join(format!("loot-initat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        Workspace::init_at(&dir, "bob").unwrap();
        let ws = Workspace::open_at(&dir).unwrap();
        assert_eq!(ws.identity(), "bob");
    }

    #[test]
    fn hash_tree_is_stable() {
        use loot_core::Visibility;
        let entries: Vec<(PathBuf, Vec<u8>, Visibility)> = vec![
            (PathBuf::from("a.txt"), b"hello".to_vec(), Visibility::Public),
            (PathBuf::from("b.txt"), b"world".to_vec(), Visibility::Public),
        ];
        let h1 = hash_tree(&entries, "msg");
        let h2 = hash_tree(&entries, "msg");
        assert_eq!(h1, h2);

        // Different content -> different hash.
        let entries2: Vec<(PathBuf, Vec<u8>, Visibility)> = vec![
            (PathBuf::from("a.txt"), b"different".to_vec(), Visibility::Public),
        ];
        assert_ne!(hash_tree(&entries2, "msg"), h1);

        // Different message -> different hash.
        assert_ne!(hash_tree(&entries, "other"), h1);
    }

    #[test]
    fn snapshot_is_idempotent_when_tree_unchanged() {
        let dir = std::env::temp_dir().join(format!("loot-idem-snap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut ws = Workspace::init_at(&dir, "alice").unwrap();

        // Write a file into the repo root.
        std::fs::write(dir.join("file.txt"), b"content").unwrap();

        let (id1, _) = ws.snapshot("init").unwrap();
        let (id2, _) = ws.snapshot("init").unwrap();  // same tree + same message
        assert_eq!(id1, id2, "snapshot must be idempotent when nothing changed");

        // Different message breaks idempotency (message is part of the hash).
        let (id3, _) = ws.snapshot("new message").unwrap();
        assert_ne!(id1, id3);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fresh unique repo dir for a dock test.
    fn dock_repo(tag: &str) -> (PathBuf, Workspace) {
        let dir = std::env::temp_dir().join(format!("loot-dock-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ws = Workspace::init_at(&dir, "alice").unwrap();
        (dir, ws)
    }

    #[test]
    fn a_repo_that_never_docks_writes_no_dock_files() {
        // The CA1 compatibility guarantee (ADR 0022): docks are opt-in, so a repo
        // that never runs a dock command is byte-for-byte its pre-dock self.
        let (dir, mut ws) = dock_repo("compat");
        std::fs::write(dir.join("a.txt"), b"x").unwrap();
        ws.snapshot("work").unwrap();
        ws.finalize_working().unwrap();
        ws.snapshot("more").unwrap();

        let dot = dir.join(".loot");
        assert!(!dot.join("dock").exists(), "no ambient-dock pointer");
        assert!(!dot.join("docks").exists(), "no docks directory");
        assert!(!dot.join("tip").exists(), "home persists no explicit tip pre-dock");
        assert_eq!(ws.current_dock(), "home");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_docks_hold_independent_tips_and_isolated_trees() {
        // Acceptance: two docks editing disjoint paths reach independent tips over
        // one store, and switching re-materializes each dock's own tree.
        let (dir, mut ws) = dock_repo("iso");
        std::fs::write(dir.join("base.txt"), b"base").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();

        // Fork a dock and give it a file the home dock never sees.
        ws.dock_goto("feature").unwrap();
        assert_eq!(ws.current_dock(), "feature");
        std::fs::write(dir.join("feature.txt"), b"F").unwrap();
        let (feat_tip, _) = ws.snapshot("feature work").unwrap();

        // Back on home: feature.txt is pruned from disk, base.txt remains.
        ws.dock_goto("home").unwrap();
        assert!(dir.join("base.txt").exists(), "shared base kept");
        assert!(!dir.join("feature.txt").exists(), "feature-only file pruned on switch home");
        std::fs::write(dir.join("home.txt"), b"H").unwrap();
        let (home_tip, _) = ws.snapshot("home work").unwrap();

        assert_ne!(feat_tip, home_tip, "docks advance to independent tips");

        // Switching back restores the feature tree in full — nothing was lost.
        ws.dock_goto("feature").unwrap();
        assert!(dir.join("feature.txt").exists(), "feature file restored on switch back");
        assert!(!dir.join("home.txt").exists(), "home-only file absent on feature");

        // Both docks are listed, home first, with the ambient one marked.
        let docks = ws.dock_list();
        assert_eq!(docks.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(), ["home", "feature"]);
        assert!(docks.iter().find(|d| d.name == "feature").unwrap().current);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dock_goto_is_idempotent_and_rejects_bad_names() {
        let (dir, mut ws) = dock_repo("names");
        std::fs::write(dir.join("a.txt"), b"x").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();

        assert!(matches!(ws.dock_goto("home"), Ok(DockAction::Already)), "self-switch is a no-op");
        assert!(ws.dock_goto("../escape").is_err(), "path traversal rejected");
        assert!(matches!(ws.dock_goto("feat").unwrap(), DockAction::Created));
        assert!(matches!(ws.dock_goto("feat"), Ok(DockAction::Already)));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
