//! Lane-registry lifecycle (ADR 0034/0035, #231/#232; extracted by the
//! codebase-design review's candidate 2). Spawn a sealed lane over the shared
//! store, promote it to a dock by naming it, observe every lane's status, and
//! reap lanes by hand (`rm`) or by sweep (`gc`) — the registry side of the
//! [[Lane]] concept, plus the placement/id derivation helpers.
//!
//! These are `Workspace` methods in a child module of `workspace`, so they
//! reach the Workspace's private position, store, and root exactly as they did
//! inline (`super::*`) — a pure relocation, no interface or behaviour change,
//! the same shape as the engine's Custody (#323) and negotiation extractions.
//! The lane *convergence* verbs (`merge_lane`, `adopt_harbor`) stay with the
//! reconcile code: they are folds, not registry lifecycle. `find_lane` is
//! `pub(super)` because `merge_lane` in the parent still resolves its source
//! through it.

use super::*;

impl Workspace {
    /// `loot lane new [--name <n>] [--at <dir>]`: spawn a sealed lane over this
    /// repo's shared store. The lane is born already-adopted at the primary's
    /// finalized anchor (spawn is the degenerate adopt, ADR 0034) with its tree
    /// materialized in a fresh directory — by default a sibling of the repo
    /// root under `<repo>-lanes/`, never nested inside the primary's tree.
    /// Primary-only, and requires a keyed repo: only signed changes can cross
    /// the seal, so a keyless lane could never land anything.
    pub fn spawn_lane(&mut self, name: Option<&str>, at: Option<&Path>) -> Result<SpawnedLane, CliError> {
        self.spawn_lane_as(name, at, None)
    }

    /// [`spawn_lane`](Self::spawn_lane) with an explicit handle — the
    /// ticket-derived spawn (`loot lane new --ticket <n>` → handle `t<n>`,
    /// ADR 0035 / #232). The handle names the default directory *and* becomes
    /// the registry id, suffixed until free like any auto-handle, so `loot
    /// lanes` reads as a claim board. When `at` overrides placement the handle
    /// still wins the id (the claim linkage survives a custom directory).
    pub fn spawn_lane_as(
        &mut self,
        name: Option<&str>,
        at: Option<&Path>,
        handle: Option<&str>,
    ) -> Result<SpawnedLane, CliError> {
        self.ensure_primary("`loot lane new`")?;
        if let Some(h) = handle {
            valid_dock_name(h).map_err(|e| format!("lane handle: {e}"))?;
        }
        if self.signer.is_none() {
            return Err(
                "lanes require a keyed repo — only signed changes cross the seal; \
                 run `loot keygen` first"
                    .into(),
            );
        }
        if let Some(n) = name {
            valid_dock_name(n)?;
            self.ensure_lane_name_free(n, None)?;
        }
        // Capture current disk edits so the lane forks from a real finalized
        // anchor (the same move as `bind_dock_dir`).
        if self.working.is_some() {
            let msg = self.working_message_or_placeholder();
            self.snapshot(&msg)?;
        }
        let anchor = self
            .anchor()
            .ok_or("nothing to fork yet — record a change first (`loot new`)")?;
        // Pin the primary's tip before the graph gains sibling heads (see
        // dock_goto): a later `status` here must never merge the lane's line.
        if self.position.dock_name() == HOME_DOCK && self.position.tip().is_none() {
            let _ = self.store.write_tip(None, Some(&anchor));
        }

        let dir = match at {
            Some(d) => d.to_path_buf(),
            None => self.default_lane_dir(handle)?,
        };
        if dir.join(DOT).exists() {
            return Err(format!(
                "{} is already a loot position (its .loot exists)",
                dir.display()
            ).into());
        }
        let created = !dir.exists();
        std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let dir = std::fs::canonicalize(&dir).map_err(|e| format!("resolve {}: {e}", dir.display()))?;
        // Never nested inside the primary's working tree (ADR 0034): the
        // primary's snapshot walks would swallow the lane's whole tree as WIP.
        let root =
            std::fs::canonicalize(&self.root).map_err(|e| format!("resolve repo root: {e}"))?;
        if dir.starts_with(&root) {
            if created {
                let _ = std::fs::remove_dir_all(&dir);
            }
            return Err(format!(
                "a lane cannot live inside the primary's working tree ({}) — \
                 pick a sibling directory (the default is <repo>-lanes/)",
                root.display()
            ).into());
        }
        let shared =
            std::fs::canonicalize(&self.dot).map_err(|e| format!("resolve store path: {e}"))?;
        let id = self.free_lane_id(&dir, handle);

        // Stamp the lane's `.loot/`: the store pointer, its id, and its view —
        // heads = [anchor] (its own frontier), tip = anchor.
        let lane_dot = dir.join(DOT);
        RepoStore::write_lane_pointer(&lane_dot, &shared, &id)
            .map_err(|e| format!("write lane .loot: {e}"))?;
        let lane_store = RepoStore::for_lane(&shared, &lane_dot);
        lane_store
            .write_heads(std::slice::from_ref(&anchor))
            .map_err(|e| format!("seed lane heads: {e}"))?;
        lane_store
            .write_tip(None, Some(&anchor))
            .map_err(|e| format!("seed lane tip: {e}"))?;
        self.store
            .create_lane_entry(&id, &dir, name, self.now)
            .map_err(|e| format!("register lane: {e}"))?;
        self.persist()?;

        // Materialize the lane's tree and mint its first change handle by
        // opening it — the same self-hosting move as `bind_dock_dir`.
        let mut lane_ws = Workspace::open_at(&dir)?;
        lane_ws.surface()?;
        lane_ws.start_fresh_change()?;
        Ok(SpawnedLane { id, dir })
    }

    /// `loot lane name <name>`: promote this lane mid-flight — a named lane is
    /// a dock (ADR 0034) and persists until an explicit `loot lane rm`; the
    /// gc-sweep never touches it. Lane-side on purpose: the registry entry is
    /// per-entry single-writer, and the entry's writer is its own lane.
    pub fn name_lane(&self, name: &str) -> Result<(), CliError> {
        let id = self.position.lane_id().ok_or(
            "`loot lane name` runs inside a lane — the primary is not a lane \
             (`loot lane new` spawns one)",
        )?;
        valid_dock_name(name)?;
        self.ensure_lane_name_free(name, Some(id))?;
        self.store
            .write_lane_name(id, name)
            .map_err(|e| CliError::from(format!("name lane: {e}")))
    }

    /// Every registered lane (for `loot lane list`), sorted by id.
    pub fn lane_list(&self) -> Vec<LaneEntry> {
        self.store.list_lane_entries()
    }

    /// The observable status of every registered lane — `loot lanes` (#232),
    /// the machine-readable check agents (and the human) run before acting on
    /// shared state. Read-only **by construction**: each lane's `.loot` is
    /// peeked at directly instead of opening a workspace there, so no
    /// heartbeat refreshes — a registry entry is written only by its own lane
    /// (ADR 0034/0035), and an observer that touched heartbeats would blind
    /// the gc-sweep's staleness signal. Runs from any position (observing is
    /// multi-reader; only mutation is single-owner).
    pub fn lane_statuses(&self) -> Vec<LaneStatus> {
        // The harbor-owned pr-map ledger (ADR 0033/0034): reading it is fine,
        // its writer stays the loot-first orchestrator. `read_replaced`, not a
        // bare read: the orchestrator replaces the ledger atomically (#336),
        // and on Windows a reader racing that rename transiently hits
        // PermissionDenied (#293 tail) — swallowed here, that would read as an
        // empty ledger and blank every lane's in-flight PR for one listing.
        let pr_map = crate::ledger::PrMap::parse(
            &loot_core::store::read_replaced(&self.store.git_pr_map())
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default(),
        );
        self.store
            .list_lane_entries()
            .into_iter()
            .map(|entry| {
                let (tip, change, dirty) = self.peek_lane(&entry);
                // The review-lane key (`wip_key`): durable change id, version
                // hex for legacy changes — the same key `review` recorded.
                let pr = change
                    .as_deref()
                    .and_then(|c| pr_map.lanes.iter().find(|l| l.change == c))
                    .map(|l| l.pr);
                LaneStatus { entry, tip, change, pr, dirty }
            })
            .collect()
    }

    /// Read-only peek at one lane's position: its tip, the review-lane key of
    /// its in-flight change (the working change if one is captured, else the
    /// tip — a finalized-but-unlanded change is still in flight), and whether
    /// its tree holds uncaptured edits (the same emptiness check as the #219
    /// capture chokepoint). All-`None` when the lane's `.loot` or store state
    /// is unreadable (a hand-deleted directory) — the row still renders, so a
    /// broken lane stays visible rather than vanishing from the report.
    fn peek_lane(&self, entry: &LaneEntry) -> (Option<Oid>, Option<String>, Option<bool>) {
        let lane_dot = entry.path.join(DOT);
        if !lane_dot.is_dir() {
            return (None, None, None);
        }
        let lane_store = RepoStore::for_lane(&self.dot, &lane_dot);
        let Ok(mut lane_repo) = DagRepo::load_from(&lane_store, entry.path.clone()) else {
            return (None, None, None);
        };
        let tip = lane_store.read_tip(None);
        let working = lane_store.read_working(None);
        let subject = working.or_else(|| tip.clone());
        let change = subject.as_ref().map(|v| {
            lane_repo
                .change_change_id(v)
                .map(|cid| loot_core::hex::encode(&cid))
                .unwrap_or_else(|| loot_core::hex::encode(&v.0))
        });
        let dirty = read_tree_at(&mut lane_repo, &entry.path, self.now)
            .ok()
            .map(|(entries, _)| !lane_repo.working_preview(subject.as_ref(), &entries, "", self.now).1);
        (tip, change, dirty)
    }

    /// `loot lane rm <id-or-name>`: reap a lane — delete its directory and its
    /// registry entry. Unsigned WIP dies with the directory (the seal keeps it
    /// lane-local); the lane's *signed* changes stay in the shared graph
    /// regardless, exactly like `loot dock rm`'s pointer rationale. Not
    /// undoable: the op log never captures lane state. Primary-only.
    pub fn remove_lane(&mut self, id_or_name: &str) -> Result<LaneEntry, CliError> {
        self.ensure_primary("`loot lane rm`")?;
        let entry = self.find_lane(id_or_name)?;
        reap_lane_dir(&entry)?;
        self.store
            .remove_lane_entry(&entry.id)
            .map_err(|e| format!("remove lane entry: {e}"))?;
        Ok(entry)
    }

    /// `loot lane gc`: sweep unnamed lanes — reap those whose change **landed**
    /// (the land path marked them) and those whose heartbeat has been silent
    /// longer than `stale_secs` (abandoned; their unsigned WIP drops, the
    /// premise's stance). Named lanes always survive. Returns every entry with
    /// its outcome. Primary-only.
    pub fn lane_gc(&mut self, stale_secs: u64) -> Result<Vec<(LaneEntry, SweepOutcome)>, CliError> {
        self.ensure_primary("`loot lane gc`")?;
        let mut out = Vec::new();
        for entry in self.store.list_lane_entries() {
            let outcome = if entry.name.is_some() {
                SweepOutcome::Kept("named — persists until `loot lane rm`")
            } else if entry.landed {
                self.reap_entry(&entry, "landed")
            } else if entry.stale(self.now, stale_secs) {
                self.reap_entry(&entry, "stale heartbeat, never landed")
            } else {
                SweepOutcome::Kept("live")
            };
            out.push((entry, outcome));
        }
        Ok(out)
    }

    fn reap_entry(&self, entry: &LaneEntry, why: &'static str) -> SweepOutcome {
        if let Err(e) = reap_lane_dir(entry) {
            return SweepOutcome::Failed(e);
        }
        if let Err(e) = self.store.remove_lane_entry(&entry.id) {
            return SweepOutcome::Failed(format!("remove lane entry: {e}"));
        }
        SweepOutcome::Reaped(why)
    }

    pub(super) fn find_lane(&self, key: &str) -> Result<LaneEntry, CliError> {
        self.store
            .list_lane_entries()
            .into_iter()
            .find(|e| e.id == key || e.name.as_deref() == Some(key))
            .ok_or_else(|| CliError::from(format!("no such lane '{key}' (see `loot lane list`)")))
    }

    /// Refuse a lane name (or id) already claimed by another lane. Ids share
    /// the lookup space with names (`lane rm <id-or-name>`), so both count.
    fn ensure_lane_name_free(&self, name: &str, except: Option<&str>) -> Result<(), CliError> {
        for e in self.store.list_lane_entries() {
            if Some(e.id.as_str()) == except {
                continue;
            }
            if e.id == name || e.name.as_deref() == Some(name) {
                return Err(format!("lane name '{name}' is taken (by lane '{}')", e.id).into());
            }
        }
        Ok(())
    }

    /// Default spawn placement: `<repo-parent>/<repo-name>-lanes/<handle>` — a
    /// sibling of the repo root, never inside the primary's working tree (the
    /// primary's snapshot walks must not see foreign trees; ADR 0034). An
    /// explicit `handle` (the ticket-derived spawn, #232) seeds the directory
    /// name; either way the name is suffixed until free against the registry
    /// (ids *and* promoted names) and the disk, so
    /// [`free_lane_id`](Self::free_lane_id) then derives an id equal to the
    /// directory name.
    fn default_lane_dir(&self, handle: Option<&str>) -> Result<PathBuf, CliError> {
        let root =
            std::fs::canonicalize(&self.root).map_err(|e| format!("resolve repo root: {e}"))?;
        let name = root
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("repo root has no directory name to derive a lanes dir from")?
            .to_string();
        let parent = root
            .parent()
            .ok_or("repo root has no parent directory to place lanes beside")?;
        let lanes_root = parent.join(format!("{name}-lanes"));
        let base = handle.map(str::to_string).unwrap_or_else(gen_lane_handle);
        let entries = self.store.list_lane_entries();
        let mut candidate = base.clone();
        let mut n = 2;
        while self.lane_key_taken(&entries, &candidate) || lanes_root.join(&candidate).exists() {
            candidate = format!("{base}-{n}");
            n += 1;
        }
        Ok(lanes_root.join(candidate))
    }

    /// Whether `key` is claimed in the lane lookup space — as a registry id or a
    /// promoted name (the two share `lane rm <id-or-name>`'s space). Named docks
    /// are retired (#253/ADR 0034), so the primary's only review handle is `main`
    /// — refused for every lane by `valid_dock_name` — and no `.loot/docks/` name
    /// can collide with a lane id on `review/<x>` anymore (the former #281 arm).
    fn lane_key_taken(&self, entries: &[LaneEntry], key: &str) -> bool {
        self.store.lane_entry_exists(key)
            || entries.iter().any(|e| e.name.as_deref() == Some(key))
    }

    /// The handle that becomes the registry id: the explicit (ticket-derived)
    /// handle when given — even under `--at`, so the claim board never loses
    /// the ticket linkage — else dir-derived when the directory's name is a
    /// valid lane name, else generated; suffixed until free. Ids share the
    /// lookup space with promoted names (`lane rm <id-or-name>`), so a
    /// candidate is taken when *either* matches.
    fn free_lane_id(&self, dir: &Path, handle: Option<&str>) -> String {
        let entries = self.store.list_lane_entries();
        let base = handle
            .map(str::to_string)
            .or_else(|| {
                dir.file_name()
                    .and_then(|n| n.to_str())
                    .filter(|n| valid_dock_name(n).is_ok())
                    .map(str::to_string)
            })
            .unwrap_or_else(gen_lane_handle);
        if !self.lane_key_taken(&entries, &base) {
            return base;
        }
        let mut n = 2;
        loop {
            let candidate = format!("{base}-{n}");
            if !self.lane_key_taken(&entries, &candidate) {
                return candidate;
            }
            n += 1;
        }
    }
}

// --- lane report DTOs + registry-side free helpers (candidate 5: DTOs out of
// workspace.rs). Re-exported from `workspace` so `workspace::LaneStatus` etc.
// stay stable for main.rs. ---

/// A freshly spawned lane, for CLI reporting.
#[derive(Debug)]
pub struct SpawnedLane {
    /// The registry id (the auto-handle, or suffixed until free).
    pub id: String,
    /// The lane's working directory, canonicalized.
    pub dir: PathBuf,
}

/// One lane's observable status (`loot lanes`, #232): the registry entry plus
/// a read-only peek at the lane's position. `change` is the review-lane key
/// ([`crate::ledger::PrMap`]'s `change` column), which is what matched `pr`.
/// `dirty` means uncaptured edits beyond the lane's captured state; `None`
/// peek fields mean the lane's directory or store state was unreadable.
#[derive(Debug)]
pub struct LaneStatus {
    pub entry: LaneEntry,
    pub tip: Option<Oid>,
    pub change: Option<String>,
    pub pr: Option<u64>,
    pub dirty: Option<bool>,
}

/// One lane's fate in a `loot lane gc` sweep.
pub enum SweepOutcome {
    Reaped(&'static str),
    Kept(&'static str),
    Failed(String),
}

/// Delete a lane's working directory, guarded: only a directory whose
/// `.loot/lane-id` matches the registry entry is deleted, so a corrupted or
/// hand-edited `path` file can never point the reaper at an innocent tree. A
/// path that is already gone reaps as a no-op.
fn reap_lane_dir(entry: &loot_core::LaneEntry) -> Result<(), String> {
    if !entry.path.exists() {
        return Ok(());
    }
    match RepoStore::read_lane_id(&entry.path.join(DOT)) {
        Some(id) if id == entry.id => std::fs::remove_dir_all(&entry.path)
            .map_err(|e| format!("remove {}: {e} (is it in use?)", entry.path.display())),
        _ => Err(format!(
            "{} does not look like lane '{}' (no matching lane-id) — refusing to delete it",
            entry.path.display(),
            entry.id
        )),
    }
}

/// A generated lane handle for spawns without a usable directory name —
/// short, unique enough for one registry (collisions are suffixed anyway).
fn gen_lane_handle() -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
        .hash(&mut h);
    std::process::id().hash(&mut h);
    format!("lane-{:06x}", h.finish() & 0xff_ffff)
}
