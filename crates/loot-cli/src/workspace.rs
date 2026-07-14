//! Workspace — the process-bound ambient repo (ADR 0006).
//!
//! Owns everything a command needs but shouldn't re-derive: where `.loot/` is,
//! the current identity, the clock, the loaded engine, and the id of the
//! *working change* being rewritten in place. Commands are thin verbs over it.
//!
//! The snapshot invariant itself lives in the engine (`DagRepo::snapshot`); the
//! Workspace only reads the working tree + `.lootattributes` into the entries
//! the engine reconciles, and persists state after a mutation.

use loot_core::bridge::{FerryState, MarkMap};
use loot_core::{
    oplog, valid_dock_name, DagRepo, LaneEntry, MergeOutcome, Oid, Operation, Repo, RepoStore,
    Visibility, HOME_DOCK,
};
use loot_identity::Identity;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const DOT: &str = ".loot";
const ATTRS: &str = ".lootattributes";
const IGNORE: &str = ".lootignore";

/// The transport a pull negotiates over (#217, map #215): exactly the two
/// questions the pipeline asks a relay — nothing about URLs, HTTP, or batch
/// size crosses this seam. Defined here because the Workspace is the
/// consumer (the interface belongs to the caller, not to loot-net); the
/// production adapter wraps `loot_net::offer`/`fetch` in main.rs, and the
/// in-memory test adapter wraps a relay-role `DagRepo`.
pub trait SyncTransport {
    /// Round 1 (S5): send our heads, receive the object addresses in the
    /// closure of the changes the relay would ship.
    fn offer(&self, have: &[Oid]) -> Result<Vec<Oid>, String>;
    /// Round 2 (S5/S6): send our heads + the wanted subset, receive a sync
    /// bundle whose object bytes are limited to `wants`.
    fn fetch(&self, have: &[Oid], wants: &[Oid]) -> Result<Vec<u8>, String>;
}

/// One fetch round-trip's object budget (S6) — pipeline-internal, never part
/// of the [`SyncTransport`] interface.
const OBJECTS_PER_BATCH: usize = 32;

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
    /// The durable change id `loot new` minted eagerly for the *next* change
    /// (ADR 0029/0030), before any snapshot has recorded it. The fresh working
    /// change already has a handle to print and show in `status`/`log`; the
    /// first snapshot carries this id onto the change (then clears it). `None`
    /// on a keyless repo (unsigned changes get no durable handle) or once
    /// consumed.
    next_change_id: Option<[u8; 16]>,
    /// The loaded signing keypair, if this repo has one. Stamps the author on new
    /// changes and signs at finalization (S3, ADR 0018). `None` for a keyless
    /// repo, which then produces unauthored (legacy) changes.
    signer: Option<Identity>,
    /// The registry id of the spawned lane this workspace is, or `None` on the
    /// primary directory (lane #0). A lane's `.loot` is a directory carrying a
    /// `store` pointer plus every lane-owned file (ADR 0034); store-mutating
    /// verbs with one owner (`gc`, remotes, the dock family, lane spawn/reap)
    /// refuse from a lane.
    lane_id: Option<String>,
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
        let loot = dir.join(DOT);
        // A `--at` worktree dock has a `.loot` *pointer file* (not a directory)
        // naming the shared store and its dock (ADR 0022 physical model).
        if loot.is_file() {
            return Self::open_worktree(dir, &loot);
        }
        // A spawned lane's `.loot` is a *directory* whose `store` file points at
        // the shared store; every lane-owned file lives here (ADR 0034).
        if let Some(shared) = RepoStore::read_store_pointer(&loot) {
            return Self::open_lane(dir, &loot, &shared);
        }
        let store = RepoStore::new(&loot);
        if !store.identity().exists() {
            return Err(format!(
                "not a loot repo at {} (no .loot/). Run `loot init` first.",
                dir.display()
            ));
        }
        let dock = store.read_dock();
        Self::assemble(loot, store, dir.to_path_buf(), dock, None)
    }

    /// Load a spawned lane: position is place (ADR 0034) — the cwd's `.loot`
    /// directory carries the lane's private mutable state, `shared` the
    /// append-only store. Refreshes the lane's registry heartbeat (the gc-sweep
    /// signal); the touch is best-effort and self-healing.
    fn open_lane(dir: &Path, lane_dot: &Path, shared: &Path) -> Result<Self, String> {
        let store = RepoStore::for_lane(shared, lane_dot);
        if !store.identity().exists() {
            return Err(format!(
                "lane at {} points at a missing store {}",
                dir.display(),
                shared.display()
            ));
        }
        let lane_id = RepoStore::read_lane_id(lane_dot).ok_or_else(|| {
            format!("malformed lane at {} — no lane-id in its .loot/", dir.display())
        })?;
        let _ = store.touch_lane_heartbeat(&lane_id, dir, real_now());
        let dock = store.read_dock();
        Self::assemble(shared.to_path_buf(), store, dir.to_path_buf(), dock, Some(lane_id))
    }

    /// Load a worktree dock: its `.loot` pointer file names the shared store (where
    /// the graph/objects/dock state live) and this dock; files materialize here.
    fn open_worktree(dir: &Path, pointer: &Path) -> Result<Self, String> {
        let text = read_to_string(pointer)?;
        let mut shared: Option<PathBuf> = None;
        let mut dock: Option<String> = None;
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("store =") {
                shared = Some(PathBuf::from(v.trim()));
            } else if let Some(v) = line.strip_prefix("dock =") {
                dock = Some(v.trim().to_string());
            }
        }
        let shared = shared.ok_or("malformed .loot pointer: missing `store`")?;
        let dock = dock.ok_or("malformed .loot pointer: missing `dock`")?;
        let store = RepoStore::new(&shared);
        if !store.identity().exists() {
            return Err(format!(
                "worktree at {} points at a missing store {}",
                dir.display(),
                shared.display()
            ));
        }
        Self::assemble(shared, store, dir.to_path_buf(), dock, None)
    }

    /// Finish loading once the store, working `root`, and ambient `dock` are
    /// known (shared by the primary, worktree, and lane open paths). `dot` is
    /// the *shared* store's `.loot/` (identity and keys are shared — all lanes
    /// author as the one identity, ADR 0034).
    fn assemble(
        dot: PathBuf,
        store: RepoStore,
        root: PathBuf,
        dock: String,
        lane_id: Option<String>,
    ) -> Result<Self, String> {
        let mut repo = DagRepo::load_from(&store, root.clone()).map_err(|e| e.to_string())?;
        let identity = read_to_string(&store.identity())?;
        let dock_opt = opt(&dock);
        let working = store.read_working(dock_opt);
        let tip = store.read_tip(dock_opt);
        let next_change_id = store.read_next_change(dock_opt);
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
        Ok(Workspace {
            dot,
            store,
            root,
            identity,
            repo,
            dock,
            working,
            tip,
            next_change_id,
            signer,
            lane_id,
            now: real_now(),
        })
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// Begin the repo's first change with an eagerly-minted durable handle (ADR
    /// 0029/0030) when nothing is in progress and none is pending — called right
    /// after `init` generates the keypair, so the very first change has a name
    /// from birth just as `new` gives every later one. No-op once a change or a
    /// pending handle exists, and on a keyless repo (mints `None`).
    pub fn start_fresh_change(&mut self) -> Result<(), String> {
        if self.working.is_none() && self.next_change_id.is_none() {
            self.next_change_id = self.repo.mint_next_change_id();
            self.persist()?;
        }
        Ok(())
    }

    /// The `.loot/` directory for this repo (used by identity keypair commands).
    pub fn dot(&self) -> &std::path::Path {
        &self.dot
    }

    /// Prune orphaned loose objects from `.loot/objects/` (ADR 0012, #66).
    /// Delegates to the engine, which owns the object store and the reachability
    /// walk over the change graph. `dry_run` reports what would be pruned
    /// without deleting. Refuses from a lane (ADR 0034): a lane's view is a
    /// subgraph, so a lane-side reachability walk could prune objects another
    /// lane still references — the shared object store has one pruner.
    pub fn gc(&mut self, dry_run: bool) -> Result<loot_core::GcReport, String> {
        self.ensure_primary("`loot gc`")?;
        self.repo.gc(&self.dot, dry_run).map_err(|e| e.to_string())
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

    /// Raw engine access — **compiled only for tests** (R1, #177): production
    /// verbs go through the named faces below (`history`/`graph`/
    /// `buoy_resolution`/the sync queries), so the engine's concrete surface
    /// physically cannot leak past this seam outside a test build. The
    /// `test-support` feature widens the gate to loot-cli's *binary* test target
    /// (which links this lib as a dependency, where `cfg(test)` is inactive);
    /// it is off by default, so a production build still cannot reach it.
    #[cfg(any(test, feature = "test-support"))]
    pub fn repo(&self) -> &DagRepo {
        &self.repo
    }

    // --- the CLI's read face over the engine (R1, #177) ---

    /// Read-only graph/content queries, grouped: the face the git bridge and
    /// the wip lane consume. Content reads carry the ambient identity + clock,
    /// so callers stop threading them.
    pub fn graph(&self) -> Graph<'_> {
        Graph { repo: &self.repo, identity: &self.identity, now: self.now }
    }

    /// The full view `log` renders (R1): finalized rows newest-first with
    /// abandoned versions dropped and the working node excluded (it renders
    /// once, as the live row), authors as pubkeys (name resolution is display),
    /// divergence marks, and — when heads sit on ≥2 *distinct change lines*
    /// (ADR 0029) — the per-head fork view instead of the flat list.
    pub fn history(&mut self) -> Result<HistoryView, String> {
        let working = self.live_working_row()?;
        let working_node = self.working.clone();
        // One Liveness view (#216): superseded versions (ADR 0032) leave the
        // live view exactly like abandoned ones — an amended change renders
        // once, as its live version. No hand-assembled union here anymore.
        let lv = self.liveness();
        let divergent = lv.divergent().clone();

        let row_of = |id: &Oid, message: &str, total: usize, restricted: usize, embargoed: usize| HistoryRow {
            version: id.clone(),
            message: message.to_string(),
            total,
            restricted,
            embargoed,
            change_id: self.repo.change_change_id(id),
            author: self.repo.change_author(id),
            attestations: self
                .repo
                .attestations_for(id)
                .iter()
                .map(|a| (a.attester, a.role.clone()))
                .collect(),
        };

        // Route by distinct change lines, not head count: a divergent change's
        // several heads share one change id and stay the flat listing (S3).
        let head_lines: std::collections::BTreeSet<Vec<u8>> = self
            .repo
            .heads()
            .iter()
            .map(|h| match self.repo.change_change_id(h) {
                Some(cid) => cid.to_vec(),
                None => h.0.to_vec(),
            })
            .collect();

        let detailed = self.repo.log_detailed();
        if head_lines.len() <= 1 {
            let rows = detailed
                .into_iter()
                .rev()
                .filter(|(id, ..)| Some(id) != working_node.as_ref() && lv.is_live(id))
                .map(|(id, m, t, r, e)| row_of(&id, &m, t, r, e))
                .collect();
            return Ok(HistoryView { rows, divergent, working, graph: None });
        }

        // Diverged graph: each head's own lineage, then the shared ancestry.
        let meta: BTreeMap<Oid, (String, usize, usize, usize)> = detailed
            .into_iter()
            .map(|(id, m, t, r, e)| (id, (m, t, r, e)))
            .collect();
        let node_row = |id: &Oid| match meta.get(id) {
            Some((m, t, r, e)) => row_of(id, m, *t, *r, *e),
            None => row_of(id, "", 0, 0, 0),
        };
        let g = self.repo.log_graph();
        let per_head = (0..g.heads.len())
            .map(|hi| {
                g.changes
                    .iter()
                    .filter(|n| n.reachable_from == [hi] && lv.is_live(&n.id))
                    .map(|n| node_row(&n.id))
                    .collect()
            })
            .collect();
        let shared = g
            .changes
            .iter()
            .filter(|n| n.reachable_from.len() > 1 && lv.is_live(&n.id))
            .map(|n| node_row(&n.id))
            .collect();
        Ok(HistoryView {
            rows: Vec::new(),
            divergent,
            working,
            graph: Some(GraphHistory { heads: g.heads, per_head, shared }),
        })
    }

    /// Resolve the buoy for `role` (CA4, ADR 0025), owning the whole read:
    /// present set, parent lookup, attestation stream, and the trust predicate
    /// (peer registry ∪ self). Also reports trusted attestations naming changes
    /// absent locally, for `--verbose`.
    pub fn buoy_resolution(&self, role: &str) -> BuoyResolution {
        let reg = loot_identity::PeerRegistry::load(&self.dot);
        let my_pubkey = self.author_pubkey();
        let trusted = |pk: &[u8; 32]| -> bool {
            if my_pubkey.as_ref() == Some(pk) {
                return true;
            }
            reg.list().iter().any(|(_name, line)| {
                loot_identity::PeerRegistry::parse_pubkey_bytes_from_line(line)
                    .map(|p| &p == pk)
                    .unwrap_or(false)
            })
        };
        let present: std::collections::BTreeSet<Oid> = self.version_ids().into_iter().collect();
        let parents_fn = |id: &Oid| self.repo.parents_of(id);
        let all = self.repo.all_attestations();
        let excluded = all
            .iter()
            .filter(|a| {
                a.role == role && a.verify() && trusted(&a.attester) && !present.contains(&a.change_id)
            })
            .map(|a| a.change_id.clone())
            .collect();
        let result = loot_core::buoy::resolve(&present, &parents_fn, all.iter().copied(), &trusted, role);
        BuoyResolution { result, excluded }
    }

    /// Every recorded change's version id, topo order (prefix resolution for
    /// `attest`/`abandon` targets).
    pub fn version_ids(&self) -> Vec<Oid> {
        self.repo.log().into_iter().map(|(id, _)| id).collect()
    }

    /// The manifest — the append-only grant audit trail (display reads).
    pub fn manifest(&self) -> &loot_core::manifest::Manifest {
        self.repo.manifest()
    }

    /// Every attestation in the log, cloned for display.
    pub fn all_attestations(&self) -> Vec<loot_core::attestation::Attestation> {
        self.repo.all_attestations().into_iter().cloned().collect()
    }

    /// The recorded conflict set (`loot conflicts` / `resolve` preflight).
    pub fn conflicts(&self) -> &BTreeMap<PathBuf, (Oid, Oid)> {
        self.repo.conflicts()
    }

    /// The ambient dock's live head set (sync negotiation, pull bookkeeping).
    pub fn heads(&self) -> Vec<Oid> {
        self.repo.heads()
    }

    /// A path's content address in the current tree (grant/maroon targets).
    pub fn current_tree_oid(&self, path: &Path) -> Result<Oid, loot_core::RepoError> {
        self.repo.current_tree_oid(path)
    }

    /// A stored object's visibility (grant --relay reads the embargo clock).
    pub fn visibility_of(&self, oid: &Oid) -> Option<Visibility> {
        self.repo.visibility_of(oid)
    }

    /// Every embargoed path this repo holds a key for (push's deposit pass).
    pub fn embargoed_paths(&self) -> Vec<(PathBuf, Oid, u64)> {
        self.repo.embargoed_paths()
    }

    /// Object addresses we'd offer a peer holding `have` (S5 negotiation).
    pub fn offered_objects(&self, have: &[Oid]) -> Vec<Oid> {
        self.repo.offered_objects(have)
    }

    /// The subset of a relay's `offered` addresses this repo lacks (S5).
    pub fn missing_objects(&self, offered: &[Oid]) -> Vec<Oid> {
        self.repo.missing_objects(offered)
    }

    /// True when an authored-but-unsigned change exists — such changes never
    /// travel (ADR 0018), so a push would silently transfer nothing.
    pub fn has_unsigned_tip(&self) -> bool {
        self.repo.has_unsigned_tip()
    }

    /// The batched bundles shipping `wants` to a peer holding `have` (S6,
    /// resumable transfer — each batch stows independently, ADR 0024).
    pub fn bundle_wanted_batched(
        &self,
        have: &[Oid],
        wants: &[Oid],
        per_batch: usize,
    ) -> Result<Vec<loot_core::SyncBundle>, String> {
        self.repo.bundle_wanted_batched(have, wants, per_batch).map_err(|e| e.to_string())
    }

    /// The full sneakernet bundle (`loot bundle`): have = [], apply idempotent.
    pub fn bundle_full(&self) -> Result<loot_core::SyncBundle, String> {
        self.repo.bundle(&[]).map_err(|e| e.to_string())
    }

    // --- named mutations (R1): the with_repo escapes, given names ---

    /// Apply a sync bundle into the working change and persist (`apply`,
    /// `clone`, each `pull` batch). The clock is the ambient one.
    pub fn apply_bundle(
        &mut self,
        bytes: Vec<u8>,
    ) -> Result<BTreeMap<PathBuf, MergeOutcome>, String> {
        let now = self.now;
        // The local abandoned set rides into ingest classification (#216): an
        // incoming co-version of an abandoned version is not divergence-forming.
        let abandoned = self.store.read_abandoned();
        self.with_repo(|repo| {
            repo.apply_with(&loot_core::SyncBundle(bytes), now, &abandoned)
                .map_err(|e| e.to_string())
        })
    }

    /// Apply one relay-delivered sealed grant (ADR 0015): unseal with the
    /// ambient keypair, verify + file the key, persist. Errors on a keyless
    /// repo — receiving a grant requires the recipient key by construction.
    pub fn apply_sealed_grant(
        &mut self,
        bundle_bytes: Vec<u8>,
        grantor_pubkey: [u8; 32],
    ) -> Result<(), String> {
        let now = self.now;
        let signer = self.signer.as_ref().ok_or("this repo has no keypair (run `loot keygen`)")?;
        self.repo
            .apply_sealed_grant(&loot_core::SyncBundle(bundle_bytes), grantor_pubkey, now, |wrapped| {
                signer
                    .unseal_key(wrapped)
                    .map_err(|e| loot_core::RepoError::Backend(e.to_string()))
            })
            .map_err(|e| e.to_string())?;
        self.persist()
    }

    /// Seal + deliver one timed grant atomically (ADR 0027): `deliver` runs
    /// inside the mutation, so a failed delivery aborts before persist and the
    /// manifest never records an undelivered grant — the next push retries.
    #[allow(clippy::too_many_arguments)]
    pub fn deposit_sealed_grant(
        &mut self,
        oid: &Oid,
        peer: &str,
        peer_pubkey: [u8; 32],
        grantor_pubkey: [u8; 32],
        reveal_at: u64,
        seal: impl FnOnce(&[u8; 32]) -> Result<[u8; 80], loot_core::RepoError>,
        deliver: impl FnOnce(Vec<u8>) -> Result<(), String>,
    ) -> Result<(), String> {
        let now = self.now;
        let oid = oid.clone();
        let peer = peer.to_string();
        self.with_repo(|repo| {
            let bundle = repo
                .grant_sealed(&oid, &peer, peer_pubkey, grantor_pubkey, reveal_at, now, seal)
                .map_err(|e| e.to_string())?;
            deliver(bundle.0)
        })
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
        self.snapshot_allowing(message, &[])
    }

    /// `snapshot` with an explicit demotion allowlist (#62): paths listed here
    /// may re-seal more readably than the tree records (`--allow-demote`).
    pub fn snapshot_allowing(
        &mut self,
        message: &str,
        allow_demote: &[PathBuf],
    ) -> Result<(Oid, Vec<(PathBuf, Visibility)>), String> {
        let tip = self.tip.clone();
        self.snapshot_from(tip.as_ref(), message, allow_demote)
    }

    /// This position's working tree, via [`read_tree_at`] — the shared front
    /// half of a snapshot and of the read-only `status`/`log` working-row
    /// preview. Reads only; the caller decides whether to record.
    fn read_working_tree(
        &mut self,
    ) -> Result<(Vec<(PathBuf, Vec<u8>, Visibility)>, Vec<(PathBuf, Visibility)>), String> {
        read_tree_at(&mut self.repo, &self.root, self.now)
    }

    /// `snapshot_allowing` with an explicit fork base instead of the ambient
    /// dock tip — the bridge captures against its pinned pre-ingest anchor so
    /// a pre-dock home capture never folds a freshly ingested head in.
    fn snapshot_from(
        &mut self,
        base: Option<&Oid>,
        message: &str,
        allow_demote: &[PathBuf],
    ) -> Result<(Oid, Vec<(PathBuf, Visibility)>), String> {
        let (entries, reported) = self.read_working_tree()?;

        // Hash the current working tree content + message. Skip the engine
        // snapshot if nothing changed — running `loot status` repeatedly is safe.
        let tree_hash = hash_tree(&entries, message);
        let last_hash = self.store.read_tree_hash(self.dock_opt());
        if last_hash == tree_hash {
            if let Some(id) = &self.working {
                return Ok((id.clone(), reported));
            }
        }

        // When starting a fresh change (no working node), assign the durable
        // handle `loot new` minted eagerly (ADR 0029/0030) so the id printed at
        // `new` and shown in `status`/`log` is the one that lands on the first
        // version. A re-snapshot (working `Some`) carries the node's own handle
        // and ignores this.
        let assign = if self.working.is_none() { self.next_change_id } else { None };

        // Fork the working change from `base` — the ambient dock's tip (ADR
        // 0022) on the normal path. `None` (the pre-dock home dock) preserves
        // the original fork-from-all-heads behavior exactly.
        let id = self
            .repo
            .snapshot_assigning(
                base,
                self.working.as_ref(),
                &entries,
                message,
                self.now,
                allow_demote,
                assign,
            )
            .map_err(|e| e.to_string())?;
        self.working = Some(id.clone());
        // The pending next-change handle is now recorded on the working node,
        // so it is no longer pending — clear it before persisting.
        self.next_change_id = None;
        // Persist the new tree hash before persisting the rest of state.
        let _ = self.store.write_tree_hash(self.dock_opt(), &tree_hash);
        self.persist()?;
        Ok((id, reported))
    }

    /// The working change's current message, if one is in progress — so an
    /// implicit snapshot (ADR 0030) re-records the tree without clobbering a
    /// name a prior `describe` set. `None` when there is no working change.
    pub fn working_message(&self) -> Option<String> {
        self.working
            .as_ref()
            .and_then(|w| self.repo.change_message(w))
    }

    /// `loot new` under implicit snapshot (ADR 0030): capture any edits made
    /// since the last command into the working change *first* — so `edit; new`
    /// never loses work — then finalize. A snapshot that adds nothing over the
    /// dock tip (an empty or tip-duplicate working change) is dropped rather
    /// than finalized, so a bare `loot new` does not mint an empty signed
    /// change. `--no-snapshot` skips the capture (`skip_snapshot`); the
    /// demotion guard rides the capture via `allow_demote`.
    /// Returns the finalized change's **version id**, or `None` when there was
    /// nothing to finalize (a bare `new` whose capture added nothing over the
    /// tip) — so `loot new` can name the finalized version alongside the freshly
    /// minted next change id.
    pub fn finalize_capturing(
        &mut self,
        allow_demote: &[PathBuf],
        skip_snapshot: bool,
    ) -> Result<Option<Oid>, String> {
        if !skip_snapshot {
            let msg = self.working_message().unwrap_or_else(|| "(working change)".to_string());
            let (id, _) = self.snapshot_allowing(&msg, allow_demote)?;
            let anchor = self.anchor();
            let empty = self.repo.change_tree(&id).is_none_or(|t| t.is_empty());
            let duplicate = empty
                || anchor.as_ref().is_some_and(|a| self.repo.same_tree_content(a, &id, self.now));
            if duplicate {
                self.repo.drop_working(&id);
                self.working = None;
                self.persist()?;
            }
        }
        let finalized = self.working.clone();
        self.finalize_working()?;
        Ok(finalized)
    }

    /// Finalize the working change and start fresh: the next snapshot appends a
    /// new change rather than rewriting this one.
    pub fn finalize_working(&mut self) -> Result<(), String> {
        // Sign the finalized change id with our identity key (S3, ADR 0018). The
        // working change is ephemeral until now (rewritten on each `status`), so
        // we sign exactly once, here. A keyless repo finalizes unsigned (legacy).
        if let (Some(signer), Some(working)) = (&self.signer, self.working.clone()) {
            // Sign over `version_id ‖ change_id ‖ predecessors` (ADR 0029/0032)
            // so the durable handle is bound to this exact version and a
            // supersession claim cannot be relabelled or stripped on the wire.
            let change_id = self.repo.change_change_id(&working);
            let preds = self.repo.change_predecessors(&working);
            let sig =
                signer.sign(&loot_core::change_signing_message(&working, &change_id, &preds));
            self.repo
                .attach_signature(&working, sig)
                .map_err(|e| e.to_string())?;
        }
        // The finalized change becomes this dock's tip — the anchor the next
        // change forks from. Persist it only once docks are in play; the pristine
        // home dock keeps `tip` absent so its on-disk shape (and its
        // fork-from-all-heads behavior) is unchanged (ADR 0022). With no working
        // change (e.g. `loot new` right after a clean dock merge already sealed the
        // tip) there is nothing to finalize — leave the dock's tip intact.
        //
        // A lane (ADR 0034) is on the home dock but is *born with a seeded tip*
        // (spawn pins it at the finalized anchor over the shared store), so
        // `docks_active()` is false yet the tip is real and must advance — else
        // it stays stuck at the spawn anchor while `heads` moves on, and a land
        // from the lane aims git-main at the parent, moving nothing (caught live
        // by the #195 guard while dogfooding ADR 0036). Advance the tip for a
        // lane too.
        if self.docks_active() || self.lane_id.is_some() {
            if self.working.is_some() {
                self.tip = self.working.take();
                let _ = self.store.write_tip(self.dock_opt(), self.tip.as_ref());
            }
        } else {
            self.working = None;
        }
        // Clear the tree-hash so the next snapshot always runs the engine.
        self.store.clear_tree_hash(self.dock_opt());
        // Eagerly mint the fresh change's durable handle (ADR 0029/0030): the
        // change that begins now has a name from birth, printed by `new` and
        // shown in `status`/`log`, and the first snapshot carries it onto the
        // change's first version. Keyless repos mint `None` and stay legacy.
        self.next_change_id = self.repo.mint_next_change_id();
        self.persist()
    }

    /// Finalize a specific already-recorded change by signing it (S3, ADR 0018),
    /// so it stops counting as a working change and propagates via push/bundle.
    /// Used by `maroon`, which records a complete re-seal change the engine
    /// leaves unsigned. In a keyless repo the change is unauthored and already
    /// travels, so this is a no-op there.
    pub fn sign_change(&mut self, change_id: &Oid) -> Result<(), String> {
        if let Some(signer) = &self.signer {
            // Same finalize signature as `finalize_working`: over
            // `version_id ‖ change_id ‖ predecessors` (ADR 0029/0032).
            let cid = self.repo.change_change_id(change_id);
            let preds = self.repo.change_predecessors(change_id);
            let sig = signer.sign(&loot_core::change_signing_message(change_id, &cid, &preds));
            self.repo
                .attach_signature(change_id, sig)
                .map_err(|e| e.to_string())?;
            self.persist()?;
        }
        Ok(())
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

    /// The durable change id `loot new` minted eagerly for the next change (ADR
    /// 0029/0030), if one is pending and unrecorded. `loot new` prints it.
    pub fn next_change_id(&self) -> Option<[u8; 16]> {
        self.next_change_id
    }

    /// The live working-change row for read-only `status`/`log` (ADR 0030): the
    /// durable change id (the working node's handle, or the eagerly-minted next
    /// handle when no snapshot exists yet) paired with the **live, non-durable**
    /// version id + emptiness the engine computes from the current tree. Never
    /// persists. `None` when there is no working change to show — a keyless or
    /// pre-`new` repo with no pending handle and no in-progress change.
    pub fn live_working_row(&mut self) -> Result<Option<WorkingRow>, String> {
        if self.working.is_none() && self.next_change_id.is_none() {
            return Ok(None);
        }
        let change_id = match &self.working {
            Some(w) => self.repo.change_change_id(w),
            None => self.next_change_id,
        };
        let (entries, reported) = self.read_working_tree()?;
        let message = self.working_message().unwrap_or_else(|| "(working change)".to_string());
        let base = self.anchor();

        // When a working node exists AND the tree on disk still matches its last
        // snapshot, show that node's *recorded* version id — the sealed id
        // `describe`/`new` printed — so the read-only views agree with the
        // mutating verbs. Only genuine un-snapshotted drift (a save with no loot
        // command since) falls through to the live plaintext fingerprint
        // (Seam #1, ADR 0030), which by construction differs from a sealed id.
        if let Some(w) = &self.working {
            let up_to_date = self.store.read_tree_hash(self.dock_opt()) == hash_tree(&entries, &message);
            if up_to_date {
                let empty = self.repo.change_tree(w).is_none_or(|t| t.is_empty())
                    || base.as_ref().is_some_and(|a| self.repo.same_tree_content(a, w, self.now));
                return Ok(Some(WorkingRow {
                    change_id,
                    version: w.clone(),
                    message,
                    entries: reported,
                    empty,
                }));
            }
        }

        let (version, empty) =
            self.repo.working_preview(base.as_ref(), &entries, &message, self.now);
        Ok(Some(WorkingRow { change_id, version, message, entries: reported, empty }))
    }

    /// Run a closure that mutates the repo, then persist. The single path for
    /// "mutation ⇒ save" — callers can't forget to persist (e.g. `apply`).
    ///
    /// **Private** (#177, retired as an interface): verbs mutate through the
    /// named methods on this type or the [`Snapshotted`] handle (whose
    /// construction *is* the ADR 0030 capture). This stays as the shared
    /// implementation underneath both.
    fn with_repo<T>(
        &mut self,
        f: impl FnOnce(&mut DagRepo) -> Result<T, String>,
    ) -> Result<T, String> {
        let out = f(&mut self.repo)?;
        self.persist()?;
        Ok(out)
    }

    /// Raw mutate-then-persist — **compiled only for tests**: the mutation
    /// twin of [`Workspace::repo`], for white-box state seeding. Production
    /// code cannot call it (R1, #177); gated with [`Workspace::repo`].
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_repo_mut<T>(
        &mut self,
        f: impl FnOnce(&mut DagRepo) -> Result<T, String>,
    ) -> Result<T, String> {
        self.with_repo(f)
    }

    /// Promote any due embargoed keys into the Keyring and persist (ADR 0007)
    /// — the bridge calls this before reading content, exactly as every
    /// content-reading verb does.
    pub fn flush_due_escrow(&mut self) -> Result<(), String> {
        let now = self.now;
        self.with_repo(|repo| {
            repo.flush_escrow(now);
            Ok(())
        })
    }

    /// Record one bridge-ingested change (ADR 0028): apply `acts` over
    /// `parent_tree` — sealing new content *at ingest* under the ingested
    /// commit's own policy — then record it authored (as self) or unauthored
    /// (preserving the git author, ADR 0018), and persist. The ingest loop's
    /// one mutation, named (#177).
    pub fn ingest_change(
        &mut self,
        parent_tree: BTreeMap<PathBuf, (Oid, Visibility)>,
        acts: Vec<(PathBuf, IngestAct)>,
        parents: Vec<Oid>,
        message: &str,
        authored: bool,
    ) -> Result<Oid, String> {
        let message = message.to_string();
        self.with_repo(|repo| {
            let mut tree = parent_tree;
            for (path, act) in acts {
                match act {
                    IngestAct::Remove => {
                        tree.remove(&path);
                    }
                    IngestAct::Reuse { entry } => {
                        tree.insert(path, entry);
                    }
                    IngestAct::Put { bytes, vis } => {
                        let oid = repo.put(&bytes, vis.clone()).map_err(|e| e.to_string())?;
                        tree.insert(path, (oid, vis));
                    }
                }
            }
            let change = loot_core::Change { id: Oid([0; 32]), parents, message, tree };
            if authored {
                repo.record(change).map_err(|e| e.to_string())
            } else {
                repo.record_unauthored(change).map_err(|e| e.to_string())
            }
        })
    }

    /// The one door to the snapshotting (mutating) verbs (ADR 0030): capture
    /// the working tree first — honoring the demotion allowlist (#62) and the
    /// `--no-snapshot`/`--ignore-working-copy` escape — then hand back the
    /// handle that exposes mutation. Holding a [`Snapshotted`] *is* the proof
    /// the capture ran (or was explicitly skipped); a verb that forgets it
    /// cannot mutate, so the invariant is a type, not a hand-maintained call
    /// list (which had drifted across main.rs and ferry.rs — #182). Preserves
    /// a `describe`d name: an implicit capture must not clobber it.
    pub fn snapshotted(&mut self, opts: &SnapshotOpts) -> Result<Snapshotted<'_>, String> {
        if !opts.skip {
            let msg = self.working_message().unwrap_or_else(|| "(working change)".to_string());
            self.snapshot_allowing(&msg, &opts.allow_demote)?;
        }
        Ok(Snapshotted { ws: self })
    }

    // --- operation log + undo (S4, ADR 0031) ---

    /// Record one view-changing command in the local operation log. Capture the
    /// resulting on-disk view, so call this *after* the command's own persist.
    /// `barrier` marks a one-way op (push/grant/maroon/pull-grants) that `undo`
    /// must refuse to cross. Best-effort: a log-write failure never fails the
    /// command it records (undo history is a convenience layer, not repo data).
    pub fn record_op(&self, command: &str, description: &str, barrier: bool) {
        let _ = oplog::record(&self.store, command, &self.dock, description, barrier, self.now);
    }

    /// The full operation log, oldest first (`loot op log`).
    pub fn op_log(&self) -> Result<Vec<Operation>, String> {
        oplog::read(&self.store).map_err(|e| e.to_string())
    }

    /// `loot undo`: step the view back one operation, refusing across a barrier.
    pub fn undo(&mut self) -> Result<StepReport, String> {
        self.step(oplog::undo)
    }

    /// `loot op restore <n>`: jump the view to operation `n` (redo included).
    pub fn restore_op(&mut self, target: u32) -> Result<StepReport, String> {
        self.step(move |s, dock, now| oplog::restore(s, dock, target, now))
    }

    /// Shared driver for `undo`/`restore_op`: note the paths currently on disk,
    /// perform the pointer-level view step (which appends a compensating op),
    /// reload from the restored files, then re-materialize the ambient dock —
    /// writing the restored tree and pruning whatever the step removed. The graph
    /// and object store are never touched, so no change is ever deleted.
    fn step(
        &mut self,
        f: impl FnOnce(&RepoStore, &str, u64) -> Result<oplog::Stepped, oplog::StepError>,
    ) -> Result<StepReport, String> {
        let old_paths = self.ambient_visible_paths();
        let stepped = f(&self.store, &self.dock, self.now).map_err(step_error)?;
        self.reload()?;
        self.resurface(old_paths)?;
        Ok(StepReport {
            description: stepped.appended.description.clone(),
            restored_to: stepped.restored_to,
            heads: stepped.appended.heads(),
            working: self.working.clone(),
        })
    }

    /// The paths the ambient dock currently materializes — the "before" picture a
    /// view step prunes against.
    fn ambient_visible_paths(&self) -> Vec<PathBuf> {
        let tip = self
            .working
            .clone()
            .or_else(|| self.tip.clone())
            .or_else(|| self.repo.heads().into_iter().next());
        tip.map(|t| self.repo.visible_paths_at(&t, &self.identity, self.now))
            .unwrap_or_default()
    }

    /// Rebuild in-memory state (engine, pointers, ambient dock) from the on-disk
    /// files a view restore just rewrote. Re-runs the full open path so a `--at`
    /// worktree resolves its dock from its pointer, not the shared ambient one.
    /// Preserves the injected clock.
    fn reload(&mut self) -> Result<(), String> {
        let now = self.now;
        let root = self.root.clone();
        *self = Self::open_at(&root)?;
        self.now = now;
        Ok(())
    }

    /// Materialize the (reloaded) ambient dock's tree to disk and prune any path
    /// in `old_paths` the restored tree no longer contains, so `undo` leaves a
    /// working tree the next auto-snapshot won't silently re-capture.
    ///
    /// This is the one tree write deliberately EXEMPT from the #219 capture
    /// chokepoint ([`tree_is_dirty_over`](Self::tree_is_dirty_over)):
    /// `undo`/`abandon` resurface exists precisely to rewrite the tree the
    /// operator asked to walk back, so it never consults it — overwriting the
    /// current disk is the point, not an accident.
    fn resurface(&mut self, old_paths: Vec<PathBuf>) -> Result<(), String> {
        self.repo.flush_escrow(self.now);
        let to = self
            .working
            .clone()
            .or_else(|| self.tip.clone())
            .or_else(|| self.repo.heads().into_iter().next());
        let written = match &to {
            Some(to) => self
                .repo
                .surface_with_report(to, &self.identity, self.now)
                .map_err(|e| e.to_string())?
                .0,
            // Restored to an empty view: nothing to write, prune everything.
            None => Vec::new(),
        };
        let keep: std::collections::BTreeSet<&PathBuf> = written.iter().map(|(p, _)| p).collect();
        for p in &old_paths {
            if keep.contains(p) {
                continue;
            }
            let dest = self.root.join(p);
            let _ = std::fs::remove_file(&dest);
            let mut dir = dest.parent().map(Path::to_path_buf);
            while let Some(d) = dir {
                if d == self.root || std::fs::remove_dir(&d).is_err() {
                    break;
                }
                dir = d.parent().map(Path::to_path_buf);
            }
        }
        Ok(())
    }

    // --- divergent changes (S3, ADR 0029/0030) ---

    /// The change ids that are currently **divergent** — one change id, more than
    /// one live version (ADR 0029). `log`/`status` mark these with a trailing `!`.
    pub fn divergent_change_ids(&self) -> std::collections::BTreeSet<[u8; 16]> {
        self.liveness().divergent().clone()
    }

    /// The [`Liveness`] view for the current operation (#216, map #215): the
    /// graph plus this store's abandoned set and the sibling docks' parked
    /// working changes — everything the rule behind the `!` marker needs, in
    /// one place. Build once per operation; queries answer from the cached
    /// view. Public because it IS the read interface for liveness questions
    /// (version resolution in the CLI included).
    pub fn liveness(&self) -> loot_core::Liveness {
        let parked: Vec<Oid> = self
            .store
            .list_docks()
            .iter()
            .filter(|name| name.as_str() != self.dock)
            .filter_map(|name| self.store.read_working(opt(name)))
            .collect();
        self.repo.liveness(&self.store.read_abandoned(), &parked)
    }

    /// Resolve a **version-id** hex prefix among this dock's LIVE version
    /// nodes — the one Liveness rule (#216): abandoned and superseded
    /// versions do not resolve (pre-#216 a superseded version still resolved
    /// here), and the still-changing working change is excluded. `loot
    /// abandon` targets a version by this id.
    pub fn resolve_live_version(&self, prefix: &str) -> Result<Oid, String> {
        let lv = self.liveness();
        let working = self.working.clone();
        let matches: Vec<Oid> = self
            .version_ids()
            .into_iter()
            .filter(|id| lv.is_live(id))
            .filter(|id| Some(id) != working.as_ref())
            .filter(|id| loot_core::hex::encode(&id.0).starts_with(prefix))
            .collect();
        match matches.len() {
            0 => Err(format!("no live version matching '{prefix}'")),
            1 => Ok(matches.into_iter().next().unwrap()),
            n => Err(format!("ambiguous version prefix '{prefix}' — matches {n} versions")),
        }
    }

    /// `loot abandon <version>`: drop `version` from its divergent change, leaving
    /// the other live version(s) under the change id (ADR 0030). Refuses a version
    /// that is not a live member of a *divergent* change, so it only ever collapses
    /// a fork and never hides a change's sole version. Nothing is deleted — the
    /// version stops being a live head and joins the abandoned set — and the whole
    /// step is one **undoable** operation (ADR 0031): the oplog captures both the
    /// heads and the abandoned set, so `loot undo` brings the version back.
    pub fn abandon(&mut self, version: &Oid) -> Result<(), String> {
        let mut abandoned = self.store.read_abandoned();
        if abandoned.contains(version) {
            return Err("that version is already abandoned".into());
        }
        let cid = self
            .repo
            .change_change_id(version)
            .ok_or("that version has no change id (a legacy/unsigned change is never divergent)")?;
        let live = self.liveness().live_of(&cid);
        if !live.contains(version) {
            return Err("no such live version in this repo".into());
        }
        if live.len() < 2 {
            return Err(
                "that change is not divergent — nothing to abandon (it keeps its single version)"
                    .into(),
            );
        }

        // The "before" tree, so resurface can prune if we abandoned the very tip
        // the ambient dock sits on (unusual, but keeps the working tree coherent).
        let old_paths = self.ambient_visible_paths();
        self.repo.abandon_head(version); // drop from live heads if it is one
        abandoned.insert(version.clone());
        self.store
            .write_abandoned(&abandoned)
            .map_err(|e| format!("write abandoned: {e}"))?;
        // Divergence stays flat (#203), so the abandoned version may be the very
        // tip the ambient dock sits on. Hop to the surviving live version —
        // otherwise the tip names a dead version and the next snapshot forks
        // from it. Captured by the op view (per-dock tips), so undo restores it.
        if self.tip.as_ref() == Some(version) {
            let survivor = live.into_iter().find(|v| v != version);
            if let Some(s) = survivor {
                self.tip = Some(s);
                let _ = self.store.write_tip(self.dock_opt(), self.tip.as_ref());
            }
        }
        self.persist()?;
        self.record_op("abandon", &format!("abandon version {}", short_version(version)), false);
        self.reload()?;
        self.resurface(old_paths)?;
        Ok(())
    }

    /// `loot abandon --head <version>`: drop an independent live **head** (a whole
    /// fork tip), the non-divergent counterpart to [`abandon`](Self::abandon).
    /// Where `abandon` collapses one version of a *divergent* change, this
    /// discards a stale *fork* — a head that is the sole version of its change id,
    /// which `abandon` refuses ("it keeps its single version"). The reconcile use
    /// (#243): walk a drifted dock back off a stale line so a re-ferry
    /// fast-forwards onto landed git main instead of *merging* the stale tree.
    ///
    /// Same undoable machinery as `abandon`: the node is union-preserved on disk
    /// (the shared graph is an immutable node store, [`DagRepo::save_to`]), the
    /// abandoned set keeps it out of the live view, and `loot undo` restores it.
    /// Refuses a version that is not a live head, and refuses dropping the dock's
    /// *last* live head so the operation can never leave the dock with no line.
    pub fn abandon_fork(&mut self, version: &Oid) -> Result<(), String> {
        let mut abandoned = self.store.read_abandoned();
        if abandoned.contains(version) {
            return Err("that version is already abandoned".into());
        }
        let live_heads = self.repo.heads();
        if !live_heads.contains(version) {
            return Err(
                "that version is not a live head — `--head` drops a whole fork tip; \
                 use `loot abandon` (no flag) for a divergent co-version"
                    .into(),
            );
        }
        if live_heads.len() < 2 {
            return Err(
                "that is the dock's only live head — abandoning it would leave the dock \
                 with no live line; nothing to fork-drop"
                    .into(),
            );
        }
        // Same shape as `abandon`, minus the divergence gate: drop from live
        // heads (parents re-surface as heads only if now childless), record the
        // abandoned mark, and hop the dock's tip off the dropped head.
        let old_paths = self.ambient_visible_paths();
        self.repo.abandon_head(version);
        abandoned.insert(version.clone());
        self.store
            .write_abandoned(&abandoned)
            .map_err(|e| format!("write abandoned: {e}"))?;
        if self.tip.as_ref() == Some(version) {
            let survivor = self
                .repo
                .heads()
                .into_iter()
                .find(|v| v != version && !abandoned.contains(v));
            self.tip = survivor;
            let _ = self.store.write_tip(self.dock_opt(), self.tip.as_ref());
        }
        self.persist()?;
        self.record_op("abandon", &format!("abandon fork head {}", short_version(version)), false);
        self.reload()?;
        self.resurface(old_paths)?;
        Ok(())
    }

    /// `loot adopt <version>`: settle this dock **wholesale** onto a landed change
    /// `T`, discarding its divergent local line (#244, spec `loot-adopt-target.md`,
    /// amends ADR 0034). Where the no-arg `adopt` *merges* the harbor lineage in,
    /// the explicit-target arm **replaces** the dock's line: it abandons every
    /// competing live head down to the shared anchor and materializes `T`'s tree,
    /// with **no content merge** at any point — the whole point, since a merge
    /// against a stale fork resurrects files deleted upstream (the live #243
    /// hazard). It is the mechanical core of a re-baseline; after adopt the
    /// mirror's `main` can be reset to `origin/main` and the drift guard goes
    /// quiet.
    ///
    /// The primitive is a composition of shipped, tested parts — [`abandon_head`]
    /// per competing head, [`drop_working`] for the WIP, the `resurface`
    /// checkout, and one undoable op (ADR 0031) — so `loot undo` restores the
    /// pre-adopt view exactly (no node is deleted; the graph is an append-only
    /// union store).
    ///
    /// Guards (§4): the target must be a live, finalized change (never the
    /// unsigned working change), and it must lie on the harbor/main lineage — the
    /// same fence ADR 0034 draws. A dirty dock is refused unless `discard_wip`,
    /// which is the sanctioned override of the #219 tree-write chokepoint (adopt
    /// is the one verb whose *intent* is to replace the tree).
    ///
    /// [`abandon_head`]: DagRepo::abandon_head
    /// [`drop_working`]: DagRepo::drop_working
    pub fn adopt(&mut self, prefix: &str, discard_wip: bool) -> Result<AdoptReport, String> {
        // The unsigned working change is never a target: adopt settles a dock on
        // *landed* work (§4). Name that precisely before the generic resolver's
        // "no live version" — the operator pointed at their own WIP.
        if let Some(w) = &self.working {
            if loot_core::hex::encode(&w.0).starts_with(prefix) {
                return Err(
                    "cannot adopt onto an unsigned working change — adopt settles a dock on \
                     landed work; finalize it (`loot new`) to make it a target"
                        .into(),
                );
            }
        }
        // Resolve among live, finalized versions (the working change is excluded).
        let target = self.resolve_live_version(prefix)?;

        // Harbor/main lineage fence (§4): T must be reachable from the change the
        // mirror's `main` projects — never an arbitrary signed change in the graph.
        self.assert_on_mirror_main_lineage(&target)?;

        // WIP gate (§3): a live working change or uncaptured disk edits are work
        // adopt would silently eat. Refuse unless the operator opts to discard.
        let dirty = {
            let (entries, _) = self.read_working_tree()?;
            let anchor = self.anchor();
            let (_, clean) = self.repo.working_preview(anchor.as_ref(), &entries, "", self.now);
            !clean
        };
        let has_wip = self.working.is_some() || dirty;
        if has_wip && !discard_wip {
            return Err(
                "the dock has work adopt would discard — finalize it (`loot new`) or walk it \
                 back (`loot undo`) first, or pass `--discard-wip` to drop it and take the target"
                    .into(),
            );
        }

        // Already settled: T is the sole live head and nothing is dirty (§4 — a
        // no-op with a note, not an error).
        let heads = self.repo.heads();
        if !has_wip && heads.len() == 1 && heads[0] == target {
            return Ok(AdoptReport { target, abandoned: vec![], discarded_wip: false, already_there: true });
        }

        // T must be reachable from some live line, or there is nothing to settle
        // onto (guards against emptying the dock — checked before any mutation).
        let reachable = heads.iter().any(|h| h == &target || self.graph().is_ancestor(&target, h));
        if !reachable {
            return Err(format!(
                "{} is not on any live line of this dock — nothing to settle onto",
                short_version(&target)
            ));
        }

        let old_paths = self.ambient_visible_paths();

        // Drop the WIP first so the working node stops being a competing head.
        let discarded_wip = has_wip;
        if let Some(w) = self.working.clone() {
            self.repo.drop_working(&w);
            self.working = None;
        }

        // Abandon every competing head to a fixpoint: dropping a merge head
        // resurfaces its parents (both the target's line and the stale fork), so
        // one pass is not enough — walk the whole divergent line into the
        // abandoned set until only T (and its ancestors, never heads) remains.
        let mut abandoned = self.store.read_abandoned();
        let mut competing_all: Vec<Oid> = Vec::new();
        loop {
            let competing: Vec<Oid> = self
                .repo
                .heads()
                .into_iter()
                .filter(|h| h != &target && !self.graph().is_ancestor(h, &target))
                .collect();
            if competing.is_empty() {
                break;
            }
            for h in &competing {
                self.repo.abandon_head(h);
                abandoned.insert(h.clone());
                competing_all.push(h.clone());
            }
        }
        self.store
            .write_abandoned(&abandoned)
            .map_err(|e| format!("write abandoned: {e}"))?;

        // Settle the dock on T with a fresh (empty) working change, ADR 0006.
        self.tip = Some(target.clone());
        let _ = self.store.write_tip(self.dock_opt(), self.tip.as_ref());
        self.persist()?;
        self.record_op(
            "adopt",
            &format!("adopt {} (settle dock, discard divergent line)", short_version(&target)),
            false,
        );
        self.reload()?;
        self.resurface(old_paths)?;
        Ok(AdoptReport { target, abandoned: competing_all, discarded_wip, already_there: false })
    }

    /// The harbor/main lineage fence for [`adopt`](Self::adopt) (§4): `target`
    /// must be reachable (ancestor-or-equal) from the loot change the git
    /// mirror's `main` projects — the same "harbor lineage only" invariant
    /// ADR 0034 draws, so adopt can never settle a dock on an unreviewed signed
    /// change and violate the after-it-lands premise.
    ///
    /// Reads only the local ferry spine (`.loot/git-mirror/{state,marks}`, the
    /// plain files ferry writes at the end of every pass): `state.git_main` is
    /// the mirror's `refs/heads/main` tip sha, mapped through the mark map to its
    /// loot change. No network and no git process — a pure graph reachability
    /// check over data already on disk.
    fn assert_on_mirror_main_lineage(&self, target: &Oid) -> Result<(), String> {
        let main_change = self.mirror_main_change().ok_or(
            "no mirror main to settle onto — bind and `loot ferry` a mirror first; \
             `adopt <version>` settles a dock onto landed git-main work",
        )?;
        if target == &main_change || self.graph().is_ancestor(target, &main_change) {
            Ok(())
        } else {
            Err(format!(
                "{} is not on the mirror's main lineage — adopt settles only on landed work \
                 reachable from git-main (the ADR 0034 harbor-lineage fence)",
                short_version(target)
            ))
        }
    }

    /// The loot change the git mirror's `main` currently projects, via the local
    /// ferry spine: `state.git_main` (the main tip sha ferry records at the end
    /// of each pass) mapped through the mark map. `None` when no mirror is bound,
    /// the spine is absent, or the sha has no mark yet.
    fn mirror_main_change(&self) -> Option<Oid> {
        let read = |p: PathBuf| std::fs::read_to_string(p).unwrap_or_default();
        let state = FerryState::parse(&read(self.store.git_state())).ok()?;
        let sha = state.git_main?;
        let marks = MarkMap::parse(&read(self.store.git_marks())).ok()?;
        marks.change_for(&sha).map(|(id, _)| id.clone())
    }

    /// `loot edit <change-id>`: reopen a finalized change as the working change,
    /// **superseding** it (ADR 0032). The reopened change is a *sibling* of the
    /// edited version — parents = its parents, tree = its tree, durable handle
    /// carried — with `predecessors` naming it, so once finalized (`loot new`)
    /// the replacement is signed data that travels: peers drop the superseded
    /// version instead of rendering a false divergence. Three refusals, no
    /// magic: an in-progress working change or uncaptured edits (edit *replaces*
    /// the working change — the documented ADR 0030 exception: it never
    /// implicit-captures), a divergent handle (abandon a version first), and a
    /// change with descendants (v1 amends only a tip/childless change). One
    /// undoable operation (ADR 0031).
    pub fn edit(&mut self, prefix: &str) -> Result<EditReport, String> {
        // Refuse rather than capture (ADR 0032/0030): capture-first would
        // strand the WIP as an unsigned stray head, and carrying it would mix
        // in-flight work into the reopened change's content.
        if self.working.is_some() {
            return Err(
                "a working change is in progress — finalize it (`loot new`) or walk it back \
                 (`loot undo`) first; `edit` replaces the working change"
                    .into(),
            );
        }
        let (entries, _) = self.read_working_tree()?;
        let anchor = self.anchor();
        let (_, clean) = self.repo.working_preview(anchor.as_ref(), &entries, "", self.now);
        if !clean {
            return Err(
                "the tree has uncaptured edits — describe or finalize your work first; \
                 `edit` replaces the working change"
                    .into(),
            );
        }

        // Resolve the reverse-hex letters prefix to one durable handle.
        let mut cids: std::collections::BTreeSet<[u8; 16]> = std::collections::BTreeSet::new();
        for v in self.version_ids() {
            if let Some(cid) = self.repo.change_change_id(&v) {
                if loot_core::hex::letters(&cid).starts_with(prefix) {
                    cids.insert(cid);
                }
            }
        }
        let cid = match cids.len() {
            0 => return Err(format!("no change id matching '{prefix}'")),
            1 => cids.into_iter().next().unwrap(),
            n => return Err(format!("ambiguous change id '{prefix}' ({n} matches) — give more letters")),
        };
        let handle = loot_core::hex::short_letters(&cid, 4);

        // One live version to reopen: a divergent handle is refused with its
        // truthful remedy (ADR 0032) rather than a guess or a disambiguator.
        let live = self.liveness().live_of(&cid);
        let target = match live.len() {
            0 => return Err(format!("change {handle} has no live version (abandoned or superseded)")),
            1 => live.into_iter().next().unwrap(),
            _ => {
                return Err(format!(
                    "change {handle} is divergent (!) — `loot abandon` a version first, then edit"
                ))
            }
        };
        if self.repo.change_signature(&target).is_none() {
            return Err(format!("change {handle} is not finalized — edit reopens signed changes"));
        }
        if self.repo.has_children(&target) {
            return Err(format!(
                "change {handle} has descendants — v1 edits only a tip (childless) change"
            ));
        }

        // Reopen: the engine mints the superseding sibling working node; the
        // dock re-anchors on the edited change's parent so re-snapshots keep
        // the sibling parentage (the working change forks from the tip, ADR
        // 0006 — after `edit`, the tip is the parent and the working change is
        // the reopened version). The cleanliness guard proved the disk already
        // shows the target's tree, so nothing materializes.
        let reopened = self.repo.reopen_change(&target).map_err(|e| e.to_string())?;
        let parent = self.repo.parents_of(&target).into_iter().next();
        self.working = Some(reopened.clone());
        if self.docks_active() {
            self.tip = parent;
            let _ = self.store.write_tip(self.dock_opt(), self.tip.as_ref());
        }
        // Prime the snapshot-idempotence hash for the reopened content so the
        // next command doesn't spuriously re-record an unchanged tree.
        let msg = self.repo.change_message(&reopened).unwrap_or_default();
        let _ = self.store.write_tree_hash(self.dock_opt(), &hash_tree(&entries, &msg));
        self.persist()?;
        self.record_op(
            "edit",
            &format!("edit change {handle} (reopen {} for amend)", short_version(&target)),
            false,
        );
        Ok(EditReport { change_id: cid, superseded: target })
    }

    /// The named-remote registry (`.loot/config`, ADR 0013) as one small value —
    /// the four Workspace forwarders it replaces were interface padding (#177).
    pub fn remotes(&self) -> Remotes {
        Remotes { path: self.store.config(), lane: self.lane_id.clone() }
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
            next_change_id: None,
            // A freshly-initialized repo has no keypair yet (`loot keygen` adds one);
            // its early changes are unauthored until then (S3, ADR 0018).
            signer: None,
            lane_id: None,
            now: real_now(),
        };
        ws.persist()?;
        Ok(ws)
    }

    // --- docks (ADR 0022) ---

    /// The ambient dock name, or `None` on the primary/default dock (which the
    /// CLI displays as `main`). `Some(name)` for a named or `--at` dock.
    pub fn current_dock(&self) -> Option<&str> {
        if self.dock == HOME_DOCK {
            None
        } else {
            Some(&self.dock)
        }
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
        self.ensure_primary("`loot dock`")?;
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
        // Drop an empty/tip-duplicate capture, exactly as `finalize_capturing`
        // does: an idle dock must not park a stray "(working change)" child on
        // its tip — it pollutes the tip's descendants (blocking `loot edit`'s
        // childless guard, ADR 0032) and a later merge would carry the
        // superseded tip's content against an amend.
        if let Some(id) = self.working.clone() {
            let anchor = self.anchor();
            let empty = self.repo.change_tree(&id).is_none_or(|t| t.is_empty());
            let duplicate = empty
                || anchor.as_ref().is_some_and(|a| self.repo.same_tree_content(a, &id, self.now));
            if duplicate {
                self.repo.drop_working(&id);
                self.working = None;
                // Persist while this dock is still ambient, so its working
                // pointer clears and the graph saves without the dropped node.
                self.persist()?;
            }
        }
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

    /// `loot dock <name> [--at <dir>]` — the physical-model dock verb (ADR 0022).
    /// Without `at`, create-or-switch the ambient dock in place and re-materialize
    /// (the single-dir checkout flow, [`dock_goto`]). With `at`, bind a *separate*
    /// working directory to this repo's shared store via a `.loot` pointer file
    /// and materialize the dock's tree there, so concurrent agents edit physically
    /// separate trees over one object store.
    ///
    /// [`dock_goto`]: Workspace::dock_goto
    pub fn create_dock(&mut self, name: &str, at: Option<&Path>) -> Result<(), String> {
        self.ensure_primary("`loot dock`")?;
        match at {
            None => {
                self.dock_goto(name)?;
                Ok(())
            }
            Some(dir) => self.bind_dock_dir(name, dir),
        }
    }

    /// Bind a new named dock to a separate working directory `dir` (a git-worktree
    /// analogue). The dock's process state lives in the shared store under
    /// `.loot/docks/<name>/`; `dir` gets a `.loot` *pointer file* naming the shared
    /// store + dock, and the dock's tree is materialized into it. Does not disturb
    /// the ambient dock or the primary working tree.
    fn bind_dock_dir(&mut self, name: &str, dir: &Path) -> Result<(), String> {
        valid_dock_name(name)?;
        if self.store.dock_exists(name) {
            return Err(format!("dock '{name}' already exists — pick a fresh name"));
        }
        // Capture the current dock's work so the new dock forks from a real tip.
        if self.working.is_some() {
            let msg = self
                .working
                .as_ref()
                .and_then(|w| self.repo.change_message(w))
                .unwrap_or_else(|| "(working change)".to_string());
            self.snapshot(&msg)?;
        }
        let anchor = self
            .anchor()
            .ok_or("nothing to fork yet — record a change first (`loot new`)")?;
        // Pin the primary's tip if it's about to gain a sibling (see dock_goto).
        if self.dock == HOME_DOCK && self.tip.is_none() {
            let _ = self.store.write_tip(None, Some(&anchor));
        }
        self.store.ensure_dock_dir(name).map_err(|e| e.to_string())?;
        self.store
            .write_tip(Some(name), Some(&anchor))
            .map_err(|e| e.to_string())?;
        self.persist()?;

        // Write the worktree dir + its `.loot` pointer at the shared store.
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let shared = std::fs::canonicalize(&self.dot)
            .map_err(|e| format!("resolve store path: {e}"))?;
        let pointer = format!("store = {}\ndock = {}\n", shared.display(), name);
        std::fs::write(dir.join(DOT), pointer)
            .map_err(|e| format!("write {} pointer: {e}", dir.join(DOT).display()))?;

        // Materialize the dock's tree into the new worktree by opening it.
        Workspace::open_at(dir)?.surface()?;
        Ok(())
    }

    /// `loot dock rm <name>`: remove a named dock — pointer bookkeeping, not
    /// graph surgery (#212, amending ADR 0022). The dock's **parked unsigned
    /// working change** (if any) is dropped from the live heads — nothing
    /// signed, nothing travelled, the same rationale as abandoning a docking
    /// PR — and its node leaves the working-change blob on the next save. The
    /// dock's pinned **tip is just a pointer**: signed work lives in the
    /// shared graph regardless of dock pointers (which is why no "only copy
    /// of signed work" refusal exists — there is no such state), so a
    /// finalized unmerged head simply stays a live head, still mergeable
    /// later. `.loot/docks/<name>/` is deleted. One **undoable** operation
    /// (ADR 0031): the op view captures the heads file, the working-change
    /// blob, and every dock's pointer files, and restore recreates the
    /// directory. A worktree bound to the dock via `--at` is not tracked
    /// here; removing its dock leaves that worktree's `.loot` pointer
    /// dangling (opening it then errors) — the directory is the caller's to
    /// delete. Refuses the ambient dock (switch away first) and home.
    /// Returns the dropped parked working change, if there was one.
    pub fn remove_dock(&mut self, name: &str) -> Result<Option<Oid>, String> {
        self.ensure_primary("`loot dock rm`")?;
        if name == HOME_DOCK {
            return Err(format!("'{HOME_DOCK}' is the default dock — it always exists"));
        }
        if name == self.dock {
            return Err(format!(
                "'{name}' is the ambient dock — `loot dock <other>` first, then remove it"
            ));
        }
        if !self.store.dock_exists(name) {
            return Err(format!("no such dock '{name}' (see `loot docks`)"));
        }
        let parked = self.store.read_working(opt(name));
        if let Some(w) = &parked {
            self.repo.drop_working(w); // unsigned WIP: drop from live heads
        }
        self.store
            .remove_dock_dir(name)
            .map_err(|e| format!("remove dock '{name}': {e}"))?;
        self.persist()?;
        self.record_op("dock rm", &format!("remove dock {name}"), false);
        Ok(parked)
    }

    // --- lanes (ADR 0034, #231) ---
    //
    // A lane is a working directory whose `.loot/` carries all its positional
    // state over the shared store; the primary is lane #0. Lanes are
    // ephemeral-unless-named: an unnamed lane is reaped after its change lands
    // (the land path marks it, `loot lane gc` deletes it) or gc-swept once its
    // heartbeat goes stale; naming persists it. Reap = delete the directory —
    // unsigned WIP dies with the lane, zero graph surgery, which is why lane
    // removal is **not undoable** (the op log never references lane state).

    /// The registry id of this lane, or `None` on the primary.
    pub fn lane_id(&self) -> Option<&str> {
        self.lane_id.as_deref()
    }

    /// Refuse a single-owner store mutation from a lane (ADR 0034): a lane owns
    /// only its own position; `gc`, remotes, the dock family, and lane
    /// spawn/reap belong to the primary.
    pub fn ensure_primary(&self, verb: &str) -> Result<(), String> {
        match &self.lane_id {
            Some(id) => Err(format!(
                "{verb} must run from the primary directory — this is lane '{id}', \
                 which owns only its own position (ADR 0034)"
            )),
            None => Ok(()),
        }
    }

    /// `loot lane new [--name <n>] [--at <dir>]`: spawn a sealed lane over this
    /// repo's shared store. The lane is born already-adopted at the primary's
    /// finalized anchor (spawn is the degenerate adopt, ADR 0034) with its tree
    /// materialized in a fresh directory — by default a sibling of the repo
    /// root under `<repo>-lanes/`, never nested inside the primary's tree.
    /// Primary-only, and requires a keyed repo: only signed changes can cross
    /// the seal, so a keyless lane could never land anything.
    pub fn spawn_lane(&mut self, name: Option<&str>, at: Option<&Path>) -> Result<SpawnedLane, String> {
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
    ) -> Result<SpawnedLane, String> {
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
            let msg = self
                .working
                .as_ref()
                .and_then(|w| self.repo.change_message(w))
                .unwrap_or_else(|| "(working change)".to_string());
            self.snapshot(&msg)?;
        }
        let anchor = self
            .anchor()
            .ok_or("nothing to fork yet — record a change first (`loot new`)")?;
        // Pin the primary's tip before the graph gains sibling heads (see
        // dock_goto): a later `status` here must never merge the lane's line.
        if self.dock == HOME_DOCK && self.tip.is_none() {
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
            ));
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
            ));
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
    pub fn name_lane(&self, name: &str) -> Result<(), String> {
        let id = self.lane_id.as_deref().ok_or(
            "`loot lane name` runs inside a lane — the primary is not a lane \
             (`loot lane new` spawns one)",
        )?;
        valid_dock_name(name)?;
        self.ensure_lane_name_free(name, Some(id))?;
        self.store
            .write_lane_name(id, name)
            .map_err(|e| format!("name lane: {e}"))
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
        // its writer stays the loot-first orchestrator.
        let pr_map = crate::ledger::PrMap::parse(
            &std::fs::read_to_string(self.store.git_pr_map()).unwrap_or_default(),
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
    pub fn remove_lane(&mut self, id_or_name: &str) -> Result<LaneEntry, String> {
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
    pub fn lane_gc(&mut self, stale_secs: u64) -> Result<Vec<(LaneEntry, SweepOutcome)>, String> {
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

    fn find_lane(&self, key: &str) -> Result<LaneEntry, String> {
        self.store
            .list_lane_entries()
            .into_iter()
            .find(|e| e.id == key || e.name.as_deref() == Some(key))
            .ok_or_else(|| format!("no such lane '{key}' (see `loot lane list`)"))
    }

    /// Refuse a lane name (or id) already claimed by another lane. Ids share
    /// the lookup space with names (`lane rm <id-or-name>`), so both count.
    fn ensure_lane_name_free(&self, name: &str, except: Option<&str>) -> Result<(), String> {
        for e in self.store.list_lane_entries() {
            if Some(e.id.as_str()) == except {
                continue;
            }
            if e.id == name || e.name.as_deref() == Some(name) {
                return Err(format!("lane name '{name}' is taken (by lane '{}')", e.id));
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
    fn default_lane_dir(&self, handle: Option<&str>) -> Result<PathBuf, String> {
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

    /// Whether `key` is claimed in the lane lookup space — as a registry id or
    /// a promoted name (the two share `lane rm <id-or-name>`'s space).
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

    /// Merge dock `name`'s finalized tip into the current dock, in process (CA2,
    /// ADR 0022). Docks share one object store and graph, so this is a local fork
    /// collapse — no relay, no bundle file. Reuses the ADR 0001 convergence rule
    /// via [`DagRepo::merge_tips`]; adds none.
    ///
    /// Only *finalized* (signed) history merges (ADR 0018): the source contributes
    /// its `tip`, and our own in-progress work is captured and finalized first, so
    /// both parents of the merge change are signed and can travel in a later
    /// bundle. The merge change is then signed and becomes this dock's tip; its
    /// tree is materialized. Conflicts flow through the existing
    /// `conflicts`/`resolve` path — no side is dropped. Returns
    /// `(source dock, per-path outcomes)`.
    pub fn merge_dock(&mut self, name: &str) -> Result<(String, BTreeMap<PathBuf, MergeOutcome>), String> {
        self.ensure_primary("`loot dock merge`")?;
        if name == self.dock {
            return Err(format!("'{name}' is the current dock — nothing to merge"));
        }
        if !self.store.dock_exists(name) {
            return Err(format!("no such dock '{name}' (see `loot docks`)"));
        }
        // The source dock's finalized tip — only signed history merges.
        let their = self.store.read_tip(opt(name)).ok_or_else(|| {
            format!("dock '{name}' has no finalized change to merge — run `loot new` in it first")
        })?;

        // Short-circuit BEFORE touching our work: if their tip is already our
        // finalized tip, there is nothing to merge. `anchor()` reads the finalized
        // tip without disturbing any in-progress change, so an up-to-date no-op
        // never seals our pending work into a spurious tip.
        if self.anchor() == Some(their.clone()) {
            return Ok((name.to_string(), BTreeMap::new()));
        }

        // Capture and finalize any in-progress work so our side of the merge is a
        // signed tip (a merge parent must be finalized to travel in a bundle).
        if self.working.is_some() {
            let msg = self
                .working
                .as_ref()
                .and_then(|w| self.repo.change_message(w))
                .unwrap_or_else(|| "(working change)".to_string());
            self.snapshot(&msg)?;
            self.finalize_working()?;
        }
        let ours = self
            .anchor()
            .ok_or("nothing to merge into yet — record a change first (`loot new`)")?;
        if ours == their {
            return Ok((name.to_string(), BTreeMap::new()));
        }

        // Supersession-aware fork collapse (ADR 0032). If their line *amended*
        // our tip, merging would content-merge a version with its own
        // replacement — resurrecting what the amend removed. Adopt the amend
        // instead: fast-forward this dock onto their tip. Symmetrically, a
        // their-tip our own line already superseded has nothing left to offer.
        // Both tests demand the replacement sit ON the other line — a
        // supersession elsewhere in the shared store proves nothing here.
        if self.repo.supersedes(&ours, &their) {
            return Ok((name.to_string(), BTreeMap::new()));
        }
        if self.repo.supersedes(&their, &ours) {
            self.repo
                .materialize(Some(&ours), &their, &self.identity, self.now)
                .map_err(|e| e.to_string())?;
            self.tip = Some(their.clone());
            let _ = self.store.write_tip(self.dock_opt(), self.tip.as_ref());
            self.persist()?;
            return Ok((name.to_string(), BTreeMap::new()));
        }

        // Reconcile the two lines into a merge change (reuses converge), then sign
        // it and make it this dock's tip.
        let msg = format!("merge dock '{name}' into '{}'", self.dock);
        let (merge_id, outcomes) = self
            .repo
            .merge_tips(&ours, &their, &msg, self.now)
            .map_err(|e| e.to_string())?;
        self.working = Some(merge_id.clone());
        self.finalize_working()?;
        // Reflect the merged tree in the working directory.
        self.repo
            .materialize(Some(&ours), &merge_id, &self.identity, self.now)
            .map_err(|e| e.to_string())?;
        Ok((name.to_string(), outcomes))
    }

    /// Capture-first for pull/apply (#219, ADR 0030 amendment): fold any
    /// uncaptured disk edits into the working change *before* an ingest/converge
    /// touches the tree, exactly like every other mutating verb. A clean tree
    /// captures nothing and leaves `working` absent — so a clean-tree pull still
    /// converges; a dirty tree lands in the working change, and the
    /// working-change guard in [`converge_heads`](Self::converge_heads) then
    /// defers convergence for this pass (the heads stay flat until the operator
    /// finalizes). Returns the working change id when the tree was dirty (or one
    /// was already in progress), else `None`.
    pub fn capture_uncaptured_edits(&mut self) -> Result<Option<Oid>, String> {
        // An in-progress working change already holds the edits and converge
        // defers on it; there is nothing new to capture.
        if let Some(w) = &self.working {
            return Ok(Some(w.clone()));
        }
        let anchor = self.anchor();
        // Skip while a transfer is mid-flight (#217/#219): if the disk's
        // reference head is not yet fully received (an interrupted pull ingested
        // the change node before all its objects), the working tree is not a
        // materialization of it, so a diff against it is not real dirt —
        // capturing here would strand an empty working change over a fetch we
        // are about to resume. This is the ONLY empty-disk special case: a
        // genuine delete-all edit over a fully-held tip still captures below.
        if let Some(a) = &anchor {
            if !self.repo.closure_complete(a) {
                return Ok(None);
            }
        }
        let (entries, _) = self.read_working_tree()?;
        let (_, clean) = self.repo.working_preview(anchor.as_ref(), &entries, "", self.now);
        if clean {
            return Ok(None);
        }
        // Implicit snapshot (ADR 0030): the demotion guard rides the default
        // allowlist, matching a bare mutating verb.
        let (id, _) = self.snapshot_allowing("(working change)", &[])?;
        Ok(Some(id))
    }

    /// The one tree-write capture chokepoint (#219, ADR 0030 amendment): does
    /// the working tree hold edits beyond `reflected` (the change it currently
    /// mirrors — what a materialize diffs from)? A materialize over a dirty tree
    /// would silently drop those edits, so the converge/adopt write paths
    /// consult this and refuse ([`REFUSE_UNCAPTURED_TREE`]) rather than clobber.
    /// It is evaluated ONCE at converge entry, before any head is dropped, so
    /// the reference stays queryable and the no-op converge paths never trip it;
    /// capture-first verbs (pull/apply) snapshot before converging, so by the
    /// time a write runs this is false. `undo`/`abandon`
    /// [`resurface`](Self::resurface) is the one deliberate exemption —
    /// rewriting the tree is exactly what the operator asked for — and never
    /// consults it.
    fn tree_is_dirty_over(&mut self, reflected: Option<&Oid>) -> Result<bool, String> {
        let (entries, _) = self.read_working_tree()?;
        Ok(!self.repo.working_preview(reflected, &entries, "", self.now).1)
    }

    /// Run the whole pull pipeline over a [`SyncTransport`] (#217, map #215):
    /// negotiate (offer → missing → wants), fetch in batches — each applied
    /// batch persists, so an interrupted pull resumes by re-negotiating and
    /// fetching only what's left (S6, ADR 0024) — then collapse any fork the
    /// pull left us on (the keyholder fork-collapse of ADR 0011, #128).
    ///
    /// Two correctness points the pipeline owns (previously restated at the
    /// CLI): `have` is re-read after each batch so the relay's change-delta
    /// stays relative to our current heads; and outcomes fold with
    /// `converge::worst` across batches AND across the post-pull converge, so
    /// a Conflict can never be masked by a later Converged for the same path.
    /// There is no caller-supplied "ours": the head partition derives the
    /// converge base from the dock's anchor (#216 — the #203 wrong-base class
    /// is unrepresentable). Returns the folded per-path outcomes; rendering
    /// and op-recording stay with the caller (R5 #181; ADR 0031).
    pub fn pull_via(
        &mut self,
        transport: &impl SyncTransport,
    ) -> Result<PullReport, String> {
        // Capture-first (#219, ADR 0030 amendment): fold any uncaptured disk
        // edits into the working change before we touch the tree. A dirty tree
        // then holds a working change, so the ingest below still runs (graph
        // append is always safe) but converge waits — it cannot fold heads
        // under an in-progress working change without orphaning it.
        let captured = self.capture_uncaptured_edits()?;
        // Negotiate with COMPLETE heads only (#217 find): an interrupted
        // batched pull already ingested change nodes whose object bytes never
        // arrived; claiming those heads would make the relay skip exactly the
        // changes we still need, stranding the pull forever.
        let offered = transport.offer(&self.repo.negotiation_have())?;
        let wants = self.missing_objects(&offered);
        let mut outcomes: BTreeMap<PathBuf, MergeOutcome> = BTreeMap::new();
        for batch in wants.chunks(OBJECTS_PER_BATCH) {
            let current_have = self.repo.negotiation_have();
            let bytes = transport.fetch(&current_have, batch)?;
            let batch_outcomes = self.apply_bundle(bytes)?;
            fold_worst(&mut outcomes, batch_outcomes);
        }
        let converged = self.converge_heads(None)?;
        fold_worst(&mut outcomes, converged);
        // Converge is a no-op whenever capture-first left a working change in
        // progress (the guard at the top of `converge_heads`). Report the defer
        // only when it actually left a fork standing — a captured tree with no
        // ingested co-head has nothing to converge, so no note is warranted.
        let deferred = captured.filter(|_| self.repo.heads().len() > 1);
        Ok(PullReport { outcomes, deferred })
    }

    /// Collapse a fork the ambient dock is sitting on into one materialized tip
    /// (#128). `pull`/`apply` ingest a peer's divergent tip as a *sibling head*
    /// — engine `apply_sync` records + classifies but never merges tips — so a
    /// keyholder that has also advanced its own line ends up on multiple heads
    /// with a working tree showing only its own side (the other side's content
    /// is in the graph but never materialized). This is the peer-side analogue
    /// of `merge_dock` (ADR 0011: keyholders collapse forks on pull+apply): fold
    /// every other head into our line via `merge_tips`, signing each merge so it
    /// travels, then materialize the merged tree. Only genuinely independent
    /// heads fold: superseded heads drop (ADR 0032), and divergent co-versions
    /// of one `change_id` — plus sibling docks' parked working changes — stay
    /// flat as live heads, never content-merged (#198/#203).
    ///
    /// `base` names our side — the tip the working directory already reflects
    /// (the caller's pre-pull head); materialize is diffed from it so a stale
    /// side's untouched paths are not disturbed. On the home dock `anchor()` is
    /// ambiguous under divergence, which is why the caller must pass it. A single
    /// head, or an in-progress working change, is a no-op. Under capture-first
    /// (#219) an in-progress working change is the ordinary dirty-tree case, not
    /// an impossibility: pull/apply snapshot uncaptured edits before converging,
    /// so a dirty pull leaves a working change here and convergence WAITS — the
    /// heads stay flat until the operator finalizes (`loot new`) and re-pulls.
    /// (The former "`pull`/`apply` have none" claim was an accident of ADR 0030
    /// not yet reaching them, not a guarantee — ADR 0030 amendment.) Returns the
    /// per-path merge outcomes.
    pub fn converge_heads(&mut self, base: Option<&Oid>) -> Result<BTreeMap<PathBuf, MergeOutcome>, String> {
        // You cannot fold heads under an in-progress working change without
        // orphaning it, so converge defers whenever capture-first captured a
        // dirty tree — ingest already ran; the operator finalizes then re-pulls.
        if self.working.is_some() {
            return Ok(BTreeMap::new());
        }
        // Chokepoint (#219): evaluate dirtiness ONCE, up front — before any
        // head is dropped, while `reflected` (the disk's pre-pull head) is still
        // queryable. The write paths below consult `disk_dirty`; the no-op paths
        // (divergent-flat, parked-base, superseded-with-nothing-to-adopt) return
        // without ever reading it, so a deliberately foreign `base` never
        // refuses a converge that touches nothing.
        let reflected = base.cloned().or_else(|| self.anchor());
        let disk_dirty = self.tree_is_dirty_over(reflected.as_ref())?;
        // The head partition (#216) decides everything converge may do; this
        // method only EXECUTES it: drop `stale` (superseded heads, ADR 0032 —
        // a solo amend lands as a clean replacement, never content-merged
        // with what it removed), leave `flat` alone (divergent co-versions +
        // parked working changes stay live heads, never content-merged,
        // #198/#203), fold `fold` (the genuinely independent lines) onto
        // `ours` — which the partition guarantees is never a parked head.
        let lv = self.liveness();
        let part = lv.partition(&self.repo.heads(), base, self.anchor().as_ref());
        for h in &part.stale {
            self.repo.abandon_head(h);
        }
        let heads = self.repo.heads();
        if heads.len() <= 1 {
            // Nothing left to merge — but if dropping superseded heads moved
            // the dock off its old tip (the solo-amend case), adopt the
            // survivor: re-point the tip and materialize its tree.
            if let (Some(survivor), true) = (heads.first().cloned(), !part.stale.is_empty()) {
                // `reflected` (captured at entry, pre-drop) is the disk truth.
                let from = reflected.clone();
                if from.as_ref() != Some(&survivor) {
                    // Chokepoint (#219): refuse before the adopt write if the
                    // disk holds uncaptured edits. The in-memory stale-drop above
                    // is not persisted on this error path, so the refusal is
                    // atomic.
                    if disk_dirty {
                        return Err(REFUSE_UNCAPTURED_TREE.into());
                    }
                    if self.docks_active() {
                        self.tip = Some(survivor.clone());
                        let _ = self.store.write_tip(self.dock_opt(), self.tip.as_ref());
                    }
                    self.repo
                        .materialize(from.as_ref(), &survivor, &self.identity, self.now)
                        .map_err(|e| e.to_string())?;
                    self.persist()?;
                }
            }
            return Ok(BTreeMap::new());
        }
        // Dropping a stale head can restore parents as heads the first pass
        // never saw — re-partition over the post-drop heads.
        let part = if part.stale.is_empty() {
            part
        } else {
            lv.partition(&heads, base, self.anchor().as_ref())
        };
        let ours = part.ours.ok_or("nothing to converge onto")?;
        let others = part.fold;
        if others.is_empty() {
            return Ok(BTreeMap::new());
        }
        // Materialize diffs from what the DISK currently shows — the caller's
        // pre-pull base even if it was just dropped as superseded — not from
        // whichever head the merge starts on. `reflected` is that disk truth
        // (base, or the dock anchor for pull_via #217), captured at entry so a
        // stale-head drop cannot move it off what the tree actually shows.
        let from = reflected.clone().unwrap_or_else(|| ours.clone());
        // Chokepoint (#219): refuse BEFORE the merge loop mutates the graph, so a
        // dirty tree refuses atomically rather than stranding signed merge nodes
        // with the disk left unmaterialized. Capture-first verbs snapshot first,
        // so this passes; a direct caller that skipped capture is refused here.
        if disk_dirty {
            return Err(REFUSE_UNCAPTURED_TREE.into());
        }
        let mut acc = ours;
        let mut all: BTreeMap<PathBuf, MergeOutcome> = BTreeMap::new();
        for h in others {
            let msg = format!("converge diverged head into '{}'", self.dock);
            let (merge_id, outcomes) = self
                .repo
                .merge_tips(&acc, &h, &msg, self.now)
                .map_err(|e| e.to_string())?;
            self.working = Some(merge_id.clone());
            self.finalize_working()?;
            acc = merge_id;
            for (path, outcome) in outcomes {
                let slot = all.entry(path).or_insert(MergeOutcome::Converged);
                *slot = loot_core::converge::worst(slot.clone(), outcome);
            }
        }
        // Reflect the merged tree in the working directory (visibility-aware:
        // sealed paths the identity can't open are skipped, staying relayed).
        self.repo
            .materialize(Some(&from), &acc, &self.identity, self.now)
            .map_err(|e| e.to_string())?;
        self.persist()?;
        Ok(all)
    }

    /// Resolve a conflict at `path` with `resolution` bytes. On a dock the
    /// resolution is built on — and becomes — the dock's tip (its conflicted merge
    /// change), then is signed like any finalized change, so a later `status`
    /// forks from the resolved line rather than the pre-resolution merge (CA2, ADR
    /// 0022). On the pre-dock home dock it keeps the original behavior (resolve
    /// against all heads; finalize with `loot new`). Returns the resolution
    /// content oid, for display.
    pub fn resolve_conflict(&mut self, path: &Path, resolution: &[u8], vis: Visibility) -> Result<Oid, String> {
        let base = self.tip.clone();
        let (change_id, content) = self
            .repo
            .resolve(base.as_ref(), path, resolution, vis, self.now)
            .map_err(|e| e.to_string())?;
        // A resolution is a deliberate, finished change — sign it now (S3, ADR
        // 0018) in both modes. The pre-dock hint to "finalize with `loot new`"
        // never worked: resolve doesn't set the working pointer, so `new` had
        // nothing to sign and the resolution (and every descendant) was
        // stranded as untravelable working history.
        if let Some(signer) = &self.signer {
            // Finalize over `version_id ‖ change_id ‖ predecessors` (ADR
            // 0029/0032), like every other finalize path — `resolve` mints a
            // durable change id for the change (and no predecessors).
            let cid = self.repo.change_change_id(&change_id);
            let preds = self.repo.change_predecessors(&change_id);
            let sig = signer.sign(&loot_core::change_signing_message(&change_id, &cid, &preds));
            self.repo
                .attach_signature(&change_id, sig)
                .map_err(|e| e.to_string())?;
        }
        // On a dock or lane, the resolution also advances the tip so it isn't
        // orphaned and the next snapshot builds on it. (A lane is a home dock
        // with a seeded tip, so gate on `lane_id` too — the same class of
        // stuck-tip bug #229 fixed in `finalize_working`.)
        if self.docks_active() || self.lane_id.is_some() {
            // Reflect ONLY the resolved path on disk (#233). The rest of the
            // merged tree is already materialized — the merge that produced the
            // conflicts wrote it — and the operator may be holding uncommitted
            // edits to *other* files (unresolved sibling conflicts, or unrelated
            // work). A whole-tree `materialize` here re-writes every file at the
            // resolution change and so reverts those edits — the very clobber
            // capture-first (#219) exists to prevent, and the reason reconciling
            // a multi-conflict bounce used to demand "resolve one at a time" plus
            // manual git surgery. `resolve` touches exactly one path in the tree
            // (engine `resolve` inserts just `path`), so write exactly that one
            // path and leave every other file on disk untouched.
            let dest = self.root.join(path);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&dest, resolution).map_err(|e| e.to_string())?;
            self.tip = Some(change_id);
            let _ = self.store.write_tip(self.dock_opt(), self.tip.as_ref());
        }
        self.persist()?;
        Ok(content)
    }

    // --- git interop bridge support (GB1, ADR 0028) ---

    /// The repo's on-disk layout — the bridge keeps its marks/state/config
    /// under `.loot/git-mirror/` via these paths.
    pub fn store(&self) -> &RepoStore {
        &self.store
    }

    /// The ambient dock's display name (`main` for home).
    pub fn dock_name(&self) -> &str {
        &self.dock
    }

    /// The finalized change the ambient dock sits on, without disturbing any
    /// in-progress work — the loot side of the bridge's divergence check.
    pub fn finalized_anchor(&self) -> Option<Oid> {
        self.anchor()
    }

    /// SSHSIG-sign `msg` under `namespace` with this repo's keypair (mirrored
    /// commits sign under `"git"`). Errors on a keyless repo.
    pub fn ssh_sign(&self, namespace: &str, msg: &[u8]) -> Result<String, String> {
        let signer = self
            .signer
            .as_ref()
            .ok_or("no identity keypair — run `loot keygen` to generate one")?;
        signer.ssh_sign(namespace, msg).map_err(|e| e.to_string())
    }

    /// This repo's OpenSSH public key line, if it has a keypair — seeds the
    /// bridge's allowed-signers file so `git verify-commit` can check mirrors.
    pub fn public_key_openssh(&self) -> Option<String> {
        let comment = format!("{}@loot", self.identity);
        self.signer.as_ref().and_then(|s| s.public_key_openssh(&comment).ok())
    }

    /// This repo's author pubkey, if it has a keypair.
    pub fn author_pubkey(&self) -> Option<[u8; 32]> {
        self.signer.as_ref().map(|s| s.public_key_bytes())
    }

    // --- reconcile: THE home for "advance a tip to cover another line" (R2, #178) ---
    //
    // The converge classifier (ADR 0001) is the pure per-path rule; everything
    // above it — when to capture disk work, whether to adopt or merge, which
    // tip advances — decides HERE. `reconcile_onto` is the bridge/pull-shaped
    // entry (an incoming finalized line meets the ambient dock);
    // [`Workspace::merge_dock`] is the dock-shaped entry; and
    // [`Workspace::converge_heads`] is the post-pull fork collapse. The
    // ferry_* mechanics below are private to this decision.

    /// Advance the ambient dock to cover `target` — the whole reconcile
    /// decision, one place (previously smeared across ferry.rs's match and
    /// these mechanics; the four live ferry bugs of 2026-07-10 all lived in
    /// that smear). With `capture`, in-progress disk work is captured first
    /// against `pinned` (the caller's pre-ingest anchor, so the two lines meet
    /// only through the converge classifier); a capture matching `pinned` or
    /// `target` is dropped, not minted. Then:
    ///   - real concurrent work captured → merge it with `target`;
    ///   - no local line (`pinned` None) → adopt (fast-forward);
    ///   - `target` covered by us        → no-op (the other side is behind);
    ///   - we are behind `target`        → adopt (fast-forward);
    ///   - genuinely diverged            → merge via the classifier.
    ///
    /// Returns the per-path outcomes (empty on adopt/no-op).
    pub fn reconcile_onto(
        &mut self,
        target: Option<&Oid>,
        pinned: Option<&Oid>,
        capture: bool,
        label: &str,
    ) -> Result<BTreeMap<PathBuf, MergeOutcome>, String> {
        let wip = if capture { self.reconcile_capture(pinned, target)? } else { None };
        let Some(target) = target else {
            return Ok(BTreeMap::new());
        };
        match (wip, pinned) {
            (Some(w), _) => self.reconcile_merge(&w, target, label),
            (None, None) => {
                self.reconcile_adopt(target)?;
                Ok(BTreeMap::new())
            }
            (None, Some(o)) if o == target || self.graph().is_ancestor(target, o) => {
                Ok(BTreeMap::new())
            }
            // The git target is a version our line has *superseded* (ADR 0032/
            // 0033): a landed change reopened and amended while its old commit is
            // still the git tip. A superseded version is dead — never merge into
            // it (that resurrects what the amend removed); keep our line and let
            // projection thread the amend onto the stale tip (a fast-forward
            // downstream). This is the reconcile twin of dock-merge's
            // `supersedes` short-circuit and converge's superseded-head drop.
            (None, Some(o)) if self.repo.supersedes(o, target) => Ok(BTreeMap::new()),
            (None, Some(o)) if self.graph().is_ancestor(o, target) => {
                self.reconcile_adopt(target)?;
                Ok(BTreeMap::new())
            }
            (None, Some(o)) => {
                let ours = o.clone();
                self.reconcile_merge(&ours, target, label)
            }
        }
    }

    /// Capture in-progress disk work before the bridge moves the dock tip,
    /// exactly as `merge_dock` captures before merging: adopt/merge
    /// re-materialize the full target tree, so uncaptured edits — including
    /// ones that never saw a `status` and so have no working change yet —
    /// would be silently overwritten.
    ///
    /// Forks explicitly from `base` (the bridge's pinned pre-ingest anchor):
    /// the pre-dock home dock would otherwise fork from every head and fold
    /// the freshly ingested line in without the converge classifier seeing
    /// it. A snapshot identical to `base` (nothing new) or to `target` (the
    /// disk already holds exactly what the ingested line delivers — the
    /// co-located checkout after a `git pull`) is dropped from the graph
    /// again, so no redundant change is minted and no stray head is left for
    /// reconcile or a later pass's anchor derivation to trip over. Returns
    /// the captured change when real work was finalized.
    fn reconcile_capture(
        &mut self,
        base: Option<&Oid>,
        target: Option<&Oid>,
    ) -> Result<Option<Oid>, String> {
        let msg = self
            .working
            .as_ref()
            .and_then(|w| self.repo.change_message(w))
            .unwrap_or_else(|| "(working change)".to_string());
        let (id, _) = self.snapshot_from(base, &msg, &[])?;
        let empty = self.repo.change_tree(&id).is_none_or(|t| t.is_empty());
        let duplicate = empty
            || [base, target]
                .into_iter()
                .flatten()
                .any(|o| self.repo.same_tree_content(o, &id, self.now));
        if duplicate {
            self.repo.drop_working(&id);
            self.working = None;
            self.persist()?;
            Ok(None)
        } else {
            self.finalize_working()?;
            Ok(Some(id))
        }
    }

    /// Fast-forward the ambient dock to `new_tip` (an ingested change that
    /// descends from the current anchor) and materialize its tree. The bridge's
    /// no-fork path: git advanced, loot didn't.
    fn reconcile_adopt(&mut self, new_tip: &Oid) -> Result<(), String> {
        let from = self.anchor();
        self.repo
            .materialize(from.as_ref(), new_tip, &self.identity, self.now)
            .map_err(|e| e.to_string())?;
        if self.docks_active() {
            self.tip = Some(new_tip.clone());
            let _ = self.store.write_tip(self.dock_opt(), self.tip.as_ref());
        }
        self.store.clear_tree_hash(self.dock_opt());
        self.persist()
    }

    /// Merge an ingested head into `ours` (the dock tip the bridge pinned
    /// before ingest) — `merge_dock`'s reconcile step with the source being
    /// the bridge instead of a dock. Caller runs [`reconcile_capture`] first.
    /// Conflicts flow through the shared `conflicts`/`resolve` path. Returns
    /// the per-path outcomes.
    ///
    /// [`reconcile_capture`]: Workspace::reconcile_capture
    fn reconcile_merge(
        &mut self,
        ours: &Oid,
        their: &Oid,
        message: &str,
    ) -> Result<BTreeMap<PathBuf, MergeOutcome>, String> {
        if ours == their {
            return Ok(BTreeMap::new());
        }
        let (merge_id, outcomes) = self
            .repo
            .merge_tips(ours, their, message, self.now)
            .map_err(|e| e.to_string())?;
        self.working = Some(merge_id.clone());
        self.finalize_working()?;
        self.repo
            .materialize(Some(ours), &merge_id, &self.identity, self.now)
            .map_err(|e| e.to_string())?;
        Ok(outcomes)
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
        // Two-root save (ADR 0034): shared artifacts to the store root, this
        // position's heads/working-change to the lane root (equal on the primary).
        self.repo.save_to(&self.store).map_err(|e| e.to_string())?;
        self.store
            .write_working(self.dock_opt(), self.working.as_ref())
            .map_err(|e| format!("write working: {e}"))?;
        self.store
            .write_next_change(self.dock_opt(), self.next_change_id.as_ref())
            .map_err(|e| format!("write next-change: {e}"))
    }
}

/// The refusal the tree-write chokepoint prints when a converge/adopt would
/// materialize over uncaptured disk edits (#219, ADR 0030 amendment). Reachable
/// only when a caller skipped capture-first; pull/apply never see it.
const REFUSE_UNCAPTURED_TREE: &str =
    "refusing to materialize over uncaptured working-tree edits — capture them first \
     (`loot describe` or `loot new`), then retry";

/// Resolve visibility for `path` under an explicit `.lootattributes` text.
/// The bridge classifies ingested files under the *ingested commit's own*
/// rules — a commit that adds a sealing rule and the file it seals lands
/// sealed, exactly as if it had been snapshotted locally (GB1, ADR 0028).
pub fn visibility_under(attrs_text: &str, path: &str) -> Visibility {
    Attributes::parse(attrs_text).visibility_for(path)
}

/// Whether `rel` is excluded under an explicit `.lootignore` text — the
/// ingest-side twin of the snapshot walk's exclusion (#64).
pub fn ignored_under(ignore_text: &str, rel: &str) -> bool {
    Ignore::parse(ignore_text).ignores_file(rel)
}

/// Fold one call's per-path outcomes into the running map with
/// `converge::worst`, so a Conflict from one call can never be masked by a
/// later Converged for the same path — the cross-call half of the invariant
/// `apply_sync`/`converge_heads` each honour within a call (#217).
fn fold_worst(
    all: &mut BTreeMap<PathBuf, MergeOutcome>,
    batch: BTreeMap<PathBuf, MergeOutcome>,
) {
    for (path, outcome) in batch {
        let slot = all.entry(path).or_insert(MergeOutcome::Converged);
        *slot = loot_core::converge::worst(slot.clone(), outcome);
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
#[derive(Debug)]
pub enum DockAction {
    Already,
    Switched,
    Created,
}

// --- lane lifecycle plumbing (ADR 0034, #231) ---

/// The gc-sweep reap threshold: an unnamed lane whose heartbeat has been
/// silent this long (and whose change never landed) is considered abandoned.
/// The heartbeat is touched on every workspace open from the lane — every loot
/// verb run there — so a day of silence means no agent is in it; agent
/// sessions run hours, not days. Landed lanes reap without any wait, and named
/// lanes never reap, so the threshold only decides how long abandoned WIP
/// lingers.
pub const LANE_STALE_SECS: u64 = 24 * 60 * 60;

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

/// Read-only graph/content queries over the ambient repo (R1, #177): the face
/// the git bridge and the wip lane consume, so the engine's concrete surface
/// stays out of the bridge. Content reads carry the ambient identity + clock.
/// The pure DAG walks (`is_ancestor`/`ancestor_closure`/`generations`) live
/// here too — they are graph queries, not bridge logic.
pub struct Graph<'a> {
    repo: &'a DagRepo,
    identity: &'a str,
    now: u64,
}

impl Graph<'_> {
    pub fn ids_topo(&self) -> Vec<Oid> {
        self.repo.change_ids_topo()
    }

    pub fn parents(&self, id: &Oid) -> Vec<Oid> {
        self.repo.parents_of(id)
    }

    /// The version ids this change supersedes (ADR 0032): non-empty only on an
    /// amend. Drives the bridge's predecessor-conditional git threading
    /// (ADR 0033) and the `Loot-Predecessors` trailer.
    pub fn predecessors(&self, id: &Oid) -> Vec<Oid> {
        self.repo.change_predecessors(id)
    }

    pub fn tree(&self, id: &Oid) -> Option<BTreeMap<PathBuf, (Oid, Visibility)>> {
        self.repo.change_tree(id)
    }

    pub fn author(&self, id: &Oid) -> Option<[u8; 32]> {
        self.repo.change_author(id)
    }

    pub fn signature(&self, id: &Oid) -> Option<[u8; 64]> {
        self.repo.change_signature(id)
    }

    pub fn change_id(&self, id: &Oid) -> Option<[u8; 16]> {
        self.repo.change_change_id(id)
    }

    pub fn message(&self, id: &Oid) -> Option<String> {
        self.repo.change_message(id)
    }

    pub fn conflicts(&self) -> &BTreeMap<PathBuf, (Oid, Oid)> {
        self.repo.conflicts()
    }

    /// Open a stored object as the ambient identity at the ambient clock.
    pub fn content(&self, oid: &Oid) -> Result<Vec<u8>, loot_core::RepoError> {
        self.repo.get(oid, self.identity, self.now)
    }

    /// Is `ancestor` reachable from `descendant` through parent edges?
    pub fn is_ancestor(&self, ancestor: &Oid, descendant: &Oid) -> bool {
        let mut stack = vec![descendant.clone()];
        let mut seen = std::collections::BTreeSet::new();
        while let Some(id) = stack.pop() {
            if id == *ancestor {
                return true;
            }
            if seen.insert(id.clone()) {
                stack.extend(self.repo.parents_of(&id));
            }
        }
        false
    }

    /// Every change reachable from `seeds` (inclusive) through parent edges.
    pub fn ancestor_closure<'a>(
        &self,
        seeds: impl Iterator<Item = &'a Oid>,
    ) -> std::collections::BTreeSet<Oid> {
        let mut out = std::collections::BTreeSet::new();
        let mut stack: Vec<Oid> = seeds.cloned().collect();
        while let Some(id) = stack.pop() {
            if out.insert(id.clone()) {
                stack.extend(self.repo.parents_of(&id));
            }
        }
        out
    }

    /// Longest-path generation number per change (deterministic commit dates
    /// for the bridge: `BASE_EPOCH + generation`, ADR 0028).
    pub fn generations(&self) -> BTreeMap<Oid, u64> {
        let mut gen: BTreeMap<Oid, u64> = BTreeMap::new();
        for id in self.repo.change_ids_topo() {
            let g = self
                .repo
                .parents_of(&id)
                .iter()
                .filter_map(|p| gen.get(p))
                .max()
                .map(|m| m + 1)
                .unwrap_or(0);
            gen.insert(id, g);
        }
        gen
    }
}

/// One render-ready `log` row (R1): the per-change data with the author as a
/// pubkey — resolving it to a display name is the renderer's job.
pub struct HistoryRow {
    pub version: Oid,
    pub message: String,
    pub total: usize,
    pub restricted: usize,
    pub embargoed: usize,
    pub change_id: Option<[u8; 16]>,
    pub author: Option<[u8; 32]>,
    /// (attester pubkey, role) per attestation on this change.
    pub attestations: Vec<([u8; 32], String)>,
}

/// What `log` renders (R1). `graph: None` is the flat, newest-first listing in
/// `rows`; `Some` means heads sit on ≥2 distinct change lines (a real fork,
/// ADR 0029) and the fork view renders instead.
pub struct HistoryView {
    pub rows: Vec<HistoryRow>,
    pub divergent: std::collections::BTreeSet<[u8; 16]>,
    pub working: Option<WorkingRow>,
    pub graph: Option<GraphHistory>,
}

impl HistoryView {
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty() && self.graph.is_none() && self.working.is_none()
    }
}

/// The diverged-graph half of a [`HistoryView`]: each head's own lineage, then
/// the ancestry shared by more than one head.
pub struct GraphHistory {
    pub heads: Vec<Oid>,
    pub per_head: Vec<Vec<HistoryRow>>,
    pub shared: Vec<HistoryRow>,
}

/// A buoy resolution plus the trusted-but-absent attestations `--verbose`
/// reveals (CA4, ADR 0025).
pub struct BuoyResolution {
    pub result: loot_core::buoy::BuoyResult,
    /// Change ids named by trusted attestations for the role but absent from
    /// the local store (not candidates — you cannot build from what you do not
    /// hold).
    pub excluded: Vec<Oid>,
}

/// `.loot/config`'s `name = url` remote registry (ADR 0013), detached from the
/// Workspace surface as one small value (#177): resolve, add, remove, list.
/// The config is a shared repo-level fact with one writer (ADR 0034): lanes
/// read it, writes refuse from a lane — the guard lives here so every caller
/// gets it, not just the CLI.
pub struct Remotes {
    path: PathBuf,
    /// The registry id when this view of the config comes from a lane.
    lane: Option<String>,
}

impl Remotes {
    /// The URL for a named remote (e.g. "origin"), or `None` if unset.
    pub fn url(&self, name: &str) -> Option<String> {
        Config::load(&self.path).get(name)
    }

    /// Refuse a config write from a lane (ADR 0034: single-writer, the primary).
    fn ensure_primary(&self, verb: &str) -> Result<(), String> {
        match &self.lane {
            Some(id) => Err(format!(
                "{verb} must run from the primary directory — this is lane '{id}', \
                 and the shared config has one writer (ADR 0034)"
            )),
            None => Ok(()),
        }
    }

    /// Add or update a named remote.
    pub fn add(&self, name: &str, url: &str) -> Result<(), String> {
        self.ensure_primary("`loot remote add`")?;
        let mut cfg = Config::load(&self.path);
        cfg.set(name, url);
        cfg.save(&self.path)
    }

    /// Remove a named remote. No-ops if not present.
    pub fn remove(&self, name: &str) -> Result<(), String> {
        self.ensure_primary("`loot remote remove`")?;
        let mut cfg = Config::load(&self.path);
        cfg.remove(name);
        cfg.save(&self.path)
    }

    /// Every named remote, as `(name, url)` pairs.
    pub fn list(&self) -> Vec<(String, String)> {
        Config::load(&self.path).entries()
    }
}

/// One path's action when the bridge ingests a git commit (ADR 0028): new or
/// changed bytes seal fresh, an untouched path reuses its `(oid, visibility)`
/// (#98), a deleted path leaves the tree.
pub enum IngestAct {
    Put { bytes: Vec<u8>, vis: Visibility },
    Reuse { entry: (Oid, Visibility) },
    Remove,
}

/// The two global controls every snapshotting verb honors under implicit
/// auto-snapshot (ADR 0030): the demotion allowlist (#62) and the
/// `--no-snapshot`/`--ignore-working-copy` escape. The CLI parses its flags
/// into this; [`Workspace::snapshotted`] consumes it.
#[derive(Default)]
pub struct SnapshotOpts {
    /// Paths permitted to re-seal more readably on this snapshot.
    pub allow_demote: Vec<PathBuf>,
    /// Skip the implicit capture, acting on the last recorded working change.
    pub skip: bool,
}

/// Proof-of-capture handle for the snapshotting verbs (ADR 0030), constructed
/// only by [`Workspace::snapshotted`]. Mutation for those verbs lives here —
/// [`Snapshotted::mutate`] is `with_repo` gated behind the capture the handle
/// proves — so "forgot the implicit snapshot" is a compile error, not a silent
/// edit-drop (#182). Reads pass through via [`Snapshotted::ws`].
pub struct Snapshotted<'a> {
    ws: &'a mut Workspace,
}

impl Snapshotted<'_> {
    /// Read-only view of the workspace (`now`, `dot`, `repo`, remote
    /// resolution). Reads are not the hazard the handle exists for.
    pub fn ws(&self) -> &Workspace {
        self.ws
    }

    /// Run a closure that mutates the repo, then persist — the snapshotting
    /// verbs' `with_repo`, reachable only through the capture.
    pub fn mutate<T>(
        &mut self,
        f: impl FnOnce(&mut DagRepo) -> Result<T, String>,
    ) -> Result<T, String> {
        self.ws.with_repo(f)
    }

    /// Finalize (sign) a change this verb recorded — maroon's re-seal must be
    /// signed or it never travels (ADR 0018).
    pub fn sign_change(&mut self, change_id: &Oid) -> Result<(), String> {
        self.ws.sign_change(change_id)
    }

    /// Record the verb in the op log (after its persist, ADR 0031).
    pub fn record_op(&self, command: &str, description: &str, barrier: bool) {
        self.ws.record_op(command, description, barrier);
    }
}

/// The live working-change row `status`/`log` render (ADR 0030). `change_id` is
/// the durable handle (`None` only for a keyless/legacy working change);
/// `version` is the live, non-durable content fingerprint; `empty` is true when
/// the working tree has no delta over the tip, so callers show `—` for the
/// version and omit the per-path listing.
pub struct WorkingRow {
    pub change_id: Option<[u8; 16]>,
    pub version: Oid,
    pub message: String,
    pub entries: Vec<(PathBuf, Visibility)>,
    pub empty: bool,
}

impl WorkingRow {
    /// The working version as full hex — the form the `wip` ledger stores, so
    /// the loot-first review-currency guard (ADR 0033) compares like with like
    /// without reaching into the `Oid` newtype at the call site.
    pub fn version_hex(&self) -> String {
        loot_core::hex::encode(&self.version.0)
    }
}

/// What `loot edit` did, for CLI reporting (ADR 0032).
#[derive(Debug)]
pub struct EditReport {
    /// The durable handle the reopened change keeps.
    pub change_id: [u8; 16],
    /// The finalized version that was reopened — superseded when the amend
    /// finalizes (`loot new`).
    pub superseded: Oid,
}

/// What `loot adopt <version>` did, for CLI reporting (#244).
#[derive(Debug)]
pub struct AdoptReport {
    /// The landed change the dock now sits on.
    pub target: Oid,
    /// The competing heads (the discarded divergent line) abandoned to settle.
    pub abandoned: Vec<Oid>,
    /// Whether a live working change or uncaptured disk edits were dropped
    /// (`--discard-wip`).
    pub discarded_wip: bool,
    /// The dock was already on `target` with a clean tree — a no-op with a note.
    pub already_there: bool,
}

/// The outcome of a pull (#219). Carries the folded per-path merge outcomes,
/// plus the working change id when capture-first *deferred* convergence — a
/// dirty tree was captured and the working-change guard left the freshly
/// ingested heads flat for this pass. `deferred: None` is the ordinary
/// converged pull; `Some(id)` is the CLI's cue to print the "finalize then
/// re-run" note (ADR 0030 amendment).
#[derive(Debug)]
pub struct PullReport {
    /// The folded per-path merge outcomes, for rendering the verdict rows.
    pub outcomes: BTreeMap<PathBuf, MergeOutcome>,
    /// The captured working change id when converge was deferred, else `None`.
    pub deferred: Option<Oid>,
}

/// What a completed `undo`/`op restore` did, for CLI reporting (ADR 0031).
#[derive(Debug)]
pub struct StepReport {
    /// Its human description (e.g. `undid op 7 (new)`).
    pub description: String,
    /// The 1-based ordinal of the op whose view is now current.
    pub restored_to: u32,
    /// The change-graph heads the view now sits on.
    pub heads: Vec<Oid>,
    /// The working change now in progress, if any.
    pub working: Option<Oid>,
}

/// Flatten an [`oplog::StepError`] into a CLI message. A barrier refusal is
/// expanded into the "why + real remedy" prose ADR 0031 mandates.
fn step_error(e: oplog::StepError) -> String {
    match e {
        oplog::StepError::Nothing(m) | oplog::StepError::Io(m) => m,
        oplog::StepError::Barrier(b) => barrier_message(&b),
    }
}

/// The refusal `undo` prints at a one-way barrier: it names the op, states *why*
/// the act cannot be retracted, and points at the real remedy (ADR 0031). The
/// keyring/manifest/escrow are never touched by undo, so the guidance is always
/// "reverse it forward," never "undo it."
fn barrier_message(b: &oplog::BarrierRefusal) -> String {
    let remedy = match b.command.as_str() {
        "push" => "a push discloses; it cannot be retracted by undo. to reverse a \
                   published change, record a new change or `loot maroon` the path.",
        "grant" => "a grant hands a content key to a peer; undo cannot recall it. to cut \
                    off access going forward, `loot maroon` the path from that identity.",
        "maroon" => "a maroon is an audited, one-way revocation; undo cannot reinstate a \
                     key. re-grant explicitly to restore access.",
        "pull-grants" => "pull-grants filed keys into your keyring; undo only moves view \
                          pointers, never keys, so there is nothing for it to reverse.",
        _ => "this operation changed permission or key state that undo cannot retract.",
    };
    format!(
        "refusing to undo across a barrier (op {}, {}).\n      {remedy}",
        b.index, b.description
    )
}

/// A dock's summary for `loot docks`: its head change, visibility counts
/// `(total, restricted, embargoed)`, and whether it's the ambient dock.
pub struct DockInfo {
    pub name: String,
    pub head: Option<Oid>,
    pub visibility: Option<(usize, usize, usize)>,
    pub current: bool,
}

/// The workspace clock (unix seconds). `LOOT_CLOCK` overrides it when set —
/// deliberately: the client clock is an input the embargo design must survive
/// (the relay never reads it; there is no clock field on the wire, ADR 0027),
/// so letting a holder lie with it is not a weakening but the attack demo's
/// first exhibit (#89). Everything a lying clock gates locally (Escrow flush,
/// embargo checks in `open`) fails anyway for lack of key bytes.
fn real_now() -> u64 {
    if let Ok(fake) = std::env::var("LOOT_CLOCK") {
        if let Ok(t) = fake.parse() {
            return t;
        }
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn read_to_string(path: &Path) -> Result<String, String> {
    String::from_utf8(std::fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

/// A short hex prefix of a version id, for operation-log descriptions.
fn short_version(id: &Oid) -> String {
    loot_core::hex::encode(&id.0).chars().take(8).collect()
}

/// Read a working tree + its `.lootattributes` into engine entries `(path,
/// bytes, vis)` plus a sorted `(path, vis)` report — the shared front half of a
/// snapshot and of the read-only `status`/`log`/`lanes` previews. A free
/// function (not a method) because `lane_statuses` walks *another* position's
/// tree with a repo loaded from that lane's store. Reads only, bar an
/// in-memory escrow flush: embargoed keys whose reveal time has passed are
/// promoted before reading content, so `sealed::open` finds them in the
/// Keyring (ADR 0007).
fn read_tree_at(
    repo: &mut DagRepo,
    root: &Path,
    now: u64,
) -> Result<(Vec<(PathBuf, Vec<u8>, Visibility)>, Vec<(PathBuf, Visibility)>), String> {
    repo.flush_escrow(now);
    let attrs = Attributes::load(&root.join(ATTRS));
    let ignore = Ignore::load(&root.join(IGNORE));
    let mut entries: Vec<(PathBuf, Vec<u8>, Visibility)> = Vec::new();
    let mut reported: Vec<(PathBuf, Visibility)> = Vec::new();
    for path in walk(root, &ignore)? {
        // Store paths relative to the repo root so tree keys are stable
        // regardless of whether the root is "." (the CLI) or an absolute dir
        // (tests, `clone` into a path). Fall back to stripping a leading "./".
        let rel = path
            .strip_prefix(root)
            .or_else(|_| path.strip_prefix("./"))
            .unwrap_or(&path)
            .to_path_buf();
        let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let vis = attrs.visibility_for(&rel.to_string_lossy());
        reported.push((rel.clone(), vis.clone()));
        entries.push((rel, bytes, vis));
    }
    reported.sort_by(|a, b| a.0.cmp(&b.0));
    Ok((entries, reported))
}

/// Recursively list files under `dir`, skipping `.loot/`, `.git`, and paths
/// matched by `.lootignore` (#64). Ignored directories are pruned without
/// descending, so an ignored `target/` is never read — the pilot's 38 MB
/// mis-seal cost nothing but a glob match.
/// `.lootattributes` is deliberately included (#62): the policy is versioned
/// like any file so it travels to peers and clones — a fresh keyholder clone
/// without the rules would silently re-seal restricted content Public.
fn walk(dir: &Path, ignore: &Ignore) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d).map_err(|e| format!("read_dir {}: {e}", d.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == DOT || name == ".git" {
                continue;
            }
            let rel = path.strip_prefix(dir).unwrap_or(&path).to_string_lossy().to_string();
            if path.is_dir() {
                if !ignore.ignores_dir(&rel) {
                    stack.push(path);
                }
            } else if !ignore.ignores_file(&rel) {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Parsed `.lootignore` (#64): ordered globs excluding paths from snapshot,
/// in the same dialect as `.lootattributes` (full relative path, `*` stops at
/// `/`, `**` crosses it — see `Glob`). A trailing `/` ignores the whole
/// subtree (`target/` ≡ `target/**`). One pattern per line; `#` comments.
///
/// Semantics: an ignored path simply isn't part of the tree the engine
/// reconciles — if it was previously snapshotted and is readable, the next
/// snapshot records its deletion (which is the remedy for a mis-sealed
/// `target/`: add the ignore line, run `loot status`, the working change
/// drops it). The policy files themselves (`.lootattributes`, `.lootignore`)
/// are never ignorable — like #62, policy must stay versioned and travel.
struct Ignore {
    globs: Vec<Glob>,
}

impl Ignore {
    fn load(path: &Path) -> Self {
        Self::parse(&std::fs::read_to_string(path).unwrap_or_default())
    }

    fn parse(text: &str) -> Self {
        let mut globs = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(subtree) = line.strip_suffix('/') {
                globs.push(Glob::new(&format!("{subtree}/**")));
            } else {
                globs.push(Glob::new(line));
            }
        }
        Ignore { globs }
    }

    fn ignores_file(&self, rel: &str) -> bool {
        let unix = rel.replace('\\', "/");
        if unix == ATTRS || unix == IGNORE {
            return false;
        }
        self.globs.iter().any(|g| g.matches(&unix))
    }

    /// A directory is pruned when every possible descendant is ignored. That
    /// is provable only for subtree globs (`…/**`): strip the suffix and match
    /// the prefix against the dir. File globs (`target/*.o`) never prune —
    /// deeper non-matching descendants may exist — their files are still
    /// excluded one-by-one in `ignores_file`.
    fn ignores_dir(&self, rel: &str) -> bool {
        let unix = rel.replace('\\', "/");
        self.globs
            .iter()
            .any(|g| g.pattern.strip_suffix("/**").is_some_and(|prefix| glob_match(prefix, &unix)))
    }
}

/// Parsed `.lootattributes`: ordered (glob, visibility) rules. First match wins;
/// unmatched paths default to Public.
struct Attributes {
    rules: Vec<(Glob, Visibility)>,
}

impl Attributes {
    fn load(path: &Path) -> Self {
        Self::parse(&std::fs::read_to_string(path).unwrap_or_default())
    }

    fn parse(text: &str) -> Self {
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
/// Patterns and paths are both normalized to `/` before matching — snapshot
/// hands over OS-native paths (`docs\private\x` on Windows), and a portable
/// rule like `docs/private/*` that silently fails to match seals content
/// **Public**: fail-open, the worst failure mode for a privacy-first VCS (#61).
struct Glob {
    pattern: String,
}

impl Glob {
    fn new(pattern: &str) -> Self {
        Glob { pattern: pattern.replace('\\', "/") }
    }
    fn matches(&self, path: &str) -> bool {
        glob_match(&self.pattern, &path.replace('\\', "/"))
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

    /// An authored workspace at `dir` with a generated keypair, so its changes
    /// carry a durable change id (S2/ADR 0029) — `init_at` alone stays keyless.
    fn authored_ws(dir: &Path) -> Workspace {
        let _ = std::fs::remove_dir_all(dir);
        Workspace::init_at(dir, "connor").unwrap();
        loot_identity::generate_and_save(&dir.join(DOT), "connor@loot").unwrap();
        let mut ws = Workspace::open_at(dir).unwrap();
        ws.start_fresh_change().unwrap();
        ws
    }

    #[test]
    fn new_mints_next_handle_and_first_snapshot_carries_it() {
        let dir = std::env::temp_dir().join(format!("loot-s2-new-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        // `init`/`start_fresh_change` eagerly minted the first change's handle.
        let first = ws.next_change_id();
        assert!(first.is_some(), "authored repo mints the first handle");

        std::fs::write(dir.join("a.txt"), b"one").unwrap();
        ws.snapshot("m").unwrap();
        let working = ws.working_id().cloned().unwrap();
        assert_eq!(
            ws.repo().change_change_id(&working),
            first,
            "the first snapshot carries the eagerly-minted handle onto the change"
        );
        assert!(ws.next_change_id().is_none(), "handle is consumed once recorded");

        // Finalize (`new`) signs and mints a *fresh* next handle.
        ws.finalize_working().unwrap();
        let next = ws.next_change_id();
        assert!(next.is_some() && next != first, "new mints a fresh next handle");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn live_working_row_never_advances_the_graph() {
        let dir = std::env::temp_dir().join(format!("loot-s2-ro-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        std::fs::write(dir.join("a.txt"), b"one").unwrap();
        ws.snapshot("m").unwrap();
        ws.finalize_working().unwrap(); // working -> tip; a fresh handle is pending

        let heads_before = ws.repo().heads();
        let nodes_before = ws.repo().log_detailed().len();

        // An on-disk edit with no mutating verb: the read-only row reports the
        // pending delta live, but records nothing.
        std::fs::write(dir.join("a.txt"), b"changed").unwrap();
        let row = ws.live_working_row().unwrap().expect("a pending working change");
        assert!(!row.empty, "an un-snapshotted edit is a pending delta");
        assert_eq!(ws.repo().heads(), heads_before, "status/log never advance heads");
        assert_eq!(ws.repo().log_detailed().len(), nodes_before, "no node is recorded");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn undo_walks_the_view_back_and_prunes_disk() {
        let dir = std::env::temp_dir().join(format!("loot-s4-undo-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        ws.record_op("init", "init", false); // op 1

        // op 2: record a.txt and finalize it as a signed change.
        std::fs::write(dir.join("a.txt"), b"one").unwrap();
        ws.snapshot("first").unwrap();
        ws.finalize_working().unwrap();
        ws.record_op("new", "finalize a", false);

        // op 3: add b.txt and finalize.
        std::fs::write(dir.join("b.txt"), b"two").unwrap();
        ws.snapshot("second").unwrap();
        ws.finalize_working().unwrap();
        ws.record_op("new", "finalize b", false);
        assert!(dir.join("b.txt").exists());

        // Undo op 3: the view returns to op 2 and the working tree is
        // re-materialized — b.txt pruned, a.txt kept.
        let r = ws.undo().unwrap();
        assert_eq!(r.restored_to, 2);
        assert!(!dir.join("b.txt").exists(), "undo prunes the file the reverted op added");
        assert!(dir.join("a.txt").exists(), "the earlier file survives");

        // The oplog grew (undo is itself an op), so redo has a landing spot.
        assert_eq!(ws.op_log().unwrap().len(), 4, "undo appends a compensating op");

        // Nothing was deleted: redoing forward to op 3 recovers the "b" change
        // in full — undo only ever moved pointers over an append-only graph.
        let redo = ws.restore_op(3).unwrap();
        assert_eq!(redo.restored_to, 3);
        assert_eq!(std::fs::read(dir.join("b.txt")).unwrap(), b"two", "redo restores the change");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn abandon_collapses_a_divergent_change_and_is_undoable() {
        use loot_core::{Change, Oid};
        let dir = std::env::temp_dir().join(format!("loot-s3-abandon-{}", std::process::id()));
        let mut ws = authored_ws(&dir);

        // Seed a divergent change: record one finalized root, then two versions
        // carrying the SAME change id on independent lines (the amend primitive,
        // ADR 0029). Both become live heads under one change id.
        let cid = [7u8; 16];
        let (va, vb) = ws
            .with_repo(|repo| {
                let root = repo
                    .record(Change {
                        id: Oid([0; 32]),
                        parents: vec![],
                        message: "root".into(),
                        tree: Default::default(),
                    })
                    .map_err(|e| e.to_string())?;
                let va = repo
                    .record_carrying(
                        Change { id: Oid([0; 32]), parents: vec![root.clone()], message: "A".into(), tree: Default::default() },
                        Some(cid),
                    )
                    .map_err(|e| e.to_string())?;
                let vb = repo
                    .record_carrying(
                        Change { id: Oid([0; 32]), parents: vec![root], message: "B".into(), tree: Default::default() },
                        Some(cid),
                    )
                    .map_err(|e| e.to_string())?;
                Ok((va, vb))
            })
            .unwrap();
        // Record the pre-abandon (divergent) view as the undo floor.
        ws.record_op("seed", "seeded divergence", false);

        assert!(ws.divergent_change_ids().contains(&cid), "the change is divergent");

        // Abandon vb: divergence collapses, and it is one op in the log.
        ws.abandon(&vb).unwrap();
        assert!(!ws.divergent_change_ids().contains(&cid), "abandon collapsed the fork");
        assert!(ws.store().read_abandoned().contains(&vb));
        assert!(!ws.repo().heads().contains(&vb), "vb stopped being a live head");
        assert!(ws.repo().heads().contains(&va), "va survives");

        // Undo restores the divergent state — nothing was deleted.
        let r = ws.undo().unwrap();
        let _ = r;
        assert!(ws.divergent_change_ids().contains(&cid), "undo brought the version back");
        assert!(!ws.store().read_abandoned().contains(&vb), "undo cleared the abandoned mark");
        assert!(ws.repo().heads().contains(&vb), "vb is a live head again");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn abandon_refuses_a_non_divergent_change() {
        use loot_core::{Change, Oid};
        let dir = std::env::temp_dir().join(format!("loot-s3-refuse-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        let only = ws
            .with_repo(|repo| {
                repo.record_carrying(
                    Change { id: Oid([0; 32]), parents: vec![], message: "solo".into(), tree: Default::default() },
                    Some([1u8; 16]),
                )
                .map_err(|e| e.to_string())
            })
            .unwrap();
        // A change with a single version is not divergent — abandon must refuse
        // rather than hide the change's only version.
        let err = ws.abandon(&only).unwrap_err();
        assert!(err.contains("not divergent"), "message explains the refusal: {err}");
        assert!(ws.store().read_abandoned().is_empty(), "nothing was abandoned");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn abandon_head_drops_a_fork_and_is_undoable() {
        use loot_core::{Change, Oid};
        let dir = std::env::temp_dir().join(format!("loot-243-forkdrop-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        // Two INDEPENDENT heads off one root — distinct change ids, so this is a
        // fork, not a divergent change. `loot abandon` refuses them (each is the
        // sole version of its change id); `--head` is the tool that drops one.
        let (a, b) = ws
            .with_repo(|repo| {
                let root = repo
                    .record(Change { id: Oid([0; 32]), parents: vec![], message: "root".into(), tree: Default::default() })
                    .map_err(|e| e.to_string())?;
                let a = repo
                    .record_carrying(
                        Change { id: Oid([0; 32]), parents: vec![root.clone()], message: "A".into(), tree: Default::default() },
                        Some([1u8; 16]),
                    )
                    .map_err(|e| e.to_string())?;
                let b = repo
                    .record_carrying(
                        Change { id: Oid([0; 32]), parents: vec![root], message: "B".into(), tree: Default::default() },
                        Some([2u8; 16]),
                    )
                    .map_err(|e| e.to_string())?;
                Ok((a, b))
            })
            .unwrap();
        ws.record_op("seed", "seeded a fork", false);

        assert!(ws.repo().heads().contains(&a) && ws.repo().heads().contains(&b), "two live heads");
        // Not divergent → plain abandon refuses; this is exactly the gap.
        assert!(ws.abandon(&b).is_err(), "abandon refuses a non-divergent fork head");

        ws.abandon_fork(&b).unwrap();
        assert!(ws.store().read_abandoned().contains(&b), "b recorded abandoned");
        assert!(!ws.repo().heads().contains(&b), "b stopped being a live head");
        assert!(ws.repo().heads().contains(&a), "a survives as the live line");

        // Undoable: nothing is deleted, the abandoned mark clears (append-only graph).
        ws.undo().unwrap();
        assert!(!ws.store().read_abandoned().contains(&b), "undo cleared the mark");
        assert!(ws.repo().heads().contains(&b), "b is a live head again");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn abandon_head_refuses_non_head_and_last_head() {
        use loot_core::{Change, Oid};
        let dir = std::env::temp_dir().join(format!("loot-243-forkguard-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        let (root, only) = ws
            .with_repo(|repo| {
                let root = repo
                    .record(Change { id: Oid([0; 32]), parents: vec![], message: "root".into(), tree: Default::default() })
                    .map_err(|e| e.to_string())?;
                let only = repo
                    .record_carrying(
                        Change { id: Oid([0; 32]), parents: vec![root.clone()], message: "only".into(), tree: Default::default() },
                        Some([1u8; 16]),
                    )
                    .map_err(|e| e.to_string())?;
                Ok((root, only))
            })
            .unwrap();
        ws.record_op("seed", "seeded", false);
        // The root is not a head (`only` descends from it) → refuse.
        let err = ws.abandon_fork(&root).unwrap_err();
        assert!(err.contains("not a live head"), "{err}");
        // The sole live head is refused — never empty the dock.
        let err = ws.abandon_fork(&only).unwrap_err();
        assert!(err.contains("only live head"), "{err}");
        assert!(ws.store().read_abandoned().is_empty(), "nothing was abandoned");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- loot adopt <version> (#244) ---

    /// Seed the local ferry spine so `change` reads as the loot change the git
    /// mirror's `main` projects (the §4 harbor-lineage fence's oracle): a mark
    /// map entry `sha -> change` and a `state` naming `sha` as `git-main`.
    fn seed_mirror_main(ws: &Workspace, sha: &str, change: &loot_core::Oid) {
        use loot_core::bridge::{FerryState, MarkMap, MarkOrigin};
        std::fs::create_dir_all(ws.store().git_mirror_dir()).unwrap();
        let mut marks = MarkMap::new();
        marks.insert(sha.to_string(), change.clone(), MarkOrigin::Git);
        std::fs::write(ws.store().git_marks(), marks.encode()).unwrap();
        let state = FerryState { git_main: Some(sha.to_string()), loot_heads: vec![] };
        std::fs::write(ws.store().git_state(), state.encode()).unwrap();
    }

    /// Seed a two-head fork off one root — `a` and `b`, distinct change ids, each
    /// the sole version of its id (independent lines, not a divergent change).
    fn seed_fork(ws: &mut Workspace) -> (loot_core::Oid, loot_core::Oid) {
        use loot_core::{Change, Oid};
        let (a, b) = ws
            .with_repo(|repo| {
                let root = repo
                    .record(Change { id: Oid([0; 32]), parents: vec![], message: "root".into(), tree: Default::default() })
                    .map_err(|e| e.to_string())?;
                let a = repo
                    .record_carrying(
                        Change { id: Oid([0; 32]), parents: vec![root.clone()], message: "A".into(), tree: Default::default() },
                        Some([1u8; 16]),
                    )
                    .map_err(|e| e.to_string())?;
                let b = repo
                    .record_carrying(
                        Change { id: Oid([0; 32]), parents: vec![root], message: "B".into(), tree: Default::default() },
                        Some([2u8; 16]),
                    )
                    .map_err(|e| e.to_string())?;
                Ok((a, b))
            })
            .unwrap();
        ws.record_op("seed", "seeded a fork", false);
        (a, b)
    }

    #[test]
    fn adopt_settles_on_target_and_abandons_forks() {
        let dir = std::env::temp_dir().join(format!("loot-244-settle-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        let (a, b) = seed_fork(&mut ws);
        // Mirror main projects `a`: it is on the harbor lineage, `b` a fork off it.
        seed_mirror_main(&ws, &"a".repeat(40), &a);

        let a_hex = loot_core::hex::encode(&a.0);
        let report = ws.adopt(&a_hex, false).unwrap();
        assert_eq!(report.target, a, "settled on the target");
        assert!(report.abandoned.contains(&b), "the fork is the discarded line");
        assert_eq!(ws.repo().heads(), vec![a.clone()], "a is the sole live head — no merge");
        assert!(ws.store().read_abandoned().contains(&b), "b joined the abandoned set");

        // Undoable: nothing deleted, both heads live again (append-only graph).
        ws.undo().unwrap();
        let heads = ws.repo().heads();
        assert!(heads.contains(&a) && heads.contains(&b), "undo restores both heads");
        assert!(!ws.store().read_abandoned().contains(&b), "undo cleared the mark");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn adopt_refuses_dirty_without_discard() {
        let dir = std::env::temp_dir().join(format!("loot-244-dirty-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        let (a, _b) = seed_fork(&mut ws);
        seed_mirror_main(&ws, &"a".repeat(40), &a);
        // An uncaptured disk edit is work adopt would silently eat → refuse.
        std::fs::write(dir.join("dirty.txt"), b"uncaptured").unwrap();

        let a_hex = loot_core::hex::encode(&a.0);
        let err = ws.adopt(&a_hex, false).unwrap_err();
        assert!(err.contains("discard-wip"), "message names the remedy: {err}");
        assert!(ws.store().read_abandoned().is_empty(), "nothing was abandoned");
        assert!(dir.join("dirty.txt").exists(), "the edit was left intact");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn adopt_discard_wip_drops_the_working_change() {
        let dir = std::env::temp_dir().join(format!("loot-244-discard-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        let (a, _b) = seed_fork(&mut ws);
        seed_mirror_main(&ws, &"a".repeat(40), &a);
        // A live working change on top of the fork.
        std::fs::write(dir.join("wip.txt"), b"wip").unwrap();
        ws.snapshot("wip").unwrap();
        assert!(ws.working_id().is_some(), "a working change is in progress");

        let a_hex = loot_core::hex::encode(&a.0);
        let report = ws.adopt(&a_hex, true).unwrap();
        assert!(report.discarded_wip, "the WIP was discarded");
        assert!(ws.working_id().is_none(), "the working change was dropped");
        assert_eq!(ws.repo().heads(), vec![a.clone()], "settled on the target");
        assert!(!dir.join("wip.txt").exists(), "the target tree materialized over the WIP file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn adopt_refuses_a_non_lineage_target() {
        let dir = std::env::temp_dir().join(format!("loot-244-nolineage-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        let (a, b) = seed_fork(&mut ws);
        // Mirror main projects `a`; `b` is a signed change off the lineage.
        seed_mirror_main(&ws, &"a".repeat(40), &a);

        let b_hex = loot_core::hex::encode(&b.0);
        let err = ws.adopt(&b_hex, false).unwrap_err();
        assert!(err.contains("lineage"), "refuses an off-lineage target: {err}");
        assert!(ws.store().read_abandoned().is_empty(), "nothing was abandoned");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn adopt_refuses_an_unsigned_target() {
        let dir = std::env::temp_dir().join(format!("loot-244-unsigned-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        // The only unsigned thing that could be pointed at is the working change.
        std::fs::write(dir.join("w.txt"), b"w").unwrap();
        ws.snapshot("wip").unwrap();
        let w = ws.working_id().cloned().unwrap();

        let w_hex = loot_core::hex::encode(&w.0);
        let err = ws.adopt(&w_hex, false).unwrap_err();
        assert!(err.contains("working change"), "refuses adopting onto WIP: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn adopt_walks_a_merge_over_a_stale_fork_down_to_the_landed_change() {
        // The §6 shape: a re-ferry produced a transient MERGE head folding the
        // landed line `e` with a stale two-commit fork. Adopting `e` must walk the
        // *whole* divergent line — the merge and both stale commits — into the
        // abandoned set (the merge resurfaces its parents, so one pass is not
        // enough), leaving `e` the sole clean head: no merge, no resurrection.
        use loot_core::{Change, Oid};
        let dir = std::env::temp_dir().join(format!("loot-244-walk-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        let (e, s1, s2, m) = ws
            .with_repo(|repo| {
                let root = repo
                    .record(Change { id: Oid([0; 32]), parents: vec![], message: "root".into(), tree: Default::default() })
                    .map_err(|err| err.to_string())?;
                let e = repo
                    .record_carrying(
                        Change { id: Oid([0; 32]), parents: vec![root.clone()], message: "landed E".into(), tree: Default::default() },
                        Some([9u8; 16]),
                    )
                    .map_err(|err| err.to_string())?;
                let s1 = repo
                    .record_carrying(
                        Change { id: Oid([0; 32]), parents: vec![root], message: "stale S1".into(), tree: Default::default() },
                        Some([3u8; 16]),
                    )
                    .map_err(|err| err.to_string())?;
                let s2 = repo
                    .record_carrying(
                        Change { id: Oid([0; 32]), parents: vec![s1.clone()], message: "stale S2".into(), tree: Default::default() },
                        Some([4u8; 16]),
                    )
                    .map_err(|err| err.to_string())?;
                let m = repo
                    .record_carrying(
                        Change { id: Oid([0; 32]), parents: vec![e.clone(), s2.clone()], message: "ferry merge".into(), tree: Default::default() },
                        Some([7u8; 16]),
                    )
                    .map_err(|err| err.to_string())?;
                Ok((e, s1, s2, m))
            })
            .unwrap();
        ws.record_op("seed", "seeded a merge over a stale fork", false);
        assert_eq!(ws.repo().heads(), vec![m.clone()], "the merge is the only head after ferry");
        seed_mirror_main(&ws, &"e".repeat(40), &e);

        let e_hex = loot_core::hex::encode(&e.0);
        let report = ws.adopt(&e_hex, false).unwrap();
        assert_eq!(ws.repo().heads(), vec![e.clone()], "e is the sole clean head — no merge survives");
        let abandoned = ws.store().read_abandoned();
        for (name, v) in [("merge", &m), ("stale S2", &s2), ("stale S1", &s1)] {
            assert!(abandoned.contains(v), "{name} was walked into the abandoned set");
        }
        assert_eq!(report.abandoned.len(), 3, "the whole divergent line was discarded");

        // One op, fully undoable: the merge head is live again.
        ws.undo().unwrap();
        assert_eq!(ws.repo().heads(), vec![m.clone()], "undo restores the pre-adopt view");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn adopt_settles_a_dock_so_a_re_ferry_projects_nothing() {
        // The §6 payoff, end-to-end over a real mirror: once adopt settles the
        // dock exactly on the change git-main projects, a re-ferry ingests
        // nothing and — crucially — **projects nothing** (the §6.4/§6.5 "projects
        // nothing … Nothing reached GitHub" guarantee, upheld by the #195/#201
        // no-backward-projection guards). Here the dock had drifted *ahead* of
        // main (a divergent local line); adopting main's change discards it, and
        // the subsequent ferry is a genuine no-op on the git side.
        let base = std::env::temp_dir().join(format!("loot-244-noproj-{}", std::process::id()));
        let dir = base.join("repo");
        let mirror = base.join("mirror.git");
        let mut ws = authored_ws(&dir);

        // c1: the landed change. Ferry projects it and writes the spine.
        std::fs::write(dir.join("a.txt"), b"one").unwrap();
        ws.snapshot("c1").unwrap();
        ws.finalize_working().unwrap();
        let c1 = ws.repo().heads()[0].clone();
        let r1 = crate::ferry::run(&mut ws, Some(mirror.to_str().unwrap()), None, false).unwrap();
        assert_eq!(r1.projected, 1, "c1 projects to git-main");

        // Drift the dock ahead of main with a divergent c2.
        std::fs::write(dir.join("a.txt"), b"two").unwrap();
        ws.snapshot("c2").unwrap();
        ws.finalize_working().unwrap();
        assert_ne!(ws.repo().heads(), vec![c1.clone()], "the dock has moved off main");

        // Adopt main's change: the dock settles back on c1, discarding c2.
        let c1_hex = loot_core::hex::encode(&c1.0);
        let report = ws.adopt(&c1_hex, false).unwrap();
        assert_eq!(report.target, c1);
        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"one", "disk materialized to c1");

        // The re-ferry is a no-op on the git side: nothing to ingest, and c1 is
        // already main, so nothing projects backward.
        let r2 = crate::ferry::run(&mut ws, None, None, false).unwrap();
        assert_eq!(r2.ingested, 0, "no git-native commits to ingest");
        assert_eq!(r2.projected, 0, "the dock is on main — nothing projects (§6.5)");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn undo_refuses_to_cross_a_barrier_op() {
        let dir = std::env::temp_dir().join(format!("loot-s4-barrier-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        std::fs::write(dir.join("a.txt"), b"one").unwrap();
        ws.snapshot("first").unwrap();
        ws.finalize_working().unwrap();
        ws.record_op("new", "finalize a", false); // op 1
        ws.record_op("push", "push → origin", true); // op 2 — a barrier

        let err = ws.undo().unwrap_err();
        assert!(err.contains("barrier"), "message names the barrier: {err}");
        assert!(err.contains("push"), "message names the offending op: {err}");
        assert_eq!(ws.op_log().unwrap().len(), 2, "a refused undo appends no op");
        let _ = std::fs::remove_dir_all(&dir);
    }

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
    fn glob_normalizes_separators_both_ways() {
        // #61: portable `/` rules must match OS-native `\` paths — a rule that
        // silently matches nothing seals content Public (fail-open).
        assert!(Glob::new("docs/private/*").matches(r"docs\private\secrets.md"));
        assert!(Glob::new("secrets/**").matches(r"secrets\a\b.txt"));
        // The non-portable backslash spelling keeps working.
        assert!(Glob::new(r"docs\private\*").matches("docs/private/secrets.md"));
        // `*` must not leak across a `\` separator any more than a `/` one.
        assert!(!Glob::new("*.md").matches(r"docs\x.md"));
    }

    #[test]
    fn snapshot_seals_forward_slash_rule_in_subdir() {
        // End-to-end #61 reproduction: on Windows, snapshot's relative paths are
        // backslash-native; the portable rule must still seal the file.
        let dir = std::env::temp_dir().join(format!("loot-attrs-sep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Workspace::init_at(&dir, "connor").unwrap();
        std::fs::create_dir_all(dir.join("docs/private")).unwrap();
        std::fs::write(dir.join("docs/private/secret.md"), b"sealed?").unwrap();
        std::fs::write(dir.join(".lootattributes"), "docs/private/* restricted=connor\n").unwrap();

        let mut ws = Workspace::open_at(&dir).unwrap();
        let (_, reported) = ws.snapshot("").unwrap();
        let vis = reported
            .iter()
            .find(|(p, _)| p.ends_with("secret.md"))
            .map(|(_, v)| v.clone())
            .expect("secret.md snapshotted");
        assert!(
            matches!(vis, Visibility::Restricted(ref ids) if *ids == ["connor"]),
            "docs/private/* must seal OS-native paths, got {vis:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lootignore_excludes_subtree_and_never_reads_it() {
        // #64 (pilot finding 4): one `status` with target/ present sealed
        // 301 files / 38 MB into the working change.
        let dir = std::env::temp_dir().join(format!("loot-ignore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Workspace::init_at(&dir, "connor").unwrap();
        std::fs::create_dir_all(dir.join("target/debug")).unwrap();
        std::fs::write(dir.join("target/debug/junk.o"), b"38MB of regret").unwrap();
        std::fs::write(dir.join("src.rs"), b"fn main() {}").unwrap();
        std::fs::write(dir.join(".lootignore"), "# build output\ntarget/\n").unwrap();

        let mut ws = Workspace::open_at(&dir).unwrap();
        let (_, reported) = ws.snapshot("").unwrap();
        assert!(
            !reported.iter().any(|(p, _)| p.to_string_lossy().contains("target")),
            "ignored subtree must not be snapshotted: {reported:?}"
        );
        assert!(reported.iter().any(|(p, _)| p.ends_with("src.rs")));
        // The ignore policy itself is versioned, like .lootattributes (#62).
        assert!(
            reported.iter().any(|(p, _)| p.ends_with(".lootignore")),
            ".lootignore must be snapshotted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lootignore_drops_previously_tracked_path() {
        // The pilot remedy: after a mis-seal, add the ignore line and re-run
        // `status` — the (still-working) change must drop the path.
        let dir = std::env::temp_dir().join(format!("loot-ignore2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Workspace::init_at(&dir, "connor").unwrap();
        std::fs::write(dir.join("junk.log"), b"oops").unwrap();
        std::fs::write(dir.join("keep.rs"), b"fn main() {}").unwrap();

        let mut ws = Workspace::open_at(&dir).unwrap();
        let (_, reported) = ws.snapshot("mis-seal").unwrap();
        assert!(reported.iter().any(|(p, _)| p.ends_with("junk.log")));

        std::fs::write(dir.join(".lootignore"), "*.log\n").unwrap();
        let mut ws = Workspace::open_at(&dir).unwrap();
        let (_, reported) = ws.snapshot("remedied").unwrap();
        assert!(
            !reported.iter().any(|(p, _)| p.ends_with("junk.log")),
            "ignored path must leave the working change: {reported:?}"
        );
        assert!(reported.iter().any(|(p, _)| p.ends_with("keep.rs")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lootignore_cannot_ignore_policy_files() {
        // Ignoring the policy files would strand peers without the rules —
        // the same fail-open shape #62 closed for attributes edits.
        let dir = std::env::temp_dir().join(format!("loot-ignore3-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Workspace::init_at(&dir, "connor").unwrap();
        std::fs::write(dir.join(".lootattributes"), "# empty\n").unwrap();
        std::fs::write(dir.join(".lootignore"), ".lootattributes\n.lootignore\n.loot*\n").unwrap();

        let mut ws = Workspace::open_at(&dir).unwrap();
        let (_, reported) = ws.snapshot("").unwrap();
        assert!(reported.iter().any(|(p, _)| p.ends_with(".lootattributes")));
        assert!(reported.iter().any(|(p, _)| p.ends_with(".lootignore")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lootignore_nested_subtree_rule_prunes_any_depth() {
        let dir = std::env::temp_dir().join(format!("loot-ignore4-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Workspace::init_at(&dir, "connor").unwrap();
        std::fs::create_dir_all(dir.join("crates/a/target/debug")).unwrap();
        std::fs::write(dir.join("crates/a/target/debug/x.o"), b"junk").unwrap();
        std::fs::create_dir_all(dir.join("crates/a/src")).unwrap();
        std::fs::write(dir.join("crates/a/src/lib.rs"), b"pub fn a() {}").unwrap();
        std::fs::write(dir.join(".lootignore"), "**/target/\n").unwrap();

        let mut ws = Workspace::open_at(&dir).unwrap();
        let (_, reported) = ws.snapshot("").unwrap();
        assert!(
            !reported.iter().any(|(p, _)| p.to_string_lossy().contains("target")),
            "nested target/ must be ignored: {reported:?}"
        );
        assert!(reported.iter().any(|(p, _)| p.ends_with("lib.rs")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn attributes_edit_cannot_silently_demote() {
        // #62 (pilot finding 2): deleting the .lootattributes line used to
        // re-seal the path Public on the next snapshot with no warning.
        let dir = std::env::temp_dir().join(format!("loot-demote-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Workspace::init_at(&dir, "connor").unwrap();
        std::fs::write(dir.join("secret.txt"), b"private").unwrap();
        std::fs::write(dir.join(".lootattributes"), "secret.txt restricted=connor\n").unwrap();

        let mut ws = Workspace::open_at(&dir).unwrap();
        let (_, reported) = ws.snapshot("seal").unwrap();
        // The policy itself is versioned (travels to peers and clones).
        assert!(
            reported.iter().any(|(p, v)| p.ends_with(".lootattributes")
                && matches!(v, Visibility::Public)),
            ".lootattributes must be snapshotted"
        );

        // Mangle the policy: the next snapshot must refuse, not leak.
        std::fs::write(dir.join(".lootattributes"), "").unwrap();
        let mut ws = Workspace::open_at(&dir).unwrap();
        let err = ws.snapshot("oops").unwrap_err();
        assert!(err.contains("demote") && err.contains("secret.txt"), "got: {err}");

        // Deliberate demotion goes through with --allow-demote.
        let mut ws = Workspace::open_at(&dir).unwrap();
        let (_, reported) =
            ws.snapshot_allowing("public now", &[PathBuf::from("secret.txt")]).unwrap();
        let vis = reported.iter().find(|(p, _)| p.ends_with("secret.txt")).unwrap();
        assert!(matches!(vis.1, Visibility::Public));
        let _ = std::fs::remove_dir_all(&dir);
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
        assert_eq!(ws.current_dock(), None);
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
        assert_eq!(ws.current_dock(), Some("feature"));
        std::fs::write(dir.join("feature.txt"), b"F").unwrap();
        let (feat_tip, _) = ws.snapshot("feature work").unwrap();

        // Back on home: feature.txt is pruned from disk, base.txt remains.
        ws.dock_goto("main").unwrap();
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
        assert_eq!(docks.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(), ["main", "feature"]);
        assert!(docks.iter().find(|d| d.name == "feature").unwrap().current);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dock_goto_is_idempotent_and_rejects_bad_names() {
        let (dir, mut ws) = dock_repo("names");
        std::fs::write(dir.join("a.txt"), b"x").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();

        assert!(matches!(ws.dock_goto("main"), Ok(DockAction::Already)), "self-switch is a no-op");
        assert!(ws.dock_goto("../escape").is_err(), "path traversal rejected");
        assert!(matches!(ws.dock_goto("feat").unwrap(), DockAction::Created));
        assert!(matches!(ws.dock_goto("feat"), Ok(DockAction::Already)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- lanes (ADR 0034, #231) ---

    /// A keyed primary with one finalized change, plus a scratch area the
    /// test's lanes spawn into (lane dirs must live outside the primary tree).
    fn lane_setup(tag: &str) -> (PathBuf, PathBuf, Workspace) {
        let area = std::env::temp_dir().join(format!("loot-lane-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&area);
        let dir = area.join("repo");
        let mut ws = authored_ws(&dir);
        std::fs::write(dir.join("base.txt"), b"base").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();
        (area, dir, ws)
    }

    #[test]
    fn lane_spawn_materializes_forks_the_anchor_and_registers() {
        let (area, dir, mut ws) = lane_setup("spawn");
        // Uncaptured primary WIP is captured, but does NOT ride into the lane:
        // the lane is born at the finalized anchor.
        std::fs::write(dir.join("dirty.txt"), b"wip").unwrap();
        ws.snapshot("primary wip").unwrap();

        let lane_dir = area.join("l1");
        let spawned = ws.spawn_lane(None, Some(&lane_dir)).unwrap();
        assert_eq!(spawned.id, "l1", "auto-handle derives from the directory name");
        assert!(spawned.dir.join("base.txt").exists(), "anchor tree materialized");
        assert!(!spawned.dir.join("dirty.txt").exists(), "primary WIP stays out of the lane");
        assert!(spawned.dir.join(DOT).is_dir(), "a lane's .loot is a directory");
        assert!(dir.join("dirty.txt").exists(), "primary tree untouched by the spawn");

        // Registered, unnamed, with a live heartbeat.
        let lanes = ws.lane_list();
        assert_eq!(lanes.len(), 1);
        assert_eq!(lanes[0].id, "l1");
        assert_eq!(lanes[0].name, None, "ephemeral by default");
        assert!(lanes[0].heartbeat > 0);
        assert!(!lanes[0].landed);

        // The lane opens as a lane, and a second spawn of the same dir refuses.
        let lw = Workspace::open_at(&spawned.dir).unwrap();
        assert_eq!(lw.lane_id(), Some("l1"));
        assert!(ws.spawn_lane(None, Some(&lane_dir)).is_err(), "dir already a position");

        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn lane_spawn_requires_a_keyed_repo_and_the_primary() {
        // Keyless: nothing could ever cross the seal, so spawning refuses.
        let (dir, mut keyless) = dock_repo("lane-keyless");
        std::fs::write(dir.join("a.txt"), b"x").unwrap();
        keyless.snapshot("base").unwrap();
        keyless.finalize_working().unwrap();
        let err = keyless.spawn_lane(None, None).unwrap_err();
        assert!(err.contains("keyed"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);

        // From a lane: spawn (and the other single-owner verbs) refuse.
        let (area, _dir, mut ws) = lane_setup("primary-only");
        let spawned = ws.spawn_lane(None, Some(&area.join("l1"))).unwrap();
        let mut lw = Workspace::open_at(&spawned.dir).unwrap();
        for err in [
            lw.spawn_lane(None, None).unwrap_err(),
            lw.gc(true).unwrap_err(),
            lw.dock_goto("elsewhere").unwrap_err(),
            lw.create_dock("elsewhere", None).unwrap_err(),
            lw.remove_dock("elsewhere").unwrap_err(),
            lw.merge_dock("elsewhere").map(|_| ()).unwrap_err(),
            lw.remove_lane("l1").map(|_| ()).unwrap_err(),
            lw.lane_gc(0).map(|_| ()).unwrap_err(),
        ] {
            assert!(err.contains("primary"), "expected a primary-only refusal, got: {err}");
        }
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn lane_wip_is_sealed_and_finalized_work_stays_out_of_the_primary_view() {
        let (area, dir, mut ws) = lane_setup("seal");
        let spawned = ws.spawn_lane(None, Some(&area.join("l1"))).unwrap();
        let primary_dot = dir.join(DOT);
        let heads_before = std::fs::read(primary_dot.join("heads")).unwrap();
        let wc_before = std::fs::read(primary_dot.join("working-change")).ok();
        let ops_before = std::fs::read(primary_dot.join("ops")).ok();

        // Work in the lane: WIP, an op, then finalize (sign).
        let mut lw = Workspace::open_at(&spawned.dir).unwrap();
        std::fs::write(spawned.dir.join("lane.txt"), b"L").unwrap();
        lw.snapshot("lane work").unwrap();
        lw.record_op("describe", "lane work", false);
        let lane_dot = spawned.dir.join(DOT);
        assert!(lane_dot.join("working-change").exists(), "lane WIP lives lane-side");
        assert!(lane_dot.join("ops").exists(), "lane ops live lane-side");
        lw.finalize_working().unwrap();
        let lane_tip = lw.heads();

        // The seal: nothing primary-side moved — not heads, not the working
        // change, not the op log (undo in the lane can never rewind us).
        assert_eq!(std::fs::read(primary_dot.join("heads")).unwrap(), heads_before);
        assert_eq!(std::fs::read(primary_dot.join("working-change")).ok(), wc_before);
        assert_eq!(std::fs::read(primary_dot.join("ops")).ok(), ops_before);

        // Isolation is by view: the primary re-opens and does not see the
        // lane's (signed, unlanded) tip in its frontier; the lane still does.
        let primary = Workspace::open_at(&dir).unwrap();
        for t in &lane_tip {
            assert!(!primary.heads().contains(t), "lane tip must not enter the primary view");
        }
        let lw2 = Workspace::open_at(&spawned.dir).unwrap();
        assert_eq!(lw2.heads(), lane_tip, "the lane keeps its own frontier");

        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn lane_finalize_advances_the_tip_to_the_signed_change() {
        // Regression (ADR 0036 dogfood): a lane sits on the home dock but is born
        // with a *seeded* tip, so `docks_active()` is false; finalize must still
        // advance the tip. Before the fix it stayed pinned at the spawn anchor
        // while `heads` moved on, so a land aimed git-main at the change's parent
        // and moved nothing — the #195 guard caught it live.
        let (area, _dir, mut ws) = lane_setup("tip-advance");
        let spawned = ws.spawn_lane(None, Some(&area.join("l1"))).unwrap();
        let mut lw = Workspace::open_at(&spawned.dir).unwrap();
        let spawn_anchor = lw.finalized_anchor();

        std::fs::write(spawned.dir.join("lane.txt"), b"L").unwrap();
        lw.snapshot("lane work").unwrap();
        let finalized = lw.finalize_capturing(&[], false).unwrap();

        assert!(finalized.is_some(), "the lane change was finalized");
        assert_ne!(lw.finalized_anchor(), spawn_anchor, "tip must leave the spawn anchor");
        assert_eq!(lw.finalized_anchor(), finalized, "the finalized change is the new tip");
        // And it is the lane's single head — tip and frontier agree.
        assert_eq!(lw.heads(), finalized.into_iter().collect::<Vec<_>>(), "tip == the head");
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn lane_spawn_ticket_handle_names_dir_and_id_suffixed_until_free() {
        let (area, _dir, mut ws) = lane_setup("ticket");

        // `--ticket 232` (#232): the ticket-derived handle names both the
        // default directory and the registry id — one command, no --at.
        let s1 = ws.spawn_lane_as(None, None, Some("t232")).unwrap();
        assert_eq!(s1.id, "t232");
        assert_eq!(s1.dir.file_name().unwrap().to_string_lossy(), "t232");
        assert_eq!(
            s1.dir.parent().unwrap().file_name().unwrap().to_string_lossy(),
            "repo-lanes",
            "default placement stays the <repo>-lanes sibling"
        );

        // A second claim of the same ticket suffixes until free (ADR 0035),
        // and id still matches the directory name.
        let s2 = ws.spawn_lane_as(None, None, Some("t232")).unwrap();
        assert_eq!(s2.id, "t232-2");
        assert_eq!(s2.dir.file_name().unwrap().to_string_lossy(), "t232-2");

        // Handles live in the dock-name space.
        assert!(ws.spawn_lane_as(None, None, Some("bad handle")).is_err());

        // An explicit --at keeps the ticket linkage: the handle still wins the
        // registry id, so the claim board never loses the ticket.
        let s3 = ws.spawn_lane_as(None, Some(&area.join("elsewhere")), Some("t232")).unwrap();
        assert_eq!(s3.id, "t232-3");

        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn lane_statuses_observe_tip_dirt_and_pr_without_touching_heartbeats() {
        let (area, _dir, mut ws) = lane_setup("statuses");
        let anchor = ws.heads()[0].clone();
        let spawned = ws.spawn_lane(None, Some(&area.join("l1"))).unwrap();
        // Age the heartbeat so an accidental refresh is detectable.
        ws.store().touch_lane_heartbeat(&spawned.id, &spawned.dir, 42).unwrap();

        // A fresh lane: at the anchor, clean, nothing in review.
        let st = ws.lane_statuses();
        assert_eq!(st.len(), 1);
        assert_eq!(st[0].entry.id, "l1");
        assert_eq!(st[0].tip.as_ref(), Some(&anchor), "born at the finalized anchor");
        assert_eq!(st[0].dirty, Some(false), "freshly materialized tree is clean");
        assert_eq!(st[0].pr, None);

        // Observing is read-only: the heartbeat did not refresh (the entry's
        // one writer is its own lane — ADR 0034/0035; a touching observer
        // would blind the gc-sweep).
        assert_eq!(ws.lane_list()[0].heartbeat, 42);

        // Uncaptured lane edits read as dirty from the primary.
        std::fs::write(spawned.dir.join("lane.txt"), b"L").unwrap();
        assert_eq!(ws.lane_statuses()[0].dirty, Some(true));

        // Captured WIP reads clean again and keys the status on the lane's
        // working change; a pr-map row under that key surfaces as the PR.
        let mut lw = Workspace::open_at(&spawned.dir).unwrap();
        lw.snapshot("lane work").unwrap();
        let wid = lw.working_id().cloned().unwrap();
        let key = loot_core::hex::encode(&lw.repo().change_change_id(&wid).unwrap());
        let st = ws.lane_statuses();
        assert_eq!(st[0].dirty, Some(false), "captured WIP is not dirt");
        assert_eq!(st[0].change.as_deref(), Some(key.as_str()));
        std::fs::create_dir_all(ws.store().git_mirror_dir()).unwrap();
        std::fs::write(ws.store().git_pr_map(), format!("{key} main 235\n")).unwrap();
        assert_eq!(ws.lane_statuses()[0].pr, Some(235));

        // A hand-deleted lane directory still renders a row — all-None peek
        // fields — instead of vanishing or erroring.
        std::fs::remove_dir_all(&spawned.dir).unwrap();
        let st = ws.lane_statuses();
        assert_eq!(st.len(), 1);
        assert_eq!(st[0].tip, None);
        assert_eq!(st[0].dirty, None);

        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn lane_naming_promotes_and_gc_reaps_only_the_abandoned_and_the_landed() {
        let (area, _dir, mut ws) = lane_setup("gc");
        let a = ws.spawn_lane(None, Some(&area.join("stale"))).unwrap();
        let b = ws.spawn_lane(None, Some(&area.join("keeper"))).unwrap();
        let c = ws.spawn_lane(None, Some(&area.join("fresh"))).unwrap();
        let d = ws.spawn_lane(None, Some(&area.join("done"))).unwrap();

        // Promote b mid-flight from inside the lane; the sweep must spare it.
        let lw_b = Workspace::open_at(&b.dir).unwrap();
        lw_b.name_lane("kept-work").unwrap();
        assert!(ws.name_lane("nope").is_err(), "the primary is not a lane");
        // A taken name (or id) refuses.
        let lw_c = Workspace::open_at(&c.dir).unwrap();
        assert!(lw_c.name_lane("kept-work").is_err());
        assert!(lw_c.name_lane(&a.id).is_err());

        // Age a and b far past the threshold; d lands instead (fresh heartbeat).
        ws.store().touch_lane_heartbeat(&a.id, &a.dir, 1).unwrap();
        ws.store().touch_lane_heartbeat(&b.id, &b.dir, 1).unwrap();
        ws.store().mark_lane_landed(&d.id).unwrap();

        let outcomes = ws.lane_gc(LANE_STALE_SECS).unwrap();
        let fate = |id: &str| {
            outcomes
                .iter()
                .find(|(e, _)| e.id == id)
                .map(|(_, o)| match o {
                    SweepOutcome::Reaped(w) => format!("reaped: {w}"),
                    SweepOutcome::Kept(w) => format!("kept: {w}"),
                    SweepOutcome::Failed(w) => format!("failed: {w}"),
                })
                .unwrap()
        };
        assert!(fate(&a.id).starts_with("reaped: stale"), "{}", fate(&a.id));
        assert!(fate(&b.id).starts_with("kept: named"), "named lanes never sweep: {}", fate(&b.id));
        assert!(fate(&c.id).starts_with("kept: live"), "{}", fate(&c.id));
        assert!(fate(&d.id).starts_with("reaped: landed"), "{}", fate(&d.id));

        assert!(!a.dir.exists(), "reap deletes the lane directory (WIP dies with it)");
        assert!(!d.dir.exists());
        assert!(b.dir.exists() && c.dir.exists());
        let ids: Vec<_> = ws.lane_list().into_iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![c.id.clone(), b.id.clone()], "only the kept lanes stay registered");

        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn lane_rm_reaps_by_id_or_name_and_the_reaper_verifies_the_directory() {
        let (area, _dir, mut ws) = lane_setup("rm");
        let a = ws.spawn_lane(Some("feat"), Some(&area.join("named"))).unwrap();
        let b = ws.spawn_lane(None, Some(&area.join("plain"))).unwrap();
        assert_eq!(ws.lane_list()[0].name.as_deref(), Some("feat"), "born named");

        // Remove by name; unsigned WIP simply dies with the directory.
        std::fs::write(a.dir.join("wip.txt"), b"never signed").unwrap();
        let removed = ws.remove_lane("feat").unwrap();
        assert_eq!(removed.id, a.id);
        assert!(!a.dir.exists());

        // A tampered registry path never points the reaper at an innocent tree.
        let innocent = area.join("innocent");
        std::fs::create_dir_all(&innocent).unwrap();
        std::fs::write(innocent.join("precious.txt"), b"!").unwrap();
        std::fs::write(
            ws.store().lane_entry_dir(&b.id).join("path"),
            innocent.display().to_string(),
        )
        .unwrap();
        let err = ws.remove_lane(&b.id).unwrap_err();
        assert!(err.contains("refusing"), "{err}");
        assert!(innocent.join("precious.txt").exists(), "innocent tree untouched");
        assert!(b.dir.exists(), "the real lane dir was not the recorded path — untouched");

        assert!(ws.remove_lane("nope").is_err(), "unknown lane refuses");
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn lane_spawn_refuses_a_dir_inside_the_primary_tree() {
        // ADR 0034: lane dirs never nest inside the primary's working tree —
        // the primary's snapshot walks would swallow the lane's tree as WIP.
        let (area, dir, mut ws) = lane_setup("nest");
        let inside = dir.join("sub").join("lane");
        let err = ws.spawn_lane(None, Some(&inside)).unwrap_err();
        assert!(err.contains("inside the primary"), "{err}");
        assert!(!inside.exists(), "the refused spawn cleans up the dir it created");
        assert!(ws.lane_list().is_empty(), "nothing registered");
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn lane_auto_handle_avoids_ids_and_promoted_names() {
        // Ids and names share the `lane rm <id-or-name>` lookup space, so the
        // dir-derived auto-handle must dodge both or lookups turn ambiguous.
        let (area, _dir, mut ws) = lane_setup("handle");
        ws.spawn_lane(Some("feat"), Some(&area.join("a"))).unwrap();
        // A dir literally named after the taken *name* gets suffixed…
        let clash_name = ws.spawn_lane(None, Some(&area.join("feat"))).unwrap();
        assert_eq!(clash_name.id, "feat-2");
        // …and so does a dir named after a taken *id*.
        let clash_id = ws.spawn_lane(None, Some(&area.join("x").join("a"))).unwrap();
        assert_eq!(clash_id.id, "a-2");
        let _ = std::fs::remove_dir_all(&area);
    }

    // --- CA2: local dock merge ---

    #[test]
    fn dock_merge_converges_disjoint_edits() {
        // Acceptance: two docks editing disjoint paths merge cleanly with no
        // conflict, and the merged tree carries both lines' files.
        let (dir, mut ws) = dock_repo("merge-disjoint");
        std::fs::write(dir.join("base.txt"), b"base").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();

        ws.dock_goto("feature").unwrap();
        std::fs::write(dir.join("feature.txt"), b"F").unwrap();
        ws.snapshot("feature work").unwrap();
        ws.finalize_working().unwrap();

        ws.dock_goto("main").unwrap();
        std::fs::write(dir.join("home.txt"), b"H").unwrap();
        ws.snapshot("home work").unwrap();
        ws.finalize_working().unwrap();

        let (src, outcomes) = ws.merge_dock("feature").unwrap();
        assert_eq!(src, "feature");
        assert!(ws.repo().conflicts().is_empty(), "disjoint edits: no conflicts");
        assert_eq!(outcomes[&PathBuf::from("feature.txt")], MergeOutcome::Converged);
        // Merge materialized both lines onto the home working tree.
        assert!(dir.join("base.txt").exists());
        assert!(dir.join("home.txt").exists());
        assert!(dir.join("feature.txt").exists(), "feature work present after merge");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dock_merge_same_path_conflicts_and_keeps_both_sides() {
        // Acceptance: a genuine same-path divergence surfaces as a Conflict via the
        // existing conflicts/resolve flow, with neither side dropped.
        let (dir, mut ws) = dock_repo("merge-conflict");
        std::fs::write(dir.join("a.txt"), b"base\n").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();

        ws.dock_goto("feature").unwrap();
        std::fs::write(dir.join("a.txt"), b"feature side\n").unwrap();
        ws.snapshot("feat").unwrap();
        ws.finalize_working().unwrap();

        ws.dock_goto("main").unwrap();
        std::fs::write(dir.join("a.txt"), b"home side\n").unwrap();
        ws.snapshot("home").unwrap();
        ws.finalize_working().unwrap();

        let (_src, outcomes) = ws.merge_dock("feature").unwrap();
        assert!(matches!(outcomes[&PathBuf::from("a.txt")], MergeOutcome::Conflict { .. }));
        assert!(
            ws.repo().conflicts().contains_key(&PathBuf::from("a.txt")),
            "conflict recorded for `loot resolve`"
        );
        // Ours is kept on disk; theirs is preserved in the recorded conflict and
        // via the merge change's second parent — no side dropped.
        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"home side\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dock_merge_conflict_resolution_advances_the_dock_tip() {
        // Regression (CA2 review): after a conflicted dock merge, `resolve` must
        // build on and advance the dock's tip — not orphan the resolution onto a
        // stray head — so later work on the dock sees the resolved content.
        let (dir, mut ws) = dock_repo("merge-resolve");
        std::fs::write(dir.join("a.txt"), b"base\n").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();

        ws.dock_goto("feature").unwrap();
        std::fs::write(dir.join("a.txt"), b"feature side\n").unwrap();
        ws.snapshot("feat").unwrap();
        ws.finalize_working().unwrap();

        ws.dock_goto("main").unwrap();
        std::fs::write(dir.join("a.txt"), b"home side\n").unwrap();
        ws.snapshot("home").unwrap();
        ws.finalize_working().unwrap();

        let (_src, outcomes) = ws.merge_dock("feature").unwrap();
        assert!(matches!(outcomes[&PathBuf::from("a.txt")], MergeOutcome::Conflict { .. }));

        // Resolve — the resolution becomes the dock tip and lands on disk.
        ws.resolve_conflict(Path::new("a.txt"), b"resolved\n", Visibility::Public).unwrap();
        assert!(ws.repo().conflicts().is_empty(), "conflict cleared");
        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"resolved\n", "resolution written to disk");

        // Later work forks from the resolution, not the pre-resolution merge:
        // a fresh snapshot keeps the resolved a.txt and surfacing re-materializes it.
        std::fs::write(dir.join("b.txt"), b"more\n").unwrap();
        ws.snapshot("after resolve").unwrap();
        ws.finalize_working().unwrap();
        ws.surface_with_report().unwrap();
        assert_eq!(
            std::fs::read(dir.join("a.txt")).unwrap(),
            b"resolved\n",
            "dock line carries the resolution, not the conflicted merge"
        );
        assert!(dir.join("b.txt").exists(), "new work sits on the resolved tip");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_does_not_clobber_unrelated_uncommitted_edits() {
        // Regression (#233): resolving one conflicted path used to re-materialize
        // the *whole* resolution tree onto disk, reverting the operator's
        // uncommitted edits to unrelated files (and forcing the "resolve one
        // conflict at a time, then do manual git surgery" reconcile workaround
        // when a harbor bounce left several conflicts). `resolve` touches exactly
        // one path, so it must write exactly that path and leave every other file
        // — unrelated edits and still-unresolved sibling conflicts — untouched.
        let (dir, mut ws) = dock_repo("resolve-no-clobber");
        // Base carries the two files that will conflict plus an unrelated file.
        std::fs::write(dir.join("a.txt"), b"base a\n").unwrap();
        std::fs::write(dir.join("d.txt"), b"base d\n").unwrap();
        std::fs::write(dir.join("c.txt"), b"base c\n").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();

        ws.dock_goto("feature").unwrap();
        std::fs::write(dir.join("a.txt"), b"feature a\n").unwrap();
        std::fs::write(dir.join("d.txt"), b"feature d\n").unwrap();
        ws.snapshot("feat").unwrap();
        ws.finalize_working().unwrap();

        ws.dock_goto("main").unwrap();
        std::fs::write(dir.join("a.txt"), b"home a\n").unwrap();
        std::fs::write(dir.join("d.txt"), b"home d\n").unwrap();
        ws.snapshot("home").unwrap();
        ws.finalize_working().unwrap();

        // Merge produces two conflicts (a.txt and d.txt); the merge leaves ours
        // on disk and c.txt at its base content.
        let (_src, outcomes) = ws.merge_dock("feature").unwrap();
        assert!(matches!(outcomes[&PathBuf::from("a.txt")], MergeOutcome::Conflict { .. }));
        assert!(matches!(outcomes[&PathBuf::from("d.txt")], MergeOutcome::Conflict { .. }));

        // The operator makes an uncommitted edit to the unrelated file c.txt
        // while working through the conflicts — nothing captures it.
        std::fs::write(dir.join("c.txt"), b"uncommitted work\n").unwrap();

        // Resolve only a.txt.
        ws.resolve_conflict(Path::new("a.txt"), b"resolved a\n", Visibility::Public).unwrap();

        // The resolved path landed on disk...
        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"resolved a\n");
        // ...the unrelated uncommitted edit survived (the clobber #233 kills)...
        assert_eq!(
            std::fs::read(dir.join("c.txt")).unwrap(),
            b"uncommitted work\n",
            "resolving a.txt must not revert the uncommitted edit to c.txt"
        );
        // ...and the sibling conflict is still open, its ours-content undisturbed,
        // so the operator resolves it next in the same pass — no manual surgery.
        assert!(
            ws.repo().conflicts().contains_key(&PathBuf::from("d.txt")),
            "d.txt stays conflicted until its own resolve"
        );
        assert_eq!(std::fs::read(dir.join("d.txt")).unwrap(), b"home d\n");

        // Resolving the second conflict clears it and, again, leaves c.txt alone.
        ws.resolve_conflict(Path::new("d.txt"), b"resolved d\n", Visibility::Public).unwrap();
        assert!(ws.repo().conflicts().is_empty(), "all conflicts resolved in one pass");
        assert_eq!(std::fs::read(dir.join("d.txt")).unwrap(), b"resolved d\n");
        assert_eq!(std::fs::read(dir.join("c.txt")).unwrap(), b"uncommitted work\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn harbor_is_an_ordinary_dock_that_round_trips() {
        // Acceptance: `harbor` is a plain dock by convention; merging into it and
        // re-basing from it round-trips through the same machinery.
        let (dir, mut ws) = dock_repo("harbor");
        std::fs::write(dir.join("base.txt"), b"base").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();

        ws.dock_goto("feature").unwrap();
        std::fs::write(dir.join("feat.txt"), b"F").unwrap();
        ws.snapshot("feat").unwrap();
        ws.finalize_working().unwrap();

        // Create harbor from a neutral base (home), then integrate feature into
        // it — an ordinary dock playing the integrator role by convention.
        ws.dock_goto("main").unwrap();
        ws.dock_goto("harbor").unwrap();
        assert!(!dir.join("feat.txt").exists(), "harbor forks from home, without feature's work");
        let (_s, o1) = ws.merge_dock("feature").unwrap();
        assert!(o1.contains_key(&PathBuf::from("feat.txt")));
        assert!(dir.join("feat.txt").exists(), "harbor integrated feature work");

        // Re-base home from harbor: the work flows back cleanly.
        ws.dock_goto("main").unwrap();
        assert!(!dir.join("feat.txt").exists(), "home has not merged yet");
        ws.merge_dock("harbor").unwrap();
        assert!(dir.join("feat.txt").exists(), "home re-based from harbor");
        assert!(ws.repo().conflicts().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn converge_heads_collapses_a_two_writer_fork_no_side_dropped() {
        // #128: after a peer's divergent tip is ingested (pull/apply), the graph
        // has two heads and the working tree shows only our side — apply records +
        // classifies but never merges tips. `converge_heads` collapses the fork
        // into ONE head whose tree carries BOTH sides. Two lines stand in for the
        // two independently-advanced writers (the exact shape a pull leaves).
        let (dir, mut ws) = dock_repo("converge-fork");
        std::fs::write(dir.join("base.txt"), b"base").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();

        // "Their" line, advanced independently.
        ws.dock_goto("peer").unwrap();
        std::fs::write(dir.join("their.txt"), b"T").unwrap();
        ws.snapshot("theirs").unwrap();
        ws.finalize_working().unwrap();

        // "Our" line, back on main — now the graph is forked.
        ws.dock_goto("main").unwrap();
        std::fs::write(dir.join("ours.txt"), b"O").unwrap();
        ws.snapshot("ours").unwrap();
        ws.finalize_working().unwrap();
        assert!(ws.repo().heads().len() >= 2, "precondition: a real two-writer fork");

        let ours = ws.anchor();
        let outcomes = ws.converge_heads(ours.as_ref()).unwrap();

        assert_eq!(ws.repo().heads().len(), 1, "the fork collapsed to a single head");
        assert!(dir.join("ours.txt").exists(), "our side kept");
        assert!(dir.join("their.txt").exists(), "the peer's side materialized — no side dropped");
        assert!(dir.join("base.txt").exists(), "the shared base carried");
        assert!(
            outcomes.contains_key(&PathBuf::from("their.txt")),
            "the collapse reports the peer's file as a merge outcome"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- ADR 0032: amend via `loot edit` — supersession ---

    /// An authored repo with a two-change line on the home dock: `base` then
    /// `target` (the amend candidate), tree = `a.txt`. Returns the target's
    /// version id and durable handle.
    fn amendable_ws(tag: &str) -> (PathBuf, Workspace, Oid, [u8; 16]) {
        let dir = std::env::temp_dir().join(format!("loot-edit-{tag}-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        std::fs::write(dir.join("a.txt"), b"base").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();
        std::fs::write(dir.join("a.txt"), b"target").unwrap();
        ws.snapshot("target").unwrap();
        ws.finalize_working().unwrap();
        let x = ws.repo().heads()[0].clone();
        let cid = ws.repo().change_change_id(&x).unwrap();
        (dir, ws, x, cid)
    }

    #[test]
    fn edit_reopens_a_change_and_finalize_supersedes_it() {
        let (dir, mut ws, x, cid) = amendable_ws("e2e");
        let report = ws.edit(&loot_core::hex::letters(&cid)).unwrap();
        assert_eq!(report.superseded, x);
        assert_eq!(report.change_id, cid);
        let reopened = ws.working_id().cloned().expect("the reopen is the working change");
        assert_eq!(ws.repo().change_change_id(&reopened), Some(cid), "handle carried");
        assert_eq!(ws.repo().change_predecessors(&reopened), vec![x.clone()]);
        assert!(ws.liveness().superseded().clone().contains(&x), "the claim is live from the reopen");
        assert!(!ws.divergent_change_ids().contains(&cid), "an amend is not divergence");
        assert_eq!(
            std::fs::read(dir.join("a.txt")).unwrap(),
            b"target",
            "the tree already showed the target — edit materializes nothing"
        );

        // Amend and finalize: a NEW signed version under the SAME handle.
        std::fs::write(dir.join("a.txt"), b"target amended").unwrap();
        ws.snapshot("target").unwrap();
        ws.finalize_working().unwrap();
        let live = ws.liveness().live_of(&cid);
        assert_eq!(live.len(), 1, "one live version — no divergence, no resurrection");
        let x2 = live.into_iter().next().unwrap();
        assert_ne!(x2, x, "the amend minted a new version id");
        assert_eq!(ws.repo().change_change_id(&x2), Some(cid), "…under the same change id");
        assert_eq!(ws.repo().change_predecessors(&x2), vec![x.clone()], "…naming what it supersedes");
        assert!(ws.repo().change_signature(&x2).is_some(), "…and signed, so the claim travels");
        // The live view shows exactly one row for the change; the superseded
        // version is hidden the way an abandoned one is.
        let hist = ws.history().unwrap();
        let showing: Vec<&HistoryRow> =
            hist.rows.iter().filter(|r| r.change_id == Some(cid)).collect();
        assert_eq!(showing.len(), 1, "the superseded version left the live view");
        assert_eq!(showing[0].version, x2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn edit_refuses_descendants_dirt_wip_and_divergence() {
        use loot_core::Change;
        let (dir, mut ws, x, cid) = amendable_ws("guards");
        let letters = loot_core::hex::letters(&cid);

        // A change with descendants (the base under the target) is not editable.
        let base = ws.repo().parents_of(&x).into_iter().next().unwrap();
        let base_cid = ws.repo().change_change_id(&base).unwrap();
        let err = ws.edit(&loot_core::hex::letters(&base_cid)).unwrap_err();
        assert!(err.contains("descendants"), "unexpected: {err}");

        // Uncaptured edits on disk: edit refuses instead of capturing (the ADR
        // 0030 exception class) — the e6fde8e sweep must be impossible here.
        std::fs::write(dir.join("b.txt"), b"uncaptured").unwrap();
        let err = ws.edit(&letters).unwrap_err();
        assert!(err.contains("uncaptured"), "unexpected: {err}");
        std::fs::remove_file(dir.join("b.txt")).unwrap();

        // An in-progress working change: same refusal family.
        std::fs::write(dir.join("a.txt"), b"wip").unwrap();
        ws.snapshot("wip").unwrap();
        let err = ws.edit(&letters).unwrap_err();
        assert!(err.contains("working change is in progress"), "unexpected: {err}");
        ws.finalize_working().unwrap();

        // A divergent handle: refuse with the abandon-first remedy. Seed two
        // live versions of one handle below the current head (the S3 amend
        // primitive, as the abandon tests do).
        let head = ws.repo().heads()[0].clone();
        let dcid = [9u8; 16];
        ws.with_repo(|repo| {
            for msg in ["A", "B"] {
                repo.record_carrying(
                    Change {
                        id: Oid([0; 32]),
                        parents: vec![head.clone()],
                        message: msg.into(),
                        tree: Default::default(),
                    },
                    Some(dcid),
                )
                .map_err(|e| e.to_string())?;
            }
            Ok(())
        })
        .unwrap();
        assert!(ws.divergent_change_ids().contains(&dcid), "precondition: divergent");
        let err = ws.edit(&loot_core::hex::letters(&dcid)).unwrap_err();
        assert!(err.contains("divergent"), "unexpected: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn edit_is_one_undoable_operation() {
        let (dir, mut ws, x, cid) = amendable_ws("undo");
        ws.record_op("new", "finalize target", false); // the undo floor
        ws.edit(&loot_core::hex::letters(&cid)).unwrap(); // records its own op
        assert!(ws.working_id().is_some(), "the reopen is in progress");

        let r = ws.undo().unwrap();
        let _ = r;
        assert!(ws.working_id().is_none(), "undo closed the reopen");
        assert_eq!(ws.repo().heads(), vec![x.clone()], "the view is back on the target");
        assert!(
            ws.liveness().superseded().clone().is_empty(),
            "the unfinalized claim left the view with the reopen"
        );
        assert_eq!(
            std::fs::read(dir.join("a.txt")).unwrap(),
            b"target",
            "the tree is untouched — edit never materialized anything to walk back"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Shared setup for the collapse tests: main holds `target` (a.txt =
    /// "target"); an `amender` dock reopens it and finalizes an amended version.
    /// Returns main's pre-amend tip `x` and the amend `x2`, with `ws` on main.
    fn amended_on_a_dock(tag: &str) -> (PathBuf, Workspace, Oid, Oid) {
        let (dir, mut ws, x, cid) = amendable_ws(tag);
        ws.dock_goto("amender").unwrap();
        ws.edit(&loot_core::hex::letters(&cid)).unwrap();
        std::fs::write(dir.join("a.txt"), b"target amended").unwrap();
        ws.snapshot("target").unwrap();
        ws.finalize_working().unwrap();
        let x2 = ws
            .liveness()
            .live_of(&cid)
            .into_iter()
            .next()
            .unwrap();
        ws.dock_goto("main").unwrap();
        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"target", "main still pre-amend");
        (dir, ws, x, x2)
    }

    #[test]
    fn dock_merge_adopts_an_amend_as_a_fast_forward() {
        // ADR 0032: merging a dock whose line SUPERSEDES our tip must not
        // content-merge the two versions (that would resurrect what the amend
        // removed) — it adopts the amend.
        let (dir, mut ws, _x, x2) = amended_on_a_dock("dockff");
        let nodes_before = ws.repo().log_detailed().len();
        let (_name, outcomes) = ws.merge_dock("amender").unwrap();
        assert!(outcomes.is_empty(), "a supersession adopts — no merge outcomes");
        assert_eq!(ws.repo().log_detailed().len(), nodes_before, "no merge node minted");
        assert_eq!(
            std::fs::read(dir.join("a.txt")).unwrap(),
            b"target amended",
            "main adopted the amend"
        );
        assert!(ws.divergent_change_ids().is_empty(), "a solo amend never renders divergence");
        // And the mirror case: merging main back into the amender is a no-op —
        // our superseded tip has nothing to offer their line.
        ws.dock_goto("amender").unwrap();
        let (_n, back) = ws.merge_dock("main").unwrap();
        assert!(back.is_empty(), "the superseded direction is a no-op");
        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"target amended");
        let _ = x2;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn converge_heads_drops_a_superseded_head_without_merging() {
        // The peer-side pull path (ADR 0032): a solo amend arrives as a sibling
        // head; converge must DROP the superseded side and adopt the amend —
        // never fold the two into a content merge.
        let (dir, mut ws, x, x2) = amended_on_a_dock("convdrop");
        let nodes_before = ws.repo().log_detailed().len();
        let outcomes = ws.converge_heads(Some(&x)).unwrap();
        assert!(outcomes.is_empty(), "dropping a superseded head is not a merge");
        assert_eq!(
            ws.repo().log_detailed().len(),
            nodes_before - 1,
            "the superseded head left the live view; no merge node was minted"
        );
        assert_eq!(ws.repo().heads(), vec![x2.clone()], "the amend is the sole head");
        assert_eq!(
            std::fs::read(dir.join("a.txt")).unwrap(),
            b"target amended",
            "the amend materialized"
        );
        assert!(ws.divergent_change_ids().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A store shaped like a divergent pull (#198/#203): our amend `x2` is the
    /// line the tree shows; the peer's concurrent amend of the same handle sits
    /// beside it as a head (white-box, as the S3 tests construct divergence —
    /// the live cross-store proof is the amend-divergence demo). Both name `x`
    /// in `predecessors`, neither names the other, and both share `x`'s
    /// parentage shape (the home dock finalizes an amend as `x`'s child).
    fn divergent_ws(tag: &str) -> (PathBuf, Workspace, Oid, Oid, [u8; 16]) {
        use loot_core::Change;
        let (dir, mut ws, x, cid) = amendable_ws(tag);
        ws.edit(&loot_core::hex::letters(&cid)).unwrap();
        std::fs::write(dir.join("a.txt"), b"target amended").unwrap();
        ws.snapshot("target").unwrap();
        ws.finalize_working().unwrap();
        let x2 = ws
            .liveness()
            .live_of(&cid)
            .into_iter()
            .next()
            .unwrap();
        let theirs = ws
            .with_repo(|repo| {
                repo.record_superseding(
                    Change {
                        id: Oid([0; 32]),
                        parents: vec![x.clone()],
                        message: "their amend".into(),
                        tree: Default::default(),
                    },
                    Some(cid),
                    vec![x.clone()],
                )
                .map_err(|e| e.to_string())
            })
            .unwrap();
        (dir, ws, x2, theirs, cid)
    }

    /// The in-memory adapter at the SyncTransport seam (#217): a relay-role
    /// DagRepo answering offer/fetch with exactly the engine methods the HTTP
    /// relay's handlers call (`offered_objects`, `bundle_wanted`) — the second
    /// adapter that makes the seam real.
    struct InMemoryRelay(loot_core::DagRepo);
    impl SyncTransport for InMemoryRelay {
        fn offer(&self, have: &[Oid]) -> Result<Vec<Oid>, String> {
            Ok(self.0.offered_objects(have))
        }
        fn fetch(&self, have: &[Oid], wants: &[Oid]) -> Result<Vec<u8>, String> {
            self.0.bundle_wanted(have, wants).map(|b| b.0).map_err(|e| e.to_string())
        }
    }

    /// A relay already stowing everything `ws` has finalized. `tag` keeps the
    /// dir test-unique (tests run as parallel threads of ONE process, so pid
    /// alone would share state); callers clean it up like their own dirs.
    fn relay_holding(tag: &str, ws: &Workspace) -> (std::path::PathBuf, InMemoryRelay) {
        use loot_core::Repo as _;
        let dir = std::env::temp_dir().join(format!("loot-relay-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut relay = loot_core::DagRepo::init(dir.clone(), "relay").unwrap();
        relay.stow(&ws.repo().bundle(&[]).unwrap()).unwrap();
        (dir, InMemoryRelay(relay))
    }

    #[test]
    fn pull_via_fetches_and_converges_through_the_transport_seam() {
        // #217: the whole pull pipeline — negotiate, batched fetch, apply,
        // post-pull converge — behind one Workspace method, driven in-process
        // through the SyncTransport seam.
        let dir_a = std::env::temp_dir().join(format!("loot-pull-a-{}", std::process::id()));
        let mut alice = authored_ws(&dir_a);
        std::fs::write(dir_a.join("doc.txt"), b"v1").unwrap();
        alice.snapshot("doc").unwrap();
        alice.finalize_working().unwrap();
        let (relay_dir, relay) = relay_holding("basic", &alice);

        let dir_b = std::env::temp_dir().join(format!("loot-pull-b-{}", std::process::id()));
        let mut bob = authored_ws(&dir_b);

        let report = bob.pull_via(&relay).unwrap();
        assert!(!report.outcomes.is_empty(), "the pull reports per-path outcomes");
        assert!(report.deferred.is_none(), "a clean-tree pull converges, not defers");
        assert_eq!(
            bob.heads(),
            alice.heads(),
            "bob converged onto alice's line through the seam"
        );
        assert!(bob.repo().conflicts().is_empty());

        // A re-pull is a no-op: negotiation finds nothing missing.
        let again = bob.pull_via(&relay).unwrap();
        assert!(again.outcomes.is_empty(), "nothing new (already up to date)");
        assert!(again.deferred.is_none());
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
        let _ = std::fs::remove_dir_all(&relay_dir);
    }

    #[test]
    fn pull_via_divergent_pull_stays_flat_in_process() {
        // #217's done-when: the amend-divergence demo's Act 2 as an ordinary
        // Rust test — two identities each `loot edit` the same handle; the
        // pull ingests the peer's amend and the divergence stays FLAT
        // (#198/#203): both heads live, no per-path conflict, tree clean on
        // ours, `!` renders, abandon settles.
        use loot_core::Repo as _;
        let dir_a = std::env::temp_dir().join(format!("loot-div-a-{}", std::process::id()));
        let mut alice = authored_ws(&dir_a);
        std::fs::write(dir_a.join("feat.txt"), b"feat: base").unwrap();
        alice.snapshot("add feat").unwrap();
        alice.finalize_working().unwrap();
        let base_head = alice.heads()[0].clone();
        let cid = alice.repo().change_change_id(&base_head).unwrap();
        let (relay_dir, mut relay) = relay_holding("divergent", &alice);

        // Bob shares the base through the seam.
        let dir_b = std::env::temp_dir().join(format!("loot-div-b-{}", std::process::id()));
        let mut bob = authored_ws(&dir_b);
        bob.pull_via(&relay).unwrap();
        bob.surface().unwrap();
        assert_eq!(std::fs::read(dir_b.join("feat.txt")).unwrap(), b"feat: base");

        // Concurrent amends of the SAME handle: alice's travels to the relay;
        // bob amends his own line before pulling it.
        alice.edit(&loot_core::hex::letters(&cid)).unwrap();
        std::fs::write(dir_a.join("feat.txt"), b"feat: alice's take").unwrap();
        alice.snapshot("add feat").unwrap();
        alice.finalize_working().unwrap();
        relay.0.stow(&alice.repo().bundle(&[]).unwrap()).unwrap();

        bob.edit(&loot_core::hex::letters(&cid)).unwrap();
        std::fs::write(dir_b.join("feat.txt"), b"feat: bob's take").unwrap();
        bob.snapshot("add feat").unwrap();
        bob.finalize_working().unwrap();

        // The divergent pull: alice's amend lands next to bob's.
        let report = bob.pull_via(&relay).unwrap();
        assert!(
            !report
                .outcomes
                .values()
                .any(|o| matches!(o, MergeOutcome::Conflict { .. })),
            "no per-path conflict is minted for the co-version"
        );
        assert!(bob.divergent_change_ids().contains(&cid), "the ! marker state renders");
        assert_eq!(bob.heads().len(), 2, "both co-versions stay flat as live heads");
        assert!(bob.repo().conflicts().is_empty(), "loot conflicts reports nothing");
        assert_eq!(
            std::fs::read(dir_b.join("feat.txt")).unwrap(),
            b"feat: bob's take",
            "the tree stays clean on OURS"
        );

        // Abandon the peer's side: the whole settle.
        let alices = bob
            .liveness()
            .live_of(&cid)
            .into_iter()
            .find(|v| Some(v) != bob.anchor().as_ref())
            .unwrap();
        bob.abandon(&alices).unwrap();
        assert!(!bob.divergent_change_ids().contains(&cid));
        assert!(bob.repo().conflicts().is_empty());
        assert_eq!(std::fs::read(dir_b.join("feat.txt")).unwrap(), b"feat: bob's take");
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
        let _ = std::fs::remove_dir_all(&relay_dir);
    }

    #[test]
    fn pull_via_interrupted_fetch_resumes() {
        // S6/ADR 0024 through the seam: each applied batch persists, so a
        // transport that dies mid-pull loses nothing — the next pull
        // re-negotiates and fetches only what's left.
        struct FlakyTransport {
            inner: InMemoryRelay,
            fetches_before_failure: std::cell::Cell<u32>,
        }
        impl SyncTransport for FlakyTransport {
            fn offer(&self, have: &[Oid]) -> Result<Vec<Oid>, String> {
                self.inner.offer(have)
            }
            fn fetch(&self, have: &[Oid], wants: &[Oid]) -> Result<Vec<u8>, String> {
                let left = self.fetches_before_failure.get();
                if left == 0 {
                    return Err("transport died mid-pull".into());
                }
                self.fetches_before_failure.set(left - 1);
                self.inner.fetch(have, wants)
            }
        }

        // One change with more objects than a single batch carries.
        let dir_a = std::env::temp_dir().join(format!("loot-resume-a-{}", std::process::id()));
        let mut alice = authored_ws(&dir_a);
        for i in 0..40 {
            std::fs::write(dir_a.join(format!("f{i}.txt")), format!("content {i}")).unwrap();
        }
        alice.snapshot("forty files").unwrap();
        alice.finalize_working().unwrap();
        let (relay_dir, relay) = relay_holding("resume", &alice);

        let dir_b = std::env::temp_dir().join(format!("loot-resume-b-{}", std::process::id()));
        let mut bob = authored_ws(&dir_b);

        let flaky = FlakyTransport {
            inner: relay,
            fetches_before_failure: std::cell::Cell::new(1), // batch 1 lands, batch 2 dies
        };
        let err = bob.pull_via(&flaky).unwrap_err();
        assert!(err.contains("transport died"), "the failure surfaces: {err}");

        // Resume over a healthy transport: negotiation finds only the rest.
        // (Negotiation must use COMPLETE heads — the #217 find: the partial
        // pull already ingested the change node, and claiming it as `have`
        // would make the relay offer nothing, stranding the pull forever.)
        let relay = flaky.inner;
        let offered = relay.offer(&bob.repo().negotiation_have()).unwrap();
        let still_missing = bob.missing_objects(&offered).len();
        assert!(
            still_missing > 0 && still_missing < 40,
            "the first batch persisted; only the remainder is re-fetched (missing {still_missing})"
        );
        bob.pull_via(&relay).unwrap();
        assert_eq!(bob.heads(), alice.heads(), "resumed to convergence");
        assert!(
            bob.missing_objects(&relay.offer(&bob.repo().negotiation_have()).unwrap()).is_empty(),
            "nothing left dangling after the resume"
        );
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
        let _ = std::fs::remove_dir_all(&relay_dir);
    }

    #[test]
    fn pull_over_a_dirty_tree_captures_edits_and_defers_a_divergent_pull() {
        // #219 done-when (1): a divergent pull run over a DIRTY tree captures
        // the uncaptured edits into the working change FIRST (capture-first,
        // ADR 0030 amendment), so ingest still lands the peer's co-version and
        // the `!` divergence stays flat — but converge WAITS (the working-change
        // guard), the tree is never clobbered, and `deferred` carries the note.
        use loot_core::Repo as _;
        let dir_a = std::env::temp_dir().join(format!("loot-219div-a-{}", std::process::id()));
        let mut alice = authored_ws(&dir_a);
        std::fs::write(dir_a.join("feat.txt"), b"feat: base").unwrap();
        alice.snapshot("add feat").unwrap();
        alice.finalize_working().unwrap();
        let cid = alice.repo().change_change_id(&alice.heads()[0]).unwrap();
        let (relay_dir, mut relay) = relay_holding("219div", &alice);

        let dir_b = std::env::temp_dir().join(format!("loot-219div-b-{}", std::process::id()));
        let mut bob = authored_ws(&dir_b);
        bob.pull_via(&relay).unwrap();
        bob.surface().unwrap();

        // Concurrent amends of the SAME handle; bob finalizes his own line.
        alice.edit(&loot_core::hex::letters(&cid)).unwrap();
        std::fs::write(dir_a.join("feat.txt"), b"feat: alice's take").unwrap();
        alice.snapshot("add feat").unwrap();
        alice.finalize_working().unwrap();
        relay.0.stow(&alice.repo().bundle(&[]).unwrap()).unwrap();

        bob.edit(&loot_core::hex::letters(&cid)).unwrap();
        std::fs::write(dir_b.join("feat.txt"), b"feat: bob's take").unwrap();
        bob.snapshot("add feat").unwrap();
        bob.finalize_working().unwrap();

        // Uncaptured edit on disk when the divergent pull arrives.
        std::fs::write(dir_b.join("notes.txt"), b"scratch").unwrap();
        let report = bob.pull_via(&relay).unwrap();

        // Deferred: a working change captured the edit, heads left unconverged.
        let captured = report.deferred.expect("the pull deferred convergence with a note");
        assert_eq!(bob.working_id(), Some(&captured), "the edit landed in the working change");
        assert_eq!(
            bob.repo().change_tree(&captured).unwrap().keys().cloned().collect::<Vec<_>>(),
            vec![PathBuf::from("feat.txt"), PathBuf::from("notes.txt")],
            "notes.txt was captured, not clobbered"
        );
        // Ingest happened; the divergence renders flat, tree untouched on disk.
        assert!(bob.divergent_change_ids().contains(&cid), "the ! marker state renders");
        assert!(bob.repo().conflicts().is_empty(), "no per-path conflict is minted");
        assert_eq!(std::fs::read(dir_b.join("feat.txt")).unwrap(), b"feat: bob's take");
        assert_eq!(std::fs::read(dir_b.join("notes.txt")).unwrap(), b"scratch");
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
        let _ = std::fs::remove_dir_all(&relay_dir);
    }

    #[test]
    fn pull_over_a_dirty_tree_ingests_without_converging_then_converges_after_finalize() {
        // #219 done-when (2): a dirty-tree pull that brings an INDEPENDENT head
        // ingests it (graph append is always safe) but does NOT converge — the
        // captured working change defers the fold. After the operator finalizes
        // (`loot new`) and re-pulls, the now-clean tree converges the two lines.
        use loot_core::Repo as _;
        let dir_a = std::env::temp_dir().join(format!("loot-219ind-a-{}", std::process::id()));
        let mut alice = authored_ws(&dir_a);
        std::fs::write(dir_a.join("shared.txt"), b"shared").unwrap();
        alice.snapshot("shared").unwrap();
        alice.finalize_working().unwrap();
        let (relay_dir, mut relay) = relay_holding("219ind", &alice);

        let dir_b = std::env::temp_dir().join(format!("loot-219ind-b-{}", std::process::id()));
        let mut bob = authored_ws(&dir_b);
        bob.pull_via(&relay).unwrap();
        bob.surface().unwrap();

        // Bob advances his own line; alice advances an INDEPENDENT line (both
        // fork from `shared`, so the two heads are a genuine two-writer fork).
        std::fs::write(dir_b.join("bob.txt"), b"B").unwrap();
        bob.snapshot("bob line").unwrap();
        bob.finalize_working().unwrap();
        std::fs::write(dir_a.join("alice.txt"), b"A").unwrap();
        alice.snapshot("alice line").unwrap();
        alice.finalize_working().unwrap();
        relay.0.stow(&alice.repo().bundle(&[]).unwrap()).unwrap();

        // Uncaptured edit, then the pull: it ingests alice's head but defers.
        std::fs::write(dir_b.join("scratch.txt"), b"wip").unwrap();
        let report = bob.pull_via(&relay).unwrap();
        assert!(report.deferred.is_some(), "the dirty pull deferred the fold");
        assert!(bob.working_id().is_some(), "the edit was captured");
        assert_eq!(bob.heads().len(), 2, "alice's head ingested; the fork stands unconverged");
        assert!(!dir_b.join("alice.txt").exists(), "converge waited — alice's file not yet materialized");
        assert_eq!(std::fs::read(dir_b.join("scratch.txt")).unwrap(), b"wip", "the edit is intact");

        // Finalize, then re-pull: the clean tree now converges the two lines.
        bob.finalize_working().unwrap();
        let report = bob.pull_via(&relay).unwrap();
        assert!(report.deferred.is_none(), "a clean re-pull converges");
        assert_eq!(bob.heads().len(), 1, "the independent lines folded onto one");
        assert_eq!(std::fs::read(dir_b.join("alice.txt")).unwrap(), b"A", "alice's line materialized");
        assert_eq!(std::fs::read(dir_b.join("bob.txt")).unwrap(), b"B", "bob's line kept");
        assert_eq!(std::fs::read(dir_b.join("scratch.txt")).unwrap(), b"wip", "the captured edit carried");
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
        let _ = std::fs::remove_dir_all(&relay_dir);
    }

    #[test]
    fn pull_captures_a_delete_all_edit_rather_than_refusing() {
        // #219 regression: an empty disk is only "not dirt" when a transfer is
        // mid-flight (the anchor's closure is incomplete). A genuine delete-all
        // over a fully-held tip is a real uncaptured edit — it must CAPTURE (so
        // the deletion is not lost) and DEFER, never refuse (refuse-on-dirt is
        // rejected for pull/apply).
        use loot_core::Repo as _;
        let dir_a = std::env::temp_dir().join(format!("loot-219del-a-{}", std::process::id()));
        let mut alice = authored_ws(&dir_a);
        std::fs::write(dir_a.join("shared.txt"), b"shared").unwrap();
        alice.snapshot("shared").unwrap();
        alice.finalize_working().unwrap();
        let (relay_dir, mut relay) = relay_holding("219del", &alice);

        let dir_b = std::env::temp_dir().join(format!("loot-219del-b-{}", std::process::id()));
        let mut bob = authored_ws(&dir_b);
        bob.pull_via(&relay).unwrap();
        bob.surface().unwrap();
        std::fs::write(dir_b.join("bob.txt"), b"B").unwrap();
        bob.snapshot("bob line").unwrap();
        bob.finalize_working().unwrap();

        // Alice advances an independent line the pull will bring.
        std::fs::write(dir_a.join("alice.txt"), b"A").unwrap();
        alice.snapshot("alice line").unwrap();
        alice.finalize_working().unwrap();
        relay.0.stow(&alice.repo().bundle(&[]).unwrap()).unwrap();

        // Delete every tracked file — an uncaptured edit — then pull.
        std::fs::remove_file(dir_b.join("shared.txt")).unwrap();
        std::fs::remove_file(dir_b.join("bob.txt")).unwrap();
        let report = bob.pull_via(&relay).expect("a delete-all pull captures, never refuses");
        let captured = report.deferred.expect("the deletion was captured and converge deferred");
        assert!(
            bob.repo().change_tree(&captured).unwrap().is_empty(),
            "the working change records the delete-all (an empty tree)"
        );
        assert!(!dir_b.join("shared.txt").exists(), "the deletion was not clobbered back");
        assert!(!dir_b.join("bob.txt").exists(), "…nor bob.txt");
        assert!(!dir_b.join("alice.txt").exists(), "converge deferred — nothing re-materialized");
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
        let _ = std::fs::remove_dir_all(&relay_dir);
    }

    #[test]
    fn converge_refuses_to_materialize_over_uncaptured_edits() {
        // #219 done-when (3): the tree-write chokepoint. A converge that WOULD
        // fold a fork refuses when the disk holds uncaptured edits rather than
        // clobbering them — the backstop behind capture-first. The refusal is
        // atomic: no side is merged, both heads survive.
        let (dir, mut ws) = dock_repo("219choke");
        std::fs::write(dir.join("base.txt"), b"base").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();
        ws.dock_goto("peer").unwrap();
        std::fs::write(dir.join("their.txt"), b"T").unwrap();
        ws.snapshot("theirs").unwrap();
        ws.finalize_working().unwrap();
        ws.dock_goto("main").unwrap();
        std::fs::write(dir.join("ours.txt"), b"O").unwrap();
        ws.snapshot("ours").unwrap();
        ws.finalize_working().unwrap();
        assert!(ws.repo().heads().len() >= 2, "precondition: a real two-writer fork");

        // Skip capture-first (a direct converge): scribble an uncaptured edit.
        let heads_before = ws.repo().heads().len();
        std::fs::write(dir.join("ours.txt"), b"O edited but not captured").unwrap();
        let ours = ws.anchor();
        let err = ws.converge_heads(ours.as_ref()).unwrap_err();
        assert!(err.contains("uncaptured"), "unexpected refusal: {err}");
        assert_eq!(ws.repo().heads().len(), heads_before, "refusal is atomic — no side merged");
        assert_eq!(
            std::fs::read(dir.join("ours.txt")).unwrap(),
            b"O edited but not captured",
            "the uncaptured edit was not clobbered"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn converge_heads_leaves_divergent_co_versions_flat() {
        // #198/#203: two live versions of one change id are ONE two-writer
        // event, already rendered by the `!` marker — converge must not
        // re-represent it as a per-path conflict on a signed merge that
        // `abandon` cannot un-mint. The co-versions stay live heads, the tip
        // stays on ours, and the tree is clean.
        let (dir, mut ws, x2, theirs, cid) = divergent_ws("convflat");
        let nodes_before = ws.repo().log_detailed().len();
        let outcomes = ws.converge_heads(Some(&x2)).unwrap();
        assert!(outcomes.is_empty(), "divergence is not a merge");
        assert_eq!(ws.repo().log_detailed().len(), nodes_before, "no merge node was minted");
        let heads = ws.repo().heads();
        assert!(
            heads.contains(&x2) && heads.contains(&theirs) && heads.len() == 2,
            "both co-versions stay flat as live heads"
        );
        assert!(ws.divergent_change_ids().contains(&cid), "the ! marker state persists");
        assert!(ws.repo().conflicts().is_empty(), "no per-path conflict is minted");
        assert_eq!(
            std::fs::read(dir.join("a.txt")).unwrap(),
            b"target amended",
            "the tree stays clean on ours"
        );

        // The canonical tree-settle: abandon the peer's side. One live version
        // remains, the tree is already the survivor's — nothing to re-merge.
        ws.abandon(&theirs).unwrap();
        assert_eq!(ws.repo().heads(), vec![x2.clone()], "the survivor is the sole head");
        assert!(!ws.divergent_change_ids().contains(&cid), "abandon collapsed the divergence");
        assert!(ws.repo().conflicts().is_empty(), "no standing conflict to settle");
        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"target amended");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn abandoning_our_own_side_materializes_the_survivor() {
        // Flat divergence means either side can be the one abandoned — including
        // the version the ambient dock sits on. The dock must hop to the
        // survivor and materialize its tree, not keep forking from a dead tip.
        let (dir, mut ws, x2, theirs, cid) = divergent_ws("convflat-ours");
        ws.converge_heads(Some(&x2)).unwrap();
        ws.abandon(&x2).unwrap();
        assert_eq!(ws.repo().heads(), vec![theirs.clone()], "the peer's side survives");
        assert!(!ws.divergent_change_ids().contains(&cid));
        assert!(
            !dir.join("a.txt").exists(),
            "the survivor's tree materialized (its empty tree pruned ours)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn converge_heads_skips_a_sibling_docks_parked_working_change() {
        // The bd926e81 specimen (#199 finding → #203): a dock switched away
        // from mid-work leaves its unsigned working change parked as a head in
        // the shared graph. Converge on another dock must not fold that
        // in-flight WIP into a content-merge — the parked dock's next snapshot
        // rewrites it in place.
        let (dir, mut ws) = dock_repo("convpark");
        std::fs::write(dir.join("base.txt"), b"base").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();

        ws.dock_goto("side").unwrap();
        std::fs::write(dir.join("side.txt"), b"parked WIP").unwrap();
        ws.snapshot("side wip").unwrap(); // in progress, never finalized
        ws.dock_goto("main").unwrap(); // parks it on the side dock
        let parked = ws
            .store()
            .read_working(Some("side"))
            .expect("the side dock parked its working change");

        // main advances so a real fork exists beside the parked WIP.
        std::fs::write(dir.join("ours.txt"), b"O").unwrap();
        ws.snapshot("ours").unwrap();
        ws.finalize_working().unwrap();

        let nodes_before = ws.repo().log_detailed().len();
        let ours = ws.anchor();
        let outcomes = ws.converge_heads(ours.as_ref()).unwrap();
        assert!(outcomes.is_empty(), "parked WIP is not a line to converge");
        assert_eq!(ws.repo().log_detailed().len(), nodes_before, "no merge node minted");
        assert!(
            ws.repo().heads().contains(&parked),
            "the parked working change stays the side dock's live head"
        );
        assert!(!dir.join("side.txt").exists(), "the parked WIP never entered main's tree");

        // The live #203 footgun: `pull` used to pass "first head" as the
        // base, handing converge the parked head as OURS — the dock's own tip
        // was then merged INTO foreign in-flight WIP. A parked base must never
        // become the merge side.
        let outcomes = ws.converge_heads(Some(&parked)).unwrap();
        assert!(outcomes.is_empty(), "a parked base never becomes the merge side");
        assert_eq!(ws.repo().log_detailed().len(), nodes_before, "still no merge node");
        assert!(ws.repo().heads().contains(&parked), "the parked head survives");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_live_version_refuses_abandoned_and_superseded_prefixes() {
        // The #216 regression: pre-Liveness, version resolution filtered
        // abandoned but NOT superseded, so a superseded version still
        // resolved by prefix. Both are dead to the live view; neither
        // resolves.
        let (dir, mut ws, x, cid) = amendable_ws("resolve-live");
        ws.edit(&loot_core::hex::letters(&cid)).unwrap();
        std::fs::write(dir.join("a.txt"), b"target amended").unwrap();
        ws.snapshot("target").unwrap();
        ws.finalize_working().unwrap();
        let x2 = ws.liveness().live_of(&cid).into_iter().next().unwrap();

        let err = ws.resolve_live_version(&loot_core::hex::encode(&x.0)).unwrap_err();
        assert!(err.contains("no live version"), "superseded must not resolve: {err}");
        assert_eq!(
            ws.resolve_live_version(&loot_core::hex::encode(&x2.0)).unwrap(),
            x2,
            "the live amend resolves"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dock_rm_reaps_a_parked_working_head_and_is_undoable() {
        // #212: the bd926e81 shape — a dock switched away from mid-work parks
        // its unsigned working change as a live head. `dock rm` drops the
        // parked head + the dock's pointers (bookkeeping, not graph surgery),
        // and one undo brings both back.
        let (dir, mut ws) = dock_repo("dockrm");
        std::fs::write(dir.join("base.txt"), b"base").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();
        ws.record_op("new", "finalize base", false); // the undo floor

        ws.dock_goto("stale").unwrap();
        ws.record_op("dock", "dock stale", false); // as cmd_dock records
        std::fs::write(dir.join("wip.txt"), b"parked").unwrap();
        ws.snapshot("stale wip").unwrap();
        ws.dock_goto("main").unwrap();
        ws.record_op("dock", "dock main", false);
        let base = ws.anchor().expect("main sits on the finalized base");
        let parked = ws.store().read_working(Some("stale")).expect("wip parked");
        assert!(ws.repo().heads().contains(&parked), "precondition: the parked WIP is a head");

        let dropped = ws.remove_dock("stale").unwrap();
        assert_eq!(dropped, Some(parked.clone()), "the parked working change is reported");
        assert!(!ws.repo().heads().contains(&parked), "the parked head is gone");
        assert_eq!(
            ws.repo().heads(),
            vec![base],
            "the base the WIP forked from is the sole head again"
        );
        assert!(!ws.store().dock_exists("stale"), "the dock's directory is gone");
        assert!(
            !ws.dock_list().iter().any(|d| d.name == "stale"),
            "the dock left the listing"
        );

        // One undo restores the dock, its pointers, and the parked head.
        ws.undo().unwrap();
        assert!(ws.store().dock_exists("stale"), "undo recreated the dock");
        assert_eq!(ws.store().read_working(Some("stale")), Some(parked.clone()));
        assert!(ws.repo().heads().contains(&parked), "undo restored the parked head");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dock_rm_without_parked_wip_removes_pointers_only() {
        // The proof-amend-divergence shape: a dock idle on a finalized tip
        // that is an ancestor of another line. Removal is pure bookkeeping —
        // heads and graph are untouched.
        let (dir, mut ws) = dock_repo("dockrm-idle");
        std::fs::write(dir.join("base.txt"), b"base").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();
        ws.dock_goto("idle").unwrap();
        ws.dock_goto("main").unwrap();
        std::fs::write(dir.join("more.txt"), b"more").unwrap();
        ws.snapshot("more").unwrap();
        ws.finalize_working().unwrap();
        let heads_before = ws.repo().heads();
        let nodes_before = ws.repo().log_detailed().len();

        let dropped = ws.remove_dock("idle").unwrap();
        assert_eq!(dropped, None, "nothing was parked, nothing dropped");
        assert_eq!(ws.repo().heads(), heads_before, "heads untouched");
        assert_eq!(ws.repo().log_detailed().len(), nodes_before, "graph untouched");
        assert!(!ws.store().dock_exists("idle"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dock_rm_refuses_home_ambient_and_unknown() {
        let (dir, mut ws) = dock_repo("dockrm-guard");
        std::fs::write(dir.join("base.txt"), b"base").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();

        let err = ws.remove_dock("main").unwrap_err();
        assert!(err.contains("default dock"), "unexpected: {err}");

        ws.dock_goto("here").unwrap();
        let err = ws.remove_dock("here").unwrap_err();
        assert!(err.contains("ambient dock"), "unexpected: {err}");

        let err = ws.remove_dock("nope").unwrap_err();
        assert!(err.contains("no such dock"), "unexpected: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dock_at_binds_a_separate_worktree_over_the_shared_store() {
        // Physical model (ADR 0022): `--at` creates a separate working directory
        // with a `.loot` pointer file at the shared store, materialized with the
        // dock's tree, without disturbing the primary.
        let (dir, mut ws) = dock_repo("worktree");
        std::fs::write(dir.join("base.txt"), b"base").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();

        let wt = std::env::temp_dir().join(format!("loot-wt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&wt);
        ws.create_dock("feature", Some(&wt)).unwrap();

        // A worktree has a `.loot` pointer *file* (not a dir) and the dock's tree.
        assert!(wt.join(".loot").is_file(), "worktree has a .loot pointer file");
        assert!(wt.join("base.txt").exists(), "dock tree materialized into worktree");

        // Opening the worktree loads the shared store on dock `feature`; the
        // primary is untouched (still the default `main` dock).
        let wtws = Workspace::open_at(&wt).unwrap();
        assert_eq!(wtws.current_dock(), Some("feature"));
        assert_eq!(ws.current_dock(), None, "primary stays on the default dock");

        let _ = std::fs::remove_dir_all(&wt);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
