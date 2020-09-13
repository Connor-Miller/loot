//! Workspace — the process-bound ambient repo (ADR 0006).
//!
//! Owns everything a command needs but shouldn't re-derive: where `.loot/` is,
//! the current identity, the clock, the loaded engine, and the id of the
//! *working change* being rewritten in place. Commands are thin verbs over it.
//!
//! The snapshot invariant itself lives in the engine (`DagRepo::snapshot`); the
//! Workspace only reads the working tree + `.lootattributes` into the entries
//! the engine reconciles, and persists state after a mutation.

use crate::position::Position;
use crate::reconcile::{self, REFUSE_UNDESCRIBED_PARENT};
use loot_core::bridge::{FerryState, MarkMap};
use loot_core::{
    oplog, valid_dock_name, DagRepo, LaneEntry, MergeOutcome, Oid, Operation, Repo, RepoError,
    RepoStore, Visibility, HOME_DOCK,
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
    /// Where this workspace sits — dock, lane id, pinned tip — owned by
    /// [`Position`] (#324, ADR 0034 "position is place, not state"). The
    /// primary and every lane use the root `.loot/` process files of their own
    /// store instance, so a repo that never spawns a lane is byte-for-byte
    /// unchanged on disk.
    position: Position,
    /// The working change being rewritten in place, if one is in progress.
    /// `None` right after `init` or `apply` (finalized history, no WIP change).
    working: Option<Oid>,
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
        Self::open_at_clocked(dir, real_now())
    }

    /// [`open_at`](Self::open_at) with the clock injected (#322). The engine
    /// already takes `now` as a value everywhere; this is the workspace-level
    /// twin, so an in-process test drives embargo/heartbeat timing race-free —
    /// the `LOOT_CLOCK` env override stays as the *cross-process* adapter (a
    /// spawned binary can only be reached through its environment, and the
    /// attack demo's lying-clock exhibit depends on it). Production callers use
    /// `open`/`open_at`, which pass [`real_now`].
    pub fn open_at_clocked(dir: &Path, now: u64) -> Result<Self, String> {
        let loot = dir.join(DOT);
        // A `.loot` *pointer file* (not a directory) is a retired `--at` worktree
        // dock (#253/ADR 0034): named docks are gone, so this only ever appears as
        // a dangling pointer from before the retirement. Refuse with the remedy.
        if loot.is_file() {
            return Err(format!(
                "{} is a retired `--at` worktree-dock pointer (named docks are gone, \
                 ADR 0034/#253). Delete this directory and use `loot lane new` for a \
                 sealed position over the shared store.",
                dir.display()
            ));
        }
        // A spawned lane's `.loot` is a *directory* whose `store` file points at
        // the shared store; every lane-owned file lives here (ADR 0034).
        if let Some(shared) = RepoStore::read_store_pointer(&loot) {
            return Self::open_lane(dir, &loot, &shared, now);
        }
        let store = RepoStore::new(&loot);
        if !store.identity().exists() {
            return Err(format!(
                "not a loot repo at {} (no .loot/). Run `loot init` first.",
                dir.display()
            ));
        }
        let dock = store.read_dock();
        Self::assemble(loot, store, dir.to_path_buf(), dock, None, now)
    }

    /// Load a spawned lane: position is place (ADR 0034) — the cwd's `.loot`
    /// directory carries the lane's private mutable state, `shared` the
    /// append-only store. Refreshes the lane's registry heartbeat (the gc-sweep
    /// signal); the touch is best-effort and self-healing.
    fn open_lane(dir: &Path, lane_dot: &Path, shared: &Path, now: u64) -> Result<Self, String> {
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
        let _ = store.touch_lane_heartbeat(&lane_id, dir, now);
        let dock = store.read_dock();
        Self::assemble(shared.to_path_buf(), store, dir.to_path_buf(), dock, Some(lane_id), now)
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
        now: u64,
    ) -> Result<Self, String> {
        let mut repo = DagRepo::load_from(&store, root.clone()).map_err(|e| e.to_string())?;
        let identity = read_to_string(&store.identity())?;
        let position = Position::load(&store, dock, lane_id);
        let working = store.read_working(position.dock_opt());
        let next_change_id = store.read_next_change(position.dock_opt());
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
            position,
            working,
            next_change_id,
            signer,
            now,
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

    /// The position's working directory — where this workspace's tree
    /// materializes: the lane (or `--at` worktree) dir for a spawned position,
    /// the checkout itself for the primary. Distinct from [`Workspace::dot`],
    /// which is always the *shared* store's `.loot/` (identity and keys are
    /// shared across positions, ADR 0034) — deriving a working root from
    /// `dot()` is exactly how loot-first's pre-land gate ended up testing the
    /// primary's tree on a lane land (#287).
    pub fn root(&self) -> &std::path::Path {
        &self.root
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

    /// Narrow a [`HistoryView`] to the rows whose recorded tree includes
    /// `path` (#6, `loot log --path`) — a straight filter over the same
    /// per-change full tree `log_detailed` already sizes, not a new walk.
    /// Every row (the flat listing, each fork lane, and the shared section)
    /// is filtered identically, so visibility hints and every other column
    /// a surviving row carries are untouched — only membership changes. The
    /// live working row survives only when the *current* working tree (not
    /// its last sealed version, which may predate an uncaptured edit) holds
    /// the path — checked directly against its `entries`, not the graph, so
    /// this works whether or not the working change has been snapshotted.
    ///
    /// Composes with selector scoping (`loot log <selector>`, #315): apply
    /// both filters and the result is their intersection — order does not
    /// matter, `retain` is commutative here.
    pub fn filter_history_to_path(&self, view: &mut HistoryView, path: &Path) {
        let touches = |id: &Oid| self.repo.change_has_path(id, path);
        view.rows.retain(|r| touches(&r.version));
        if let Some(g) = &mut view.graph {
            for lane in &mut g.per_head {
                lane.retain(|r| touches(&r.version));
            }
            g.shared.retain(|r| touches(&r.version));
        }
        if let Some(w) = &view.working {
            if !w.entries.iter().any(|(p, _)| p.as_path() == path) {
                view.working = None;
            }
        }
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

    /// A path's most recently recorded `(oid, visibility)` — current tree
    /// first, else searched across all of history (`loot embargo-status`,
    /// #15). `None` if `path` never appears in any recorded change.
    pub fn path_history_entry(&self, path: &Path) -> Option<(Oid, Visibility)> {
        self.repo.path_history_entry(path)
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
    /// resumable transfer — each batch stows independently, ADR 0024). A batch
    /// closes at `per_batch` objects or `batch_bytes` of ciphertext (#309).
    pub fn bundle_wanted_batched(
        &self,
        have: &[Oid],
        wants: &[Oid],
        per_batch: usize,
        batch_bytes: usize,
    ) -> Result<Vec<loot_core::SyncBundle>, String> {
        self.repo
            .bundle_wanted_batched(have, wants, per_batch, batch_bytes)
            .map_err(|e| e.to_string())
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
                // Push-time embargo deposits (ADR 0027) don't set an explicit
                // grant expiry — only the embargo's own reveal_at applies.
                .grant_sealed(&oid, &peer, peer_pubkey, grantor_pubkey, reveal_at, None, now, seal)
                .map_err(|e| e.to_string())?;
            deliver(bundle.0)
        })
    }

    /// The rotation re-grant wave (`loot id rotate`, #16): re-issue every
    /// still-live grant this identity holds as a targeted bundle for the new
    /// key's machine(s), each carrying its original `expires_at` exactly
    /// (#20), then persist. Reads the Manifest, not the working tree — no
    /// snapshot handle needed (ADR 0030 guards tree capture, and rotation
    /// captures nothing from disk).
    pub fn rotate_regrants(&mut self) -> Result<loot_core::RotateReport, String> {
        let now = self.now;
        self.with_repo(|repo| repo.rotate_regrants(now).map_err(|e| e.to_string()))
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
        let tip = self.position.tip().cloned();
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

    /// The working change's message, or [`UNDESCRIBED_MESSAGE`] when nobody has
    /// named it. The carry-along captures (dock switch, adopt, ferry, merge) all
    /// re-record the tree *under the name it already has*, so they share this —
    /// it is the one place the placeholder is minted.
    pub fn working_message_or_placeholder(&self) -> String {
        self.working_message().unwrap_or_else(|| UNDESCRIBED_MESSAGE.to_string())
    }

    /// Has nobody named the working change yet? Both shapes of "un-described"
    /// are the same state: no message at all (a capture `new` is about to make),
    /// and [`UNDESCRIBED_MESSAGE`] (a carry-along capture already stored it).
    /// [`finalize_capturing`](Self::finalize_capturing) refuses on this (#174).
    fn working_is_undescribed(&self) -> bool {
        self.working_message().is_none_or(|m| is_undescribed(&m))
    }

    /// Nothing signs an un-described change (#174, extended to the merges by
    /// #275) — one rule, two refusals, because the two callers must explain
    /// themselves very differently. [`REFUSE_UNDESCRIBED`] answers a deliberate
    /// `loot new`; [`REFUSE_UNDESCRIBED_PARENT`] answers a merge that seals the
    /// operator's work as a parent in passing, where a bare "name it" would
    /// read as a non-sequitur. This helper's sole remaining caller is
    /// `fold_line_in` (`loot dock merge` / the `loot adopt` catch-up); the
    /// `loot ferry` reconcile asks the same question through
    /// [`crate::reconcile::decide`] instead (#325) — same wording
    /// ([`crate::reconcile::Refusal::UndescribedParent`] returns this exact
    /// constant), decided in the pure planner rather than here.
    ///
    /// The merge *nodes* those paths mint (`merge_tips`) never come through here:
    /// they are machine-authored and carry an honest mechanical subject.
    ///
    /// Every caller must sit **below** its capture (so the refusal costs the
    /// signature, never the work) and **below** its redundant-capture drop (see
    /// [`drop_capture_if_redundant`](Self::drop_capture_if_redundant)) — a pass
    /// with no real work to sign must stay a no-op, not become a nag.
    fn refuse_if_undescribed(&self, refusal: &str) -> Result<(), String> {
        if self.working.is_some() && self.working_is_undescribed() {
            return Err(refusal.to_string());
        }
        Ok(())
    }

    /// Drop the working capture `id` when it adds nothing over `against` (the
    /// tip, and for the bridge the incoming target too): manifest-identical —
    /// same path set AND same content — to something already held. Returns
    /// whether it was dropped.
    ///
    /// The shared shape behind three sites that must not mint a redundant signed
    /// change: `finalize_capturing` (a bare `new` on a clean tree), `fold_line_in`
    /// (a `dock merge` with nothing pending), and `reconcile_capture` (the
    /// co-located checkout after a `git pull` already holds the incoming tree).
    /// It is also what keeps [`refuse_if_undescribed`](Self::refuse_if_undescribed)
    /// honest — without it, those passes would demand a name for work that does
    /// not exist.
    ///
    /// Deletions count (#289): the judgment compares recorded manifests, so a
    /// capture that only *deletes* paths is real work, never a tip-duplicate.
    /// Likewise an **empty** capture is redundant only when there is nothing
    /// held to compare against (a bare `new` in a fresh repo) — over a
    /// non-empty tip it is a delete-everything change, and `same_tree_content`
    /// already equates it with a tip whose manifest is itself empty.
    fn drop_capture_if_redundant(&mut self, id: &Oid, against: &[&Oid]) -> Result<bool, String> {
        let redundant = if against.is_empty() {
            self.repo.change_tree(id).is_none_or(|t| t.is_empty())
        } else {
            against.iter().any(|o| self.repo.same_tree_content(o, id, self.now))
        };
        if redundant {
            self.repo.drop_working(id);
            self.working = None;
            self.persist()?;
        }
        Ok(redundant)
    }

    /// `loot new` under implicit snapshot (ADR 0030): capture any edits made
    /// since the last command into the working change *first* — so `edit; new`
    /// never loses work — then finalize. A snapshot that adds nothing over the
    /// dock tip (manifest-identical — same paths, same content; deletions are
    /// real work, #289) is dropped rather than finalized, so a bare `loot new`
    /// does not mint an empty signed change. `--no-snapshot` skips the capture (`skip_snapshot`); the
    /// demotion guard rides the capture via `allow_demote`.
    /// Returns the finalized change's **version id**, or `None` when there was
    /// nothing to finalize (a bare `new` whose capture added nothing over the
    /// tip) — so `loot new` can name the finalized version alongside the freshly
    /// minted next change id.
    ///
    /// **Refuses an un-described change** ([`REFUSE_UNDESCRIBED`], #174): this is
    /// the signing boundary, and a signed change's message is permanent — it
    /// becomes the subject of the commit projected onto git `main`. The refusal
    /// lands *after* the capture, so the edits are held safely in the working
    /// change; only the signature is withheld, and `describe -m` clears it.
    pub fn finalize_capturing(
        &mut self,
        allow_demote: &[PathBuf],
        skip_snapshot: bool,
    ) -> Result<Option<Oid>, String> {
        self.finalize_capturing_allowing(allow_demote, &[], skip_snapshot).map(|(id, _)| id)
    }

    /// [`finalize_capturing`](Self::finalize_capturing) with the mis-seal
    /// override threaded through (#353): the full finalize seam. Every
    /// capture-and-sign — `loot new`, the amend re-finalize after `loot edit`,
    /// and `loot-first land` — funnels through here, so the mis-seal gate
    /// (#63, ADR 0038 §1) runs at the seam itself and no verb can miss it.
    /// Returns the finalized version id (as `finalize_capturing`) plus the
    /// gate's first-seal summary, computed at the moment of signing.
    pub fn finalize_capturing_allowing(
        &mut self,
        allow_demote: &[PathBuf],
        allow_reveal: &[PathBuf],
        skip_snapshot: bool,
    ) -> Result<(Option<Oid>, Vec<(PathBuf, Visibility)>), String> {
        // The mis-seal gate (#63/#353, ADR 0038 §1) at the signing seam: refuse
        // a first-time public-by-fallthrough seal of a secret-shaped path
        // before anything is captured or signed. Running it here (not only in
        // the verbs) is what closes the amend re-finalize and `loot-first
        // land`, which reach this seam without passing through `cmd_new`.
        let first_seals = self.seal_gate(allow_reveal)?;
        if !skip_snapshot {
            let msg = self.working_message().unwrap_or_else(|| UNDESCRIBED_MESSAGE.to_string());
            let (id, _) = self.snapshot_allowing(&msg, allow_demote)?;
            let anchor = self.anchor();
            self.drop_capture_if_redundant(&id, anchor.as_ref().as_slice())?;
        }
        // Sits below the empty/duplicate drop above: a bare `new` on a clean tree
        // has no working change left by here, mints no signed change, and so has
        // no subject to get wrong — it must stay a no-op, not become a refusal.
        self.refuse_if_undescribed(REFUSE_UNDESCRIBED)?;
        let finalized = self.working.clone();
        self.finalize_working()?;
        Ok((finalized, first_seals))
    }

    /// The **mis-seal gate** (#63, ADR 0038 §1) — run at every signing seam:
    /// inside [`finalize_capturing_allowing`](Self::finalize_capturing_allowing)
    /// (`loot new`, the amend re-finalize after `loot edit`, `loot-first
    /// land`), at `fold_line_in`'s and `reconcile_onto`'s wip-signing steps
    /// (#353), and as `describe`'s pre-capture preflight. Two guarantees in one
    /// pass over the working tree, both content-agnostic (name + resolution
    /// provenance only, never plaintext):
    ///
    /// - **Refusal.** A path whose basename is [secret-shaped](SECRET_NAMES),
    ///   that resolves Public *by fallthrough* (the default or a catch-all, not
    ///   an explicit `.lootattributes` rule naming it), and is being sealed for
    ///   the **first time** (absent from the finalized anchor tree) is refused
    ///   with [`RepoError::MisSeal`] — unless the operator listed it in
    ///   `allow_reveal` (the `--allow-reveal <path>` override, mirroring
    ///   `--allow-demote`). First-seal scoping mirrors the demotion guard's
    ///   history-relative nature (#62): once a path is in the anchor the gate is
    ///   silent, so an override (or an explicit rule) is a one-time ceremony and
    ///   carry-along captures (ferry/adopt/merge) never re-trip it.
    /// - **First-seal summary.** Returns every never-before-sealed path with its
    ///   resolved visibility, so `new` can print what it is about to seal for the
    ///   first time — surfacing surprises even outside the secret-name set.
    ///
    /// A read-only preflight: it never mutates the store, so the subsequent
    /// capture sees the same disk tree it vetted.
    pub fn seal_gate(&self, allow_reveal: &[PathBuf]) -> Result<Vec<(PathBuf, Visibility)>, String> {
        let anchor_tree = self
            .anchor()
            .and_then(|a| self.repo.change_tree(&a))
            .unwrap_or_default();
        let items = read_seal_provenance(&self.root)?;
        let mut refusals: Vec<String> = Vec::new();
        let mut first_seals: Vec<(PathBuf, Visibility)> = Vec::new();
        for (path, vis, fallthrough) in items {
            // A path already in the finalized anchor is not a first seal —
            // it was vetted (and sealed) when it first appeared.
            if anchor_tree.contains_key(&path) {
                continue;
            }
            first_seals.push((path.clone(), vis.clone()));
            if is_secret_name(&path)
                && matches!(vis, Visibility::Public)
                && fallthrough
                && !allow_reveal.iter().any(|p| p == &path)
            {
                refusals.push(path.display().to_string());
            }
        }
        if !refusals.is_empty() {
            return Err(RepoError::MisSeal { paths: refusals }.to_string());
        }
        Ok(first_seals)
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
        // A seeded tip must always advance, even on the pristine-looking home
        // dock — `Position::tracks_tip` names the predicate and the stuck-tip
        // bug class it exists for (#229, #234, #265).
        if self.position.tracks_tip() {
            if self.working.is_some() {
                self.position.advance(&self.store, self.working.take());
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
            .or_else(|| self.position.tip().cloned())
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
        let message = self.working_message_or_placeholder();
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
                // Same manifest judgment as the finalize drop (#289): a
                // deletion-only (or delete-everything) working change is NOT
                // empty; an empty manifest reads empty only with no anchor to
                // have deleted from.
                let empty = match base.as_ref() {
                    Some(a) => self.repo.same_tree_content(a, w, self.now),
                    None => self.repo.change_tree(w).is_none_or(|t| t.is_empty()),
                };
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

    /// Roll back changes an aborting ferry pass minted (#307): walk them into
    /// the abandoned set, children first, so no dangling ingested head
    /// survives the abort — the next `snapshot` would fold such a head under
    /// the working change, making `anchor()` claim the dock covers git main
    /// while the disk never materialized it. The nodes stay in the shared
    /// graph (append-only union store, like every abandonment); the re-run
    /// simply re-ingests. This is the recovery ritual the live incident ran
    /// by hand (`loot abandon --head` to the fixpoint), mechanized.
    pub fn rollback_ingested(&mut self, minted: &[Oid]) -> Result<(), String> {
        if minted.is_empty() {
            return Ok(());
        }
        let mut abandoned = self.store.read_abandoned();
        for id in minted.iter().rev() {
            self.repo.abandon_head(id);
            abandoned.insert(id.clone());
        }
        self.store
            .write_abandoned(&abandoned)
            .map_err(|e| format!("write abandoned: {e}"))?;
        self.persist()
    }

    /// Load `tip`'s lineage from the shared graph into this position's view
    /// ([`DagRepo::ingest_shared_lineage`], the #265 catch-up primitive),
    /// returning whether the tip is now loaded. Named "load", not "ingest":
    /// on the bridge, ingest means minting persistent changes — this is a
    /// view catch-up, not a store mutation, and nothing persists. It is the
    /// bridge's guard before composing an ingest: a change landed from a lane
    /// sits outside the lineage-filtered load, and composing over its
    /// silently-missing tree minted a delta-only change that read as a tree
    /// wipe (#307).
    pub fn load_shared_lineage(&mut self, tip: &Oid) -> Result<bool, String> {
        self.repo.ingest_shared_lineage(&self.store, tip).map_err(|e| e.to_string())
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
            let msg = self.working_message_or_placeholder();
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
        let _ =
            oplog::record(&self.store, command, self.position.dock_name(), description, barrier, self.now);
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
        let stepped = f(&self.store, self.position.dock_name(), self.now).map_err(step_error)?;
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
            .or_else(|| self.position.tip().cloned())
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
            .or_else(|| self.position.tip().cloned())
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
    /// graph plus this store's abandoned set — everything the rule behind the
    /// `!` marker needs, in one place. Build once per operation; queries answer
    /// from the cached view. Public because it IS the read interface for
    /// liveness questions (version resolution in the CLI included).
    ///
    /// No parked working changes feed in anymore (#253/ADR 0034): with named
    /// docks retired, the only other positions are sealed lanes whose unsigned
    /// WIP is lane-local and never visible here — there is no cross-position
    /// parked head for this position to skip.
    pub fn liveness(&self) -> loot_core::Liveness {
        self.repo.liveness(&self.store.read_abandoned(), &[])
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

    /// Resolve a change **selector** (#305 "git-lite" grammar) to a **version
    /// id** — a tree, since the verbs that take a selector (`loot diff`, and any
    /// future change-taking verb) compare trees. The grammar, and its refusals,
    /// which never guess: every failure names the exact ids to paste next.
    ///
    /// | `@`        | the working change                                       |
    /// | `HEAD`     | the dock's tip — errors, listing the heads, if diverged  |
    /// | `HEAD~n`   | the n-th ancestor on a single-parent chain — errors, naming the parents, at a merge |
    /// | `<prefix>` | an id prefix; the **alphabet self-selects the namespace** (ADR 0029) — hex digits → a version id ([`resolve_live_version`]), letters `k–z` → a change id resolved *through liveness* to its live version (a divergent change errors, naming the versions) |
    ///
    /// [`resolve_live_version`]: Workspace::resolve_live_version
    pub fn resolve_selector(&self, sel: &str) -> Result<Oid, String> {
        // `@` — the working change (its live version's tree).
        if sel == "@" {
            return self.working.clone().ok_or_else(|| {
                "@ names the working change, but there is none \
                 (run `loot describe -m \"<subject>\"` to start one)"
                    .to_string()
            });
        }
        // `HEAD` / `HEAD~n` — the dock tip and its single-parent ancestors.
        if sel == "HEAD" {
            return self.resolve_head();
        }
        if let Some(rest) = sel.strip_prefix("HEAD~") {
            let n: usize = rest
                .parse()
                .map_err(|_| format!("HEAD~<n>: '{rest}' is not a number"))?;
            return self.walk_single_parent(self.resolve_head()?, n);
        }
        // `<prefix>` — the alphabet self-selects the namespace (ADR 0029). The
        // version alphabet (`0–9a–f`) and the change alphabet (`k–z`) are
        // disjoint, so a prefix is never ambiguous about *which* namespace.
        if !sel.is_empty() && sel.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)) {
            return self.resolve_live_version(sel);
        }
        if !sel.is_empty() && sel.chars().all(|c| ('k'..='z').contains(&c)) {
            return self.resolve_change_to_version(sel);
        }
        Err(format!(
            "'{sel}' is not a valid selector — use @ (working change), HEAD, HEAD~<n>, \
             a version-id prefix (hex digits), or a change-id prefix (letters k–z)"
        ))
    }

    /// The dock's tip for `HEAD` (see [`resolve_selector`](Self::resolve_selector)):
    /// the finalized change the dock sits on — [`anchor`](Self::anchor), which is
    /// the pinned tip (dock/lane), else the working change's finalized *parent*
    /// (never the working node itself — that is `@`), else the sole head.
    /// Refuses honestly when the dock has diverged onto several heads with no
    /// working change or pinned tip to disambiguate — naming them to paste.
    fn resolve_head(&self) -> Result<Oid, String> {
        if self.position.tip().is_none() && self.working.is_none() {
            let heads = self.heads();
            if heads.len() > 1 {
                let ids: Vec<String> = heads.iter().map(short_version).collect();
                return Err(format!(
                    "HEAD is ambiguous — the dock has diverged onto {} heads; name one: {}",
                    heads.len(),
                    ids.join(", ")
                ));
            }
        }
        self.anchor().ok_or_else(|| "HEAD: this dock has no finalized change yet".to_string())
    }

    /// Walk `n` parent edges from `start` for `HEAD~n`, one parent at a time.
    /// A merge (a node with several parents) has no single `~` ancestor, and a
    /// walk that reaches a root before `n` steps has none either — both refuse
    /// with the ids to use instead, never a guess.
    fn walk_single_parent(&self, start: Oid, n: usize) -> Result<Oid, String> {
        let mut cur = start;
        for step in 0..n {
            let parents = self.repo.parents_of(&cur);
            match parents.len() {
                0 => {
                    return Err(format!(
                        "HEAD~{n}: reached the root after {step} step(s) — {} has no parent",
                        short_version(&cur)
                    ))
                }
                1 => cur = parents.into_iter().next().unwrap(),
                _ => {
                    let ids: Vec<String> = parents.iter().map(short_version).collect();
                    return Err(format!(
                        "HEAD~{n}: {} is a merge with {} parents — no single ~ ancestor; name one: {}",
                        short_version(&cur),
                        parents.len(),
                        ids.join(", ")
                    ))
                }
            }
        }
        Ok(cur)
    }

    /// Resolve a change-id letter prefix to its live version, *through liveness*
    /// (#305): the durable handle names a change, but a selector must land on a
    /// tree, so this walks to the change's single live version. A divergent
    /// change (several live versions) refuses, naming them. Parallels the
    /// prefix half of [`edit`](Self::edit), which additionally gates on
    /// finalized/childless — a selector only needs the live version.
    fn resolve_change_to_version(&self, prefix: &str) -> Result<Oid, String> {
        let mut cids: std::collections::BTreeSet<[u8; 16]> = std::collections::BTreeSet::new();
        for v in self.version_ids() {
            if let Some(cid) = self.repo.change_change_id(&v) {
                if loot_core::hex::letters(&cid).starts_with(prefix) {
                    cids.insert(cid);
                }
            }
        }
        let cid = match cids.len() {
            0 => return Err(format!("no change matching '{prefix}'")),
            1 => cids.into_iter().next().unwrap(),
            n => return Err(format!("ambiguous change prefix '{prefix}' — matches {n} changes")),
        };
        let handle = loot_core::hex::short_letters(&cid, 4);
        let live = self.liveness().live_of(&cid);
        match live.len() {
            0 => Err(format!("change {handle} has no live version (abandoned or superseded)")),
            1 => Ok(live.into_iter().next().unwrap()),
            _ => {
                let ids: Vec<String> = live.iter().map(short_version).collect();
                Err(format!(
                    "change {handle} is divergent (!) — name a version: {}",
                    ids.join(", ")
                ))
            }
        }
    }

    /// The ancestor closure of `start`, `start` included (#315): `loot log
    /// <selector>`'s "scope to here", one #305 selector resolution feeding a
    /// second, independent walk. Unlike [`walk_single_parent`](Self::walk_single_parent)'s
    /// `HEAD~n` rule — which *refuses* at a merge, because "~n" has no meaning
    /// across several parents — this follows every parent edge, so a selector
    /// on a merge scopes to its whole ancestry rather than erroring. A plain
    /// stack walk over [`parents_of`](loot_core::DagRepo::parents_of); the
    /// object graph is a DAG so `seen` also bounds the walk against repeats.
    pub fn ancestors_of(&self, start: &Oid) -> std::collections::BTreeSet<Oid> {
        let mut seen = std::collections::BTreeSet::new();
        let mut stack = vec![start.clone()];
        while let Some(id) = stack.pop() {
            if seen.insert(id.clone()) {
                stack.extend(self.repo.parents_of(&id));
            }
        }
        seen
    }

    /// Compute the path-level delta between two versions' trees (`loot diff`,
    /// #1): the [`render::PathDelta`] per changed path, ordered by path. `from`
    /// is the old side, `to` the new — a path only in `to` is added, only in
    /// `from` deleted, in both with a different content address or visibility
    /// modified; an identical pair is dropped. A path the ambient identity can't
    /// read on its side is marked **sealed** so the renderer degrades it to the
    /// content address (never the plaintext name), per the #306 contract.
    pub fn diff(&self, from: &Oid, to: &Oid) -> Result<Vec<PathDelta>, String> {
        let tree_from = self.repo.change_tree(from).unwrap_or_default();
        let tree_to = self.repo.change_tree(to).unwrap_or_default();
        let visible_from: std::collections::BTreeSet<PathBuf> =
            self.repo.visible_paths_at(from, &self.identity, self.now).into_iter().collect();
        let visible_to: std::collections::BTreeSet<PathBuf> =
            self.repo.visible_paths_at(to, &self.identity, self.now).into_iter().collect();

        let mut paths: std::collections::BTreeSet<&PathBuf> = tree_from.keys().collect();
        paths.extend(tree_to.keys());

        let mut out = Vec::new();
        for path in paths {
            let delta = match (tree_from.get(path), tree_to.get(path)) {
                (None, Some((oid, vis))) => PathDelta {
                    class: DeltaClass::Added,
                    path: path.clone(),
                    oid: oid.clone(),
                    sealed: !visible_to.contains(path),
                    visibility: vis.clone(),
                    prev_visibility: None,
                },
                (Some((oid, vis)), None) => PathDelta {
                    class: DeltaClass::Deleted,
                    path: path.clone(),
                    oid: oid.clone(),
                    sealed: !visible_from.contains(path),
                    visibility: vis.clone(),
                    prev_visibility: None,
                },
                (Some((from_oid, from_vis)), Some((to_oid, to_vis))) => {
                    if from_oid == to_oid && from_vis == to_vis {
                        continue; // unchanged — diff shows only what moved
                    }
                    PathDelta {
                        class: DeltaClass::Modified,
                        path: path.clone(),
                        oid: to_oid.clone(),
                        sealed: !visible_to.contains(path),
                        visibility: to_vis.clone(),
                        prev_visibility: (from_vis != to_vis).then(|| from_vis.clone()),
                    }
                }
                (None, None) => unreachable!("path came from the union of the two trees"),
            };
            out.push(delta);
        }
        Ok(out)
    }

    /// The working change's live path-level delta over the previous finalized
    /// change (`loot status`, #7): the [`render::PathDelta`] per changed path,
    /// ordered by path. The base is implicit — the anchor the working change
    /// forks from; no anchor (the repo's first change) reads every file as
    /// added. The working side is the tree on **disk**, keeping status's
    /// read-only live semantics (ADR 0030) rather than the last captured
    /// snapshot; a disk-side row's `oid` is the live plaintext fingerprint (the
    /// `working_preview` convention), and `prev_visibility` stays `None` — the
    /// working side has one side (#306). Stored addresses move on re-seal, so
    /// "modified" is judged on plaintext + visibility — the same judgment
    /// snapshot's address-reuse makes (#98). A base path sealed to the ambient
    /// identity is carried forward untouched by snapshot (ADR 0006), so its
    /// absence from disk is not a deletion and it does not row; a deleted row
    /// keeps the base side's stored address and visibility, as `diff` does.
    pub fn working_delta(&mut self) -> Result<Vec<PathDelta>, String> {
        let base_tree = match self.anchor() {
            Some(a) => self.repo.change_tree(&a).unwrap_or_default(),
            None => Default::default(),
        };
        let (entries, _) = self.read_working_tree()?;
        let disk: BTreeMap<PathBuf, (Vec<u8>, Visibility)> =
            entries.into_iter().map(|(path, bytes, vis)| (path, (bytes, vis))).collect();
        let plain = |bytes: &[u8]| Oid(*blake3::hash(bytes).as_bytes());

        let mut paths: std::collections::BTreeSet<&PathBuf> = base_tree.keys().collect();
        paths.extend(disk.keys());

        let mut out = Vec::new();
        for path in paths {
            let delta = match (base_tree.get(path), disk.get(path)) {
                (None, Some((bytes, vis))) => PathDelta {
                    class: DeltaClass::Added,
                    path: path.clone(),
                    oid: plain(bytes),
                    sealed: false,
                    visibility: vis.clone(),
                    prev_visibility: None,
                },
                (Some((oid, vis)), None) => {
                    // Absent from disk because sealed to us, not deleted by us.
                    if self.repo.get(oid, &self.identity, self.now).is_err() {
                        continue;
                    }
                    PathDelta {
                        class: DeltaClass::Deleted,
                        path: path.clone(),
                        oid: oid.clone(),
                        sealed: false,
                        visibility: vis.clone(),
                        prev_visibility: None,
                    }
                }
                (Some((base_oid, base_vis)), Some((bytes, vis))) => {
                    let same = base_vis == vis
                        && self
                            .repo
                            .get(base_oid, &self.identity, self.now)
                            .is_ok_and(|old| old == *bytes);
                    if same {
                        continue; // unchanged — the delta shows only what moved
                    }
                    PathDelta {
                        class: DeltaClass::Modified,
                        path: path.clone(),
                        oid: plain(bytes),
                        sealed: false,
                        visibility: vis.clone(),
                        prev_visibility: None,
                    }
                }
                (None, None) => unreachable!("path came from the union of the two trees"),
            };
            out.push(delta);
        }
        Ok(out)
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
        if self.position.tip() == Some(version) {
            let survivor = live.into_iter().find(|v| v != version);
            if let Some(s) = survivor {
                self.position.advance(&self.store, Some(s));
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
        if self.position.tip() == Some(version) {
            let survivor = self
                .repo
                .heads()
                .into_iter()
                .find(|v| v != version && !abandoned.contains(v));
            self.position.advance(&self.store, survivor);
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
        // A legal target is anything on the mirror-main lineage (the fence
        // below) — but a change landed from a lane may be outside this dock's
        // lineage-filtered load entirely (#265: `adopt <version>` reported "no
        // live version" for a landed change). Pull the harbor lineage in from
        // the shared graph first so every fence-legal target resolves.
        if let Some(m) = self.mirror_main_change() {
            self.repo.ingest_shared_lineage(&self.store, &m).map_err(|e| e.to_string())?;
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

        // Already settled: T is the sole live head, the dock's anchor agrees,
        // and nothing is dirty (§4 — a no-op with a note, not an error). The
        // anchor check matters once the harbor lineage is ingested above: the
        // graph frontier moves to the landed tip immediately, but a dock whose
        // pinned tip still sits behind it has NOT settled — its disk and tip
        // must still move (#265).
        let heads = self.repo.heads();
        if !has_wip
            && heads.len() == 1
            && heads[0] == target
            && self.anchor().as_ref() == Some(&target)
        {
            return Ok(AdoptReport { target, abandoned: vec![], discarded_wip: false, already_there: true });
        }

        // T must share a line with some live head, or there is nothing to
        // settle onto (guards against emptying the dock — checked before any
        // mutation). A *descendant* of a head is a shared line too: the
        // behind-dock catch-up onto a lane-landed change (#265), where the
        // settle is forward, not across.
        let reachable = heads.iter().any(|h| {
            h == &target
                || self.graph().is_ancestor(&target, h)
                || self.graph().is_ancestor(h, &target)
        });
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
        self.position.seed(&self.store, Some(target.clone()));
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

    /// No-arg `loot adopt`: catch this dock/lane up to the harbor's landed main
    /// **by merging it in** (ADR 0034) — the fold-in counterpart to the
    /// `<version>` take-wholesale arm. The target is the harbor lineage *as a
    /// whole* (the change the mirror's `main` projects), never an arbitrary signed
    /// change; per-change adoption stays refused. No network — the objects are
    /// already in the shared store. Unlike `<version>`, this **keeps** the local
    /// line, folding it into a merge (or fast-forwarding when strictly behind).
    /// A live working change is captured and finalized into the merge, not
    /// discarded — so there is no `--discard-wip`. Allowed from a lane (its whole
    /// point is catching a lane up), so it does not `ensure_primary`.
    pub fn adopt_harbor(&mut self) -> Result<AdoptCatchupReport, String> {
        let their = self.mirror_main_change().ok_or(
            "no mirror main to catch up to — bind and `loot ferry` a mirror first, \
             or name a landed change: `loot adopt <version-id>`",
        )?;
        // The landed change may be entirely outside this dock's loaded lineage
        // (landed from a lane, never adopted here — the #265 shape): pull its
        // line in from the shared graph first, or no ancestry check below can
        // prove the fast-forward and every catch-up degenerates to a merge.
        // `false` means the shared graph lost the node (pruned before the #265
        // gc guard); the recovery for that is ferry's baseline adoption (#263).
        if !self.repo.ingest_shared_lineage(&self.store, &their).map_err(|e| e.to_string())? {
            return Err(format!(
                "landed main {} is not in the shared graph (pruned before the #265 gc \
                 guard?) — run `loot ferry` to re-adopt its content as a baseline (#263)",
                short_version(&their)
            ));
        }
        // Capture-first (#219, ADR 0030): fold any uncaptured disk edits into a
        // working change *before* we choose fast-forward vs merge. Otherwise a
        // dirty tree with no in-progress working change (the state right after a
        // finalize) would take neither the FF's "clean" path nor `fold_line_in`'s
        // `working.is_some()` capture — and the materialize below would clobber
        // it, silently, bypassing the #219 tree-write chokepoint.
        self.capture_uncaptured_edits()?;
        let anchor = self.anchor();
        // Already current: the harbor head is our finalized tip or already behind
        // it. Any captured working change is left in place — nothing landed to
        // fold into it.
        if let Some(o) = &anchor {
            if o == &their || self.graph().is_ancestor(&their, o) {
                return Ok(AdoptCatchupReport {
                    harbor: their,
                    already_current: true,
                    merged: false,
                    outcomes: BTreeMap::new(),
                });
            }
        }
        let msg = format!("adopt: catch up to landed main {}", short_version(&their));
        // A working change that duplicates the landed content itself (the
        // primary checkout after a `git reset` onto landed main — or a capture
        // stranded by a pre-#265 catch-up attempt), adds nothing over the
        // anchor, or is empty, is not local work: drop it so the catch-up
        // fast-forwards instead of minting a merge that re-lands the same
        // tree.
        if let Some(mut w) = self.working.clone() {
            // Refresh a stale capture first: the disk may have moved *past* it
            // (a `git reset` onto landed main left an older-era snapshot
            // behind — the #265 dogfood case). `capture_uncaptured_edits`
            // returns an existing working change untouched, and judging the
            // stale version would wrongly keep — and then merge — a capture
            // the tree has already superseded. Snapshot rewrites the working
            // change in place (ADR 0006), so the redundancy check below judges
            // what the disk actually holds.
            if self.tree_is_dirty_over(Some(&w))? {
                let m = self.working_message_or_placeholder();
                w = self.snapshot(&m)?.0;
            }
            // Manifest comparison, deletions included (#289): a deletion-only
            // capture is local work and folds in; an empty capture over a held
            // tree is a delete-everything change, only redundant when nothing
            // is held (no anchor — `same_tree_content` equates it with an
            // empty-manifest tip on its own).
            let empty = self.repo.change_tree(&w).is_none_or(|t| t.is_empty());
            let redundant = (empty && anchor.is_none())
                || self.repo.same_tree_content(&their, &w, self.now)
                || anchor.as_ref().is_some_and(|a| self.repo.same_tree_content(a, &w, self.now));
            if redundant {
                self.repo.drop_working(&w);
                self.working = None;
                self.persist()?;
            }
        }
        // Clean fast-forward: no captured local work and our line is strictly
        // behind the harbor's — settle *exactly* on it. A merge would leave the
        // dock at a node that is not main, defeating "catch up"; the FF keeps the
        // primary's tip == git-main after a lane land (the common case, unlike
        // `dock merge` which reports the fold as merge outcomes). With captured
        // WIP we fall through to the merge, folding the local line in.
        if self.working.is_none() {
            if let Some(o) = anchor.clone() {
                if self.graph().is_ancestor(&o, &their) {
                    self.fast_forward_to(&o, &their)?;
                    self.record_op("adopt", &msg, false);
                    return Ok(AdoptCatchupReport {
                        harbor: their,
                        already_current: false,
                        merged: true,
                        outcomes: BTreeMap::new(),
                    });
                }
            }
        }
        // Otherwise fold the local line into a merge (`fold_line_in` finalizes the
        // captured WIP as our signed merge parent).
        let before = self.anchor();
        let outcomes = self.fold_line_in(&their, &msg)?;
        let merged = self.anchor() != before;
        if merged {
            self.record_op("adopt", &msg, false);
        }
        Ok(AdoptCatchupReport { harbor: their, already_current: !merged, merged, outcomes })
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
        // position re-anchors on the edited change's parent so re-snapshots keep
        // the sibling parentage (the working change forks from the tip, ADR
        // 0006 — after `edit`, the tip is the parent and the working change is
        // the reopened version). The cleanliness guard proved the disk already
        // shows the target's tree, so nothing materializes. Re-anchoring is
        // gated on `Position::tracks_tip` (via `advance`) so a pristine primary
        // that never pinned a tip stays byte-for-byte unchanged on disk (the
        // compat guarantee) — a lane, or a primary that `adopt`/`lane merge`
        // seeded, re-anchors and so amends as a sibling.
        let reopened = self.repo.reopen_change(&target).map_err(|e| e.to_string())?;
        let parent = self.repo.parents_of(&target).into_iter().next();
        self.working = Some(reopened.clone());
        self.position.advance(&self.store, parent);
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
        Remotes { path: self.store.config(), lane: self.position.lane_id().map(str::to_string) }
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
            position: Position::fresh(HOME_DOCK.to_string()),
            working: None,
            next_change_id: None,
            // A freshly-initialized repo has no keypair yet (`loot keygen` adds one);
            // its early changes are unauthored until then (S3, ADR 0018).
            signer: None,
            now: real_now(),
        };
        ws.persist()?;
        Ok(ws)
    }

    // --- positions (ADR 0034) ---
    //
    // Where this workspace sits is owned by [`Position`] (#324): these stay as
    // thin delegating accessors so nothing below (or outside this file) needs
    // to change, and every call site keeps reading position through the same
    // seam it always has.

    /// The ambient dock name, or `None` on the primary (which the CLI displays
    /// as `main`). Named docks are retired (#253/ADR 0034) and in-place
    /// switching died in layer 1, so a lane opens as the home dock too — this is
    /// `None` everywhere now, kept as the seam loot-first's land gate reads.
    pub fn current_dock(&self) -> Option<&str> {
        self.position.current_dock()
    }

    /// The store selector for this position's process files: always the home
    /// selector (`None`) now that named `.loot/docks/` are retired (#253/ADR
    /// 0034). A lane's files resolve against its own `.loot/` — its store
    /// instance's lane root — under the same home selector.
    fn dock_opt(&self) -> Option<&str> {
        self.position.dock_opt()
    }

    /// The finalized change the ambient dock currently sits on — a new dock forks
    /// from here. Uses the pinned tip when present, else derives it from the
    /// graph (the pre-dock home case): the working change's parent, or the head.
    fn anchor(&self) -> Option<Oid> {
        self.position.anchor(&self.repo, self.working.as_ref())
    }

    // Named docks and in-place switching are fully retired (#253/ADR 0034):
    // `dock_goto` (in-place switch), `create_dock`/`bind_dock_dir` (the `--at`
    // worktree dock), and `remove_dock` are gone. A second position is a sealed
    // lane (`loot lane new`), and a lane's finalized line merges into the primary
    // via [`Workspace::merge_lane`]. A dangling `--at` `.loot` pointer file from
    // before the retirement now opens with an error; its directory is the
    // operator's to delete.

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
        self.position.lane_id()
    }

    /// Refuse a single-owner store mutation from a lane (ADR 0034): a lane owns
    /// only its own position; `gc`, remotes, the dock family, and lane
    /// spawn/reap belong to the primary.
    pub fn ensure_primary(&self, verb: &str) -> Result<(), String> {
        match self.position.lane_id() {
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
        let id = self.position.lane_id().ok_or(
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

    /// `loot lane merge <id-or-name>`: fold lane `key`'s finalized line into the
    /// primary, in process (CA2; ADR 0022's convergence, ADR 0034's source
    /// resolution). A dock is a named lane now (#253), so the merge source is
    /// resolved from the **lane registry** and the lane's **own tip pointer**
    /// (`<lane>/.loot/tip`) rather than a `.loot/docks/<name>/` subtree.
    ///
    /// Only *finalized* (signed) history merges (ADR 0018): the lane contributes
    /// its tip, and our own in-progress work is captured and finalized first, so
    /// both parents of the merge change are signed and can travel in a later
    /// bundle. Because a lane's `heads` are lane-owned — its finalized tip is a
    /// sibling **outside** the primary's lineage-filtered view (ADR 0034 seal) —
    /// the tip's lineage is first pulled in from the shared graph
    /// ([`DagRepo::ingest_shared_lineage`], the #265 catch-up primitive) so the
    /// ancestry/supersession checks in [`fold_line_in`] can see it. The merge
    /// change is then signed and becomes the primary's tip with the merged tree
    /// materialized; conflicts flow through the existing `conflicts`/`resolve`
    /// path — no side dropped. Returns `(source lane id, per-path outcomes)`.
    ///
    /// [`fold_line_in`]: Workspace::fold_line_in
    pub fn merge_lane(&mut self, key: &str) -> Result<(String, BTreeMap<PathBuf, MergeOutcome>), String> {
        self.ensure_primary("`loot lane merge`")?;
        // Resolve the source from the registry (by id or promoted name) and read
        // its finalized tip from the lane's own `.loot/` — the same peek
        // `loot lanes` does, never opening a workspace there (no heartbeat touch).
        let entry = self.find_lane(key)?;
        let lane_dot = entry.path.join(DOT);
        if !lane_dot.is_dir() {
            return Err(format!(
                "lane '{}' has no live directory at {} — reap it (`loot lane rm {}`) \
                 or re-spawn it",
                entry.id,
                entry.path.display(),
                entry.id
            ));
        }
        let lane_store = RepoStore::for_lane(&self.dot, &lane_dot);
        let their = lane_store.read_tip(None).ok_or_else(|| {
            format!(
                "lane '{}' has no finalized change to merge — run `loot new` in it first",
                entry.id
            )
        })?;
        // The lane's finalized tip is a sibling head outside this position's view
        // (isolation is by view, ADR 0034): pull its lineage in from the shared
        // graph so `fold_line_in`'s ancestry checks can reason about it. `false`
        // means the shared graph never recorded it — the lane finalized nothing
        // that crossed the seal (a spawn-anchor-only lane), so there is nothing
        // to merge.
        if !self.repo.ingest_shared_lineage(&self.store, &their).map_err(|e| e.to_string())? {
            return Err(format!(
                "lane '{}'s tip {} is not in the shared graph — it has no finalized \
                 change that crossed the seal to merge",
                entry.id,
                short_version(&their)
            ));
        }

        let msg = format!("merge lane '{}' into '{}'", entry.id, self.position.dock_name());
        let outcomes = self.fold_line_in(&their, &msg)?;
        Ok((entry.id, outcomes))
    }

    /// Test-only: pull a finalized tip's lineage into this position's view as a
    /// sibling head — the shape a pull/adopt (or a lane's landed line) leaves —
    /// so converge/resolve tests can build a real two-head fork without the
    /// retired in-place dock switching (#253/ADR 0034). Returns whether the tip
    /// is now known.
    #[cfg(test)]
    pub fn ingest_sibling(&mut self, tip: &Oid) -> bool {
        self.repo.ingest_shared_lineage(&self.store, tip).unwrap()
    }

    /// Test-only: pin this position's tip at its current finalized anchor — the
    /// state a real `adopt`/`lane merge`/land leaves behind. Named docks are
    /// retired (#253), so an amend is a *sibling* only when the position
    /// tracks a tip (`Position::tracks_tip`); the old ferry amend-projection
    /// tests got that for free from `docks_active` on a non-home dock.
    #[cfg(test)]
    pub fn pin_tip_at_anchor(&mut self) {
        let anchor = self.anchor();
        self.position.seed(&self.store, anchor);
    }

    /// Fold a finalized line `their` into this dock's current line, returning the
    /// per-path merge outcomes. Capture+finalize our WIP so our side is a signed
    /// merge parent, then take the cheapest correct path: nothing to do (their tip
    /// is already ours), a fast-forward (their line superseded ours per ADR 0032,
    /// or our line is strictly behind theirs), or a reconciled signed merge change
    /// (`merge_tips` reuses converge) that becomes our tip with the merged tree
    /// materialized. Shared by `lane merge` (their = a named lane's tip, its
    /// lineage ingested first by [`merge_lane`](Self::merge_lane)) and the no-arg
    /// `loot adopt` catch-up (their = the harbor's landed main head).
    fn fold_line_in(
        &mut self,
        their: &Oid,
        msg: &str,
    ) -> Result<BTreeMap<PathBuf, MergeOutcome>, String> {
        // Short-circuit BEFORE touching our work: their tip is already our
        // finalized tip. `anchor()` reads it without disturbing any in-progress
        // change, so an up-to-date no-op never seals pending work into a spurious tip.
        if self.anchor().as_ref() == Some(their) {
            return Ok(BTreeMap::new());
        }
        // Capture and finalize any in-progress work so our side of the merge is a
        // signed tip (a merge parent must be finalized to travel in a bundle).
        // Capture first, then refuse an un-described parent (#275) — the edits
        // are held either way, and only the signature waits for a name. A capture
        // that adds nothing over our tip is dropped rather than signed (and so
        // never nagged about), exactly as `finalize_capturing` and the bridge's
        // `reconcile_capture` do.
        if self.working.is_some() {
            // Mis-seal gate (#353, ADR 0038 §1): this capture-and-sign is a
            // signing seam too — a secret that reached the disk after the WIP
            // was described (describe's own gate ran on the pre-secret tree)
            // would otherwise be sealed public ungated. No override rides the
            // folding verbs; the remedy is a `.lootattributes` rule or an
            // explicit `loot new --allow-reveal` first.
            self.seal_gate(&[])?;
            let m = self.working_message_or_placeholder();
            let (id, _) = self.snapshot(&m)?;
            let anchor = self.anchor();
            if !self.drop_capture_if_redundant(&id, anchor.as_ref().as_slice())? {
                self.refuse_if_undescribed(REFUSE_UNDESCRIBED_PARENT)?;
                self.finalize_working()?;
            }
        }
        let ours = self
            .anchor()
            .ok_or("nothing to merge into yet — record a change first (`loot new`)")?;
        if &ours == their {
            return Ok(BTreeMap::new());
        }
        // Supersession-aware fork collapse (ADR 0032). If their line *amended* our
        // tip, merging would content-merge a version with its own replacement —
        // resurrecting what the amend removed; adopt the amend by fast-forwarding.
        // Symmetrically, a their-tip our own line already superseded offers
        // nothing. Both demand the replacement sit ON the other line.
        if self.repo.supersedes(&ours, their) {
            return Ok(BTreeMap::new());
        }
        if self.repo.supersedes(their, &ours) {
            return self.fast_forward_to(&ours, their).map(|_| BTreeMap::new());
        }
        // Divergent lines: reconcile into a signed merge change (reuses converge),
        // make it our tip, and reflect the merged tree on disk.
        let (merge_id, outcomes) = self
            .repo
            .merge_tips(&ours, their, msg, self.now)
            .map_err(|e| e.to_string())?;
        self.working = Some(merge_id.clone());
        self.finalize_working()?;
        self.repo
            .materialize(Some(&ours), &merge_id, &self.identity, self.now)
            .map_err(|e| e.to_string())?;
        Ok(outcomes)
    }

    /// Fast-forward this dock's tip from `from` onto `target` (which contains
    /// `from`), materializing target's tree. Used when a merge would be redundant:
    /// a supersession, or a line strictly behind the one it folds in.
    fn fast_forward_to(&mut self, from: &Oid, target: &Oid) -> Result<(), String> {
        self.repo
            .materialize(Some(from), target, &self.identity, self.now)
            .map_err(|e| e.to_string())?;
        self.position.seed(&self.store, Some(target.clone()));
        self.persist()
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
        // allowlist, matching a bare mutating verb. Nameless by construction —
        // the named case returned above — so this mints the placeholder rather
        // than carrying a message along.
        let (id, _) = self.snapshot_allowing(UNDESCRIBED_MESSAGE, &[])?;
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
                    self.position.advance(&self.store, Some(survivor.clone()));
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
            let msg = format!("converge diverged head into '{}'", self.position.dock_name());
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
    /// content oid and the minted message — the ours-line subject with a
    /// `(conflict resolution: <path>)` suffix, or the placeholder when no
    /// subject was derivable (#337) — for display.
    pub fn resolve_conflict(
        &mut self,
        path: &Path,
        resolution: &[u8],
        vis: Visibility,
    ) -> Result<(Oid, String), String> {
        let base = self.position.tip().cloned();
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
        // On any tip-tracking position, the resolution also advances the tip so
        // it isn't orphaned and the next snapshot builds on it —
        // `Position::tracks_tip` covers the adopt/merge-seeded home dock this
        // arm used to miss (the #229/#234/#265 stuck-tip class).
        if self.position.tracks_tip() {
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
            self.position.advance(&self.store, Some(change_id.clone()));
        }
        self.persist()?;
        let message = self
            .repo
            .change_message(&change_id)
            .unwrap_or_else(|| format!("resolve conflict at {}", path.display()));
        Ok((content, message))
    }

    // --- burn: destroy + tombstone, no resurrection (ADR 0038, #344) ---

    /// `loot burn <path>` (or an oid-level burn): destroy every historical
    /// object of `path` and record a signed tombstone for each (ADR 0038 §2).
    /// The change graph is never touched. Detects the honesty tier from the op
    /// log's disclosure barriers (a prior `push` ⇒ Pushed, else NeverPushed,
    /// §3) and — for the Pushed tier — deposits a purge event so the tombstone
    /// travels to cooperating relays/peers. Also checks the git mark map: any
    /// referencing change that was projected is reported so the CLI can print
    /// the mirror-rewrite guidance (§4). Signs each tombstone with this repo's
    /// key when it has one; a keyless repo records unauthored tombstones.
    pub fn burn_path(&mut self, path: &Path, only_oid: Option<Oid>) -> Result<BurnReport, String> {
        // Tier from the disclosure barrier (ADR 0038 §3): a `push` op ever
        // recorded means the bytes may have left this machine.
        let pushed = oplog::read(&self.store)
            .map_err(|e| e.to_string())?
            .iter()
            .any(|op| op.barrier && op.command == "push");
        let tier = if pushed {
            loot_core::BurnTier::Pushed
        } else {
            loot_core::BurnTier::NeverPushed
        };

        // The oid → referencing-version-ids map to destroy. An explicit `--oid`
        // is the escape hatch (a renamed path, or an oid a scan can't reach);
        // otherwise scan every historical object recorded at `path`.
        let scanned = self
            .repo
            .objects_at_path(&self.store, path)
            .map_err(|e| e.to_string())?;
        let targets: std::collections::BTreeMap<Oid, Vec<Oid>> = match only_oid {
            Some(oid) => {
                let refs = scanned.get(&oid).cloned().unwrap_or_default();
                std::collections::BTreeMap::from([(oid, refs)])
            }
            None => scanned,
        };
        if targets.is_empty() {
            return Err(format!(
                "no historical object recorded at {} — nothing to burn (pass `--oid <hex>` to burn a specific address)",
                path.display()
            ));
        }

        // Git-mirror detection (ADR 0038 §4): the mark map keys git commits by
        // the loot version-id they projected. Report every burned object whose
        // referencing change was ever projected — and ONLY those.
        let marks = loot_core::bridge::MarkMap::parse(
            &std::fs::read_to_string(self.store.git_marks()).unwrap_or_default(),
        )
        .unwrap_or_default();

        let mut tombstones = Vec::new();
        let mut burned = Vec::new();
        let mut projected: Vec<(Oid, String)> = Vec::new();
        for (oid, referencing) in &targets {
            tombstones.push(self.make_tombstone(oid, path, tier));
            burned.push((oid.clone(), path.to_path_buf()));
            for version in referencing {
                if let Some(sha) = marks.sha_for(version) {
                    projected.push((version.clone(), sha.to_string()));
                }
            }
        }

        self.repo.burn(&tombstones);
        self.persist()?;
        Ok(BurnReport { tier, burned, projected })
    }

    /// The paths at `head` whose recorded object has been burned (ADR 0038),
    /// each as `(path, oid)` — what `surface` labels instead of writing.
    pub fn burned_paths_at(&self, head: &Oid) -> Vec<(PathBuf, Oid)> {
        self.repo.burned_paths_at(head)
    }

    /// Build a tombstone for `oid` at `path` under `tier`, signing with this
    /// repo's key if it has one (ADR 0018 verify-only core; signing at the CLI).
    fn make_tombstone(&self, oid: &Oid, path: &Path, tier: loot_core::BurnTier) -> loot_core::Tombstone {
        match &self.signer {
            Some(signer) => {
                let burner = signer.public_key_bytes();
                let signature =
                    signer.sign(&loot_core::burn::signing_bytes(oid, path, tier, &burner, self.now));
                loot_core::Tombstone {
                    oid: oid.clone(),
                    path: path.to_path_buf(),
                    tier,
                    burner,
                    burned_at: self.now,
                    signature,
                }
            }
            None => loot_core::Tombstone::unauthored(oid.clone(), path.to_path_buf(), tier, self.now),
        }
    }

    // --- git interop bridge support (GB1, ADR 0028) ---

    /// The repo's on-disk layout — the bridge keeps its marks/state/config
    /// under `.loot/git-mirror/` via these paths.
    pub fn store(&self) -> &RepoStore {
        &self.store
    }

    /// The ambient dock's display name (`main` for home).
    pub fn dock_name(&self) -> &str {
        self.position.dock_name()
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
    //
    // #325 split the home into a pure brain and a small pair of hands: the
    // decision itself — covered/adopt/merge/refuse, including the #275/#292
    // refusal policy — is [`crate::reconcile::decide`], a `View -> Plan`
    // table tested without a `Workspace`. `reconcile_onto` below is the
    // hands: it still owns the graph queries the `View` is built from, still
    // captures first (#219, mechanics untouched), and still signs/materializes/
    // persists through [`reconcile_adopt`]/[`reconcile_merge`] and the
    // Position module (#324).

    /// Advance the ambient dock to cover `target` — the whole reconcile
    /// decision, one place (previously smeared across ferry.rs's match and
    /// these mechanics; the four live ferry bugs of 2026-07-10 all lived in
    /// that smear). The order is: settle the no-ops (our line already covers
    /// `target`, so nothing materializes), then — only on the paths that write
    /// the tree — capture in-progress disk work first against `pinned` (the
    /// caller's pre-ingest anchor, so the two lines meet only through the
    /// converge classifier; a capture matching `pinned` or `target` is dropped,
    /// not minted), build a [`crate::reconcile::View`] from what capture and
    /// the graph found, and execute whatever [`crate::reconcile::decide`]
    /// returns:
    ///   - `target` covered by us        → no-op (we are on/ahead/supersede it);
    ///   - real concurrent work captured → merge it with `target`;
    ///   - no local line (`pinned` None) → adopt (fast-forward);
    ///   - we are behind `target`        → adopt (fast-forward);
    ///   - genuinely diverged            → merge via the classifier;
    ///   - #275/#292's guards            → refuse, capture already safe on disk.
    ///
    /// Capture is gated on "will this reconcile overwrite the tree?", NOT on
    /// "did git bring new commits?". That latter gate (`had_new`) was the #280
    /// data-loss bug: when git `main` moved because **another lane landed
    /// through loot**, its commit is already marked, so the ferry saw no new
    /// shas, skipped capture, and `reconcile_adopt` materialized the landed tree
    /// straight over a live, captured working change. Every materializing arm
    /// now captures first; the no-ops still touch nothing (so a `--with-wip`
    /// review of un-described WIP is never asked for a name when `main` sits
    /// where we left it).
    ///
    /// `preserve_wip` (set only by the review projection, `loot ferry
    /// --with-wip`) forbids folding a **live working change** into the reconcile
    /// merge: review's job is to project the *unfinalized* WIP, so if `main`
    /// moved under the lane and real local work is on the tree, capturing +
    /// finalizing it here would sign the WIP into a merge and leave the empty
    /// minted change as the thing to "review" — nothing (#292, now
    /// [`crate::reconcile::Refusal::ReviewStaleAnchor`]). Under `preserve_wip`
    /// that path refuses instead, leaving the WIP captured and unfinalized.
    /// The no-ops (main where we left it) never reach the capture, so an
    /// ordinary review still projects un-described WIP untouched.
    ///
    /// Returns the per-path outcomes (empty on adopt/no-op).
    pub fn reconcile_onto(
        &mut self,
        target: Option<&Oid>,
        pinned: Option<&Oid>,
        label: &str,
        preserve_wip: bool,
    ) -> Result<BTreeMap<PathBuf, MergeOutcome>, String> {
        // The incoming change may have landed from a lane this dock never
        // adopted — outside the lineage-filtered load (#265). Pull its line in
        // from the shared graph first, so the arms below see the truth: the
        // duplicate-capture drop recognizes a disk that already holds the
        // landed tree, and the strictly-behind case adopts instead of minting
        // a duplicate merge line (the spurious projection a bare ferry from a
        // behind dock used to make). A tip the shared graph lost (pruned
        // pre-guard) keeps the pre-#265 arms — ferry's baseline adoption
        // (#263) recovers its content.
        let Some(target) = target else {
            return Ok(BTreeMap::new());
        };
        self.repo.ingest_shared_lineage(&self.store, target).map_err(|e| e.to_string())?;

        // No-op fast paths — our line already covers `target`, so nothing will
        // materialize: we are exactly on it, ahead of it, or hold a version that
        // *supersedes* it (ADR 0032/0033 — a landed change reopened and amended
        // while its old commit is still the git tip; a superseded version is
        // dead, never merged into, and projection threads the amend onto the
        // stale tip as a downstream fast-forward). The reopened-for-amend case
        // is checked on the **working change** too: after `loot edit`, the dock
        // re-anchors on the edited change's parent, so `pinned` no longer
        // supersedes `target` — the live superseding version is the working
        // change itself, and it must be left in place (adopting `target` would
        // clobber the amend on disk; capturing would finalize it prematurely and
        // reap its review lane). These MUST return before the capture below:
        // with git `main` where we left it, a `loot ferry --with-wip` reviews
        // *unsigned* WIP and asks for no name — capturing here would sign (or
        // #275-refuse) an un-described working change the review lane is
        // entitled to carry. Capture belongs only on the paths that overwrite
        // the tree.
        let covered = pinned.is_some_and(|o| {
            o == target || self.graph().is_ancestor(target, o) || self.repo.supersedes(o, target)
        }) || self.working.as_ref().is_some_and(|w| self.repo.supersedes(w, target));
        if covered {
            return Ok(BTreeMap::new());
        }

        // Past the no-ops, every arm below materializes `target`'s tree over the
        // working directory (adopt) or merges into it (merge), so capture the
        // disk FIRST — unconditionally. Gating capture on "did git bring new
        // commits?" (`had_new`) was the #280 data-loss bug: when git `main`
        // moved because another lane landed through loot, its commit is already
        // marked, so `had_new` was false and capture was skipped — then
        // `reconcile_adopt` materialized the landed tree straight over a live,
        // captured working change. `reconcile_capture` drops a capture that is
        // empty or duplicates `pinned`/`target` (the co-located checkout after a
        // `git pull`), so the fast-forward path still costs nothing. It no
        // longer refuses (#325) — that policy lives in `reconcile::decide` now,
        // reachable only via the `View` built below.
        let wip = self.reconcile_capture(pinned, Some(target))?;

        // `described` only matters when `wip` is real (see `View`'s doc); with
        // no capture the working change is gone (dropped as redundant) or was
        // never there, and either way `working_is_undescribed` reads `true`,
        // which the planner never consults on that path.
        let described = wip.is_some() && !self.working_is_undescribed();
        let view = reconcile::View {
            // Always `false` here — the `covered` early return above already
            // handled `true`. Kept on `View` so the arm stays part of the one
            // decision table and table-tested (see `reconcile.rs`).
            covered: false,
            wip: wip.clone(),
            pinned: pinned.cloned(),
            pinned_is_ancestor_of_target: pinned.is_some_and(|o| self.graph().is_ancestor(o, target)),
            preserve_wip,
            described,
        };
        match reconcile::decide(&view) {
            reconcile::Plan::NoOp => Ok(BTreeMap::new()),
            reconcile::Plan::Refuse(refusal) => Err(refusal.message().to_string()),
            reconcile::Plan::Adopt => {
                self.reconcile_adopt(target)?;
                Ok(BTreeMap::new())
            }
            reconcile::Plan::Merge { ours } => {
                // Merging the just-captured wip signs it as our merge parent
                // first (#275's "this merge seals your local work into signed
                // history") — a pinned tip merged instead is already finalized,
                // nothing left to sign.
                if wip.is_some() {
                    // Mis-seal gate (#353, ADR 0038 §1): the wip about to be
                    // signed was captured from the disk this pass — same seam
                    // as `fold_line_in`'s capture-and-sign, same gate. The
                    // disk still shows the captured tree here (materialize
                    // runs after the merge), so the disk-reading gate vets
                    // exactly what is being sealed.
                    self.seal_gate(&[])?;
                    self.finalize_working()?;
                }
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
    /// the captured change when real work was found.
    ///
    /// Mechanics only (#325, #219's chokepoint semantics byte-untouched): this
    /// used to also decide whether to refuse or finalize the capture — that
    /// policy now lives in `reconcile::decide`, reached from `reconcile_onto`
    /// after this returns. Callers that still want the old "capture, refuse
    /// on an un-described real capture, else finalize" shape (`fold_line_in`)
    /// compose it themselves from `drop_capture_if_redundant` +
    /// `refuse_if_undescribed` + `finalize_working`.
    fn reconcile_capture(
        &mut self,
        base: Option<&Oid>,
        target: Option<&Oid>,
    ) -> Result<Option<Oid>, String> {
        let msg = self.working_message_or_placeholder();
        let (id, _) = self.snapshot_from(base, &msg, &[])?;
        let against: Vec<&Oid> = [base, target].into_iter().flatten().collect();
        if self.drop_capture_if_redundant(&id, &against)? {
            Ok(None)
        } else {
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
        // A pinned tip must advance too — a home dock seeded by a spawn,
        // `adopt`, or `dock merge` carries one even with no named docks, and
        // leaving it behind keeps `anchor()` at the seed forever: the ferry
        // right after this adopt then aims git-main backward and the #201
        // guard refuses every pass (#265). [`Position::advance`] is the guard.
        self.position.advance(&self.store, Some(new_tip.clone()));
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

    // `dock_list`/`DockInfo` (the `loot docks` listing) are retired with named
    // docks (#253/ADR 0034): the primary is the only dock, and every other
    // position is a lane surfaced by `loot lanes` ([`Workspace::lane_statuses`]).

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
     (`loot describe -m \"<subject>\"`), then retry";

/// The message a capture carries when nobody has named the change yet. It is a
/// *display* placeholder — honest in `status`/`log`, where it says "un-described"
/// — but it must never reach signed history, where it would become the permanent
/// subject of the commit projected onto git `main` (#174). Mint it only via
/// [`Workspace::working_message_or_placeholder`]; test it only via
/// [`is_undescribed`].
pub const UNDESCRIBED_MESSAGE: &str = "(working change)";

/// Does `message` name the change, or is it still the un-described placeholder?
/// Resolve the shared store's `.loot/` from `dir` **without loading the repo**
/// — the `loot verify` path (#19): a corrupt store is exactly the store
/// [`Workspace::open`] dies on (the object decode fails mid-load), so the
/// integrity check must find the store by layout alone. Follows a spawned
/// lane's `store` pointer to the shared root, and applies `open`'s
/// not-a-repo check (the `identity` file is the store's birthmark).
pub fn resolve_store_dot(dir: &Path) -> Result<PathBuf, String> {
    let loot = dir.join(DOT);
    let dot = RepoStore::read_store_pointer(&loot).unwrap_or(loot);
    if !RepoStore::new(&dot).identity().exists() {
        return Err(format!(
            "not a loot repo at {} (no .loot/). Run `loot init` first.",
            dir.display()
        ));
    }
    Ok(dot)
}

/// The one seam every consumer crosses — the rule is never re-derived at a call
/// site, so the refusal in [`Workspace::finalize_capturing`] and the PR-title
/// fallback in `loot-first` cannot drift apart (#174).
pub fn is_undescribed(message: &str) -> bool {
    let m = message.trim();
    m.is_empty() || m == UNDESCRIBED_MESSAGE
}

/// The refusal [`Workspace::finalize_capturing`] prints rather than sign a change
/// nobody named (#174). It names `describe -m` first — the capture-*without*-
/// finalize verb, which is the first verb on dirty work (docs/agents/workflow.md)
/// — and `new -m` second, for when finalizing really is the next step.
const REFUSE_UNDESCRIBED: &str = "refusing to sign an un-described working change — its message \
     becomes the permanent subject on git `main`\n  name it:        loot describe -m \"<subject>\"\n  \
     or in one step: loot new -m \"<subject>\"\n  (your edits are captured and safe — only the \
     signature was withheld)";

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

    /// The two sides of the conflict recorded at `path` (`loot diff --conflict`,
    /// #13): `ours` and `theirs`, each with its stored visibility and — when the
    /// ambient identity holds the key — its decrypted content. A side the caller
    /// cannot decrypt comes back with `content: None`, so the renderer degrades
    /// it to the bare content address per the #306 contract. Errors when `path`
    /// is not currently in conflict, and propagates a genuine read failure rather
    /// than passing it off as sealed.
    pub fn conflict_at(&self, path: &Path) -> Result<ConflictView, String> {
        let (our_oid, their_oid) = self.conflicts().get(path).ok_or_else(|| {
            format!("no conflict at {} — run `loot conflicts` to list them", path.display())
        })?;
        Ok(ConflictView {
            path: path.to_path_buf(),
            ours: self.conflict_side(our_oid)?,
            theirs: self.conflict_side(their_oid)?,
        })
    }

    /// One side of a conflict: try to open it as the ambient identity. The
    /// key-not-held fallback is *specifically* "can't decrypt" — `Unauthorized`
    /// (not a recipient) or `Embargoed` (key still in escrow, ADR 0007) — which
    /// yields `content: None` and the OID fallback. A genuinely missing or
    /// corrupt local object is a real failure and propagates, rather than
    /// masquerading as `(sealed — no key)`. The visibility *class* is metadata
    /// that survives even when the content can't be opened, so a sealed side
    /// still shows its class (#306).
    ///
    /// When is a side actually unreadable here? A `Conflict` is only *recorded*
    /// when the merger held both keys (an unreadable side becomes
    /// `RelayedUnmerged`, ADR 0001), so in the merger's own workspace both sides
    /// decrypt. The sealed branch is for loot's shared-store model: a
    /// non-keyholder opening `.loot/conflicts` and inspecting a conflict a
    /// keyholding peer recorded (concurrent.md) sees that peer's restricted side
    /// sealed.
    fn conflict_side(&self, oid: &Oid) -> Result<ConflictSide, String> {
        let content = match self.content(oid) {
            Ok(bytes) => Some(bytes),
            Err(loot_core::RepoError::Unauthorized(_) | loot_core::RepoError::Embargoed(_)) => None,
            Err(e) => return Err(format!("cannot read conflict side: {e}")),
        };
        Ok(ConflictSide {
            oid: oid.clone(),
            visibility: self.repo.visibility_of(oid).unwrap_or(Visibility::Public),
            content,
        })
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

/// The delta class of one path across two trees: added, modified, or deleted
/// (#306). `#7`'s first-change-in-repo case renders every path `Added`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeltaClass {
    Added,
    Modified,
    Deleted,
}

impl DeltaClass {
    /// The frozen gutter char (#306): `+` added · `M` modified · `-` deleted.
    pub fn gutter(self) -> char {
        match self {
            DeltaClass::Added => '+',
            DeltaClass::Modified => 'M',
            DeltaClass::Deleted => '-',
        }
    }
}

/// One path's computed delta — the value [`diff`](Workspace::diff) produces and
/// [`crate::render::delta_line`] renders (#1/#306). `path` and `oid` are the
/// same tree entry's two faces: the name and its content address. When `sealed`
/// the caller lacks the key, so the renderer shows the address in place of the
/// name (which they cannot read) and degrades the token to the visibility
/// *class*. `prev_visibility` is `Some` only when the visibility differs across
/// the two sides (a transition) — the demotion/mis-seal signal #63 builds on;
/// it is always `None` for `#7` (a working change has one side).
pub struct PathDelta {
    pub class: DeltaClass,
    pub path: PathBuf,
    pub oid: Oid,
    pub sealed: bool,
    pub visibility: Visibility,
    pub prev_visibility: Option<Visibility>,
}

/// One side of a conflict — the value [`conflict_at`](Graph::conflict_at)
/// produces and [`crate::render::conflict_sides`] renders (#13). `oid` is the
/// side's content address and `visibility` its stored class. `content` is `Some`
/// only when the ambient identity holds the key; `None` means the side is sealed
/// to this caller, and the renderer shows the OID in place of plaintext — the
/// same key-not-held fallback #1 uses (#306). Sealed is thus exactly
/// `content.is_none()`, so it is derived at render time rather than stored.
#[derive(Debug)]
pub struct ConflictSide {
    pub oid: Oid,
    pub visibility: Visibility,
    pub content: Option<Vec<u8>>,
}

/// A conflict at one path, both sides packaged for rendering (#13). `ours` is
/// the side kept on disk after the conflicted merge; `theirs` the incoming side
/// preserved in the recorded conflict.
#[derive(Debug)]
pub struct ConflictView {
    pub path: PathBuf,
    pub ours: ConflictSide,
    pub theirs: ConflictSide,
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

/// The outcome of a no-arg `loot adopt` (harbor catch-up merge, ADR 0034).
#[derive(Debug)]
pub struct AdoptCatchupReport {
    /// The harbor's landed main head this dock caught up to.
    pub harbor: Oid,
    /// The dock was already at or ahead of the harbor head — a no-op with a note.
    pub already_current: bool,
    /// The local line was folded in (a merge or a fast-forward advanced the tip).
    pub merged: bool,
    /// Per-path merge outcomes when a reconcile ran (empty on a fast-forward).
    pub outcomes: BTreeMap<PathBuf, MergeOutcome>,
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

/// What `loot burn` destroyed (ADR 0038, #344), for the CLI to report.
#[derive(Debug)]
pub struct BurnReport {
    /// The honesty tier the burn achieved (never-pushed ⇒ complete; pushed ⇒
    /// best-effort with a purge event).
    pub tier: loot_core::BurnTier,
    /// The destroyed `(oid, path)` pairs.
    pub burned: Vec<(Oid, PathBuf)>,
    /// Referencing changes that were projected into the git mirror, as
    /// `(version-id, git-sha)` — non-empty means the git-side guidance applies.
    pub projected: Vec<(Oid, String)>,
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
        "burn" => "a burn destroyed an object's bytes and recorded a signed tombstone; \
                   undo cannot un-destroy them. the forward fix is to re-seal the path \
                   restricted (`loot migrate <path> restricted=<you>`) or remove it at \
                   tip — and to rotate the leaked secret itself.",
        _ => "this operation changed permission or key state that undo cannot retract.",
    };
    format!(
        "refusing to undo across a barrier (op {}, {}).\n      {remedy}",
        b.index, b.description
    )
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

/// The mis-seal gate's front half (#63, ADR 0038 §1): walk the working tree and
/// resolve each path's `(visibility, public_by_fallthrough)` from
/// `.lootattributes` — **without reading a single byte of content**. Loot stays
/// content-agnostic: the gate decides on the *name* and the *resolution
/// provenance* alone. Same walk + ignore + attribute rules as [`read_tree_at`],
/// so the paths and visibilities it reports are exactly the ones a snapshot
/// would seal.
fn read_seal_provenance(root: &Path) -> Result<Vec<(PathBuf, Visibility, bool)>, String> {
    let attrs = Attributes::load(&root.join(ATTRS));
    let ignore = Ignore::load(&root.join(IGNORE));
    let mut out = Vec::new();
    for path in walk(root, &ignore)? {
        let rel = path
            .strip_prefix(root)
            .or_else(|_| path.strip_prefix("./"))
            .unwrap_or(&path)
            .to_path_buf();
        let key = rel.to_string_lossy();
        let vis = attrs.visibility_for(&key);
        let fallthrough = attrs.public_by_fallthrough(&key);
        out.push((rel, vis, fallthrough));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
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

    /// Does `path` resolve **Public via fallthrough** — the default (no rule
    /// matched) or a catch-all glob — rather than an explicit rule naming it?
    /// This is the mis-seal gate's consent test (#63, ADR 0038 §1): an explicit
    /// rule that names the path public is deliberate consent; falling through a
    /// dropped/typo'd rule to the public default (or through a `* public`
    /// catch-all every real repo wants) is the accident the gate catches. A
    /// non-Public resolution is never a fallthrough-public (it is not public at
    /// all), so the gate leaves restricted/embargoed paths alone.
    fn public_by_fallthrough(&self, path: &str) -> bool {
        for (glob, vis) in &self.rules {
            if glob.matches(path) {
                // First matching rule wins. It is a fallthrough only when it is
                // a catch-all *and* resolves Public; an explicit (named) rule is
                // consent, and any non-Public rule is not a public seal at all.
                return is_catchall(&glob.pattern) && matches!(vis, Visibility::Public);
            }
        }
        // No rule matched: the default Public — the plainest fallthrough.
        true
    }
}

/// Is a glob a **catch-all** — a pattern made only of wildcards and separators
/// (`*`, `**`, `**/*`, `*/**`), with no literal segment that ties it to a name?
/// The mis-seal gate treats a catch-all `* public` like the bare default: it
/// waves every path through, so a secret riding it is a fallthrough, not
/// consent (ADR 0038 §1 — "a catch-all rule, which every real repo wants,
/// waves the typo'd-rule case straight through"). Any literal character
/// (`*.pem`, `id_*`, `.env*`) makes the rule an explicit naming.
fn is_catchall(pattern: &str) -> bool {
    !pattern.is_empty() && pattern.chars().all(|c| c == '*' || c == '/')
}

/// The built-in **secret-shaped name set** (#63, ADR 0038 §1): file *basenames*
/// that look like credentials — matched anywhere in the tree, case-insensitively
/// (secrets do not care about case, and the gate fails closed). The gate refuses
/// a first-time *public-by-fallthrough* seal of any path whose basename matches;
/// it never inspects content. The exact set lives here, as the ADR defers it to
/// the implementation. We pick precise SSH key names over the ADR's illustrative
/// broad `id_*` to avoid false-positives on ordinary source files (`id_map.rs`),
/// while keeping the `.env*` / `*.pem` / `*.key` / `*credentials*` families it
/// names.
const SECRET_NAMES: &[&str] = &[
    ".env*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.keystore",
    "*.jks",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "*credentials*",
    ".npmrc",
    ".pgpass",
    ".htpasswd",
];

/// True when `rel`'s **basename** matches a [`SECRET_NAMES`] pattern — a
/// secret-shaped file anywhere in the tree (#63, ADR 0038 §1). Basename, not
/// full path, so a nested `config/.env` is caught while a root-anchored glob
/// would miss it. Case-insensitive.
fn is_secret_name(rel: &Path) -> bool {
    let Some(name) = rel.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    SECRET_NAMES.iter().any(|pat| glob_match(pat, &lower))
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

    /// The clock is a constructor input (#322): an in-process test pins time
    /// without the process-global `LOOT_CLOCK` env (which races under the
    /// parallel test runner — env is the *cross-process* adapter, this is the
    /// in-process one). The injected instant is what every time-stamped write
    /// in the session carries.
    #[test]
    fn the_clock_is_injectable_at_construction() {
        let dir = std::env::temp_dir().join(format!("loot-clock-inject-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Workspace::init_at(&dir, "connor").unwrap();
        let ws = Workspace::open_at_clocked(&dir, 12_345).unwrap();
        assert_eq!(ws.now(), 12_345, "the workspace runs on the injected clock");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `loot id rotate` at the workspace seam (#16): the re-grant wave rides
    /// the persisted manifest (expiry carried exactly, audit entry untouched),
    /// and the wrapper's key steps — archive then regenerate — leave a
    /// loadable old key (rollback) and a different active pubkey.
    #[test]
    fn id_rotate_wave_end_to_end_at_the_workspace_seam() {
        let dir = std::env::temp_dir().join(format!("loot-id-rotate-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        let dot = dir.join(DOT);
        let old_pub = std::fs::read_to_string(dot.join("id.pub")).unwrap();

        // Seed a grant held by this identity, with an expiry (#20). The ws
        // runs on the real clock, so the expiry must sit in the real future —
        // year ~2286 — for the grant to still be live at rotation time.
        const FUTURE: u64 = 9_999_999_999;
        let oid = ws
            .with_repo_mut(|repo| {
                let oid = repo
                    .put(b"inbound", Visibility::Restricted(vec!["connor".into()]))
                    .map_err(|e| e.to_string())?;
                repo.grant(&oid, "connor", 10, Some(FUTURE)).map_err(|e| e.to_string())?;
                Ok(oid)
            })
            .unwrap();

        let report = ws.rotate_regrants().unwrap();
        assert_eq!(report.regrants.len(), 1);
        assert_eq!(report.regrants[0].oid, oid);
        assert_eq!(
            report.regrants[0].expires_at,
            Some(FUTURE),
            "the wave preserves the original expiry exactly"
        );

        // The wrapper's steps 2–3: archive the old key, mint the new one.
        let (arch, _) = loot_identity::archive_keypair(&dot, 42).unwrap();
        loot_identity::generate_and_save(&dot, "connor@loot").unwrap();
        let new_pub = std::fs::read_to_string(dot.join("id.pub")).unwrap();
        assert_ne!(new_pub, old_pub, "a fresh keypair is the active identity");
        assert!(arch.exists(), "the old key is archived, not deleted");
        loot_identity::Identity::load(&arch).expect("the archived key still loads — rollback works");

        // Reopen: the persisted manifest's audit entry is untouched.
        drop(ws);
        let ws2 = Workspace::open_at(&dir).unwrap();
        let e = ws2.manifest().grant_for(&oid, "connor").expect("audit entry survives");
        assert_eq!((e.granted_at, e.expires_at), (10, Some(FUTURE)));
        let _ = std::fs::remove_dir_all(&dir);
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

    /// #175: the fresh-empty working state — a working node minted over a
    /// *described* tip, tree-identical to it — must render under its **own** ids,
    /// never fall back to the signed tip's. The live finding was the tip labelled
    /// `(working change)` under its own change/version while the real (empty)
    /// working node vanished. `history()` must keep the two nodes distinct: the
    /// tip stays a finalized row carrying its authored subject, and the working
    /// row carries the working node's handle with `empty = true`.
    #[test]
    fn history_keeps_the_empty_tip_duplicate_working_row_distinct_from_the_tip() {
        let dir = std::env::temp_dir().join(format!("loot-175-empty-working-{}", std::process::id()));
        let mut ws = authored_ws(&dir);

        // A described, finalized tip.
        std::fs::write(dir.join("a.txt"), b"one").unwrap();
        ws.snapshot("real work").unwrap();
        ws.finalize_working().unwrap();
        let tip = ws.repo().heads()[0].clone();
        let tip_cid = ws.repo().change_change_id(&tip);

        // A fresh working node over the *unchanged* tree — the tip-duplicate the
        // report hit. It gets the freshly-minted next handle, distinct from the
        // tip's, and its live row is empty (same content as the anchor).
        ws.snapshot("real work").unwrap();
        let working = ws.working_id().cloned().expect("snapshot minted a working node");
        let working_cid = ws.repo().change_change_id(&working);
        assert_ne!(working_cid, tip_cid, "the working node carries its own handle, not the tip's");

        let hist = ws.history().unwrap();

        // The working row is present, under the working node's ids, marked empty.
        let row = hist.working.expect("the fresh working change renders a live row");
        assert_eq!(row.change_id, working_cid, "the working row shows the working node's handle");
        assert!(row.empty, "a tip-duplicate working change is empty");

        // The tip survives as a finalized row with its authored subject — not
        // relabelled `(working change)`, and its message is not hidden.
        let tip_row = hist
            .rows
            .iter()
            .find(|r| r.version == tip)
            .expect("the signed tip stays a finalized row");
        assert_eq!(tip_row.change_id, tip_cid);
        assert_eq!(tip_row.message, "real work", "the tip keeps its authored subject");

        // The working node never doubles as a finalized row (the S2 dedupe holds).
        assert!(
            !hist.rows.iter().any(|r| r.version == working),
            "the working node renders once, as the live row — never among the finalized rows"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #6: `loot log --path` — a history where only some changes touched the
    /// target path. `ChangeNode.tree` is the *full* materialized tree, not a
    /// delta, so a change only omits a path once it is actually deleted (a
    /// change that simply never edited it still carries it forward).
    #[test]
    fn filter_history_to_path_keeps_only_matching_changes() {
        let dir = std::env::temp_dir().join(format!("loot-6-log-path-{}", std::process::id()));
        let mut ws = authored_ws(&dir);

        // c1: adds a.txt.
        std::fs::write(dir.join("a.txt"), b"one").unwrap();
        ws.snapshot("adds a").unwrap();
        ws.finalize_working().unwrap();
        let c1 = ws.repo().heads()[0].clone();

        // c2: deletes a.txt, adds b.txt — its full tree never holds a.txt.
        std::fs::remove_file(dir.join("a.txt")).unwrap();
        std::fs::write(dir.join("b.txt"), b"two").unwrap();
        ws.snapshot("adds b, drops a").unwrap();
        ws.finalize_working().unwrap();
        let c2 = ws.repo().heads()[0].clone();

        // A fresh (unfinalized) working change still carrying b.txt.
        std::fs::write(dir.join("b.txt"), b"two-edited").unwrap();
        ws.snapshot("edit b").unwrap();
        let working = ws.working_id().cloned().expect("snapshot minted a working node");

        let mut view = ws.history().unwrap();
        assert_eq!(view.rows.len(), 2, "sanity: two finalized rows before filtering");
        assert!(view.working.is_some(), "sanity: a live working row before filtering");

        ws.filter_history_to_path(&mut view, Path::new("a.txt"));
        assert_eq!(
            view.rows.iter().map(|r| r.version.clone()).collect::<Vec<_>>(),
            vec![c1.clone()],
            "only the change whose tree held a.txt survives"
        );
        assert_eq!(view.rows[0].total, 1, "the surviving row keeps its own visibility-hint fields");
        assert!(view.working.is_none(), "the working tree no longer holds a.txt");

        // A fresh view, filtered on b.txt instead: c2 and the live working
        // row (which still carries b.txt) survive; c1 does not.
        let mut view2 = ws.history().unwrap();
        ws.filter_history_to_path(&mut view2, Path::new("b.txt"));
        assert_eq!(
            view2.rows.iter().map(|r| r.version.clone()).collect::<Vec<_>>(),
            vec![c2.clone()],
            "only the change whose tree held b.txt survives"
        );
        assert_eq!(
            view2.working.as_ref().map(|w| &w.version),
            Some(&working),
            "the live working row still carries b.txt"
        );

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

    // --- no-arg `loot adopt`: harbor catch-up MERGE (#250, ADR 0034) ---

    #[test]
    fn adopt_no_arg_refuses_without_a_mirror() {
        let dir = std::env::temp_dir().join(format!("loot-250-nomirror-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        seed_fork(&mut ws);
        let err = ws.adopt_harbor().unwrap_err();
        assert!(err.contains("no mirror main"), "names the missing mirror: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn adopt_no_arg_is_a_noop_when_already_current() {
        let dir = std::env::temp_dir().join(format!("loot-250-current-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        let (c1, _x) = seed_fork(&mut ws);
        seed_mirror_main(&ws, &"1".repeat(40), &c1);
        ws.adopt(&loot_core::hex::encode(&c1.0), false).unwrap(); // settle tip on c1

        let report = ws.adopt_harbor().unwrap();
        assert!(report.already_current && !report.merged, "harbor is our tip — a no-op");
        assert_eq!(ws.anchor(), Some(c1), "the tip did not move");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn adopt_no_arg_fast_forwards_a_dock_strictly_behind_landed_main() {
        // The common post-lane-land case: the primary sits on `c1` while another
        // lane advanced main to `c2` (a descendant). Catch-up is a clean
        // fast-forward — no redundant merge change.
        use loot_core::{Change, Oid};
        let dir = std::env::temp_dir().join(format!("loot-250-ff-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        let (c1, _x) = seed_fork(&mut ws);
        seed_mirror_main(&ws, &"1".repeat(40), &c1);
        ws.adopt(&loot_core::hex::encode(&c1.0), false).unwrap(); // tip = c1

        // Main advances to c2 (a child of c1); the dock's tip stays at c1.
        let c2 = ws
            .with_repo(|repo| {
                repo.record_carrying(
                    Change { id: Oid([0; 32]), parents: vec![c1.clone()], message: "landed c2".into(), tree: Default::default() },
                    Some([5u8; 16]),
                )
                .map_err(|e| e.to_string())
            })
            .unwrap();
        ws.record_op("seed", "harbor advanced to c2", false);
        seed_mirror_main(&ws, &"2".repeat(40), &c2);

        let report = ws.adopt_harbor().unwrap();
        assert!(report.merged && !report.already_current, "caught up");
        assert!(report.outcomes.is_empty(), "a fast-forward has no merge outcomes");
        assert_eq!(ws.repo().heads(), vec![c2.clone()], "tip fast-forwarded to c2, no merge head");
        assert_eq!(ws.anchor(), Some(c2), "the dock now sits on main");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn adopt_no_arg_folds_a_divergent_local_line_into_a_merge() {
        // The dock did local work `w` while main advanced to a sibling `f`.
        // Catch-up folds both into a signed merge that keeps the local line.
        use loot_core::{Change, Oid};
        let dir = std::env::temp_dir().join(format!("loot-250-merge-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        let (c1, _x) = seed_fork(&mut ws);
        seed_mirror_main(&ws, &"1".repeat(40), &c1);
        ws.adopt(&loot_core::hex::encode(&c1.0), false).unwrap(); // tip = c1

        // Local work `w` (child of c1) — finalize advances the seeded tip to w.
        std::fs::write(dir.join("local.txt"), b"w").unwrap();
        ws.snapshot("local work").unwrap();
        ws.finalize_working().unwrap();
        let w = ws.repo().heads()[0].clone();

        // Meanwhile main advanced to `f` (a sibling of w off c1).
        let f = ws
            .with_repo(|repo| {
                repo.record_carrying(
                    Change { id: Oid([0; 32]), parents: vec![c1.clone()], message: "landed f".into(), tree: Default::default() },
                    Some([6u8; 16]),
                )
                .map_err(|e| e.to_string())
            })
            .unwrap();
        ws.record_op("seed", "harbor advanced to f", false);
        seed_mirror_main(&ws, &"6".repeat(40), &f);

        let report = ws.adopt_harbor().unwrap();
        assert!(report.merged && !report.already_current, "folded the local line in");
        let tip = ws.anchor().unwrap();
        let parents = ws.graph().parents(&tip);
        assert!(parents.contains(&w) && parents.contains(&f), "the merge carries both lines");
        assert!(ws.graph().is_ancestor(&f, &tip), "main is now an ancestor — caught up");
        assert!(ws.graph().is_ancestor(&w, &tip), "the local line survives the fold");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn adopt_no_arg_folds_uncaptured_disk_edits_into_the_merge_not_clobbered() {
        // Regression (#250 review): a dirty tree with NO in-progress working change
        // (the state right after a finalize) must be captured and folded into the
        // catch-up merge — never clobbered by the materialize. Before capture-first
        // this path took neither the FF's clean branch nor `fold_line_in`'s
        // `working.is_some()` capture, so the edit was silently lost.
        use loot_core::{Change, Oid};
        let dir = std::env::temp_dir().join(format!("loot-250-dirty-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        let (c1, _x) = seed_fork(&mut ws);
        seed_mirror_main(&ws, &"1".repeat(40), &c1);
        ws.adopt(&loot_core::hex::encode(&c1.0), false).unwrap(); // tip = c1, clean tree

        // Uncaptured local edit on disk — no snapshot, no working change.
        std::fs::write(dir.join("local.txt"), b"my work").unwrap();

        // Main advanced to `f` (a child of c1).
        let f = ws
            .with_repo(|repo| {
                repo.record_carrying(
                    Change { id: Oid([0; 32]), parents: vec![c1.clone()], message: "landed f".into(), tree: Default::default() },
                    Some([7u8; 16]),
                )
                .map_err(|e| e.to_string())
            })
            .unwrap();
        ws.record_op("seed", "harbor advanced to f", false);
        seed_mirror_main(&ws, &"7".repeat(40), &f);

        // Uncaptured dirt cannot be named in advance — naming *is* capturing — so
        // since #275 this case always takes two passes. Pass 1 captures the edit
        // (the #250 guarantee this test exists for) and refuses to sign it
        // nameless; the materialize never runs, so nothing is clobbered.
        let err = ws.adopt_harbor().unwrap_err();
        assert!(err.contains("describe"), "nameless dirt holds the merge: {err}");
        assert!(ws.working_id().is_some(), "pass 1 captured the edit — #250's whole point");
        assert_eq!(
            std::fs::read(dir.join("local.txt")).unwrap(),
            b"my work",
            "and the refusal did not clobber it either",
        );

        // Pass 2, once named: the fold happens exactly as it always did.
        ws.snapshot("feat: my local line").unwrap();
        let report = ws.adopt_harbor().unwrap();
        assert!(report.merged, "the dirty local line was folded in");
        assert_eq!(
            std::fs::read(dir.join("local.txt")).unwrap(),
            b"my work",
            "the uncaptured edit survived the catch-up — not clobbered",
        );
        assert!(ws.graph().is_ancestor(&f, &ws.anchor().unwrap()), "main is an ancestor — caught up");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- no-arg `loot adopt`: catch-up to a lane-landed change the loaded
    // --- lineage has never seen (#265) ---

    /// Seed the #265 topology: a primary on `c1`, a lane that lands `c2` (a
    /// real child with content), the mirror spine naming `c2` as landed main —
    /// and a primary whose lineage-filtered load has never seen `c2`.
    /// Returns `(area, dir, c2)`; the caller reopens the primary fresh.
    fn landed_from_lane(tag: &str) -> (PathBuf, PathBuf, loot_core::Oid) {
        let (area, dir, mut ws) = lane_setup(tag);
        let spawned = ws.spawn_lane(None, Some(&area.join("l1"))).unwrap();
        let mut lw = Workspace::open_at(&spawned.dir).unwrap();
        std::fs::write(spawned.dir.join("landed.txt"), b"landed").unwrap();
        lw.snapshot("landed c2").unwrap();
        lw.finalize_working().unwrap();
        let c2 = lw.heads()[0].clone();
        seed_mirror_main(&ws, &"2".repeat(40), &c2);
        (area, dir, c2)
    }

    #[test]
    fn adopt_no_arg_fast_forwards_a_landed_change_outside_the_loaded_lineage() {
        // The #265 repro: every catch-up used to fail here because the landed
        // change is not in the primary's loaded graph (ADR 0022 lineage
        // filter), so no ancestry check could prove the fast-forward.
        let (area, dir, c2) = landed_from_lane("adopt-265-ff");

        let mut ws = Workspace::open_at(&dir).unwrap();
        assert!(
            ws.repo().change_message(&c2).is_none(),
            "precondition: the landed change is outside the loaded lineage"
        );
        let report = ws.adopt_harbor().unwrap();
        assert!(report.merged && !report.already_current, "caught up");
        assert!(report.outcomes.is_empty(), "a fast-forward has no merge outcomes");
        assert_eq!(ws.repo().heads(), vec![c2.clone()], "clean FF — no merge node minted");
        assert_eq!(ws.anchor(), Some(c2), "the dock sits exactly on landed main");
        assert_eq!(
            std::fs::read(dir.join("landed.txt")).unwrap(),
            b"landed",
            "the landed content materialized into the primary tree"
        );
        let _ = std::fs::remove_dir_all(&area);
    }

    // -----------------------------------------------------------------------
    // #275 — the #174 residual: a merge must not seal un-described work either.
    //
    // #174 guarded the *deliberate* finalize (`loot new` / `loot-first land`).
    // These two paths sign the operator's own working change **in passing**, to
    // make a signed merge parent — only the trigger is mechanical, so the
    // placeholder could still reach `main` as a permanent subject.
    // -----------------------------------------------------------------------

    #[test]
    fn catch_up_refuses_to_seal_undescribed_local_work_as_a_merge_parent() {
        // `fold_line_in` — reached by the no-arg `loot adopt` catch-up and by
        // `loot dock merge`. Local work diverges from landed main, so the
        // catch-up must fold it in — sealing it signed, under whatever name it
        // has. Un-described, that name is the placeholder (#275).
        let (area, dir, _c2) = landed_from_lane("275-adopt-undescribed");
        std::fs::write(dir.join("local.txt"), b"my unnamed work").unwrap();

        let mut ws = Workspace::open_at(&dir).unwrap();
        let before = ws.finalized_anchor();
        let err = ws.adopt_harbor().unwrap_err();
        assert!(err.contains("describe"), "the refusal names the verb to run: {err}");

        // Safe, not lossy: the capture happened, only the signature was withheld.
        // The working change is still a placeholder-named head — that is fine and
        // is what `status` shows; what must not happen is *signing* it.
        assert!(ws.working_id().is_some(), "the local work is captured, not dropped");
        assert_eq!(ws.finalized_anchor(), before, "nothing was signed onto the line");

        // And naming it clears the refusal — the catch-up then folds it in.
        ws.snapshot("feat: my local line").unwrap();
        assert!(ws.adopt_harbor().unwrap().merged, "named work folds in");
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn catch_up_folds_described_local_work_in_as_before() {
        // The guard is about the *name*, not the fold: named work still merges.
        let (area, dir, _c2) = landed_from_lane("275-adopt-described");
        std::fs::write(dir.join("local.txt"), b"my work").unwrap();

        let mut ws = Workspace::open_at(&dir).unwrap();
        ws.snapshot("feat: my local line").unwrap();
        let report = ws.adopt_harbor().unwrap();

        assert!(report.merged, "described local work still folds in");
        let tip = ws.anchor().expect("a merge tip");
        let subject = ws.repo().change_message(&tip).unwrap_or_default();
        assert!(
            subject.starts_with("adopt: catch up to landed main"),
            "the merge node keeps its own mechanical subject — it is machine-authored: {subject}",
        );
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn ferry_reconcile_refuses_to_seal_undescribed_local_work_as_a_merge_parent() {
        // `reconcile_capture` — reached by `loot ferry` when git `main` moved
        // externally (a browser edit, an outside PR merge, a break-glass commit)
        // while un-described work sat on the disk.
        let (area, dir, c2) = landed_from_lane("275-ferry-undescribed");

        let mut ws = Workspace::open_at(&dir).unwrap();
        let ours = ws.finalized_anchor();
        std::fs::write(dir.join("local.txt"), b"my unnamed work").unwrap();
        ws.snapshot(UNDESCRIBED_MESSAGE).unwrap();

        let err = ws
            .reconcile_onto(Some(&c2), ours.as_ref(), "ferry: reconcile git main", /* preserve_wip */ false)
            .unwrap_err();
        assert!(err.contains("describe"), "the refusal names the verb to run: {err}");
        assert!(ws.working_id().is_some(), "the local work is captured, not dropped");
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn ferry_reconcile_seals_described_local_work_as_before() {
        let (area, dir, c2) = landed_from_lane("275-ferry-described");

        let mut ws = Workspace::open_at(&dir).unwrap();
        let ours = ws.finalized_anchor();
        std::fs::write(dir.join("local.txt"), b"my work").unwrap();
        ws.snapshot("feat: my local line").unwrap();

        ws.reconcile_onto(Some(&c2), ours.as_ref(), "ferry: reconcile git main", /* preserve_wip */ false)
            .expect("described work reconciles");
        let tip = ws.anchor().expect("the dock advanced onto a merge");
        assert!(ws.graph().is_ancestor(&c2, &tip), "the landed side is folded in");
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn review_catch_up_refuses_to_fold_a_described_wip_when_main_moved() {
        // #292 — the review fold. A lane spawned from an anchor already behind
        // git `main` (`landed_from_lane` moves main past the dock via a lane
        // land), then real described work on the tree. `loot-first review` runs
        // its catch-up ferry with `--with-wip` (`preserve_wip = true`). Before
        // this fix the reconcile CAPTURED + FINALIZED the described WIP into a
        // "ferry: reconcile git main" merge and minted an empty working change —
        // so review then reported "nothing to review", the work unlandable, with
        // no op-log entry to undo. The catch-up must refuse the fold instead.
        let (area, dir, c2) = landed_from_lane("292-review-fold");

        let mut ws = Workspace::open_at(&dir).unwrap();
        let ours = ws.finalized_anchor();
        std::fs::write(dir.join("local.txt"), b"my reviewable work").unwrap();
        ws.snapshot("feat: my local line").unwrap();
        let wip = ws.working_id().cloned().expect("a live, described working change");

        let err = ws
            .reconcile_onto(
                Some(&c2),
                ours.as_ref(),
                "ferry: reconcile git main",
                /* preserve_wip */ true,
            )
            .unwrap_err();
        assert!(
            err.contains("moved under this lane") && err.contains("#292"),
            "a clear, actionable refusal — not a silent fold: {err}"
        );

        // The described WIP is intact and still UNFINALIZED: nothing was signed,
        // the dock did not advance, and the landed side was NOT folded in.
        assert_eq!(
            ws.working_id(),
            Some(&wip),
            "the described WIP survives as the live working change"
        );
        assert_eq!(ws.finalized_anchor(), ours, "nothing was finalized onto the line");
        assert!(
            !ws.graph().is_ancestor(&c2, &wip),
            "the landed main was not folded into the WIP"
        );
        // And the edits are still on disk — the refusal cost only the signature.
        assert_eq!(
            std::fs::read(dir.join("local.txt")).unwrap(),
            b"my reviewable work",
            "the refusal did not clobber the working tree",
        );
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn ferry_reconcile_does_not_clobber_a_live_working_change_when_a_lane_landed_main() {
        // #280 — data loss. git `main` moved because ANOTHER LANE LANDED
        // THROUGH LOOT, so its commit is already marked: the ferry ingests no
        // new git commits, and the old gate `had_new = !new_shas.is_empty()`
        // was therefore `false`, so `capture` was `false` and the disk work
        // was never captured. `reconcile_adopt` then materialized the landed
        // tree straight over a live, *described* working change — the reported
        // ~2h loss, recovered only from an orphaned GitHub commit.
        //
        // `landed_from_lane` moves main the way a land does — a marked,
        // loot-projected commit — the fixture every prior reconcile test
        // missed (they all used `git_native_commit`, where `had_new` is true).
        // Capture is unconditional now (#280): the working change is FOLDED IN,
        // and — the symptom that mattered — its files stay on disk.
        let (area, dir, c2) = landed_from_lane("280-clobber");

        let mut ws = Workspace::open_at(&dir).unwrap();
        let ours = ws.finalized_anchor();
        // Real local work, described and captured: an EDIT to a tracked file
        // the anchor already carries (`base.txt`). Editing an existing path is
        // what makes a clobber unmistakable — `reconcile_adopt` re-surfaces the
        // target's whole tree, so it writes the landed `base.txt` straight over
        // the edit (a brand-new path, absent from both trees, materialize would
        // leave alone — which is exactly why the loss needs a tracked file).
        std::fs::write(dir.join("base.txt"), b"two hours of work").unwrap();
        ws.snapshot("feat: real local work").unwrap();

        // The reconcile a `had_new == false` ferry makes: main is the marked
        // lane-landed c2, and our line is its ancestor. Pre-#280 this hit the
        // `(None, Some(o)) if is_ancestor(o, target)` adopt arm and clobbered.
        ws.reconcile_onto(Some(&c2), ours.as_ref(), "ferry: reconcile git main", /* preserve_wip */ false)
            .expect("the working change reconciles — it is not clobbered");

        assert_eq!(
            std::fs::read(dir.join("base.txt")).unwrap(),
            b"two hours of work",
            "#280: the live working-change edit survived — not overwritten by the landed tree",
        );
        let tip = ws.anchor().expect("the dock advanced onto a merge");
        assert!(ws.graph().is_ancestor(&c2, &tip), "the landed line is folded in, not dropped");
        assert!(
            std::fs::read(dir.join("landed.txt")).map(|b| b == b"landed").unwrap_or(false),
            "and the landed content came in with the fold",
        );
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn adopt_no_arg_ffs_when_the_disk_already_holds_landed_content() {
        // The operator ran `git reset --hard origin/main` in the primary
        // checkout first: the landed file is already on disk. That is landed
        // content, not local work — catch-up must NOT capture it as a working
        // change and mint a merge that re-lands the same tree (#265's loop).
        let (area, dir, c2) = landed_from_lane("adopt-265-disk");
        std::fs::write(dir.join("landed.txt"), b"landed").unwrap();

        let mut ws = Workspace::open_at(&dir).unwrap();
        let report = ws.adopt_harbor().unwrap();
        assert!(report.merged && report.outcomes.is_empty(), "clean FF");
        assert_eq!(ws.repo().heads(), vec![c2], "no duplicate line, no merge node");
        assert!(ws.working_id().is_none(), "no stray working change survives the catch-up");
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn adopt_no_arg_drops_a_stale_capture_that_duplicates_landed_main() {
        // A previous broken catch-up attempt captured the landed content as a
        // working change and stranded it (the state #265 was reported in).
        // Re-running adopt drops the redundant capture and fast-forwards.
        let (area, dir, c2) = landed_from_lane("adopt-265-stale");
        std::fs::write(dir.join("landed.txt"), b"landed").unwrap();
        let mut ws = Workspace::open_at(&dir).unwrap();
        ws.snapshot(UNDESCRIBED_MESSAGE).unwrap();
        assert!(ws.working_id().is_some(), "precondition: the stale capture exists");

        let report = ws.adopt_harbor().unwrap();
        assert!(report.merged && report.outcomes.is_empty(), "clean FF");
        assert_eq!(ws.repo().heads(), vec![c2], "the duplicate capture did not become a merge");
        assert!(ws.working_id().is_none(), "the redundant capture was dropped");
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn adopt_no_arg_refreshes_a_stale_capture_the_disk_moved_past() {
        // The #265 dogfood case: an older-era capture is in progress, then the
        // operator `git reset`s the checkout onto landed main — the disk moves
        // *past* the capture, onto exactly the landed content. The stale
        // snapshot is not local work; catch-up must refresh it to the disk's
        // truth, see it duplicates landed main, and fast-forward — not keep
        // the stale version and mint a merge.
        let (area, dir, c2) = landed_from_lane("adopt-265-refresh");
        let mut ws = Workspace::open_at(&dir).unwrap();
        // The stale capture: pre-reset content in the landed path.
        std::fs::write(dir.join("landed.txt"), b"old guess").unwrap();
        ws.snapshot(UNDESCRIBED_MESSAGE).unwrap();
        // The reset: the disk now holds exactly the landed content.
        std::fs::write(dir.join("landed.txt"), b"landed").unwrap();

        let report = ws.adopt_harbor().unwrap();
        assert!(report.merged && report.outcomes.is_empty(), "clean FF");
        assert_eq!(ws.repo().heads(), vec![c2], "the stale capture did not become a merge");
        assert!(ws.working_id().is_none(), "the refreshed-then-redundant capture was dropped");
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn adopt_version_settles_forward_on_a_lane_landed_change_outside_the_lineage() {
        // The other #265 repro: `loot adopt <version> --discard-wip` reported
        // "no live version" for a landed-from-lane change — it was outside the
        // lineage-filtered load, and even in view a *descendant* target read
        // as "not on any live line". Take-wholesale must settle forward too.
        let (area, dir, c2) = landed_from_lane("adopt-265-version");

        let mut ws = Workspace::open_at(&dir).unwrap();
        let report = ws.adopt(&loot_core::hex::encode(&c2.0), false).unwrap();
        assert_eq!(report.target, c2);
        assert!(!report.already_there);
        assert!(report.abandoned.is_empty(), "a forward settle abandons nothing");
        assert_eq!(ws.anchor(), Some(c2), "the dock sits on the landed change");
        assert_eq!(
            std::fs::read(dir.join("landed.txt")).unwrap(),
            b"landed",
            "the landed content materialized"
        );
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn adopt_no_arg_folds_real_local_work_over_an_out_of_lineage_landed_change() {
        // Genuine local dirt is still local work: catch-up folds it into a
        // merge (capture-first, #219) even when the landed side had to be
        // ingested from the shared graph — never dropped, never clobbered.
        let (area, dir, c2) = landed_from_lane("adopt-265-dirt");
        std::fs::write(dir.join("local.txt"), b"my work").unwrap();

        let mut ws = Workspace::open_at(&dir).unwrap();
        // Named, because the fold signs it as a merge parent (#275). The name is
        // not what this test is about — that the work is folded in rather than
        // clobbered is; the refusal has its own tests.
        ws.snapshot("feat: my local line").unwrap();
        let report = ws.adopt_harbor().unwrap();
        assert!(report.merged, "the local line was folded in");
        let tip = ws.anchor().unwrap();
        assert!(ws.graph().is_ancestor(&c2, &tip), "landed main is an ancestor — caught up");
        assert_eq!(
            std::fs::read(dir.join("local.txt")).unwrap(),
            b"my work",
            "the local edit survived the catch-up"
        );
        let _ = std::fs::remove_dir_all(&area);
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

    // --- the mis-seal gate (#63, ADR 0038 §1) ---

    /// A fresh keyless workspace at a unique temp dir — enough for `seal_gate`,
    /// which reads the working tree + `.lootattributes` and never signs.
    fn gate_ws(tag: &str) -> (PathBuf, Workspace) {
        let dir = std::env::temp_dir().join(format!("loot-gate-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Workspace::init_at(&dir, "connor").unwrap();
        let ws = Workspace::open_at(&dir).unwrap();
        (dir, ws)
    }

    #[test]
    fn mis_seal_gate_refuses_secret_falling_through_to_public() {
        // `.env` with no rule naming it → the public default → refusal.
        let (dir, ws) = gate_ws("fallthrough");
        std::fs::write(dir.join(".env"), b"TOKEN=hunter2").unwrap();
        std::fs::write(dir.join("README.md"), b"# hi").unwrap();
        let err = ws.seal_gate(&[]).unwrap_err();
        assert!(err.contains("refusing to seal"), "{err}");
        assert!(err.contains(".env"), "names the offending path: {err}");
        assert!(err.contains("--allow-reveal"), "points at the fix: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mis_seal_gate_consents_to_an_explicit_public_rule() {
        // An explicit rule that *names* the path public is deliberate consent.
        let (dir, ws) = gate_ws("consent");
        std::fs::write(dir.join(".env"), b"TOKEN=hunter2").unwrap();
        std::fs::write(dir.join(".lootattributes"), ".env public\n").unwrap();
        let seals = ws.seal_gate(&[]).expect("explicit rule is consent");
        assert!(
            seals.iter().any(|(p, v)| p.ends_with(".env") && matches!(v, Visibility::Public)),
            "the consented .env is a first seal: {seals:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mis_seal_gate_override_flag_allows_the_seal() {
        // `--allow-reveal .env` waves the exact path through (still refuses others).
        let (dir, ws) = gate_ws("override");
        std::fs::write(dir.join(".env"), b"TOKEN=hunter2").unwrap();
        std::fs::write(dir.join("server.pem"), b"-----BEGIN-----").unwrap();
        // Only `.env` is allowed → `server.pem` still refuses, `.env` does not.
        let err = ws.seal_gate(&[PathBuf::from(".env")]).unwrap_err();
        assert!(err.contains("server.pem"), "the un-allowed path is named: {err}");
        assert!(!err.contains(".env"), "the allowed path is waved through: {err}");
        // Both allowed → clean.
        ws.seal_gate(&[PathBuf::from(".env"), PathBuf::from("server.pem")])
            .expect("both overridden");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mis_seal_gate_leaves_non_secret_paths_untouched() {
        // An ordinary file falling through to public is exactly the common case —
        // never a refusal, only a first-seal line.
        let (dir, ws) = gate_ws("nonsecret");
        std::fs::write(dir.join("main.rs"), b"fn main() {}").unwrap();
        std::fs::write(dir.join("notes.txt"), b"todo").unwrap();
        let seals = ws.seal_gate(&[]).expect("non-secret public paths never refuse");
        assert_eq!(seals.len(), 2, "both are first seals: {seals:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mis_seal_gate_catch_all_public_rule_still_refuses() {
        // A `* public` catch-all is the fallthrough the ADR calls out — it waves
        // the secret through without naming it, so the gate still refuses.
        let (dir, ws) = gate_ws("catchall");
        std::fs::write(dir.join("id_rsa"), b"PRIVATE KEY").unwrap();
        std::fs::write(dir.join(".lootattributes"), "* public\n").unwrap();
        let err = ws.seal_gate(&[]).unwrap_err();
        assert!(err.contains("id_rsa"), "catch-all does not count as consent: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mis_seal_gate_restricted_secret_does_not_refuse() {
        // A secret sealed *restricted* is not a public seal at all — no refusal,
        // and it is not offered as a public first-seal.
        let (dir, ws) = gate_ws("restricted");
        std::fs::write(dir.join(".env"), b"TOKEN=hunter2").unwrap();
        std::fs::write(dir.join(".lootattributes"), ".env restricted=connor\n").unwrap();
        let seals = ws.seal_gate(&[]).expect("restricted secret is safe");
        assert!(
            seals.iter().any(|(p, v)| p.ends_with(".env")
                && matches!(v, Visibility::Restricted(ids) if ids == &["connor"])),
            "the .env first-seal is restricted, not public: {seals:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mis_seal_gate_covers_the_amend_refinalize() {
        // #353: ADR 0038 §1 says the gate fires at every signing verb. An amend
        // (`loot edit` → re-finalize) signs a tree too — a secret-shaped path
        // whose FIRST seal arrives through the amend must refuse at the
        // finalize seam itself, not only via `cmd_new`'s courtesy preflight.
        let dir = std::env::temp_dir().join(format!("loot-gate-amend-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        std::fs::write(dir.join("base.txt"), b"base").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();
        std::fs::write(dir.join("app.rs"), b"fn main() {}").unwrap();
        ws.snapshot("target").unwrap();
        ws.finalize_working().unwrap();
        let x = ws.repo().heads()[0].clone();
        let cid = ws.repo().change_change_id(&x).unwrap();
        ws.edit(&loot_core::hex::letters(&cid)).unwrap();
        // The amend introduces the secret, public by fallthrough (no rule).
        std::fs::write(dir.join(".env"), b"TOKEN=hunter2").unwrap();
        // The re-finalize must run the gate: refuse, and sign nothing.
        let err = ws.finalize_capturing(&[], false).unwrap_err();
        assert!(err.contains("refusing to seal"), "{err}");
        assert!(err.contains(".env"), "names the offending path: {err}");
        let reopened = ws.working_id().cloned();
        assert!(reopened.is_some(), "the reopen is still in progress — nothing was signed");
        let live = ws.liveness().live_of(&cid);
        assert_eq!(live.len(), 1, "no divergence was minted");
        let live_v = live.into_iter().next().unwrap();
        assert_eq!(Some(live_v.clone()), reopened, "the live version is still the unsigned reopen");
        assert!(ws.repo().change_signature(&live_v).is_none(), "…and it is unsigned");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mis_seal_gate_amend_refinalize_allow_reveal_overrides() {
        // #353: the override has the same semantics at the finalize seam as at
        // `describe`/`new` — the deliberate seal goes through, signed, and the
        // first-seal summary names it.
        let dir = std::env::temp_dir().join(format!("loot-gate-amendok-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        std::fs::write(dir.join("base.txt"), b"base").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();
        std::fs::write(dir.join("app.rs"), b"fn main() {}").unwrap();
        ws.snapshot("target").unwrap();
        ws.finalize_working().unwrap();
        let x = ws.repo().heads()[0].clone();
        let cid = ws.repo().change_change_id(&x).unwrap();
        ws.edit(&loot_core::hex::letters(&cid)).unwrap();
        std::fs::write(dir.join(".env"), b"TOKEN=hunter2").unwrap();
        let (finalized, seals) = ws
            .finalize_capturing_allowing(&[], &[PathBuf::from(".env")], false)
            .expect("the override waves the amend's secret through");
        let x2 = finalized.expect("the amend finalized a new version");
        assert_ne!(x2, x, "a fresh version id");
        assert_eq!(ws.repo().change_change_id(&x2), Some(cid), "under the same handle");
        assert!(ws.repo().change_signature(&x2).is_some(), "signed");
        assert!(
            ws.repo().change_tree(&x2).unwrap().keys().any(|p| p.ends_with(".env")),
            "the amended tree carries the revealed path"
        );
        assert!(
            seals.iter().any(|(p, v)| p.ends_with(".env") && matches!(v, Visibility::Public)),
            "the first-seal summary names the deliberate reveal: {seals:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mis_seal_gate_amend_refinalize_explicit_rule_is_consent() {
        // #353: an explicit `.lootattributes` rule naming the path is consent —
        // the amend's re-finalize does not refuse, exactly as at `new`.
        let dir = std::env::temp_dir().join(format!("loot-gate-amendrule-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        std::fs::write(dir.join("base.txt"), b"base").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();
        std::fs::write(dir.join("app.rs"), b"fn main() {}").unwrap();
        ws.snapshot("target").unwrap();
        ws.finalize_working().unwrap();
        let cid = ws.repo().change_change_id(&ws.repo().heads()[0]).unwrap();
        ws.edit(&loot_core::hex::letters(&cid)).unwrap();
        std::fs::write(dir.join(".env"), b"TOKEN=hunter2").unwrap();
        std::fs::write(dir.join(".lootattributes"), ".env public\n").unwrap();
        let finalized = ws
            .finalize_capturing(&[], false)
            .expect("an explicit rule is consent — no refusal at the re-finalize");
        assert!(finalized.is_some(), "the amend finalized");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mis_seal_gate_covers_fold_line_ins_wip_finalize() {
        // #353 audit: `fold_line_in` (lane merge / adopt catch-up) captures and
        // signs in-progress WIP as the merge parent. A secret that reached the
        // disk after the WIP was described would be signed ungated — the gate
        // must run at this finalize too.
        use loot_core::Change;
        let dir = std::env::temp_dir().join(format!("loot-gate-fold-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        std::fs::write(dir.join("base.txt"), b"base").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();
        let base = ws.repo().heads()[0].clone();
        let base_tree = ws.repo().change_tree(&base).unwrap();
        // Pin the position at base so the wip below forks from base (a pristine
        // home would fork from all heads, folding `their` in before the merge).
        ws.pin_tip_at_anchor();
        // Described WIP whose disk tree grew a fallthrough-public secret.
        std::fs::write(dir.join("wip.txt"), b"wip").unwrap();
        ws.snapshot("described wip").unwrap();
        // A finalized sibling line to fold in (a reword-style sibling suffices).
        let their = ws
            .with_repo(|repo| {
                repo.record_carrying(
                    Change {
                        id: Oid([0; 32]),
                        parents: vec![base.clone()],
                        message: "their line".into(),
                        tree: base_tree.clone(),
                    },
                    Some([7u8; 16]),
                )
                .map_err(|e| e.to_string())
            })
            .unwrap();
        std::fs::write(dir.join(".env"), b"TOKEN=hunter2").unwrap();
        let err = ws.fold_line_in(&their, "fold").unwrap_err();
        assert!(err.contains("refusing to seal"), "{err}");
        assert!(err.contains(".env"), "names the offending path: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mis_seal_gate_is_silent_once_the_secret_is_anchored() {
        // First-seal scoping (mirrors the demotion guard's history-relativity):
        // once a path is in the finalized anchor, the gate never re-trips — so an
        // override is a one-time ceremony and carry-along captures stay quiet.
        let (dir, mut ws) = gate_ws("anchored");
        std::fs::write(dir.join(".env"), b"TOKEN=hunter2").unwrap();
        // Seal it (deliberately public, via the override) and finalize.
        ws.seal_gate(&[PathBuf::from(".env")]).unwrap();
        ws.snapshot("seal env").unwrap();
        ws.finalize_working().unwrap();
        // A fresh change touching another file: `.env` is now anchored, so a bare
        // gate (no override) is clean.
        std::fs::write(dir.join("app.rs"), b"fn main() {}").unwrap();
        let seals = ws.seal_gate(&[]).expect("anchored secret no longer trips the gate");
        assert!(
            !seals.iter().any(|(p, _)| p.ends_with(".env")),
            "an anchored path is not a first seal: {seals:?}"
        );
        assert!(seals.iter().any(|(p, _)| p.ends_with("app.rs")), "the new file is: {seals:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn is_catchall_distinguishes_wildcards_from_named_rules() {
        assert!(is_catchall("*"));
        assert!(is_catchall("**"));
        assert!(is_catchall("**/*"));
        assert!(is_catchall("*/**"));
        assert!(!is_catchall(""));
        assert!(!is_catchall("*.pem"));
        assert!(!is_catchall(".env*"));
        assert!(!is_catchall("id_*"));
        assert!(!is_catchall("docs/private/*"));
    }

    #[test]
    fn is_secret_name_matches_basenames_anywhere_case_insensitively() {
        for p in [".env", ".env.local", "config/.env", "server.pem", "tls.KEY", "id_ed25519",
                  "deploy/aws_credentials.json", ".npmrc", "store.p12"] {
            assert!(is_secret_name(Path::new(p)), "should be secret-shaped: {p}");
        }
        for p in ["main.rs", "README.md", "id_map.rs", "envelope.txt", "keymap.json"] {
            assert!(!is_secret_name(Path::new(p)), "should NOT be secret-shaped: {p}");
        }
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
    fn a_repo_that_never_spawns_a_lane_writes_no_dock_files() {
        // The CA1 compatibility guarantee (ADR 0022/0034): the primary is the
        // only dock and lanes are opt-in, so a repo that never spawns one is
        // byte-for-byte its pre-dock self — no ambient pointer, no `docks/` dir.
        let (dir, mut ws) = dock_repo("compat");
        std::fs::write(dir.join("a.txt"), b"x").unwrap();
        ws.snapshot("work").unwrap();
        ws.finalize_working().unwrap();
        ws.snapshot("more").unwrap();

        let dot = dir.join(".loot");
        assert!(!dot.join("dock").exists(), "no ambient-dock pointer");
        assert!(!dot.join("docks").exists(), "no docks directory (retired, #253)");
        assert!(!dot.join("tip").exists(), "the primary persists no explicit tip when idle");
        assert_eq!(ws.current_dock(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // In-place dock switching and named-dock isolation (`two_docks_hold_…`,
    // `dock_goto_is_idempotent_…`) are retired with `.loot/docks/` (#253/ADR
    // 0034): a second position is a sealed lane, and lane isolation is proven by
    // `lane_wip_is_sealed_…` / `lane_spawn_materializes_…` below.

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

    /// Spawn a named lane beside the repo (sibling of `dir`), write `files` into
    /// it, and snapshot + finalize one signed change there. The lane's finalized
    /// change enters the shared graph/objects (the seal) but stays out of the
    /// primary's view — the merge source `loot lane merge` resolves and ingests
    /// (#253). Returns the lane's finalized tip. Callers reopen the primary
    /// afterward to load the lane's new objects, exactly as the CLI's fresh
    /// `Workspace::open()` does before a merge.
    fn lane_with_change(
        ws: &mut Workspace,
        area: &Path,
        name: &str,
        files: &[(&str, &[u8])],
        msg: &str,
    ) -> Oid {
        let spawned = ws.spawn_lane_as(Some(name), Some(&area.join(name)), None).unwrap();
        let mut lw = Workspace::open_at(&spawned.dir).unwrap();
        for (rel, content) in files {
            let path = spawned.dir.join(rel);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(path, content).unwrap();
        }
        lw.snapshot(msg).unwrap();
        lw.finalize_working().unwrap();
        lw.heads().into_iter().next().expect("the lane finalized a tip")
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
    fn a_lane_workspaces_root_is_the_lane_dir_and_its_dot_the_shared_store() {
        // #287: `dot()` is ALWAYS the shared store's `.loot` (identity/keys are
        // shared across positions, ADR 0034); `root()` is the position's own
        // tree. loot-first derived its pre-land gate cwd from `dot()` and so
        // cargo-tested the primary's tree on lane lands.
        let (area, dir, mut ws) = lane_setup("root-vs-dot");
        let spawned = ws.spawn_lane(None, Some(&area.join("l287"))).unwrap();
        let lw = Workspace::open_at(&spawned.dir).unwrap();
        assert_eq!(lw.root(), spawned.dir, "a lane's root is its own tree");
        assert_eq!(
            std::fs::canonicalize(lw.dot()).unwrap(),
            std::fs::canonicalize(dir.join(DOT)).unwrap(),
            "a lane's dot is the SHARED store's .loot"
        );
        assert_eq!(ws.root(), dir, "the primary's root is the checkout itself");
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn a_lane_cannot_take_the_primary_handle_or_a_live_lane_id() {
        // #281/#253: the review-ref suffix is the lane id from a lane and `main`
        // from the primary. Named docks are retired, so the only reservations
        // left in the lane id space are `main` (the primary's handle, always
        // taken) and each live lane's own id.
        let (area, _dir, mut ws) = lane_setup("lane-namespace");
        let a = ws.spawn_lane_as(None, Some(&area.join("lane-a")), Some("t9")).unwrap();
        assert_eq!(a.id, "t9");
        // A second spawn under the same handle suffixes past the live lane.
        let b = ws.spawn_lane_as(None, Some(&area.join("lane-b")), Some("t9")).unwrap();
        assert_eq!(b.id, "t9-2", "a live lane id is taken in the lane id space");
        // `main` (the primary's review handle) never becomes a lane id: handle
        // validation already refuses the default dock's name.
        let err = ws.spawn_lane_as(None, Some(&area.join("lane-c")), Some("main")).unwrap_err();
        assert!(err.contains("default dock"), "{err}");

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
            lw.merge_lane("elsewhere").map(|_| ()).unwrap_err(),
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
    fn finalize_advances_a_seeded_home_dock_tip() {
        // Regression (#234 land dogfood): `loot adopt`/`dock merge` pins a tip on
        // the *home* dock, but with no other docks `docks_active()` is false and it
        // is not a lane — so finalize dropped the signed change WITHOUT advancing
        // the seeded tip, leaving the dock stuck at the adopt anchor while the
        // change orphaned. A land then aimed git-main at the anchor and moved
        // nothing (the #195 guard caught it live). This is the home-dock twin of
        // the lane seeded-tip case above (ADR 0036).
        let dir = std::env::temp_dir().join(format!("loot-234-seeded-tip-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        let (a, _b) = seed_fork(&mut ws);
        seed_mirror_main(&ws, &"a".repeat(40), &a);

        // Adopt pins the home dock's tip on `a` (a seeded tip; no other docks).
        let a_hex = loot_core::hex::encode(&a.0);
        ws.adopt(&a_hex, true).unwrap();
        assert_eq!(ws.finalized_anchor(), Some(a.clone()), "adopt seeded the tip on the target");

        // Work + finalize on the home dock.
        std::fs::write(dir.join("work.txt"), b"docs").unwrap();
        ws.snapshot("home work").unwrap();
        let finalized = ws.finalize_capturing(&[], false).unwrap();

        assert!(finalized.is_some(), "the change was finalized");
        assert_ne!(ws.finalized_anchor(), Some(a.clone()), "tip must leave the adopt anchor");
        assert_eq!(ws.finalized_anchor(), finalized, "the finalized change is the new tip");
        assert_eq!(
            ws.repo().heads(),
            finalized.into_iter().collect::<Vec<_>>(),
            "tip == the head",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn undescribed_is_the_one_seam_both_shapes_cross() {
        // The refusal keys on this predicate and `loot-first`'s PR title keys on
        // it too, so the placeholder must be minted and tested in one place only
        // — a stray literal that drifted would silently stop the #174 refusal
        // firing on whichever path still carried the old string.
        assert!(is_undescribed(UNDESCRIBED_MESSAGE), "the placeholder is un-described");
        assert!(is_undescribed(""), "so is an empty message");
        assert!(is_undescribed("   "), "so is whitespace");
        assert!(is_undescribed(&format!("  {UNDESCRIBED_MESSAGE}  ")), "untrimmed too");
        assert!(!is_undescribed("feat: a real subject"), "a real name is described");
    }

    #[test]
    fn finalize_refuses_an_undescribed_capture_but_keeps_the_work() {
        // #174: `status`'s hint sent a dirty tree at `loot new`, which is
        // capture-*then*-finalize — one stroke signed the edits under the
        // un-described placeholder, skipping the review lane, and that string
        // rode to git main as a permanent commit subject. Finalize is the
        // signing boundary, so it is where the refusal belongs.
        let dir = std::env::temp_dir().join(format!("loot-174-undescribed-{}", std::process::id()));
        let mut ws = authored_ws(&dir);

        std::fs::write(dir.join("work.txt"), b"unreviewed").unwrap();
        let err = ws.finalize_capturing(&[], false).unwrap_err();
        assert!(err.contains("describe"), "the refusal names the verb to run: {err}");

        // Refusing is safe, not lossy: the capture still happened, so the edits
        // are held in the working change — only the *signing* was withheld.
        assert!(ws.working.is_some(), "the edits were captured, not dropped");
        assert_eq!(ws.finalized_anchor(), None, "nothing was signed");

        // And naming it clears the refusal — the two-step the hint now points at.
        ws.snapshot("work: a subject that reads like history").unwrap();
        let finalized = ws.finalize_capturing(&[], false).unwrap();
        assert!(finalized.is_some(), "a described change finalizes");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finalize_refuses_a_capture_left_under_the_placeholder_message() {
        // The placeholder is *stored* by every carry-along capture (dock switch,
        // adopt, ferry), so by the time `new` runs, "un-described" usually looks
        // like `Some("(working change)")` rather than `None`. Both are the same
        // state and both must refuse (#174).
        let dir = std::env::temp_dir().join(format!("loot-174-placeholder-{}", std::process::id()));
        let mut ws = authored_ws(&dir);

        std::fs::write(dir.join("work.txt"), b"unreviewed").unwrap();
        ws.snapshot(UNDESCRIBED_MESSAGE).unwrap();
        let err = ws.finalize_capturing(&[], false).unwrap_err();
        assert!(err.contains("describe"), "a stored placeholder is un-described too: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finalize_refuses_an_undescribed_change_under_no_snapshot_too() {
        // `--no-snapshot` skips the capture, not the signature — the change it
        // seals is just as un-described (#174).
        let dir = std::env::temp_dir().join(format!("loot-174-no-snap-{}", std::process::id()));
        let mut ws = authored_ws(&dir);

        std::fs::write(dir.join("work.txt"), b"unreviewed").unwrap();
        ws.snapshot(UNDESCRIBED_MESSAGE).unwrap();
        let err = ws.finalize_capturing(&[], true).unwrap_err();
        assert!(err.contains("describe"), "--no-snapshot still refuses: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bare_new_on_a_clean_tree_is_still_a_no_op_not_a_refusal() {
        // The #174 refusal must fire on *unreviewed work*, never on the empty
        // capture a bare `loot new` makes on a clean tree — that path mints no
        // signed change and so has no subject to get wrong.
        let dir = std::env::temp_dir().join(format!("loot-174-bare-new-{}", std::process::id()));
        let mut ws = authored_ws(&dir);

        std::fs::write(dir.join("work.txt"), b"described").unwrap();
        ws.snapshot("work: the first change").unwrap();
        ws.finalize_capturing(&[], false).unwrap();

        // Clean tree, no working change: `new` again finalizes nothing.
        assert_eq!(ws.finalize_capturing(&[], false).unwrap(), None, "nothing to finalize");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finalize_signs_a_deletion_only_change() {
        // #289: a change whose only content is DELETING files is real work. The
        // tip-duplicate drop judged it content-identical to the tip (the tree
        // comparison never saw the missing paths) and silently destroyed the
        // working change — describe message and all — at finalize.
        let dir = std::env::temp_dir().join(format!("loot-289-del-only-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        std::fs::write(dir.join("keep.txt"), b"k").unwrap();
        std::fs::write(dir.join("gone.txt"), b"g").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();
        let tip = ws.finalized_anchor().unwrap();

        std::fs::remove_file(dir.join("gone.txt")).unwrap();
        ws.snapshot("chore: delete gone.txt").unwrap(); // describe -m
        let finalized = ws.finalize_capturing(&[], false).unwrap();
        let new_tip = finalized
            .expect("a deletion-only change must be SIGNED, not dropped as a tip-duplicate (#289)");
        assert_ne!(new_tip, tip, "the tip advanced");
        assert_eq!(ws.finalized_anchor(), Some(new_tip.clone()), "onto the signed deletion");
        let tree = ws.repo().change_tree(&new_tip).unwrap();
        assert!(!tree.contains_key(std::path::Path::new("gone.txt")), "the deletion is recorded");
        assert!(tree.contains_key(std::path::Path::new("keep.txt")), "kept content rides along");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finalize_signs_a_delete_everything_change() {
        // The #289 boundary case: an EMPTY capture over a non-empty tip is a
        // delete-everything change, not "nothing" — only a bare `new` with
        // nothing held to compare against still drops an empty capture.
        let dir = std::env::temp_dir().join(format!("loot-289-del-all-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        std::fs::write(dir.join("only.txt"), b"o").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();

        std::fs::remove_file(dir.join("only.txt")).unwrap();
        ws.snapshot("chore: delete everything").unwrap();
        let finalized = ws.finalize_capturing(&[], false).unwrap();
        let new_tip = finalized.expect("delete-everything is real work — signed, not dropped");
        assert!(
            ws.repo().change_tree(&new_tip).unwrap().is_empty(),
            "the signed manifest is empty — every path deleted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bare_new_over_an_undescribed_deletion_refuses_not_noops() {
        // Now that a deletion-only capture survives the duplicate drop, an
        // un-described one must hit the #174 refusal — it IS real work, and the
        // pre-#289 silent no-op (capture dropped, message and all) is exactly
        // how a cleanup change was destroyed. The refusal keeps the capture.
        let dir = std::env::temp_dir().join(format!("loot-289-undesc-del-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        std::fs::write(dir.join("keep.txt"), b"k").unwrap();
        std::fs::write(dir.join("gone.txt"), b"g").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();

        std::fs::remove_file(dir.join("gone.txt")).unwrap();
        let err = ws.finalize_capturing(&[], false).unwrap_err();
        assert!(err.contains("describe"), "the refusal names the verb to run: {err}");
        assert!(ws.working.is_some(), "the deletion capture is held, not dropped");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_named_tip_identical_capture_is_still_dropped() {
        // Regression guard on the #289 fix: a TRULY identical capture — same
        // path set, same content (the co-located checkout after a `git pull`,
        // or a save that changed nothing) — still evaporates at finalize, even
        // when it carries a name.
        let dir = std::env::temp_dir().join(format!("loot-289-identical-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        std::fs::write(dir.join("a.txt"), b"same").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();
        let tip = ws.finalized_anchor();

        std::fs::write(dir.join("a.txt"), b"same").unwrap(); // rewritten, same bytes
        ws.snapshot("chore: describes nothing new").unwrap();
        assert_eq!(ws.finalize_capturing(&[], false).unwrap(), None, "identical capture dropped");
        assert_eq!(ws.finalized_anchor(), tip, "the tip did not move");
        assert!(ws.working.is_none(), "no stray working change left behind");
        let _ = std::fs::remove_dir_all(&dir);
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

    // --- CA2: local lane merge (#253/ADR 0034 — a dock is a named lane) ---

    #[test]
    fn lane_merge_does_not_nag_for_a_name_when_there_is_no_real_work_to_sign() {
        // The #275 refusal must fire on *work*, never on a capture that adds
        // nothing over the tip — otherwise `lane merge` demands a name for
        // content that will never be signed. The sibling sites (`finalize_capturing`,
        // `reconcile_capture`) sit below such a drop; `fold_line_in` now does too.
        let (area, dir, mut ws) = lane_setup("merge-no-nag");
        lane_with_change(&mut ws, &area, "feature", &[("feature.txt", b"F")], "feature work");
        // Reopen the primary to load the lane's objects (the CLI's fresh open).
        let mut ws = Workspace::open_at(&dir).unwrap();

        // An un-described capture that duplicates the tip: the operator's edit,
        // reverted before merging. Real state, no real work.
        std::fs::write(dir.join("scratch.txt"), b"tmp").unwrap();
        ws.snapshot(UNDESCRIBED_MESSAGE).unwrap();
        std::fs::remove_file(dir.join("scratch.txt")).unwrap();

        let (src, _outcomes) = ws
            .merge_lane("feature")
            .expect("nothing to sign, so nothing to name — the merge just runs");
        assert_eq!(src, "feature");
        assert!(
            ws.repo().change_message(&ws.anchor().unwrap()).is_some_and(|m| !is_undescribed(&m)),
            "and no placeholder-named change was signed as a parent",
        );
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn lane_merge_refuses_to_seal_undescribed_work_as_a_merge_parent() {
        // The other half: with real un-described work pending, `lane merge` asks
        // for a name rather than signing the placeholder as its parent (#275).
        let (area, dir, mut ws) = lane_setup("merge-undescribed");
        lane_with_change(&mut ws, &area, "feature", &[("feature.txt", b"F")], "feature work");
        let mut ws = Workspace::open_at(&dir).unwrap();

        std::fs::write(dir.join("home.txt"), b"my unnamed work").unwrap();
        ws.snapshot(UNDESCRIBED_MESSAGE).unwrap();

        let err = ws.merge_lane("feature").map(|_| ()).unwrap_err();
        assert!(err.contains("describe"), "the refusal names the verb to run: {err}");
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn lane_merge_converges_disjoint_edits() {
        // Acceptance: a lane and the primary editing disjoint paths merge cleanly
        // with no conflict, and the merged tree carries both lines' files.
        let (area, dir, mut ws) = lane_setup("merge-disjoint");
        lane_with_change(&mut ws, &area, "feature", &[("feature.txt", b"F")], "feature work");
        let mut ws = Workspace::open_at(&dir).unwrap();

        std::fs::write(dir.join("home.txt"), b"H").unwrap();
        ws.snapshot("home work").unwrap();
        ws.finalize_working().unwrap();

        let (src, outcomes) = ws.merge_lane("feature").unwrap();
        assert_eq!(src, "feature");
        assert!(ws.repo().conflicts().is_empty(), "disjoint edits: no conflicts");
        assert_eq!(outcomes[&PathBuf::from("feature.txt")], MergeOutcome::Converged);
        // Merge materialized both lines onto the primary working tree.
        assert!(dir.join("base.txt").exists());
        assert!(dir.join("home.txt").exists());
        assert!(dir.join("feature.txt").exists(), "feature work present after merge");
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn lane_merge_same_path_conflicts_and_keeps_both_sides() {
        // Acceptance: a genuine same-path divergence surfaces as a Conflict via the
        // existing conflicts/resolve flow, with neither side dropped.
        let (area, dir, mut ws) = lane_setup("merge-conflict");
        lane_with_change(&mut ws, &area, "feature", &[("a.txt", b"feature side\n")], "feat");
        let mut ws = Workspace::open_at(&dir).unwrap();

        std::fs::write(dir.join("a.txt"), b"home side\n").unwrap();
        ws.snapshot("home").unwrap();
        ws.finalize_working().unwrap();

        let (_src, outcomes) = ws.merge_lane("feature").unwrap();
        assert!(matches!(outcomes[&PathBuf::from("a.txt")], MergeOutcome::Conflict { .. }));
        assert!(
            ws.repo().conflicts().contains_key(&PathBuf::from("a.txt")),
            "conflict recorded for `loot resolve`"
        );
        // Ours is kept on disk; theirs is preserved in the recorded conflict and
        // via the merge change's second parent — no side dropped.
        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"home side\n");
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn conflict_at_reads_both_sides_of_a_recorded_conflict() {
        // #13: after a same-path conflict, `conflict_at` surfaces both sides with
        // their content. Both blobs are public here, so both decrypt (key held).
        let (area, dir, mut ws) = lane_setup("conflict-at");
        lane_with_change(&mut ws, &area, "feature", &[("a.txt", b"feature side\n")], "feat");
        let mut ws = Workspace::open_at(&dir).unwrap();

        std::fs::write(dir.join("a.txt"), b"home side\n").unwrap();
        ws.snapshot("home").unwrap();
        ws.finalize_working().unwrap();
        let (_src, outcomes) = ws.merge_lane("feature").unwrap();
        assert!(matches!(outcomes[&PathBuf::from("a.txt")], MergeOutcome::Conflict { .. }));

        let view = ws.graph().conflict_at(Path::new("a.txt")).unwrap();
        assert_eq!(view.path, PathBuf::from("a.txt"));
        assert_eq!(view.ours.content.as_deref(), Some(&b"home side\n"[..]), "ours = the kept side");
        assert_eq!(
            view.theirs.content.as_deref(),
            Some(&b"feature side\n"[..]),
            "theirs = the incoming side"
        );
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn conflict_at_errors_when_the_path_is_not_in_conflict() {
        // #13: a clear, actionable error rather than an empty/None result.
        let (area, _dir, ws) = lane_setup("conflict-at-none");
        let err = ws.graph().conflict_at(Path::new("nope.txt")).unwrap_err();
        assert!(err.contains("no conflict"), "{err}");
        assert!(err.contains("loot conflicts"), "points at the listing verb: {err}");
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn lane_merge_conflict_resolution_advances_the_primary_tip() {
        // Regression (CA2 review): after a conflicted lane merge, `resolve` must
        // build on and advance the primary's tip — not orphan the resolution onto
        // a stray head — so later work sees the resolved content.
        let (area, dir, mut ws) = lane_setup("merge-resolve");
        lane_with_change(&mut ws, &area, "feature", &[("a.txt", b"feature side\n")], "feat");
        let mut ws = Workspace::open_at(&dir).unwrap();

        std::fs::write(dir.join("a.txt"), b"home side\n").unwrap();
        ws.snapshot("home").unwrap();
        ws.finalize_working().unwrap();

        let (_src, outcomes) = ws.merge_lane("feature").unwrap();
        assert!(matches!(outcomes[&PathBuf::from("a.txt")], MergeOutcome::Conflict { .. }));

        // Resolve — the resolution becomes the primary tip and lands on disk.
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
            "the primary line carries the resolution, not the conflicted merge"
        );
        assert!(dir.join("b.txt").exists(), "new work sits on the resolved tip");
        let _ = std::fs::remove_dir_all(&area);
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
        let (area, dir, mut ws) = lane_setup("resolve-no-clobber");
        // Base carries the two files that will conflict plus an unrelated file.
        std::fs::write(dir.join("a.txt"), b"base a\n").unwrap();
        std::fs::write(dir.join("d.txt"), b"base d\n").unwrap();
        std::fs::write(dir.join("c.txt"), b"base c\n").unwrap();
        ws.snapshot("base2").unwrap();
        ws.finalize_working().unwrap();

        lane_with_change(
            &mut ws,
            &area,
            "feature",
            &[("a.txt", b"feature a\n"), ("d.txt", b"feature d\n")],
            "feat",
        );
        let mut ws = Workspace::open_at(&dir).unwrap();

        std::fs::write(dir.join("a.txt"), b"home a\n").unwrap();
        std::fs::write(dir.join("d.txt"), b"home d\n").unwrap();
        ws.snapshot("home").unwrap();
        ws.finalize_working().unwrap();

        // Merge produces two conflicts (a.txt and d.txt); the merge leaves ours
        // on disk and c.txt at its base content.
        let (_src, outcomes) = ws.merge_lane("feature").unwrap();
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
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn bounced_land_resolution_inherits_the_described_subject() {
        // #337: a harbor bounce is reconciled with `loot resolve`, and the
        // resolution used to mint "resolve conflict at <path>" — projected 1:1
        // to git main, that placeholder buried the landed change's real
        // subject under a wall of identical commits. The resolution must
        // inherit the described subject instead, and the workspace must
        // surface the minted message to the operator.
        let (area, dir, mut ws) = lane_setup("337-inherit-subject");
        // A sibling forks at base and lands a conflicting edit of base.txt.
        let c2 = lane_with_change(
            &mut ws,
            &area,
            "sibling",
            &[("base.txt", b"theirs\n")],
            "sibling landed",
        );
        let mut ws = Workspace::open_at(&dir).unwrap();

        // Ours: the described change being landed edits the same path.
        std::fs::write(dir.join("base.txt"), b"ours\n").unwrap();
        ws.snapshot("loot grant-status <path>: list current grantees (#5)").unwrap();
        ws.finalize_working().unwrap();
        let ours = ws.finalized_anchor();

        // The ferry reconcile the land runs — same-path divergence bounces.
        let outcomes = ws
            .reconcile_onto(Some(&c2), ours.as_ref(), "ferry: reconcile git main", false)
            .unwrap();
        assert!(
            matches!(outcomes[&PathBuf::from("base.txt")], MergeOutcome::Conflict { .. }),
            "precondition: the reconcile bounced on base.txt"
        );

        let (_oid, message) =
            ws.resolve_conflict(Path::new("base.txt"), b"resolved\n", Visibility::Public).unwrap();
        assert_eq!(
            message,
            "loot grant-status <path>: list current grantees (#5) (conflict resolution: base.txt)",
            "the resolution inherits the landed change's subject"
        );
        // The tip change — what ferry will project to git main — carries it.
        let tip = ws.anchor().expect("resolve advanced the tip");
        assert_eq!(ws.repo().change_message(&tip).as_deref(), Some(message.as_str()));
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn the_primary_integrates_a_lane_and_re_merging_is_up_to_date() {
        // The primary IS the harbor now (#253/ADR 0034): a lane's finalized line
        // folds into it through the shared merge machinery, and folding the same
        // line again is a clean no-op — the round-trip the old three-dock
        // `harbor`-by-convention test exercised, over one primary + one lane.
        let (area, dir, mut ws) = lane_setup("harbor");
        lane_with_change(&mut ws, &area, "feature", &[("feat.txt", b"F")], "feat");
        let mut ws = Workspace::open_at(&dir).unwrap();

        assert!(!dir.join("feat.txt").exists(), "the primary has not merged yet");
        ws.merge_lane("feature").unwrap();
        assert!(dir.join("feat.txt").exists(), "the primary integrated the lane's work");
        assert!(ws.repo().conflicts().is_empty());

        // Folding the same finalized line again is safe — no conflict, the
        // integrated work stays on disk (the round-trip stays clean).
        ws.merge_lane("feature").unwrap();
        assert!(ws.repo().conflicts().is_empty(), "the re-merge stays clean");
        assert!(dir.join("feat.txt").exists());
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn converge_heads_collapses_a_two_writer_fork_no_side_dropped() {
        // #128: after a peer's divergent tip is ingested (pull/apply), the graph
        // has two heads and the working tree shows only our side — apply records +
        // classifies but never merges tips. `converge_heads` collapses the fork
        // into ONE head whose tree carries BOTH sides. The peer's line is built in
        // a sealed lane and ingested (the exact shape a pull leaves), since
        // in-place dock switching is retired (#253/ADR 0034).
        let (area, dir, mut ws) = lane_setup("converge-fork");

        // "Their" line, advanced independently in a lane, then brought into view.
        let their = lane_with_change(&mut ws, &area, "peer", &[("their.txt", b"T")], "theirs");
        let mut ws = Workspace::open_at(&dir).unwrap();

        // "Our" line advances on the primary — now the graph is forked.
        std::fs::write(dir.join("ours.txt"), b"O").unwrap();
        ws.snapshot("ours").unwrap();
        ws.finalize_working().unwrap();
        ws.ingest_sibling(&their);
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
        let _ = std::fs::remove_dir_all(&area);
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
        // Each divergent version carries the head's full manifest (a reword-style
        // amend): every change records its complete tree, and an empty manifest
        // would read as delete-everything against the disk (#289), tripping the
        // dirt refusal before the divergence one this test is about.
        let head_tree = ws.repo().change_tree(&head).unwrap();
        ws.with_repo(|repo| {
            for msg in ["A", "B"] {
                repo.record_carrying(
                    Change {
                        id: Oid([0; 32]),
                        parents: vec![head.clone()],
                        message: msg.into(),
                        tree: head_tree.clone(),
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

    /// Shared setup for the collapse tests: the primary holds `target` (a.txt =
    /// "target"); an `amender` **lane** reopens it and finalizes an amended
    /// version x2 (a.txt = "target amended", superseding x). The lane's x2 is
    /// then ingested into the primary's view as a sibling head — the shape the
    /// old `amender` dock produced when docks shared one heads file (#253/ADR
    /// 0034). Returns the primary's pre-amend tip `x` and the amend `x2`, with
    /// `ws` reopened on the primary (still showing "target").
    fn amended_in_a_lane(tag: &str) -> (PathBuf, PathBuf, Workspace, Oid, Oid) {
        let area = std::env::temp_dir().join(format!("loot-amend-lane-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&area);
        let dir = area.join("repo");
        let mut ws = authored_ws(&dir);
        std::fs::write(dir.join("a.txt"), b"base").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();
        std::fs::write(dir.join("a.txt"), b"target").unwrap();
        ws.snapshot("target").unwrap();
        ws.finalize_working().unwrap();
        let x = ws.repo().heads()[0].clone();
        let cid = ws.repo().change_change_id(&x).unwrap();

        // Amend `target` in a lane (born at the primary's tip = x).
        let spawned = ws.spawn_lane_as(Some("amender"), Some(&area.join("amender")), None).unwrap();
        let mut lw = Workspace::open_at(&spawned.dir).unwrap();
        lw.edit(&loot_core::hex::letters(&cid)).unwrap();
        std::fs::write(spawned.dir.join("a.txt"), b"target amended").unwrap();
        lw.snapshot("target").unwrap();
        lw.finalize_working().unwrap();
        let x2 = lw.liveness().live_of(&cid).into_iter().next().unwrap();

        // Reopen the primary (still on x) and pull the lane's amend into view as a
        // sibling head — the two-head precondition the collapse tests need.
        let mut ws = Workspace::open_at(&dir).unwrap();
        ws.ingest_sibling(&x2);
        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"target", "primary still pre-amend");
        (area, dir, ws, x, x2)
    }

    #[test]
    fn lane_merge_adopts_an_amend_as_a_fast_forward() {
        // ADR 0032: merging a lane whose line SUPERSEDES our tip must not
        // content-merge the two versions (that would resurrect what the amend
        // removed) — it adopts the amend by fast-forward.
        let (area, dir, mut ws, _x, x2) = amended_in_a_lane("laneff");
        let nodes_before = ws.repo().log_detailed().len();
        let (_name, outcomes) = ws.merge_lane("amender").unwrap();
        assert!(outcomes.is_empty(), "a supersession adopts — no merge outcomes");
        assert_eq!(ws.repo().log_detailed().len(), nodes_before, "no merge node minted");
        assert_eq!(
            std::fs::read(dir.join("a.txt")).unwrap(),
            b"target amended",
            "the primary adopted the amend"
        );
        assert!(ws.divergent_change_ids().is_empty(), "a solo amend never renders divergence");
        // Re-merging the now-adopted line is a clean no-op (the up-to-date
        // direction: our superseded tip has nothing to offer the amend).
        let (_n, back) = ws.merge_lane("amender").unwrap();
        assert!(back.is_empty(), "re-merging the adopted amend is a no-op");
        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"target amended");
        let _ = x2;
        let _ = std::fs::remove_dir_all(&area);
    }

    #[test]
    fn converge_heads_drops_a_superseded_head_without_merging() {
        // The peer-side pull path (ADR 0032): a solo amend arrives as a sibling
        // head; converge must DROP the superseded side and adopt the amend —
        // never fold the two into a content merge.
        let (area, dir, mut ws, x, x2) = amended_in_a_lane("convdrop");
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
        let _ = std::fs::remove_dir_all(&area);
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
        let (area, dir, mut ws) = lane_setup("219choke");
        let their = lane_with_change(&mut ws, &area, "peer", &[("their.txt", b"T")], "theirs");
        let mut ws = Workspace::open_at(&dir).unwrap();
        std::fs::write(dir.join("ours.txt"), b"O").unwrap();
        ws.snapshot("ours").unwrap();
        ws.finalize_working().unwrap();
        ws.ingest_sibling(&their);
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
        let _ = std::fs::remove_dir_all(&area);
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

    // `converge_heads_skips_a_sibling_docks_parked_working_change` is retired
    // (#253/ADR 0034): a lane's unsigned WIP is sealed lane-local and never
    // enters another position's view, so there is no cross-position parked head
    // for converge to skip — `liveness()` now feeds an empty parked set.

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

    // --- resolve_selector: the #305 "git-lite" grammar ----------------------

    #[test]
    fn selector_at_names_the_working_change() {
        let dir = std::env::temp_dir().join(format!("loot-sel-at-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        std::fs::write(dir.join("a.txt"), b"one").unwrap();
        ws.snapshot("m").unwrap();
        let working = ws.working_id().cloned().unwrap();
        assert_eq!(ws.resolve_selector("@").unwrap(), working);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn selector_at_without_a_working_change_refuses() {
        let dir = std::env::temp_dir().join(format!("loot-sel-noat-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        std::fs::write(dir.join("a.txt"), b"one").unwrap();
        ws.snapshot("m").unwrap();
        ws.finalize_working().unwrap(); // finalize clears the working change
        let err = ws.resolve_selector("@").unwrap_err();
        assert!(err.contains("no working change") || err.contains("there is none"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn selector_head_and_tilde_walk_the_single_parent_chain() {
        let dir = std::env::temp_dir().join(format!("loot-sel-head-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        std::fs::write(dir.join("a.txt"), b"one").unwrap();
        ws.snapshot("first").unwrap();
        ws.finalize_working().unwrap();
        let first = ws.heads()[0].clone();
        std::fs::write(dir.join("a.txt"), b"two").unwrap();
        ws.snapshot("second").unwrap();
        ws.finalize_working().unwrap();
        let second = ws.heads()[0].clone();

        assert_eq!(ws.resolve_selector("HEAD").unwrap(), second, "HEAD is the tip");
        assert_eq!(ws.resolve_selector("HEAD~1").unwrap(), first, "HEAD~1 is its parent");
        assert_eq!(ws.resolve_selector("HEAD~0").unwrap(), second, "HEAD~0 is HEAD");
        // Walking past the root refuses, naming the id it stalled on.
        let err = ws.resolve_selector("HEAD~5").unwrap_err();
        assert!(err.contains("root") && err.contains("HEAD~5"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn selector_head_with_a_working_change_is_the_finalized_parent_not_working() {
        // The e2e trap: with an in-progress working change, HEAD must be the
        // change it forks from (`@`'s parent), so `loot diff` (HEAD vs @) shows
        // the working edits rather than diffing a change against itself.
        let dir = std::env::temp_dir().join(format!("loot-sel-hw-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        std::fs::write(dir.join("a.txt"), b"one").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();
        let base = ws.heads()[0].clone();
        // Start a working change over the finalized base.
        std::fs::write(dir.join("a.txt"), b"two").unwrap();
        ws.snapshot("wip").unwrap();
        let working = ws.working_id().cloned().unwrap();

        assert_eq!(ws.resolve_selector("HEAD").unwrap(), base, "HEAD is the finalized parent");
        assert_eq!(ws.resolve_selector("@").unwrap(), working, "@ is the working node");
        let deltas = ws.diff(&base, &working).unwrap();
        assert!(
            deltas.iter().any(|d| d.path == Path::new("a.txt")),
            "HEAD vs @ shows the working edit"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn selector_prefix_alphabet_self_selects_the_namespace() {
        let dir = std::env::temp_dir().join(format!("loot-sel-prefix-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        std::fs::write(dir.join("a.txt"), b"one").unwrap();
        ws.snapshot("m").unwrap();
        ws.finalize_working().unwrap();
        let head = ws.heads()[0].clone();
        let cid = ws.repo().change_change_id(&head).unwrap();

        // Hex digits -> a version id.
        let hex = loot_core::hex::encode(&head.0);
        assert_eq!(ws.resolve_selector(&hex[..8]).unwrap(), head, "hex prefix -> version");
        // Letters k-z -> a change id, resolved through liveness to its version.
        let letters = loot_core::hex::letters(&cid);
        assert_eq!(ws.resolve_selector(&letters[..8]).unwrap(), head, "letter prefix -> change");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn selector_rejects_a_non_selector() {
        let dir = std::env::temp_dir().join(format!("loot-sel-bad-{}", std::process::id()));
        let ws = authored_ws(&dir);
        // 'g'..'j' are in neither alphabet (hex is 0-9a-f, change is k-z).
        let err = ws.resolve_selector("ghij").unwrap_err();
        assert!(err.contains("not a valid selector"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- #315: log/attest/abandon retrofitted onto the #305 grammar ---------
    //
    // `loot diff` already spoke `resolve_selector`; these prove the other
    // selector-taking verbs compose with it the same way, at the `Workspace`
    // level — `cmd_*` in main.rs stays a thin wrapper untested directly (the
    // CLI test module only pins flag specs; a full `cmd_*` invocation would
    // walk cwd up to a REAL `.loot`, the hazard noted in the loot-cli test
    // idiom).

    #[test]
    fn ancestors_of_walks_every_parent_edge_inclusive() {
        // `loot log <selector>`'s scoping (#315) is this closure: a full
        // multi-parent walk, `start` included, that never refuses at a merge
        // the way `walk_single_parent`'s `HEAD~n` rule does.
        use loot_core::{Change, Oid};
        let dir = std::env::temp_dir().join(format!("loot-315-ancestors-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        let (root, a, b, merge) = ws
            .with_repo(|repo| {
                let root = repo
                    .record(Change { id: Oid([0; 32]), parents: vec![], message: "root".into(), tree: Default::default() })
                    .map_err(|e| e.to_string())?;
                let a = repo
                    .record(Change { id: Oid([0; 32]), parents: vec![root.clone()], message: "a".into(), tree: Default::default() })
                    .map_err(|e| e.to_string())?;
                let b = repo
                    .record(Change { id: Oid([0; 32]), parents: vec![root.clone()], message: "b".into(), tree: Default::default() })
                    .map_err(|e| e.to_string())?;
                let merge = repo
                    .record(Change { id: Oid([0; 32]), parents: vec![a.clone(), b.clone()], message: "merge".into(), tree: Default::default() })
                    .map_err(|e| e.to_string())?;
                Ok((root, a, b, merge))
            })
            .unwrap();

        let ancestry = ws.ancestors_of(&merge);
        assert_eq!(
            ancestry,
            [root.clone(), a.clone(), b.clone(), merge.clone()].into_iter().collect(),
            "the merge's ancestry is every node behind it, once each"
        );
        // A leaf off the root: just its own single-parent chain.
        assert_eq!(ws.ancestors_of(&a), [root.clone(), a.clone()].into_iter().collect());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn attest_composes_with_a_head_selector_not_just_a_bare_prefix() {
        // #315: `cmd_attest` used to hand-roll its own version-hex-prefix match
        // (`resolve_change`, since retired); it now shares `resolve_selector`
        // with `diff`/`log`/`abandon`, so `HEAD` names the dock tip without the
        // caller ever typing its hex id. `resolve_selector` returns a version
        // `Oid`, and that composes directly with `attest` — `Attestation`
        // records under exactly that id throughout the engine (`attestations_for`
        // is keyed by version id, matching `resolve_change`'s old body, which
        // also matched hex prefixes against `version_ids()`); no separate
        // version->change-id remap belongs on this path.
        let dir = std::env::temp_dir().join(format!("loot-315-attest-head-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        std::fs::write(dir.join("a.txt"), b"one").unwrap();
        ws.snapshot("m").unwrap();
        ws.finalize_working().unwrap();
        let head = ws.heads()[0].clone();

        let version = ws.resolve_selector("HEAD").expect("HEAD resolves through the selector grammar");
        assert_eq!(version, head);
        ws.attest(&version, "reviewed").unwrap();
        let recorded = ws.repo().attestations_for(&version);
        assert_eq!(recorded.len(), 1, "the attestation is recorded under the resolved version id");
        assert_eq!(recorded[0].role, "reviewed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn abandon_fork_composes_with_a_change_id_selector_not_just_a_bare_hex_prefix() {
        // #315: `cmd_abandon` used to call `resolve_live_version` directly
        // (bare hex only); it now goes through `resolve_selector`, so a
        // change-id (letters k-z) prefix resolves too, exactly like `loot
        // diff`/`loot attest` already accept it.
        use loot_core::{Change, Oid};
        let dir = std::env::temp_dir().join(format!("loot-315-abandon-sel-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
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

        // b's full change-id, spelled as letters — the alphabet resolve_selector
        // routes to resolve_change_to_version (ADR 0029).
        let letters = loot_core::hex::letters(&[2u8; 16]);
        let version = ws
            .resolve_selector(&letters)
            .expect("a change-id prefix resolves through the selector grammar");
        assert_eq!(version, b, "resolves to b's live version");

        ws.abandon_fork(&version).unwrap();
        assert!(!ws.repo().heads().contains(&b), "b stopped being a live head");
        assert!(ws.repo().heads().contains(&a), "a survives");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- diff: the #1 path-level delta over two trees -----------------------

    #[test]
    fn diff_reports_added_modified_and_deleted_paths() {
        let dir = std::env::temp_dir().join(format!("loot-diff-amd-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        std::fs::write(dir.join("keep.txt"), b"same").unwrap();
        std::fs::write(dir.join("edit.txt"), b"v1").unwrap();
        std::fs::write(dir.join("gone.txt"), b"bye").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();
        let base = ws.heads()[0].clone();

        std::fs::write(dir.join("edit.txt"), b"v2").unwrap(); // modified
        std::fs::remove_file(dir.join("gone.txt")).unwrap(); // deleted
        std::fs::write(dir.join("new.txt"), b"hello").unwrap(); // added
        ws.snapshot("next").unwrap();
        ws.finalize_working().unwrap();
        let next = ws.heads()[0].clone();

        let deltas = ws.diff(&base, &next).unwrap();
        let by_path = |name: &str| {
            deltas
                .iter()
                .find(|d| d.path == Path::new(name))
                .unwrap_or_else(|| panic!("no delta for {name}"))
                .class
        };
        assert_eq!(by_path("new.txt"), DeltaClass::Added);
        assert_eq!(by_path("edit.txt"), DeltaClass::Modified);
        assert_eq!(by_path("gone.txt"), DeltaClass::Deleted);
        assert!(
            !deltas.iter().any(|d| d.path == Path::new("keep.txt")),
            "an unchanged path is not in the delta"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn diff_records_a_visibility_transition() {
        let dir = std::env::temp_dir().join(format!("loot-diff-vis-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        std::fs::write(dir.join("f.txt"), b"body").unwrap();
        ws.snapshot("public").unwrap();
        ws.finalize_working().unwrap();
        let base = ws.heads()[0].clone();
        // Re-seal the same path restricted: content address moves, and the
        // visibility transition is recorded old -> new.
        std::fs::write(dir.join(".lootattributes"), "f.txt restricted=connor\n").unwrap();
        ws.snapshot("seal").unwrap();
        ws.finalize_working().unwrap();
        let sealed = ws.heads()[0].clone();

        let deltas = ws.diff(&base, &sealed).unwrap();
        let d = deltas.iter().find(|d| d.path == Path::new("f.txt")).unwrap();
        assert!(matches!(d.visibility, Visibility::Restricted(_)), "new side is restricted");
        assert!(
            matches!(d.prev_visibility, Some(Visibility::Public)),
            "the old public side is carried as a transition"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn diff_marks_a_path_sealed_when_the_key_is_not_held() {
        // #1 acceptance: a caller who lacks the restricted key sees the delta as
        // sealed (the renderer then shows the address, never the name).
        let dir_a = std::env::temp_dir().join(format!("loot-diff-seal-a-{}", std::process::id()));
        let mut alice = authored_ws(&dir_a);
        std::fs::write(dir_a.join("doc.txt"), b"public").unwrap();
        alice.snapshot("public base").unwrap();
        alice.finalize_working().unwrap();
        let base = alice.heads()[0].clone();
        // A path sealed to alice alone: bob will hold the ciphertext, not the key.
        std::fs::write(dir_a.join(".lootattributes"), "secret.txt restricted=alice\n").unwrap();
        std::fs::write(dir_a.join("secret.txt"), b"top secret").unwrap();
        alice.snapshot("seal a path").unwrap();
        alice.finalize_working().unwrap();
        let sealed_head = alice.heads()[0].clone();

        let (relay_dir, relay) = relay_holding("diffseal", &alice);
        let dir_b = std::env::temp_dir().join(format!("loot-diff-seal-b-{}", std::process::id()));
        let mut bob = authored_ws(&dir_b);
        bob.pull_via(&relay).unwrap();

        let deltas = bob.diff(&base, &sealed_head).unwrap();
        let d = deltas
            .iter()
            .find(|d| d.path == Path::new("secret.txt"))
            .expect("bob sees the sealed path in the manifest");
        assert!(d.sealed, "bob lacks the key, so the path is sealed to him");
        assert!(matches!(d.visibility, Visibility::Restricted(_)), "the class survives");
        // The two seams composed (diff -> render) — the rendered line the CLI
        // prints never leaks the name, shows the address + class + tag (#306).
        let line = crate::render::delta_line(d);
        assert!(!line.contains("secret.txt"), "the sealed name never renders: {line}");
        assert!(line.contains("restricted") && line.ends_with("(sealed — no key)"), "{line}");
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
        let _ = std::fs::remove_dir_all(&relay_dir);
    }

    // --- status: the #7 working delta over the previous finalized change ----

    #[test]
    fn working_delta_reports_added_modified_and_deleted_vs_the_parent() {
        let dir = std::env::temp_dir().join(format!("loot-wdelta-amd-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        std::fs::write(dir.join("keep.txt"), b"same").unwrap();
        std::fs::write(dir.join("edit.txt"), b"v1").unwrap();
        std::fs::write(dir.join("gone.txt"), b"bye").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();

        // Live, un-captured edits: status is read-only (ADR 0030), so the delta
        // must come off the disk tree, not the last snapshot.
        std::fs::write(dir.join("edit.txt"), b"v2").unwrap(); // modified
        std::fs::remove_file(dir.join("gone.txt")).unwrap(); // deleted
        std::fs::write(dir.join("new.txt"), b"hello").unwrap(); // added

        let deltas = ws.working_delta().unwrap();
        let by_path = |name: &str| {
            deltas
                .iter()
                .find(|d| d.path == Path::new(name))
                .unwrap_or_else(|| panic!("no delta for {name}"))
        };
        assert_eq!(by_path("new.txt").class, DeltaClass::Added);
        assert_eq!(by_path("edit.txt").class, DeltaClass::Modified);
        assert_eq!(by_path("gone.txt").class, DeltaClass::Deleted);
        assert!(
            !deltas.iter().any(|d| d.path == Path::new("keep.txt")),
            "an unchanged path is not in the delta"
        );
        // A deleted path keeps its base-side visibility, exactly as `diff` does.
        assert!(matches!(by_path("gone.txt").visibility, Visibility::Public));
        // The rows render through the shared #306 line: gutter, path, token.
        let line = crate::render::delta_line(by_path("new.txt"));
        assert!(line.starts_with("  +  new.txt"), "{line}");
        assert!(line.ends_with("public"), "the visibility token trails: {line}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn working_delta_reads_every_file_as_added_with_no_parent() {
        // The repo's first change has no parent to diff against — every file on
        // disk is new (#7).
        let dir = std::env::temp_dir().join(format!("loot-wdelta-first-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        std::fs::write(dir.join("a.txt"), b"one").unwrap();
        std::fs::write(dir.join("b.txt"), b"two").unwrap();

        let deltas = ws.working_delta().unwrap();
        assert_eq!(deltas.len(), 2, "both files row");
        assert!(deltas.iter().all(|d| d.class == DeltaClass::Added), "all added");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn working_delta_carries_a_sealed_absent_base_path_untouched() {
        // A base path sealed to the ambient identity is never materialized, and
        // snapshot carries it forward untouched (ADR 0006) — so its absence from
        // disk is not a deletion and it must not row as `-`.
        let dir = std::env::temp_dir().join(format!("loot-wdelta-seal-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        std::fs::write(dir.join("doc.txt"), b"open").unwrap();
        std::fs::write(dir.join(".lootattributes"), "secret.txt restricted=alice\n").unwrap();
        std::fs::write(dir.join("secret.txt"), b"top secret").unwrap();
        ws.snapshot("seal").unwrap();
        ws.finalize_working().unwrap();
        // The sealed path leaves the disk; everything else is unchanged.
        std::fs::remove_file(dir.join("secret.txt")).unwrap();

        let deltas = ws.working_delta().unwrap();
        assert!(
            !deltas.iter().any(|d| d.path == Path::new("secret.txt")),
            "a sealed-to-us absent path is carried forward, not deleted"
        );
        assert!(deltas.is_empty(), "no other path moved");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // `dock rm` (`dock_rm_*`) and the `--at` worktree dock (`dock_at_binds_…`)
    // are retired with `.loot/docks/` (#253/ADR 0034): a second position is a
    // sealed lane, reaped by `loot lane rm` (`remove_lane`, covered by
    // `lane_spawn_requires_a_keyed_repo_and_the_primary` and the lane-lifecycle
    // tests) and spawned by `loot lane new` (`lane_spawn_materializes_…`).

    // --- quarantined grants: review + trust (#12) ---

    /// The full round trip `cmd_pull_grants`/`cmd_grants_trust` compose:
    /// a sealed grant from a sender Bob has never registered is held in
    /// quarantine (never applied), `--quarantined` lists it, and `--trust`
    /// registers the sender as a peer, re-applies the grant, and clears the
    /// entry. Driven at the `Workspace`/`RepoStore` level (no relay/HTTP
    /// mailbox — the SealedGrant bundle is built directly via
    /// `deposit_sealed_grant`, capturing its bytes instead of delivering them,
    /// exactly what `pull-grants` would have handed to the quarantine gate
    /// after unwrapping the envelope).
    #[test]
    fn quarantine_then_trust_reapplies_and_clears_the_entry() {
        let dir_a = std::env::temp_dir().join(format!("loot-12-trust-a-{}", std::process::id()));
        let mut alice = authored_ws(&dir_a);
        // `authored_ws` always names its identity "connor" (see the helper) —
        // restrict to that name so Alice, the sealer, actually holds the key
        // she is about to grant (unlike the `restricted=alice` fixture used
        // elsewhere, which deliberately seals to a name nobody present holds).
        std::fs::write(dir_a.join(".lootattributes"), "secret.txt restricted=connor\n").unwrap();
        std::fs::write(dir_a.join("secret.txt"), b"top secret").unwrap();
        alice.snapshot("seal a path").unwrap();
        alice.finalize_working().unwrap();
        let head = alice.heads()[0].clone();
        let (oid, _vis) = alice
            .repo()
            .change_tree(&head)
            .unwrap()
            .get(Path::new("secret.txt"))
            .unwrap()
            .clone();

        let dir_b = std::env::temp_dir().join(format!("loot-12-trust-b-{}", std::process::id()));
        let mut bob = authored_ws(&dir_b);

        let alice_pubkey = loot_identity::load_or_missing(alice.dot()).unwrap().public_key_bytes();
        let bob_pubkey = loot_identity::load_or_missing(bob.dot()).unwrap().public_key_bytes();
        let bob_x25519 = loot_identity::x25519_pubkey_from_ed25519_bytes(&bob_pubkey).unwrap();

        // A real SealedGrant, addressed to Bob — captured rather than
        // delivered, standing in for what an envelope-unwrap would yield.
        let mut captured: Option<Vec<u8>> = None;
        alice
            .deposit_sealed_grant(
                &oid,
                "bob",
                bob_pubkey,
                alice_pubkey,
                0,
                |key| {
                    loot_identity::seal_key(key, &bob_x25519)
                        .map_err(|e| loot_core::RepoError::Backend(e.to_string()))
                },
                |bytes| {
                    captured = Some(bytes);
                    Ok(())
                },
            )
            .unwrap();
        let bundle_bytes = captured.expect("the deliver closure ran");

        // Bob has never registered Alice — `pull-grants` would quarantine
        // this rather than apply it.
        let sender_hex = loot_core::hex::encode(&alice_pubkey);
        let oid_hex = loot_core::hex::encode(&oid.0);
        let received_at = 1_700_000_000;
        bob.store()
            .write_quarantine_entry(&sender_hex, &oid_hex, received_at, &bundle_bytes)
            .unwrap();

        // `--quarantined`: lists sender pubkey hex, oid, received timestamp.
        let listed = bob.store().read_quarantine();
        assert_eq!(listed.len(), 1, "one quarantined grant");
        assert_eq!(listed[0].sender_hex, sender_hex);
        assert_eq!(listed[0].oid_hex, oid_hex);
        assert_eq!(listed[0].received_at, received_at);

        // Not yet applied: Bob's keyring holds no key for the sealed content.
        assert!(
            bob.repo().get(&oid, bob.identity(), received_at).is_err(),
            "a quarantined grant is never applied"
        );

        // `--trust <pubkey-hex>`: register the sender, re-apply every grant
        // of theirs still quarantined, and clear each one out as it succeeds.
        let openssh_line =
            loot_identity::PeerRegistry::openssh_line_from_pubkey_bytes(alice_pubkey).unwrap();
        let mut reg = loot_identity::PeerRegistry::load(bob.dot());
        reg.add(&sender_hex, &openssh_line);
        reg.save().unwrap();

        for entry in bob.store().read_quarantine_for_sender(&sender_hex) {
            bob.apply_sealed_grant(entry.bundle_bytes.clone(), alice_pubkey).unwrap();
            bob.store().remove_quarantine_entry(&sender_hex, &entry.oid_hex).unwrap();
        }

        assert!(bob.store().read_quarantine().is_empty(), "re-applied grant leaves quarantine empty");
        assert!(
            !bob.store().quarantine_sender_dir(&sender_hex).exists(),
            "the trusted sender's now-empty subdirectory is cleaned up"
        );

        // Bob can now read what Alice sealed to him.
        let bytes = bob.repo().get(&oid, bob.identity(), received_at).unwrap();
        assert_eq!(bytes, b"top secret");

        // The peer registry recognizes Alice going forward — a second
        // `pull-grants` from her would apply directly, not quarantine again.
        let reg = loot_identity::PeerRegistry::load(bob.dot());
        assert_eq!(reg.pubkey_bytes(&sender_hex).unwrap(), Some(alice_pubkey));

        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
    }

    // --- burn: destroy + tombstone, no resurrection (ADR 0038, #344) ---

    /// Finalize `.env` as a committed change and return its content oid + the
    /// head version-id that references it.
    fn committed_secret(ws: &mut Workspace, dir: &Path) -> (Oid, Oid) {
        std::fs::write(dir.join(".env"), b"TOKEN=leaked\n").unwrap();
        ws.snapshot("leak").unwrap();
        ws.finalize_working().unwrap();
        let head = ws.repo().heads()[0].clone();
        let oid = ws.repo().current_tree_oid(Path::new(".env")).unwrap();
        (oid, head)
    }

    #[test]
    fn burn_destroys_bytes_records_signed_tombstone_and_reports_never_pushed() {
        let dir = std::env::temp_dir().join(format!("loot-burn-ws-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        let (oid, _head) = committed_secret(&mut ws, &dir);
        let obj_file = ws.store().objects_dir().join(loot_core::hex::encode(&oid.0));
        assert!(obj_file.exists(), "the sealed object exists before burning");

        let report = ws.burn_path(Path::new(".env"), None).unwrap();
        assert_eq!(report.tier, loot_core::BurnTier::NeverPushed, "no push recorded ⇒ never-pushed");
        assert_eq!(report.burned.len(), 1);
        assert!(report.projected.is_empty(), "no mirror ⇒ no git guidance");
        assert!(!obj_file.exists(), "burn destroyed the ciphertext on disk");

        // The tombstone is signed (authored repo) and survives reload; verify is clean.
        let reloaded = Workspace::open_at(&dir).unwrap();
        let ts = reloaded.repo().burn_log().get(&oid).expect("tombstone recorded");
        assert!(!ts.is_unauthored() && ts.verify(), "authored repo signs the tombstone");
        assert!(
            DagRepo::verify(reloaded.store().dot()).unwrap().is_clean(),
            "verify passes on a store with burned objects"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn burn_is_a_non_undoable_barrier() {
        let dir = std::env::temp_dir().join(format!("loot-burn-barrier-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        let _ = committed_secret(&mut ws, &dir);
        ws.burn_path(Path::new(".env"), None).unwrap();
        // Record the barrier op exactly as cmd_burn does, then undo must refuse.
        ws.record_op("burn", "burn .env", true);
        let err = ws.undo().unwrap_err();
        assert!(err.contains("barrier"), "undo refuses across a burn: {err}");
        assert!(err.to_lowercase().contains("rotate"), "the refusal names the rotate-the-secret remedy");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn burn_after_a_push_reports_the_pushed_tier() {
        let dir = std::env::temp_dir().join(format!("loot-burn-pushed-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        let _ = committed_secret(&mut ws, &dir);
        // Simulate a prior disclosure barrier (ADR 0038 §3 tier source).
        ws.record_op("push", "push → origin", true);
        let report = ws.burn_path(Path::new(".env"), None).unwrap();
        assert_eq!(report.tier, loot_core::BurnTier::Pushed, "a recorded push ⇒ pushed tier");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn burn_detects_and_reports_git_projection() {
        use loot_core::bridge::{MarkMap, MarkOrigin};
        let dir = std::env::temp_dir().join(format!("loot-burn-mirror-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        let (_oid, head) = committed_secret(&mut ws, &dir);
        // Record that the referencing change was projected into the git mirror.
        let mut marks = MarkMap::new();
        marks.insert("a".repeat(40), head.clone(), MarkOrigin::Loot);
        std::fs::create_dir_all(ws.store().git_mirror_dir()).unwrap();
        std::fs::write(ws.store().git_marks(), marks.encode()).unwrap();

        let report = ws.burn_path(Path::new(".env"), None).unwrap();
        assert_eq!(
            report.projected.iter().map(|(_, sha)| sha.clone()).collect::<Vec<_>>(),
            vec!["a".repeat(40)],
            "burn reports the projected commit so the CLI prints git guidance"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn burn_refuses_a_path_with_no_object() {
        let dir = std::env::temp_dir().join(format!("loot-burn-empty-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        let _ = committed_secret(&mut ws, &dir);
        let err = ws.burn_path(Path::new("nonexistent"), None).unwrap_err();
        assert!(err.contains("no historical object"), "burning an unknown path refuses: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
