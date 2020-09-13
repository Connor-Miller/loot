//! Workspace — the process-bound ambient repo (ADR 0006).
//!
//! Owns everything a command needs but shouldn't re-derive: where `.loot/` is,
//! the current identity, the clock, the loaded engine, and the id of the
//! *working change* being rewritten in place. Commands are thin verbs over it.
//!
//! The snapshot invariant itself lives in the engine (`DagRepo::snapshot`); the
//! Workspace only reads the working tree + `.lootattributes` into the entries
//! the engine reconciles, and persists state after a mutation.

use loot_core::{
    oplog, valid_dock_name, DagRepo, MergeOutcome, Oid, Operation, Repo, RepoStore, Visibility,
    HOME_DOCK,
};
use loot_identity::Identity;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const DOT: &str = ".loot";
const ATTRS: &str = ".lootattributes";
const IGNORE: &str = ".lootignore";

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
        let store = RepoStore::new(&loot);
        if !store.identity().exists() {
            return Err(format!(
                "not a loot repo at {} (no .loot/). Run `loot init` first.",
                dir.display()
            ));
        }
        let dock = store.read_dock();
        Self::assemble(loot, store, dir.to_path_buf(), dock)
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
        Self::assemble(shared, store, dir.to_path_buf(), dock)
    }

    /// Finish loading once the store `dot`, working `root`, and ambient `dock` are
    /// known (shared by the primary and worktree open paths).
    fn assemble(dot: PathBuf, store: RepoStore, root: PathBuf, dock: String) -> Result<Self, String> {
        let mut repo = DagRepo::load(&dot, root.clone()).map_err(|e| e.to_string())?;
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

    /// This repo's own signing pubkey, if it has a keypair (S3, ADR 0018). Lets
    /// `log` resolve a change *this* identity authored to its own name rather
    /// than a bare hex prefix — the peer registry holds peers, not self.
    pub fn identity_pubkey(&self) -> Option<[u8; 32]> {
        self.signer.as_ref().map(|s| s.public_key_bytes())
    }

    /// The `.loot/` directory for this repo (used by identity keypair commands).
    pub fn dot(&self) -> &std::path::Path {
        &self.dot
    }

    /// Prune orphaned loose objects from `.loot/objects/` (ADR 0012, #66).
    /// Delegates to the engine, which owns the object store and the reachability
    /// walk over the change graph. `dry_run` reports what would be pruned
    /// without deleting.
    pub fn gc(&mut self, dry_run: bool) -> Result<loot_core::GcReport, String> {
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

    /// Read the working tree + `.lootattributes` into engine entries `(path,
    /// bytes, vis)` plus a sorted `(path, vis)` report — the shared front half of
    /// a snapshot and of the read-only `status`/`log` working-row preview. Reads
    /// only (bar an in-memory escrow flush); the caller decides whether to record.
    fn read_working_tree(
        &mut self,
    ) -> Result<(Vec<(PathBuf, Vec<u8>, Visibility)>, Vec<(PathBuf, Visibility)>), String> {
        // Promote any embargoed keys whose reveal time has passed before reading
        // content — `sealed::open` will then find them in the Keyring (ADR 0007).
        self.repo.flush_escrow(self.now);
        let attrs = Attributes::load(&self.root.join(ATTRS));
        let ignore = Ignore::load(&self.root.join(IGNORE));
        let mut entries: Vec<(PathBuf, Vec<u8>, Visibility)> = Vec::new();
        let mut reported: Vec<(PathBuf, Visibility)> = Vec::new();
        for path in walk(&self.root, &ignore)? {
            // Store paths relative to the repo root so tree keys are stable
            // regardless of whether the root is "." (the CLI) or an absolute dir
            // (tests, `clone` into a path). Fall back to stripping a leading "./".
            let rel = path
                .strip_prefix(&self.root)
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
            // Sign over `version_id ‖ change_id` (ADR 0029) so the durable handle
            // is bound to this exact version and cannot be relabelled on the wire.
            let change_id = self.repo.change_change_id(&working);
            let sig = signer.sign(&loot_core::change_signing_message(&working, &change_id));
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
        if self.docks_active() {
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
            // `version_id ‖ change_id` (ADR 0029).
            let cid = self.repo.change_change_id(change_id);
            let sig = signer.sign(&loot_core::change_signing_message(change_id, &cid));
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
    /// Scope: the **reconciliation family** (`apply`/`pull`/`resolve`/dock
    /// merge/ferry), whose capture disciplines are their own and deliberately
    /// not the implicit snapshot. A **snapshotting verb** (grant/maroon/
    /// migrate, ADR 0030) must not call this directly — it mutates through the
    /// [`Snapshotted`] handle, whose construction *is* the capture.
    pub fn with_repo<T>(
        &mut self,
        f: impl FnOnce(&mut DagRepo) -> Result<T, String>,
    ) -> Result<T, String> {
        let out = f(&mut self.repo)?;
        self.persist()?;
        Ok(out)
    }

    /// The one door to the snapshotting (mutating) verbs (ADR 0030): capture
    /// the working tree first — honoring the demotion allowlist (#62) and the
    /// `--no-snapshot`/`--ignore-working-copy` escape — then hand back the
    /// handle that exposes mutation. Holding a [`Snapshotted`] *is* the proof
    /// the capture ran (or was explicitly skipped); a verb that forgets it
    /// cannot mutate, so the invariant is a type, not a hand-maintained call
    /// list (which had drifted across main.rs and ferry.rs — #182). Preserves
    /// a `describe`d name: an implicit capture must not clobber it.
    pub fn snapshotted(
        &mut self,
        allow_demote: &[PathBuf],
        skip: bool,
    ) -> Result<Snapshotted<'_>, String> {
        if !skip {
            let msg = self.working_message().unwrap_or_else(|| "(working change)".to_string());
            self.snapshot_allowing(&msg, allow_demote)?;
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

    /// The abandoned-version set for this repo — versions dropped from a
    /// divergent change (`loot abandon`), filtered out of the live view.
    pub fn abandoned_versions(&self) -> std::collections::BTreeSet<Oid> {
        self.store.read_abandoned()
    }

    /// The change ids that are currently **divergent** — one change id, more than
    /// one live version (ADR 0029). `log`/`status` mark these with a trailing `!`.
    pub fn divergent_change_ids(&self) -> std::collections::BTreeSet<[u8; 16]> {
        self.repo.divergent_change_ids(&self.store.read_abandoned())
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
        let live = self.repo.versions_of_change(&cid, &abandoned);
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
        self.persist()?;
        self.record_op("abandon", &format!("abandon version {}", short_version(version)), false);
        self.reload()?;
        self.resurface(old_paths)?;
        Ok(())
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
            next_change_id: None,
            // A freshly-initialized repo has no keypair yet (`loot keygen` adds one);
            // its early changes are unauthored until then (S3, ADR 0018).
            signer: None,
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

    /// `loot dock <name> [--at <dir>]` — the physical-model dock verb (ADR 0022).
    /// Without `at`, create-or-switch the ambient dock in place and re-materialize
    /// (the single-dir checkout flow, [`dock_goto`]). With `at`, bind a *separate*
    /// working directory to this repo's shared store via a `.loot` pointer file
    /// and materialize the dock's tree there, so concurrent agents edit physically
    /// separate trees over one object store.
    ///
    /// [`dock_goto`]: Workspace::dock_goto
    pub fn create_dock(&mut self, name: &str, at: Option<&Path>) -> Result<(), String> {
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

    /// Collapse a fork the ambient dock is sitting on into one materialized tip
    /// (#128). `pull`/`apply` ingest a peer's divergent tip as a *sibling head*
    /// — engine `apply_sync` records + classifies but never merges tips — so a
    /// keyholder that has also advanced its own line ends up on multiple heads
    /// with a working tree showing only its own side (the other side's content
    /// is in the graph but never materialized). This is the peer-side analogue
    /// of `merge_dock` (ADR 0011: keyholders collapse forks on pull+apply): fold
    /// every other head into our line via `merge_tips`, signing each merge so it
    /// travels, then materialize the merged tree.
    ///
    /// `base` names our side — the tip the working directory already reflects
    /// (the caller's pre-pull head); materialize is diffed from it so a stale
    /// side's untouched paths are not disturbed. On the home dock `anchor()` is
    /// ambiguous under divergence, which is why the caller must pass it. A single
    /// head, or an in-progress working change (the caller's to finalize first —
    /// `pull`/`apply` have none), is a no-op. Returns the per-path merge outcomes.
    pub fn converge_heads(&mut self, base: Option<&Oid>) -> Result<BTreeMap<PathBuf, MergeOutcome>, String> {
        let heads = self.repo.heads();
        if heads.len() <= 1 || self.working.is_some() {
            return Ok(BTreeMap::new());
        }
        let ours = base
            .cloned()
            .filter(|b| heads.contains(b))
            .or_else(|| self.anchor())
            .or_else(|| heads.first().cloned())
            .ok_or("nothing to converge onto")?;
        let others: Vec<Oid> = heads.into_iter().filter(|h| h != &ours).collect();
        if others.is_empty() {
            return Ok(BTreeMap::new());
        }
        let from = ours.clone();
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
            // Finalize over `version_id ‖ change_id` (ADR 0029), like every other
            // finalize path — `resolve` mints a durable change id for the change.
            let cid = self.repo.change_change_id(&change_id);
            let sig = signer.sign(&loot_core::change_signing_message(&change_id, &cid));
            self.repo
                .attach_signature(&change_id, sig)
                .map_err(|e| e.to_string())?;
        }
        // On a dock, the resolution also advances the dock's tip so it isn't
        // orphaned and the next snapshot builds on it.
        if self.docks_active() {
            // Reflect the resolved tree on disk (writing the resolution over the
            // still-conflicted working copy) so a later `status` captures the
            // resolution, not the pre-resolution content.
            self.repo
                .materialize(base.as_ref(), &change_id, &self.identity, self.now)
                .map_err(|e| e.to_string())?;
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
    pub fn ferry_capture(
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
    pub fn ferry_adopt(&mut self, new_tip: &Oid) -> Result<(), String> {
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
    /// the bridge instead of a dock. Caller runs [`ferry_capture`] first.
    /// Conflicts flow through the shared `conflicts`/`resolve` path. Returns
    /// the per-path outcomes.
    ///
    /// [`ferry_capture`]: Workspace::ferry_capture
    pub fn ferry_merge(
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
        self.repo.save(&self.dot).map_err(|e| e.to_string())?;
        self.store
            .write_working(self.dock_opt(), self.working.as_ref())
            .map_err(|e| format!("write working: {e}"))?;
        self.store
            .write_next_change(self.dock_opt(), self.next_change_id.as_ref())
            .map_err(|e| format!("write next-change: {e}"))
    }
}

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
        assert!(ws.abandoned_versions().contains(&vb));
        assert!(!ws.repo().heads().contains(&vb), "vb stopped being a live head");
        assert!(ws.repo().heads().contains(&va), "va survives");

        // Undo restores the divergent state — nothing was deleted.
        let r = ws.undo().unwrap();
        let _ = r;
        assert!(ws.divergent_change_ids().contains(&cid), "undo brought the version back");
        assert!(!ws.abandoned_versions().contains(&vb), "undo cleared the abandoned mark");
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
        assert!(ws.abandoned_versions().is_empty(), "nothing was abandoned");
        let _ = std::fs::remove_dir_all(&dir);
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
