//! The canonical loot engine: an encrypted content-addressed DAG.
//!
//! Graduated from the bake-off winner (ADR 0002). `DagRepo` is a thin
//! composition of an [`ObjectStore`] (content-addressed ciphertext), a
//! [`ChangeGraph`] (history), a [`Keyring`] (this identity's key custody), and
//! the policy modules [`crate::sealed`] and [`crate::converge`]. It holds no
//! storage or merge logic itself — it wires the modules to the [`Repo`] seam.
//!
//! Properties carried over from the spike that proved the model:
//!   - each object is encrypted independently; visibility == key possession
//!   - addressing is by CIPHERTEXT hash only; no plaintext-derived identity, so
//!     the store leaks no plaintext-equality oracle (ADR 0004)
//!   - storage is log-structured (append-only `Vec` + in-memory index), NOT
//!     git-style loose files
//!   - runs fully in-memory; `checkout` is the only thing that touches disk
//!
//! Encryption, visibility, and embargo live in [`crate::sealed`] (ADR 0003);
//! the merger/relay convergence rule lives in [`crate::converge`] (ADR 0001).

mod change_graph;
mod object_store;

use crate::converge::{self};
use crate::escrow::Escrow;
use crate::sealed::{self, ContentKey, Keyring, SealedObject, ANYONE};
use crate::{Change, MergeOutcome, Oid, Repo, RepoError, SyncBundle, Visibility};
use change_graph::{compute_change_id, ChangeGraph, ChangeNode};
use object_store::{ObjectStore, Stored};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// The DAG engine. Composes storage, history, key custody, and policy behind
/// the [`Repo`] interface.
pub struct DagRepo {
    root: PathBuf,
    identity: String,
    /// This identity's private key custody for non-embargoed content.
    keyring: Keyring,
    /// Embargoed content keys awaiting their reveal time. `flush_escrow` promotes
    /// eligible entries to `keyring` before any content-reading operation (ADR 0007).
    escrow: Escrow,
    objects: ObjectStore,
    graph: ChangeGraph,
}

impl DagRepo {
    /// Whether this identity is entitled to hold the key for content with these
    /// grant ids — used to decide what to file into the local keyring.
    fn entitled(&self, grant_ids: &[String]) -> bool {
        grant_ids.iter().any(|g| g == ANYONE || g == &self.identity)
    }

    /// Store a SealedObject and route its key to the right custody (ADR 0007):
    /// - Embargoed content: key goes to `escrow` (not Keyring) for ALL identities.
    /// - Everything else: key goes to `keyring` iff entitled.
    ///
    /// If dedup collapsed us onto an existing address, the minted key seals
    /// discarded ciphertext and must not be filed anywhere.
    fn store(&mut self, addr: Oid, obj: SealedObject, key: Option<ContentKey>) -> Oid {
        let entitled = self.entitled(&obj.grant_ids);
        let reveal_at = if let Visibility::Embargoed { reveal_at } = obj.vis {
            Some(reveal_at)
        } else {
            None
        };
        let stored = self.objects.put(addr, obj);
        let stored_addr = stored.addr().clone();
        if let Some(k) = key {
            if matches!(stored, Stored::New(_)) && entitled {
                if let Some(t) = reveal_at {
                    // Embargoed: key stays out of the Keyring until flush (ADR 0007).
                    if !self.escrow.holds(&stored_addr) {
                        self.escrow.insert(stored_addr.clone(), k, t);
                    }
                } else if !self.keyring.holds(&stored_addr) {
                    self.keyring.insert(stored_addr.clone(), k);
                }
            }
        }
        stored_addr
    }

    /// Promote embargoed keys whose `reveal_at <= now` from Escrow into the
    /// Keyring. Call this before any content-reading operation (`checkout`,
    /// `snapshot`). After this, `sealed::open` finds the key in the Keyring
    /// and decrypts normally — `open` itself is unmodified (ADR 0007).
    pub fn flush_escrow(&mut self, now: u64) {
        self.escrow.flush(&mut self.keyring, now);
    }

    fn object(&self, oid: &Oid) -> Result<&SealedObject, RepoError> {
        self.objects.get(oid)
    }

    /// Persist the whole repo under `dir` (typically `.loot/`): all sealed
    /// objects, the full change graph, and this identity's keyring. The keyring
    /// is written to its own LOCAL-ONLY file — it is custody, not repo content,
    /// and never travels in a bundle (ADR 0003, 0005).
    pub fn save(&self, dir: &std::path::Path) -> Result<(), RepoError> {
        let io = |e: std::io::Error| RepoError::Backend(e.to_string());
        std::fs::create_dir_all(dir).map_err(io)?;
        std::fs::write(dir.join("identity"), self.identity.as_bytes()).map_err(io)?;
        std::fs::write(dir.join("repo"), wire::encode_repo(&self.objects, &self.graph)).map_err(io)?;
        std::fs::write(dir.join("keyring"), wire::encode_keyring(&self.keyring)).map_err(io)?;
        std::fs::write(dir.join("escrow"), wire::encode_escrow(&self.escrow)).map_err(io)?;
        Ok(())
    }

    /// Visibility-aware snapshot of a working tree into the working change
    /// (ADR 0006). `entries` is the tree the caller can see — `(path, bytes,
    /// intended visibility)` — typically every file the Workspace read from disk.
    /// `working` is the id of the current working change to rewrite in place, or
    /// `None` on the first snapshot. `message` names it; `now` evaluates embargo.
    ///
    /// The working change is rewritten in place (true JJ): the prior working
    /// node is removed first, so reconcile always bases on FINALIZED history.
    /// Reconcile against that base tree:
    ///   - a base path THIS identity can open now: update to match `entries`,
    ///     or delete if absent from `entries` (a keyholder removing own content);
    ///   - a base path it cannot open: carried forward unchanged (never seen);
    ///   - an `entries` path that collides with a base path it CANNOT open:
    ///     refused (no silent clobber of sealed content).
    ///
    /// Returns the new working-change id. Idempotent on an unchanged tree.
    pub fn snapshot(
        &mut self,
        working: Option<&Oid>,
        entries: &[(PathBuf, Vec<u8>, Visibility)],
        message: &str,
        now: u64,
    ) -> Result<Oid, RepoError> {
        // Drop the prior working change so we reconcile against finalized history,
        // not against our own last snapshot.
        if let Some(w) = working {
            self.graph.remove_head(w);
        }

        let base = self.graph.current_tree();
        let by_path: BTreeMap<&PathBuf, &(PathBuf, Vec<u8>, Visibility)> =
            entries.iter().map(|e| (&e.0, e)).collect();

        // Refuse any write that lands on a base path we cannot open: it would
        // silently clobber sealed content we can't even see.
        for (path, (oid, _vis)) in &base {
            if by_path.contains_key(path) && self.get(oid, &self.identity, now).is_err() {
                return Err(RepoError::Backend(format!(
                    "sealed content exists at {}; cannot overwrite content you can't see",
                    path.display()
                )));
            }
        }

        let mut tree: BTreeMap<PathBuf, (Oid, Visibility)> = BTreeMap::new();

        // Carry forward every base path NOT visible to us, untouched.
        for (path, entry) in &base {
            if self.get(&entry.0, &self.identity, now).is_err() {
                tree.insert(path.clone(), entry.clone());
            }
        }

        // Seal every working-tree entry (visible by construction — we read it).
        // Absent-but-visible base paths simply don't get re-added => deleted.
        for (path, bytes, vis) in entries {
            let oid = self.put(bytes, vis.clone())?;
            tree.insert(path.clone(), (oid, vis.clone()));
        }

        let change = Change {
            id: Oid([0; 32]),
            parents: self.graph.heads(),
            message: message.to_string(),
            tree,
        };
        self.commit(change)
    }

    /// Change history in topo order (parents before children), as
    /// `(change id, message)` pairs — the data a `log` command needs without
    /// exposing the change graph's internals.
    pub fn log(&self) -> Vec<(Oid, String)> {
        self.graph
            .in_order()
            .into_iter()
            .map(|c| (c.id.clone(), c.message.clone()))
            .collect()
    }

    /// Load a repo previously written by [`save`] from `dir`. `root` is the
    /// working directory `checkout` will materialize into (kept separate from
    /// `dir` so the store can live in `.loot/` while files land in the repo).
    pub fn load(dir: &std::path::Path, root: PathBuf) -> Result<Self, RepoError> {
        let io = |e: std::io::Error| RepoError::Backend(e.to_string());
        let identity = String::from_utf8(std::fs::read(dir.join("identity")).map_err(io)?)
            .map_err(|e| RepoError::Backend(e.to_string()))?;
        let (objects, graph) = wire::decode_repo(&std::fs::read(dir.join("repo")).map_err(io)?)?;
        let keyring = wire::decode_keyring(&std::fs::read(dir.join("keyring")).map_err(io)?)?;
        // Escrow file may not exist in repos created before ADR 0007 — default empty.
        let escrow = match std::fs::read(dir.join("escrow")) {
            Ok(b) => wire::decode_escrow(&b)?,
            Err(_) => Escrow::new(),
        };
        Ok(DagRepo {
            root,
            identity,
            keyring,
            escrow,
            objects,
            graph,
        })
    }
}

impl Repo for DagRepo {
    fn init(path: PathBuf, identity: &str) -> Result<Self, RepoError> {
        Ok(DagRepo {
            root: path,
            identity: identity.to_string(),
            keyring: Keyring::new(),
            escrow: Escrow::new(),
            objects: ObjectStore::new(),
            graph: ChangeGraph::new(),
        })
    }

    fn put(&mut self, bytes: &[u8], vis: Visibility) -> Result<Oid, RepoError> {
        let (addr, obj, key) = sealed::seal(bytes, &vis)?;
        // We minted the key, so we file it (entitlement is enforced in `store`).
        Ok(self.store(addr, obj, Some(key)))
    }

    fn get(&self, oid: &Oid, reader: &str, now: u64) -> Result<Vec<u8>, RepoError> {
        let obj = self.object(oid)?;
        sealed::open(obj, oid, reader, &self.keyring, now)
    }

    fn commit(&mut self, change: Change) -> Result<Oid, RepoError> {
        let id = compute_change_id(&change);
        let node = ChangeNode {
            id: id.clone(),
            parents: change.parents,
            message: change.message,
            tree: change.tree,
        };
        self.graph.insert(node);
        Ok(id)
    }

    fn checkout(&self, change: &Oid, reader: &str, now: u64) -> Result<(), RepoError> {
        let node = self
            .graph
            .get(change)
            .ok_or_else(|| RepoError::NotFound(change.clone()))?;

        for (path, (oid, _vis)) in &node.tree {
            // Materialize only the visible slice: skip content this reader
            // cannot see rather than erroring on it.
            let bytes = match self.get(oid, reader, now) {
                Ok(b) => b,
                Err(RepoError::Unauthorized(_)) | Err(RepoError::Embargoed(_)) => continue,
                Err(e) => return Err(e),
            };
            let dest = self.root.join(path);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
            }
            std::fs::write(&dest, &bytes).map_err(|e| RepoError::Backend(e.to_string()))?;
        }
        Ok(())
    }

    fn bundle(&self, have: &[Oid]) -> Result<SyncBundle, RepoError> {
        // Changes reachable here but not already known to the recipient. For
        // now, "reachable-not-have" = every change id not in `have`.
        let have_set: std::collections::BTreeSet<&Oid> = have.iter().collect();
        let send: Vec<&ChangeNode> = self
            .graph
            .in_order()
            .into_iter()
            .filter(|c| !have_set.contains(&c.id))
            .collect();

        // Ship SealedObjects (ciphertext, no keys) plus:
        //   - Public content keys -> plain keyring section (ANYONE-granted, not embargoed)
        //   - Embargoed content keys -> escrow section (ANYONE-granted, time-gated)
        //   - Restricted keys NEVER travel (ADR 0003)
        let mut needed: BTreeMap<Oid, &SealedObject> = BTreeMap::new();
        let mut public_keys: BTreeMap<Oid, ContentKey> = BTreeMap::new();
        let mut escrow_entries: BTreeMap<Oid, (ContentKey, u64)> = BTreeMap::new();
        for c in &send {
            for (oid, vis) in c.tree.values() {
                if let Ok(obj) = self.object(oid) {
                    needed.insert(oid.clone(), obj);
                    if obj.grant_ids.iter().any(|g| g == ANYONE) {
                        if let Visibility::Embargoed { reveal_at } = vis {
                            // Embargoed: key rides as an escrow entry so the receiver
                            // files it into their Escrow, not their Keyring (ADR 0007).
                            if let Some(k) = self.escrow.iter()
                                .find(|(o, _)| *o == oid)
                                .map(|(_, e)| e.key)
                                .or_else(|| self.keyring.key_for(oid))
                            {
                                escrow_entries.insert(oid.clone(), (k, *reveal_at));
                            }
                        } else if let Some(k) = self.keyring.key_for(oid) {
                            public_keys.insert(oid.clone(), k);
                        }
                    }
                }
            }
        }

        Ok(SyncBundle(wire::encode(&send, &needed, &public_keys, &escrow_entries)))
    }

    fn apply(
        &mut self,
        bundle: &SyncBundle,
        now: u64,
    ) -> Result<BTreeMap<PathBuf, MergeOutcome>, RepoError> {
        let (incoming_changes, incoming_objs, incoming_keys, incoming_escrow) =
            wire::decode(&bundle.0)?;

        // Our tree before applying, used to detect concurrent same-path edits.
        let local_before = self.graph.current_tree();

        // Ingest SealedObjects, filing only the public (non-embargoed) keys that
        // rode along. Embargoed keys travel in `incoming_escrow` and go into our
        // Escrow, not the Keyring (ADR 0007). No Restricted key can be here.
        for (addr, obj) in incoming_objs {
            let key = incoming_keys.get(&addr).copied();
            self.store(addr, obj, key);
        }
        // File incoming embargoed keys into the local Escrow so they'll be
        // promoted by `flush_escrow` once their reveal time arrives.
        for (oid, (key, reveal_at)) in incoming_escrow {
            if !self.escrow.holds(&oid) && !self.keyring.holds(&oid) {
                self.escrow.insert(oid, key, reveal_at);
            }
        }

        // Classify every incoming change against our pre-apply tree using the
        // shared ADR 0001 classifier (crate::converge). We are the KeyOracle:
        // it asks us for plaintext, we answer via sealed::open. The classifier
        // owns the rule; we own only storage and crypto.
        let mut outcomes: BTreeMap<PathBuf, MergeOutcome> = BTreeMap::new();
        for node in &incoming_changes {
            let per_change = converge::classify(&local_before, &node.tree, self, now);
            for (path, outcome) in per_change {
                let slot = outcomes.entry(path).or_insert(MergeOutcome::Converged);
                *slot = converge::worst(slot.clone(), outcome);
            }
        }

        for node in incoming_changes {
            self.graph.insert(node);
        }

        Ok(outcomes)
    }

    fn heads(&self) -> Vec<Oid> {
        self.graph.heads()
    }

    fn flush_embargo(&mut self, now: u64) {
        self.flush_escrow(now);
    }
}

/// The engine answers the convergence classifier's content questions (ADR 0001).
/// `open` returns plaintext iff our own identity may read it now; `None` is the
/// relay role. The classifier owns the merge rule; we own crypto + storage.
impl converge::KeyOracle for DagRepo {
    fn open(&self, oid: &Oid, now: u64) -> Option<Vec<u8>> {
        self.get(oid, &self.identity, now).ok()
    }
}

/// Minimal length-prefixed binary wire format for `SyncBundle`, hand-rolled to
/// keep the engine dependency-light (no serde/bincode). The format is internal:
/// bundles produced by `bundle` are only ever read by `apply`.
mod wire {
    use super::ChangeNode;
    use crate::sealed::{ContentKey, SealedObject};
    use crate::{Oid, RepoError, Visibility};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn put_u32(out: &mut Vec<u8>, n: usize) {
        out.extend_from_slice(&(n as u32).to_le_bytes());
    }
    fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
        put_u32(out, b.len());
        out.extend_from_slice(b);
    }
    fn put_vis(out: &mut Vec<u8>, vis: &Visibility) {
        match vis {
            Visibility::Public => out.push(0),
            Visibility::Restricted(ids) => {
                out.push(1);
                put_u32(out, ids.len());
                for id in ids {
                    put_bytes(out, id.as_bytes());
                }
            }
            Visibility::Embargoed { reveal_at } => {
                out.push(2);
                out.extend_from_slice(&reveal_at.to_le_bytes());
            }
        }
    }

    pub fn encode(
        changes: &[&ChangeNode],
        objs: &BTreeMap<Oid, &SealedObject>,
        public_keys: &BTreeMap<Oid, ContentKey>,
        escrow_entries: &BTreeMap<Oid, (ContentKey, u64)>,
    ) -> Vec<u8> {
        let mut out = Vec::new();

        // SealedObjects: ciphertext + policy + grant_ids (NAMES), never keys,
        // and no plaintext-derived field — so the wire leaks no equality signal
        // to a relay (ADR 0004).
        put_u32(&mut out, objs.len());
        for (addr, obj) in objs {
            out.extend_from_slice(&addr.0);
            out.extend_from_slice(&obj.nonce);
            put_bytes(&mut out, &obj.ciphertext);
            put_vis(&mut out, &obj.vis);
            put_u32(&mut out, obj.grant_ids.len());
            for id in &obj.grant_ids {
                put_bytes(&mut out, id.as_bytes());
            }
        }

        // Keys for ANYONE-granted, non-embargoed content (ADR 0003).
        put_u32(&mut out, public_keys.len());
        for (addr, key) in public_keys {
            out.extend_from_slice(&addr.0);
            out.extend_from_slice(key);
        }

        // Embargoed keys as escrow entries: receiver files them into their Escrow
        // (not Keyring) so they can't be read before reveal_at (ADR 0007).
        put_u32(&mut out, escrow_entries.len());
        for (addr, (key, reveal_at)) in escrow_entries {
            out.extend_from_slice(&addr.0);
            out.extend_from_slice(key);
            out.extend_from_slice(&reveal_at.to_le_bytes());
        }

        put_u32(&mut out, changes.len());
        for c in changes {
            out.extend_from_slice(&c.id.0);
            put_u32(&mut out, c.parents.len());
            for p in &c.parents {
                out.extend_from_slice(&p.0);
            }
            put_bytes(&mut out, c.message.as_bytes());
            put_u32(&mut out, c.tree.len());
            for (path, (oid, vis)) in &c.tree {
                put_bytes(&mut out, path.to_string_lossy().as_bytes());
                out.extend_from_slice(&oid.0);
                put_vis(&mut out, vis);
            }
        }
        out
    }

    struct Cursor<'a> {
        b: &'a [u8],
        i: usize,
    }
    impl<'a> Cursor<'a> {
        fn take(&mut self, n: usize) -> Result<&'a [u8], RepoError> {
            if self.i + n > self.b.len() {
                return Err(RepoError::Backend("bundle truncated".into()));
            }
            let s = &self.b[self.i..self.i + n];
            self.i += n;
            Ok(s)
        }
        fn u32(&mut self) -> Result<usize, RepoError> {
            let s = self.take(4)?;
            Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize)
        }
        fn u64(&mut self) -> Result<u64, RepoError> {
            let s = self.take(8)?;
            let mut a = [0u8; 8];
            a.copy_from_slice(s);
            Ok(u64::from_le_bytes(a))
        }
        fn arr32(&mut self) -> Result<[u8; 32], RepoError> {
            let s = self.take(32)?;
            let mut a = [0u8; 32];
            a.copy_from_slice(s);
            Ok(a)
        }
        fn arr12(&mut self) -> Result<[u8; 12], RepoError> {
            let s = self.take(12)?;
            let mut a = [0u8; 12];
            a.copy_from_slice(s);
            Ok(a)
        }
        fn bytes(&mut self) -> Result<Vec<u8>, RepoError> {
            let n = self.u32()?;
            Ok(self.take(n)?.to_vec())
        }
        fn string(&mut self) -> Result<String, RepoError> {
            String::from_utf8(self.bytes()?).map_err(|e| RepoError::Backend(e.to_string()))
        }
        fn vis(&mut self) -> Result<Visibility, RepoError> {
            match self.take(1)?[0] {
                0 => Ok(Visibility::Public),
                1 => {
                    let n = self.u32()?;
                    let mut ids = Vec::with_capacity(n);
                    for _ in 0..n {
                        ids.push(self.string()?);
                    }
                    Ok(Visibility::Restricted(ids))
                }
                2 => Ok(Visibility::Embargoed {
                    reveal_at: self.u64()?,
                }),
                t => Err(RepoError::Backend(format!("bad vis tag {t}"))),
            }
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn decode(
        b: &[u8],
    ) -> Result<
        (
            Vec<ChangeNode>,
            Vec<(Oid, SealedObject)>,
            BTreeMap<Oid, ContentKey>,
            BTreeMap<Oid, (ContentKey, u64)>,
        ),
        RepoError,
    > {
        let mut c = Cursor { b, i: 0 };

        let n_objs = c.u32()?;
        let mut objs = Vec::with_capacity(n_objs);
        for _ in 0..n_objs {
            let addr = Oid(c.arr32()?);
            let nonce = c.arr12()?;
            let ciphertext = c.bytes()?;
            let vis = c.vis()?;
            let n_grants = c.u32()?;
            let mut grant_ids = Vec::with_capacity(n_grants);
            for _ in 0..n_grants {
                grant_ids.push(c.string()?);
            }
            objs.push((
                addr,
                SealedObject {
                    nonce,
                    ciphertext,
                    vis,
                    grant_ids,
                },
            ));
        }

        let n_keys = c.u32()?;
        let mut public_keys = BTreeMap::new();
        for _ in 0..n_keys {
            let addr = Oid(c.arr32()?);
            let key = c.arr32()?;
            public_keys.insert(addr, key);
        }

        let n_escrow = c.u32()?;
        let mut escrow_entries = BTreeMap::new();
        for _ in 0..n_escrow {
            let addr = Oid(c.arr32()?);
            let key = c.arr32()?;
            let reveal_at = c.u64()?;
            escrow_entries.insert(addr, (key, reveal_at));
        }

        let n_changes = c.u32()?;
        let mut changes = Vec::with_capacity(n_changes);
        for _ in 0..n_changes {
            let id = Oid(c.arr32()?);
            let n_parents = c.u32()?;
            let mut parents = Vec::with_capacity(n_parents);
            for _ in 0..n_parents {
                parents.push(Oid(c.arr32()?));
            }
            let message = c.string()?;
            let n_tree = c.u32()?;
            let mut tree = BTreeMap::new();
            for _ in 0..n_tree {
                let path = PathBuf::from(c.string()?);
                let oid = Oid(c.arr32()?);
                let vis = c.vis()?;
                tree.insert(path, (oid, vis));
            }
            changes.push(ChangeNode {
                id,
                parents,
                message,
                tree,
            });
        }

        Ok((changes, objs, public_keys, escrow_entries))
    }

    // --- whole-repo persistence (ADR 0005) ---
    //
    // Distinct from the bundle format above: persistence serializes EVERY object
    // and change (no have-set filtering) and does NOT touch keys. The keyring is
    // serialized separately, to its own local-only file.

    use super::{ChangeGraph, ObjectStore};
    use crate::sealed::Keyring;

    fn put_change(out: &mut Vec<u8>, c: &ChangeNode) {
        out.extend_from_slice(&c.id.0);
        put_u32(out, c.parents.len());
        for p in &c.parents {
            out.extend_from_slice(&p.0);
        }
        put_bytes(out, c.message.as_bytes());
        put_u32(out, c.tree.len());
        for (path, (oid, vis)) in &c.tree {
            put_bytes(out, path.to_string_lossy().as_bytes());
            out.extend_from_slice(&oid.0);
            put_vis(out, vis);
        }
    }

    pub fn encode_repo(objects: &ObjectStore, graph: &ChangeGraph) -> Vec<u8> {
        let mut out = Vec::new();
        let objs: Vec<_> = objects.iter().collect();
        put_u32(&mut out, objs.len());
        for (addr, obj) in objs {
            out.extend_from_slice(&addr.0);
            out.extend_from_slice(&obj.nonce);
            put_bytes(&mut out, &obj.ciphertext);
            put_vis(&mut out, &obj.vis);
            put_u32(&mut out, obj.grant_ids.len());
            for id in &obj.grant_ids {
                put_bytes(&mut out, id.as_bytes());
            }
        }
        // Changes in topo order so load() can replay them parents-first.
        let changes = graph.in_order();
        put_u32(&mut out, changes.len());
        for c in changes {
            put_change(&mut out, c);
        }
        out
    }

    pub fn decode_repo(b: &[u8]) -> Result<(ObjectStore, ChangeGraph), RepoError> {
        let mut c = Cursor { b, i: 0 };
        let mut objects = ObjectStore::new();
        let n_objs = c.u32()?;
        for _ in 0..n_objs {
            let addr = Oid(c.arr32()?);
            let nonce = c.arr12()?;
            let ciphertext = c.bytes()?;
            let vis = c.vis()?;
            let n_grants = c.u32()?;
            let mut grant_ids = Vec::with_capacity(n_grants);
            for _ in 0..n_grants {
                grant_ids.push(c.string()?);
            }
            objects.put(
                addr,
                SealedObject {
                    nonce,
                    ciphertext,
                    vis,
                    grant_ids,
                },
            );
        }
        let mut graph = ChangeGraph::new();
        let n_changes = c.u32()?;
        for _ in 0..n_changes {
            let id = Oid(c.arr32()?);
            let n_parents = c.u32()?;
            let mut parents = Vec::with_capacity(n_parents);
            for _ in 0..n_parents {
                parents.push(Oid(c.arr32()?));
            }
            let message = c.string()?;
            let n_tree = c.u32()?;
            let mut tree = BTreeMap::new();
            for _ in 0..n_tree {
                let path = PathBuf::from(c.string()?);
                let oid = Oid(c.arr32()?);
                let vis = c.vis()?;
                tree.insert(path, (oid, vis));
            }
            graph.insert(ChangeNode {
                id,
                parents,
                message,
                tree,
            });
        }
        Ok((objects, graph))
    }

    pub fn encode_keyring(keyring: &Keyring) -> Vec<u8> {
        let mut out = Vec::new();
        let entries: Vec<_> = keyring.iter().collect();
        put_u32(&mut out, entries.len());
        for (oid, key) in entries {
            out.extend_from_slice(&oid.0);
            out.extend_from_slice(&key);
        }
        out
    }

    pub fn decode_keyring(b: &[u8]) -> Result<Keyring, RepoError> {
        let mut c = Cursor { b, i: 0 };
        let mut keyring = Keyring::new();
        let n = c.u32()?;
        for _ in 0..n {
            let oid = Oid(c.arr32()?);
            let key = c.arr32()?;
            keyring.insert(oid, key);
        }
        Ok(keyring)
    }

    use crate::escrow::Escrow;

    pub fn encode_escrow(escrow: &Escrow) -> Vec<u8> {
        let mut out = Vec::new();
        let entries: Vec<_> = escrow.iter().collect();
        put_u32(&mut out, entries.len());
        for (oid, entry) in entries {
            out.extend_from_slice(&oid.0);
            out.extend_from_slice(&entry.key);
            out.extend_from_slice(&entry.reveal_at.to_le_bytes());
        }
        out
    }

    pub fn decode_escrow(b: &[u8]) -> Result<Escrow, RepoError> {
        let mut c = Cursor { b, i: 0 };
        let mut escrow = Escrow::new();
        let n = c.u32()?;
        for _ in 0..n {
            let oid = Oid(c.arr32()?);
            let key = c.arr32()?;
            let reveal_at = c.u64()?;
            escrow.insert(oid, key, reveal_at);
        }
        Ok(escrow)
    }
}

#[cfg(test)]
mod tests {
    //! White-box guards that need engine internals (`keyring`, `wire::decode`).
    //! The black-box bake-off scenarios live in the `spike-dag` shim crate,
    //! driving the engine through the public `Repo` interface (ADR 0002).
    use super::*;

    fn tmp() -> PathBuf {
        std::env::temp_dir()
    }

    /// ADR 0003 leak guard: a Restricted content key must NEVER appear in a sync
    /// bundle. Mint a restricted blob, capture its real content key from the
    /// keyring, and assert the raw key bytes are absent from the wire. Public
    /// keys may ride along; restricted ones may not.
    #[test]
    fn bundle_never_carries_restricted_keys() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let secret_oid = alice
            .put(b"TOKEN=supersecret\n", Visibility::Restricted(vec!["alice".into()]))
            .unwrap();
        let pub_oid = alice.put(b"readme\n", Visibility::Public).unwrap();

        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from(".env"), (secret_oid.clone(), Visibility::Restricted(vec!["alice".into()])));
        tree.insert(PathBuf::from("README"), (pub_oid.clone(), Visibility::Public));
        alice
            .commit(Change { id: Oid([0; 32]), parents: vec![], message: "m".into(), tree })
            .unwrap();

        let restricted_key = alice.keyring.key_for(&secret_oid).expect("alice holds her key");
        let public_key = alice.keyring.key_for(&pub_oid).expect("alice holds public key");

        let bundle = alice.bundle(&[]).unwrap();

        assert!(
            !contains_window(&bundle.0, &restricted_key),
            "restricted content key leaked into the sync bundle"
        );
        assert!(
            contains_window(&bundle.0, &public_key),
            "public content key should ride along for ANYONE-granted content"
        );
    }

    /// ADR 0004 leak guard: the sync wire must carry no plaintext-equality
    /// oracle. Commit the SAME restricted plaintext into two repos; neither
    /// bundle may contain blake3(plaintext), and the ciphertexts must differ.
    #[test]
    fn bundle_carries_no_plaintext_equality_oracle() {
        let secret = b"DUPLICATED SECRET VALUE";
        let plaintext_hash = *blake3::hash(secret).as_bytes();

        let bundle_for = |identity: &str| {
            let mut repo = DagRepo::init(tmp(), identity).unwrap();
            let oid = repo
                .put(secret, Visibility::Restricted(vec![identity.into()]))
                .unwrap();
            let mut tree = BTreeMap::new();
            tree.insert(PathBuf::from(".env"), (oid, Visibility::Restricted(vec![identity.into()])));
            repo.commit(Change { id: Oid([0; 32]), parents: vec![], message: "m".into(), tree })
                .unwrap();
            repo.bundle(&[]).unwrap().0
        };

        let a = bundle_for("alice");
        let b = bundle_for("bob");

        assert!(!contains_window(&a, &plaintext_hash));
        assert!(!contains_window(&b, &plaintext_hash));

        let ct_a = single_ciphertext(&a);
        let ct_b = single_ciphertext(&b);
        assert_ne!(ct_a, ct_b, "same plaintext must not produce equal ciphertext on the wire");
    }

    fn single_ciphertext(bundle: &[u8]) -> Vec<u8> {
        let (_changes, objs, _keys, _escrow) = wire::decode(bundle).unwrap();
        assert_eq!(objs.len(), 1, "test fixture commits exactly one object");
        objs.into_iter().next().unwrap().1.ciphertext
    }

    fn contains_window(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// ADR 0005: a repo survives save -> load with identity, content, history,
    /// and key custody intact — so a process-per-command CLI works.
    #[test]
    fn save_load_round_trips() {
        let dir = std::env::temp_dir().join(format!("loot-persist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let secret_oid;
        let change_id;
        {
            let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
            secret_oid = repo
                .put(b"TOKEN=abc\n", Visibility::Restricted(vec!["alice".into()]))
                .unwrap();
            let pub_oid = repo.put(b"hi\n", Visibility::Public).unwrap();
            let mut tree = BTreeMap::new();
            tree.insert(PathBuf::from(".env"), (secret_oid.clone(), Visibility::Restricted(vec!["alice".into()])));
            tree.insert(PathBuf::from("README"), (pub_oid, Visibility::Public));
            change_id = repo
                .commit(Change { id: Oid([0; 32]), parents: vec![], message: "init".into(), tree })
                .unwrap();
            repo.save(&dir).unwrap();
        }

        let loaded = DagRepo::load(&dir, dir.join("work")).unwrap();
        // Identity preserved -> alice can still decrypt her restricted content.
        assert_eq!(loaded.get(&secret_oid, "alice", 0).unwrap(), b"TOKEN=abc\n");
        // A different identity still cannot.
        assert!(matches!(
            loaded.get(&secret_oid, "mallory", 0),
            Err(RepoError::Unauthorized(_))
        ));
        // History preserved.
        assert!(loaded.heads().contains(&change_id));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- snapshot / reconcile (ADR 0006) ---

    fn entry(path: &str, body: &[u8], vis: Visibility) -> (PathBuf, Vec<u8>, Visibility) {
        (PathBuf::from(path), body.to_vec(), vis)
    }

    #[test]
    fn snapshot_rewrites_working_change_in_place() {
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let w1 = repo
            .snapshot(None, &[entry("a.txt", b"one", Visibility::Public)], "wip", 0)
            .unwrap();
        // Re-snapshot with new content -> same working slot, not a second change.
        let w2 = repo
            .snapshot(Some(&w1), &[entry("a.txt", b"two", Visibility::Public)], "wip", 0)
            .unwrap();
        assert_eq!(repo.log().len(), 1, "working change rewritten, not appended");
        assert!(repo.heads().contains(&w2));
        // Latest content wins.
        let tree = repo.graph.current_tree();
        let oid = &tree[&PathBuf::from("a.txt")].0;
        assert_eq!(repo.get(oid, "alice", 0).unwrap(), b"two");
    }

    #[test]
    fn snapshot_deletes_a_visible_path_absent_from_the_tree() {
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let w = repo
            .snapshot(
                None,
                &[
                    entry("keep.txt", b"k", Visibility::Public),
                    entry("gone.txt", b"g", Visibility::Public),
                ],
                "wip",
                0,
            )
            .unwrap();
        // Re-snapshot with gone.txt removed from the tree -> it's deleted.
        let w2 = repo
            .snapshot(Some(&w), &[entry("keep.txt", b"k", Visibility::Public)], "wip", 0)
            .unwrap();
        let tree = repo.graph.current_tree();
        assert!(tree.contains_key(&PathBuf::from("keep.txt")));
        assert!(!tree.contains_key(&PathBuf::from("gone.txt")), "visible+absent => deleted");
        let _ = w2;
    }

    #[test]
    fn non_keyholder_snapshot_preserves_sealed_content() {
        // The core safety property (ADR 0006): a non-keyholder snapshotting their
        // partial tree must NOT delete the sealed file they cannot see.
        // Build a repo where alice committed a restricted .env + public README.
        let mut alice = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let _ = alice
            .snapshot(
                None,
                &[
                    entry(".env", b"SECRET", Visibility::Restricted(vec!["alice".into()])),
                    entry("README", b"hi", Visibility::Public),
                ],
                "init",
                0,
            )
            .unwrap();
        // Sync the full history to bob (non-keyholder) via a bundle.
        let bundle = alice.bundle(&[]).unwrap();
        let mut bob = DagRepo::init(std::env::temp_dir(), "bob").unwrap();
        bob.apply(&bundle, 0).unwrap();

        // Bob's visible tree is README only (he can't open .env). He has no
        // working change yet (just applied finalized history), so working=None:
        // his snapshot appends on alice's change, carrying .env forward.
        let sealed_env_oid = bob.graph.current_tree()[&PathBuf::from(".env")].0.clone();
        bob.snapshot(
            None,
            &[entry("README", b"hi edited by bob", Visibility::Public)],
            "bob edits readme",
            0,
        )
        .unwrap();

        // .env must still be present in bob's tree, carried forward as ciphertext.
        let tree = bob.graph.current_tree();
        assert!(tree.contains_key(&PathBuf::from(".env")), ".env must survive bob's snapshot");
        assert_eq!(tree[&PathBuf::from(".env")].0, sealed_env_oid, ".env carried forward unchanged");
        // And bob still cannot read it.
        assert!(matches!(
            bob.get(&sealed_env_oid, "bob", 0),
            Err(RepoError::Unauthorized(_))
        ));
    }

    #[test]
    fn snapshot_refuses_write_onto_sealed_invisible_path() {
        // Bob (non-keyholder) tries to write his own .env where alice's sealed
        // .env already lives -> refused, no silent clobber.
        let mut alice = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let _ = alice
            .snapshot(
                None,
                &[entry(".env", b"ALICE", Visibility::Restricted(vec!["alice".into()]))],
                "init",
                0,
            )
            .unwrap();
        let bundle = alice.bundle(&[]).unwrap();
        let mut bob = DagRepo::init(std::env::temp_dir(), "bob").unwrap();
        bob.apply(&bundle, 0).unwrap();

        let result = bob.snapshot(
            None,
            &[entry(".env", b"BOB", Visibility::Restricted(vec!["bob".into()]))],
            "bob writes own env",
            0,
        );
        assert!(matches!(result, Err(RepoError::Backend(_))), "must refuse the collision");
    }

    // --- embargo / escrow (ADR 0007) ---

    /// Core guarantee: the originator's own embargoed key is in Escrow, not
    /// the Keyring, so `get` returns Embargoed before flush.
    #[test]
    fn embargo_key_in_escrow_not_keyring_before_reveal() {
        let mut alice = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let oid = alice.put(b"cve fix", Visibility::Embargoed { reveal_at: 100 }).unwrap();

        // Before flush: Keyring has no entry, Escrow does.
        assert!(!alice.keyring.holds(&oid), "key must be in escrow, not keyring");
        assert!(alice.escrow.holds(&oid), "key must be in escrow before reveal");
        // get() returns Embargoed (open() finds no key in keyring).
        assert!(matches!(alice.get(&oid, "alice", 99), Err(RepoError::Embargoed(100))));
    }

    /// After flush_escrow with now >= reveal_at, the key promotes to the Keyring
    /// and get() succeeds.
    #[test]
    fn flush_escrow_promotes_key_and_enables_read() {
        let mut alice = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let oid = alice.put(b"cve fix", Visibility::Embargoed { reveal_at: 100 }).unwrap();

        alice.flush_escrow(100);

        assert!(alice.keyring.holds(&oid), "key must be in keyring after flush");
        assert!(!alice.escrow.holds(&oid), "escrow must be empty after flush");
        assert_eq!(alice.get(&oid, "alice", 100).unwrap(), b"cve fix");
    }

    /// A bundle ships embargoed keys in the escrow section, not the keyring
    /// section, and the receiver's Escrow is populated — not their Keyring.
    #[test]
    fn bundle_carries_embargoed_key_as_escrow_entry_not_keyring() {
        let mut alice = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let oid = alice.put(b"cve fix", Visibility::Embargoed { reveal_at: 100 }).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("cve.txt"), (oid.clone(), Visibility::Embargoed { reveal_at: 100 }));
        alice.commit(Change { id: Oid([0; 32]), parents: vec![], message: "cve".into(), tree }).unwrap();

        let bundle = alice.bundle(&[]).unwrap();

        // The raw wire must have the key in the escrow section, not the keyring.
        let (_changes, _objs, plain_keys, escrow_entries) = wire::decode(&bundle.0).unwrap();
        assert!(plain_keys.get(&oid).is_none(), "embargoed key must not be in keyring section");
        assert!(escrow_entries.contains_key(&oid), "embargoed key must be in escrow section");

        // Bob applies: key lands in his Escrow, not his Keyring.
        let mut bob = DagRepo::init(std::env::temp_dir(), "bob").unwrap();
        bob.apply(&bundle, 50).unwrap();
        assert!(bob.escrow.holds(&oid), "bob's escrow must hold the key");
        assert!(!bob.keyring.holds(&oid), "bob's keyring must be empty before reveal");

        // Before reveal: still blocked.
        assert!(matches!(bob.get(&oid, "bob", 50), Err(RepoError::Embargoed(100))));

        // After flush at reveal time: bob can read the CVE fix.
        bob.flush_escrow(100);
        assert_eq!(bob.get(&oid, "bob", 100).unwrap(), b"cve fix");
    }

    /// Escrow persists across save/load so reveal works in a new process.
    #[test]
    fn escrow_survives_save_load() {
        let dir = std::env::temp_dir().join(format!("loot-escrow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let oid;
        {
            let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
            oid = repo.put(b"cve fix", Visibility::Embargoed { reveal_at: 100 }).unwrap();
            repo.save(&dir).unwrap();
        }

        let mut loaded = DagRepo::load(&dir, dir.join("work")).unwrap();
        // Still embargoed after reload.
        assert!(loaded.escrow.holds(&oid));
        assert!(matches!(loaded.get(&oid, "alice", 50), Err(RepoError::Embargoed(100))));
        // Flush and read.
        loaded.flush_escrow(100);
        assert_eq!(loaded.get(&oid, "alice", 100).unwrap(), b"cve fix");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
