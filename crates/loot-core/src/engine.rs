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
//!   - in memory the store is a log-structured `Vec` + index; on disk objects are
//!     loose, content-addressed files written incrementally (ADR 0012)
//!
//! Encryption, visibility, and embargo live in [`crate::sealed`] (ADR 0003);
//! the merger/relay convergence rule lives in [`crate::converge`] (ADR 0001).

mod change_graph;
mod object_store;
mod persist_codec;

use crate::attestation::{Attestation, AttestationLog};
use crate::bundle_codec::{BundleBody, Frame};
use crate::converge;
use crate::escrow::Escrow;
use crate::manifest::Manifest;
use crate::sealed::{self, ContentKey, Keyring, SealedObject, ANYONE};
use crate::{Change, MergeOutcome, Oid, Repo, RepoError, SyncBundle, Visibility};
pub(crate) use change_graph::ChangeNode;
use change_graph::{compute_change_id, ChangeGraph};
use crate::store::RepoStore;
use object_store::{ObjectStore, Stored};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// One change in a [`LogGraph`]: its id, message, and which heads can reach it
/// (as indices into [`LogGraph::heads`]). A change reachable from exactly one
/// head is unique to that head's lineage; one reachable from several is shared
/// ancestry across the divergence.
#[derive(Clone, Debug)]
pub struct LogNode {
    pub id: Oid,
    pub message: String,
    /// Indices (into `LogGraph::heads`) of the heads that can reach this change,
    /// ascending. Never empty for a change in the graph.
    pub reachable_from: Vec<usize>,
}

/// Structured history for rendering `log` when the graph has diverged into
/// multiple heads (ADR 0001, issue #18). `changes` is in reverse-topo order
/// (children before parents), so a head appears before its ancestors.
#[derive(Clone, Debug)]
pub struct LogGraph {
    /// The current heads (tips), in stable ascending order.
    pub heads: Vec<Oid>,
    /// Every change with its head-reachability, children-first.
    pub changes: Vec<LogNode>,
}

/// Returned by `grant`, `maroon`, and `maroon_hard`: the new object address
/// plus any targeted grant bundles the caller should forward to remaining
/// identities (ADR 0008, 0009, 0010).
pub struct MaroonResult {
    pub new_oid: Oid,
    pub grants: Vec<(String, SyncBundle)>,
}

/// Returned by `migrate`: the new object address plus any targeted grant
/// bundles the caller should forward to newly-granted identities (ADR 0010).
pub struct MigrateResult {
    pub new_oid: Oid,
    pub grants: Vec<(String, SyncBundle)>,
}

/// The DAG engine. Composes storage, history, key custody, and policy behind
/// the [`Repo`] interface.
pub struct DagRepo {
    root: PathBuf,
    identity: String,
    /// This identity's ed25519 public key, folded into new change ids to attribute
    /// authored history (S3, ADR 0018). `None` until the workspace sets it from the
    /// loaded keypair; unauthored changes then keep their legacy (pre-0018) ids.
    author: Option<[u8; 32]>,
    /// This identity's private key custody for non-embargoed content.
    keyring: Keyring,
    /// Embargoed content keys awaiting their reveal time. `flush_escrow` promotes
    /// eligible entries to `keyring` before any content-reading operation (ADR 0007).
    escrow: Escrow,
    /// Append-only audit trail of grant events (ADR 0008). Travels in bundles.
    manifest: Manifest,
    /// Pending purge events: (old-oid, marooned-identity). Shipped in hard-maroon
    /// bundles so cooperating peers remove the marooned identity's key (ADR 0009).
    purges: Vec<(Oid, String)>,
    objects: ObjectStore,
    graph: ChangeGraph,
    /// Paths with unresolved conflicts from the last `apply`, keyed by path,
    /// value is (our oid, their oid). Populated from `MergeOutcome::Conflict`
    /// during `apply`; cleared entry-by-entry as `resolve` is called (ADR 0001).
    conflicts: BTreeMap<PathBuf, (Oid, Oid)>,
    /// Detachable, advisory attestations over changes (S4, ADR 0018). Travels in
    /// bundles; verified-and-dropped on ingest; never affects a change id.
    attestations: AttestationLog,
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
    /// Keyring. Call this before any content-reading operation (`surface`,
    /// `snapshot`). After this, `sealed::open` finds the key in the Keyring
    /// and decrypts normally — `open` itself is unmodified (ADR 0007).
    pub fn flush_escrow(&mut self, now: u64) {
        self.escrow.flush(&mut self.keyring, now);
    }

    fn object(&self, oid: &Oid) -> Result<&SealedObject, RepoError> {
        self.objects.get(oid)
    }

    /// Produce a targeted grant bundle that gives `grantee` the key for `oid`
    /// and records the event in the local manifest (ADR 0008). The caller must
    /// hold the key for `oid`; if not, returns `Unauthorized`.
    ///
    /// The bundle carries only the objects and key for this single grant — it is
    /// a targeted hand-off, not a full sync. Apply it on the grantee side.
    pub fn grant(&mut self, oid: &Oid, grantee: &str, now: u64) -> Result<SyncBundle, RepoError> {
        // Must hold the key ourselves before we can grant it.
        let key = self.keyring.key_for(oid)
            .ok_or_else(|| RepoError::Unauthorized(oid.clone()))?;

        // A grant carries just this object and its key, addressed to grantee.
        let obj = self.object(oid)?.clone();
        let mut keys: BTreeMap<Oid, ContentKey> = BTreeMap::new();
        keys.insert(oid.clone(), key);
        let mut objs: BTreeMap<Oid, SealedObject> = BTreeMap::new();
        objs.insert(oid.clone(), obj);
        let body = BundleBody {
            changes: Vec::new(),
            objs,
            keys,
            escrow: BTreeMap::new(),
            attestations: Vec::new(),
        };

        // Record in the local manifest (file-based grant: no pubkeys known here).
        use crate::manifest::UNKNOWN_PUBKEY;
        self.manifest.record(oid.clone(), grantee.to_string(), UNKNOWN_PUBKEY, UNKNOWN_PUBKEY, now);

        Ok(SyncBundle(Frame::Grant { grantee: grantee.to_string(), body }.encode()))
    }

    /// Produce a sealed-key grant bundle (tag 3) where the content key is
    /// ECIES-wrapped to the recipient's x25519 pubkey. Safe to relay — the relay
    /// cannot read the key. The caller supplies `seal_fn` to do the wrapping,
    /// keeping identity crypto outside the engine (ADR 0014).
    ///
    /// `grantee_pubkey` — the recipient's ed25519 pubkey (32 bytes). Used for
    /// mailbox addressing and the manifest audit record (ADR 0015).
    /// `grantor_pubkey` — the issuer's ed25519 pubkey. Recorded in the manifest
    /// so every peer can verify who issued the grant (ADR 0015).
    ///
    /// Wire format: `[3][grantee_pubkey(32)][wrapped_key(80)][oid(32)][payload]`
    pub fn grant_sealed(
        &mut self,
        oid: &Oid,
        grantee_name: &str,
        grantee_pubkey: [u8; 32],
        grantor_pubkey: [u8; 32],
        now: u64,
        seal: impl FnOnce(&[u8; 32]) -> Result<[u8; 80], RepoError>,
    ) -> Result<SyncBundle, RepoError> {
        let key = self.keyring.key_for(oid)
            .ok_or_else(|| RepoError::Unauthorized(oid.clone()))?;
        let wrapped = seal(&key)?;

        // Object only — the key travels ECIES-wrapped in the frame's wrapped_key
        // field, never in the body.
        let obj = self.object(oid)?.clone();
        let mut objs: BTreeMap<Oid, SealedObject> = BTreeMap::new();
        objs.insert(oid.clone(), obj);
        let body = BundleBody {
            changes: Vec::new(),
            objs,
            keys: BTreeMap::new(),
            escrow: BTreeMap::new(),
            attestations: Vec::new(),
        };

        self.manifest.record(oid.clone(), grantee_name.to_string(), grantee_pubkey, grantor_pubkey, now);
        Ok(SyncBundle(
            Frame::SealedGrant { grantee_pubkey, wrapped_key: wrapped, oid: oid.clone(), body }.encode(),
        ))
    }

    /// Apply a sealed-key grant bundle (tag 3). The caller supplies:
    /// - `grantor_pubkey` — verified ed25519 pubkey of the sender (from the
    ///   envelope the caller already verified). Recorded in the manifest (ADR 0015).
    /// - `unseal` — closure that decrypts the 80-byte wrapped key using the
    ///   recipient's private key. If the key was not sealed for us, this fails.
    ///
    /// Authorization is purely cryptographic: if `unseal` succeeds, the grant
    /// was addressed to us. There is no name-compare gate (ADR 0015).
    pub fn apply_sealed_grant(
        &mut self,
        bundle: &SyncBundle,
        grantor_pubkey: [u8; 32],
        now: u64,
        unseal: impl FnOnce(&[u8; 80]) -> Result<[u8; 32], RepoError>,
    ) -> Result<(), RepoError> {
        // Decode through the one codec; reject anything that isn't a sealed grant.
        let Frame::SealedGrant { grantee_pubkey, wrapped_key, oid, body } =
            Frame::decode(&bundle.0)?
        else {
            return Err(RepoError::Backend("not a sealed-key grant bundle (tag 3)".into()));
        };

        // Cryptographic gate: unseal fails if this grant wasn't addressed to us.
        let key = unseal(&wrapped_key)?;

        // SealedGrant bodies carry objects only (the grant is a key handoff, not
        // a history sync), so `changes` is always empty today. Guard it anyway so
        // a future format extension can't sneak unsigned authored changes in via
        // the grant path (ADR 0018 — verify-always, not a toggle).
        for node in &body.changes {
            verify_authored_change(node)?;
        }

        for (addr, obj) in body.objs {
            self.store(addr, obj, None);
        }
        for (escrow_oid, (escrow_key, reveal_at)) in body.escrow {
            if !self.escrow.holds(&escrow_oid) && !self.keyring.holds(&escrow_oid) {
                self.escrow.insert(escrow_oid, escrow_key, reveal_at);
            }
        }
        if !self.keyring.holds(&oid) {
            self.keyring.insert(oid.clone(), key);
        }

        // Record in manifest: we know both pubkeys, and the grantee is ourselves.
        self.manifest.record(
            oid,
            self.identity.clone(),
            grantee_pubkey,
            grantor_pubkey,
            now,
        );
        Ok(())
    }

    /// Forward-maroon `marooned` from `path`: re-seal the content under a fresh
    /// key that excludes `marooned`, update the change tree, and produce grant
    /// bundles for every remaining identity in the manifest (ADR 0009).
    ///
    /// Forward maroon does NOT emit a purge event — the marooned identity keeps
    /// their existing key for content they already have; they simply won't receive
    /// the new key. Use `maroon_hard` to also emit a purge event.
    pub fn maroon(&mut self, path: &Path, marooned: &str, now: u64) -> Result<MaroonResult, RepoError> {
        self.maroon_inner(path, marooned, now, false)
    }

    /// Hard-maroon `marooned` from `path`: same as forward maroon, but also emits
    /// a purge event so cooperating peers remove the marooned identity's old key
    /// on next bundle apply (ADR 0009).
    pub fn maroon_hard(&mut self, path: &Path, marooned: &str, now: u64) -> Result<MaroonResult, RepoError> {
        self.maroon_inner(path, marooned, now, true)
    }

    fn maroon_inner(&mut self, path: &Path, marooned: &str, now: u64, hard: bool) -> Result<MaroonResult, RepoError> {
        // Find the current oid for this path.
        let tree = self.graph.current_tree();
        let (old_oid, old_vis) = tree.get(path)
            .ok_or(RepoError::NotFound(Oid([0; 32])))?
            .clone();

        // Must hold the key to re-seal.
        let plaintext = self.get(&old_oid, &self.identity, now)
            .map_err(|_| RepoError::Unauthorized(old_oid.clone()))?;

        // Build the new visibility excluding marooned.
        let new_vis = match &old_vis {
            Visibility::Restricted(ids) => {
                let remaining: Vec<String> = ids.iter().filter(|id| id.as_str() != marooned).cloned().collect();
                Visibility::Restricted(remaining)
            }
            other => other.clone(),
        };

        // Re-seal under new visibility.
        let new_oid = self.put(&plaintext, new_vis.clone())?;

        // Record a purge event if hard maroon.
        if hard {
            self.purges.push((old_oid.clone(), marooned.to_string()));
        }

        // Update the current working change (or create a new one) to point to new_oid.
        let mut new_tree = tree.clone();
        new_tree.insert(path.to_path_buf(), (new_oid.clone(), new_vis.clone()));
        let change = Change {
            id: Oid([0; 32]),
            parents: self.graph.heads(),
            message: format!("maroon {} from {}", marooned, path.display()),
            tree: new_tree,
        };
        self.record(change)?;

        // Produce grant bundles for remaining identities.
        let remaining_grantees: Vec<String> = self.manifest.grants_for(&old_oid)
            .into_iter()
            .filter(|e| e.grantee != marooned && e.grantee != self.identity)
            .map(|e| e.grantee.clone())
            .collect();

        let mut grants = Vec::new();
        for grantee in remaining_grantees {
            if let Ok(bundle) = self.grant(&new_oid, &grantee, now) {
                grants.push((grantee, bundle));
            }
        }

        Ok(MaroonResult { new_oid, grants })
    }

    /// Migrate `path` to a new visibility policy: re-seal the content under
    /// `new_vis`, update the change tree, and produce grant bundles for any
    /// identities newly granted access (ADR 0010).
    pub fn migrate(&mut self, path: &Path, new_vis: Visibility, now: u64) -> Result<MigrateResult, RepoError> {
        // Find the current oid for this path.
        let tree = self.graph.current_tree();
        let (old_oid, _old_vis) = tree.get(path)
            .ok_or(RepoError::NotFound(Oid([0; 32])))?
            .clone();

        // Must hold the key to re-seal.
        let plaintext = self.get(&old_oid, &self.identity, now)
            .map_err(|_| RepoError::Unauthorized(old_oid.clone()))?;

        // Re-seal under new visibility.
        let new_oid = self.put(&plaintext, new_vis.clone())?;

        // Update the current working change (or create a new one) to point to new_oid.
        let mut new_tree = tree.clone();
        new_tree.insert(path.to_path_buf(), (new_oid.clone(), new_vis.clone()));
        let change = Change {
            id: Oid([0; 32]),
            parents: self.graph.heads(),
            message: format!("migrate {} to {:?}", path.display(), new_vis),
            tree: new_tree,
        };
        self.record(change)?;

        // Produce grant bundles for any newly-listed identities.
        let grants_needed: Vec<String> = match &new_vis {
            Visibility::Restricted(ids) => ids.iter()
                .filter(|id| id.as_str() != self.identity.as_str())
                .cloned()
                .collect(),
            _ => vec![],
        };

        let mut grants = Vec::new();
        for grantee in grants_needed {
            if let Ok(bundle) = self.grant(&new_oid, &grantee, now) {
                grants.push((grantee, bundle));
            }
        }

        Ok(MigrateResult { new_oid, grants })
    }

    /// The grant audit trail.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The raw content key for `oid`, if held. Used by the CLI to seal the key
    /// for relay delivery of grant bundles without pulling crypto into the engine.
    pub fn content_key_for(&self, oid: &Oid) -> Option<[u8; 32]> {
        self.keyring.key_for(oid)
    }

    /// The OID for `path` in the current tree, or `NotFound` if absent.
    pub fn current_tree_oid(&self, path: &Path) -> Result<Oid, RepoError> {
        self.graph.current_tree()
            .get(path)
            .map(|(oid, _)| oid.clone())
            .ok_or(RepoError::NotFound(Oid([0; 32])))
    }

    /// All unresolved conflicts from the last `apply`, keyed by path.
    /// Each value is `(our_oid, their_oid)`.
    pub fn conflicts(&self) -> &BTreeMap<PathBuf, (Oid, Oid)> {
        &self.conflicts
    }

    /// Resolve a conflict at `path` by providing the resolution bytes.
    /// Seals the resolution under `vis`, records a change, and removes the
    /// path from the conflict set.
    pub fn resolve(&mut self, path: &Path, resolution: &[u8], vis: Visibility, now: u64) -> Result<Oid, RepoError> {
        if !self.conflicts.contains_key(path) {
            return Err(RepoError::Backend(format!(
                "no conflict recorded at {}",
                path.display()
            )));
        }

        let new_oid = self.put(resolution, vis.clone())?;

        // Update the tree with the resolution.
        let mut new_tree = self.graph.current_tree();
        new_tree.insert(path.to_path_buf(), (new_oid.clone(), vis));
        let change = Change {
            id: Oid([0; 32]),
            parents: self.graph.heads(),
            message: format!("resolve conflict at {}", path.display()),
            tree: new_tree,
        };
        self.record(change)?;

        // Clear the resolved conflict.
        self.conflicts.remove(path);

        let _ = now;
        Ok(new_oid)
    }

    /// Stow a bundle append-only: store its sealed objects and add its
    /// change-nodes as new tips, without merging, decrypting, or touching a
    /// working tree (ADR 0011). This is the **relay** ingest path — the node
    /// holds ciphertext it cannot read and forwards it for keyholders. Purge
    /// events are accumulated so they continue to propagate on the next
    /// `bundle`. Convergence is deferred to whoever pulls and holds keys.
    ///
    /// Only sync bundles (tag 0) are stowable. A grant bundle (tag 1) is a
    /// targeted key handoff with no meaning for a keyless relay, so it is
    /// rejected rather than silently dropped.
    pub fn stow(&mut self, bundle: &SyncBundle) -> Result<(), RepoError> {
        // A relay only ever stows Sync frames; a Grant/SealedGrant is a targeted
        // key handoff with no meaning for a keyless relay, so reject it.
        let Frame::Sync { purges, body } = Frame::decode(&bundle.0)? else {
            return Err(RepoError::Backend(
                "a relay can only stow sync bundles (tag 0), not grant bundles".into(),
            ));
        };
        let BundleBody { changes, objs, keys, escrow, attestations } = body;

        // Reject any change with a missing/invalid author signature before we
        // store anything — a keyless relay still enforces authorship (ADR 0018).
        for node in &changes {
            verify_authored_change(node)?;
        }

        // Ingest attestations: verify each, drop invalid (advisory, never fatal),
        // keep the rest so they keep forwarding downstream (S4, ADR 0018).
        for att in attestations {
            if att.verify() {
                self.attestations.insert(att);
            }
        }

        // Store ciphertext, retaining any keys that rode along so they keep
        // forwarding downstream. Only ANYONE-granted (public) keys and embargoed
        // escrow entries ever travel in a sync bundle — RESTRICTED keys never do
        // (ADR 0003). So the relay's "keylessness" for restricted content is
        // automatic: it cannot receive a restricted key here, and thus can never
        // read restricted content. Public keys are non-secret by definition;
        // carrying them lets the relay forward readable public content.
        for (addr, obj) in objs {
            let key = keys.get(&addr).copied();
            self.store(addr, obj, key);
        }
        for (oid, (key, reveal_at)) in escrow {
            if !self.escrow.holds(&oid) && !self.keyring.holds(&oid) {
                self.escrow.insert(oid, key, reveal_at);
            }
        }
        // Accumulate purge events so they keep propagating downstream. A relay
        // is never the marooned identity for its own keyring (it holds none),
        // so there is nothing to remove locally.
        for p in purges {
            if !self.purges.contains(&p) {
                self.purges.push(p);
            }
        }
        // Append change-nodes as new tips. Concurrent pushes legitimately fork
        // the graph; keyholders collapse the forks on pull.
        for node in changes {
            self.graph.insert(node);
        }
        Ok(())
    }

    /// Merge a parsed sync bundle into our working change — the keyholder path
    /// shared by `apply`. Honors purges against our own keyring, ingests objects
    /// and keys, classifies each incoming change against our pre-apply tree via
    /// the ADR 0001 convergence rule, and records conflicts.
    fn apply_sync(
        &mut self,
        purges: Vec<(Oid, String)>,
        body: BundleBody,
        now: u64,
    ) -> Result<BTreeMap<PathBuf, MergeOutcome>, RepoError> {
        let BundleBody { changes, objs, keys, escrow, attestations } = body;

        // Reject any change with a missing/invalid author signature before we
        // mutate state (ADR 0018 — validity is always enforced, not a toggle).
        for node in &changes {
            verify_authored_change(node)?;
        }

        // Ingest attestations: verify each, drop invalid (advisory, never fatal),
        // and merge the rest (S4, ADR 0018).
        for att in attestations {
            if att.verify() {
                self.attestations.insert(att);
            }
        }

        // Honor purge events: if we are the marooned identity, remove the old key.
        for (purge_oid, marooned) in &purges {
            if marooned == &self.identity {
                self.keyring.remove(purge_oid);
            }
        }

        // Our tree before applying, used to detect concurrent same-path edits.
        let local_before = self.graph.current_tree();

        // Ingest SealedObjects, filing only the public (non-embargoed) keys that
        // rode along. Embargoed keys travel in escrow and go into our Escrow, not
        // the Keyring (ADR 0007). No Restricted key can be here.
        for (addr, obj) in objs {
            let key = keys.get(&addr).copied();
            self.store(addr, obj, key);
        }
        for (oid, (key, reveal_at)) in escrow {
            if !self.escrow.holds(&oid) && !self.keyring.holds(&oid) {
                self.escrow.insert(oid, key, reveal_at);
            }
        }

        // Classify every incoming change against our pre-apply tree using the
        // shared ADR 0001 classifier. We are the KeyOracle: it asks us for
        // plaintext, we answer via sealed::open. The classifier owns the rule.
        let mut outcomes: BTreeMap<PathBuf, MergeOutcome> = BTreeMap::new();
        for node in &changes {
            let per_change = converge::classify(&local_before, &node.tree, self, now);
            for (path, outcome) in per_change {
                let slot = outcomes.entry(path).or_insert(MergeOutcome::Converged);
                *slot = converge::worst(slot.clone(), outcome);
            }
        }

        // Populate the conflict map from Conflict outcomes.
        for (path, outcome) in &outcomes {
            if let MergeOutcome::Conflict { ref ours, ref theirs } = outcome {
                self.conflicts.insert(path.clone(), (ours.clone(), theirs.clone()));
            }
        }

        for node in changes {
            self.graph.insert(node);
        }

        Ok(outcomes)
    }

    /// Persist the whole repo under `dir` (typically `.loot/`): all sealed
    /// objects, the full change graph, and this identity's keyring. The keyring
    /// is written to its own LOCAL-ONLY file — it is custody, not repo content,
    /// and never travels in a bundle (ADR 0003, 0005).
    pub fn save(&self, dir: &std::path::Path) -> Result<(), RepoError> {
        let io = |e: std::io::Error| RepoError::Backend(e.to_string());
        let store = RepoStore::new(dir);
        std::fs::create_dir_all(dir).map_err(io)?;
        std::fs::write(store.identity(), self.identity.as_bytes()).map_err(io)?;
        // Objects: loose, content-addressed, incremental (ADR 0012).
        persist_codec::save_objects_loose(dir, &self.objects)?;
        // Change graph + custody metadata: small, whole-file. RepoStore names them.
        std::fs::write(store.graph(), persist_codec::encode_graph(&self.graph)).map_err(io)?;
        std::fs::write(store.keyring(), persist_codec::encode_keyring(&self.keyring)).map_err(io)?;
        std::fs::write(store.escrow(), persist_codec::encode_escrow(&self.escrow)).map_err(io)?;
        std::fs::write(store.manifest(), encode_manifest(&self.manifest)).map_err(io)?;
        std::fs::write(store.purges(), encode_purges(&self.purges)).map_err(io)?;
        std::fs::write(store.conflicts(), encode_conflicts(&self.conflicts)).map_err(io)?;
        std::fs::write(store.attestations(), encode_attestations(&self.attestations)).map_err(io)?;
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
        self.record(change)
    }

    /// Set this repo's author pubkey (S3, ADR 0018): the workspace calls this
    /// after loading the identity keypair, so new changes fold the author into
    /// their id and can be signed at finalization. Left unset, changes stay
    /// unauthored (legacy ids) — keyless and pre-0018 repos keep working.
    pub fn set_author(&mut self, author: [u8; 32]) {
        self.author = Some(author);
    }

    /// This repo's author pubkey, if set.
    pub fn author(&self) -> Option<[u8; 32]> {
        self.author
    }

    /// Attach the author's signature to a finalized change (`loot new`). The
    /// signature covers the change id and is stored beside the node, so identity
    /// stays a pure function of authored content (ADR 0018). Errors if `id` is
    /// unknown to this repo.
    pub fn attach_signature(&mut self, id: &Oid, signature: [u8; 64]) -> Result<(), RepoError> {
        self.graph.set_signature(id, signature).ok_or_else(|| {
            RepoError::Backend(format!(
                "cannot sign unknown change {}",
                crate::hex::short(&id.0, 8)
            ))
        })
    }

    /// The author pubkey recorded on a change, if any (S3, ADR 0018). `None` for
    /// a legacy/unauthored change or an unknown id. Used by `loot log` to show
    /// authorship, reverse-resolved to a peer name.
    pub fn change_author(&self, id: &Oid) -> Option<[u8; 32]> {
        self.graph.get(id).and_then(|n| n.author)
    }

    /// Verify and record an attestation over a change (S4, ADR 0018). Returns
    /// `true` if it verified and was stored, `false` if the signature was invalid
    /// (dropped — an attestation is advisory and never fatal). Attestations never
    /// affect a change id or convergence.
    pub fn add_attestation(&mut self, att: Attestation) -> bool {
        let ok = att.verify();
        if ok {
            self.attestations.insert(att);
        }
        ok
    }

    /// Attestations recorded over a change, for display (`loot log`/`manifest`).
    pub fn attestations_for(&self, change_id: &Oid) -> Vec<&Attestation> {
        self.attestations.for_change(change_id)
    }

    /// Every recorded attestation, for `loot manifest` display.
    pub fn all_attestations(&self) -> Vec<&Attestation> {
        self.attestations.iter().collect()
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

    /// Like `log`, but also returns per-change file counts by visibility class.
    /// Returns `(id, message, total_files, restricted_files, embargoed_files)`.
    pub fn log_detailed(&self) -> Vec<(Oid, String, usize, usize, usize)> {
        self.graph
            .in_order()
            .into_iter()
            .map(|c| {
                let total = c.tree.len();
                let restricted = c.tree.values()
                    .filter(|(_, v)| matches!(v, Visibility::Restricted(_)))
                    .count();
                let embargoed = c.tree.values()
                    .filter(|(_, v)| matches!(v, Visibility::Embargoed { .. }))
                    .count();
                (c.id.clone(), c.message.clone(), total, restricted, embargoed)
            })
            .collect()
    }

    /// All ancestors of `id` (including `id` itself), by walking parent edges.
    /// Used to compute head reachability for multi-head `log` display.
    fn ancestors_of(&self, id: &Oid) -> BTreeSet<Oid> {
        let mut seen = BTreeSet::new();
        let mut stack = vec![id.clone()];
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur.clone()) {
                continue;
            }
            if let Some(node) = self.graph.get(&cur) {
                for p in &node.parents {
                    stack.push(p.clone());
                }
            }
        }
        seen
    }

    /// Structured history for multi-head `log` (issue #18). Reports the current
    /// heads (ascending) and, per change, which heads can reach it — enough for
    /// a caller to show branch structure when peers have diverged. Changes are
    /// returned children-first (reverse topo), so a head precedes its ancestors.
    ///
    /// This is independent of head count; the CLI keeps its flat rendering when
    /// there is a single head and only switches to a branch view for two or more.
    pub fn log_graph(&self) -> LogGraph {
        let mut heads = self.graph.heads();
        heads.sort();

        // For each head, mark every ancestor as reachable from that head index.
        let mut reach: BTreeMap<Oid, Vec<usize>> = BTreeMap::new();
        for (hi, head) in heads.iter().enumerate() {
            for anc in self.ancestors_of(head) {
                reach.entry(anc).or_default().push(hi);
            }
        }

        // Children-first: reverse the parents-first topo order.
        let changes = self
            .graph
            .in_order()
            .into_iter()
            .rev()
            .map(|c| LogNode {
                id: c.id.clone(),
                message: c.message.clone(),
                reachable_from: reach.get(&c.id).cloned().unwrap_or_default(),
            })
            .collect();

        LogGraph { heads, changes }
    }

    /// Like `surface`, but also returns the list of materialized paths and their
    /// visibility, plus a count of skipped (sealed) paths. Lets the CLI report
    /// what was written without a second pass.
    pub fn surface_with_report(
        &self,
        change: &Oid,
        reader: &str,
        now: u64,
    ) -> Result<(Vec<(PathBuf, Visibility)>, usize), RepoError> {
        let node = self
            .graph
            .get(change)
            .ok_or_else(|| RepoError::NotFound(change.clone()))?;

        let mut written: Vec<(PathBuf, Visibility)> = Vec::new();
        let mut skipped = 0usize;

        for (path, (oid, vis)) in &node.tree {
            let bytes = match self.get(oid, reader, now) {
                Ok(b) => b,
                Err(RepoError::Unauthorized(_)) | Err(RepoError::Embargoed(_)) => {
                    skipped += 1;
                    continue;
                }
                Err(e) => return Err(e),
            };
            let dest = self.root.join(path);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
            }
            std::fs::write(&dest, &bytes).map_err(|e| RepoError::Backend(e.to_string()))?;
            written.push((path.clone(), vis.clone()));
        }

        Ok((written, skipped))
    }

    /// Load a repo previously written by [`save`] from `dir`. `root` is the
    /// working directory `surface` will materialize into (kept separate from
    /// `dir` so the store can live in `.loot/` while files land in the repo).
    pub fn load(dir: &std::path::Path, root: PathBuf) -> Result<Self, RepoError> {
        let io = |e: std::io::Error| RepoError::Backend(e.to_string());
        let store = RepoStore::new(dir);
        let identity = String::from_utf8(std::fs::read(store.identity()).map_err(io)?)
            .map_err(|e| RepoError::Backend(e.to_string()))?;
        let objects = persist_codec::load_objects_loose(dir)?;
        let graph = persist_codec::decode_graph(&std::fs::read(store.graph()).map_err(io)?)?;
        let keyring = persist_codec::decode_keyring(&std::fs::read(store.keyring()).map_err(io)?)?;
        // Escrow file may not exist in repos created before ADR 0007 — default empty.
        let escrow = match std::fs::read(store.escrow()) {
            Ok(b) => persist_codec::decode_escrow(&b)?,
            Err(_) => Escrow::new(),
        };
        let manifest = match std::fs::read(store.manifest()) {
            Ok(b) => decode_manifest(&b)?,
            Err(_) => Manifest::new(),
        };
        let purges = match std::fs::read(store.purges()) {
            Ok(b) => decode_purges(&b)?,
            Err(_) => Vec::new(),
        };
        let conflicts = match std::fs::read(store.conflicts()) {
            Ok(b) => decode_conflicts(&b)?,
            Err(_) => BTreeMap::new(),
        };
        // Attestations file may not exist in repos created before S4 — default empty.
        let attestations = match std::fs::read(store.attestations()) {
            Ok(b) => decode_attestations(&b)?,
            Err(_) => AttestationLog::new(),
        };
        Ok(DagRepo {
            root,
            identity,
            author: None,
            keyring,
            escrow,
            manifest,
            purges,
            objects,
            graph,
            conflicts,
            attestations,
        })
    }
}

impl Repo for DagRepo {
    fn init(path: PathBuf, identity: &str) -> Result<Self, RepoError> {
        Ok(DagRepo {
            root: path,
            identity: identity.to_string(),
            author: None,
            keyring: Keyring::new(),
            escrow: Escrow::new(),
            manifest: Manifest::new(),
            purges: Vec::new(),
            objects: ObjectStore::new(),
            graph: ChangeGraph::new(),
            conflicts: BTreeMap::new(),
            attestations: AttestationLog::new(),
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

    /// Record a change over the current set of put() objects.
    fn record(&mut self, change: Change) -> Result<Oid, RepoError> {
        // Fold this repo's author pubkey (if set) into the id, so authorship is
        // intrinsic (ADR 0018). The signature is attached later, at finalization
        // (`attach_signature`), not on every working-change rewrite.
        let id = compute_change_id(self.author.as_ref(), &change);
        let node = ChangeNode {
            id: id.clone(),
            parents: change.parents,
            message: change.message,
            tree: change.tree,
            author: self.author,
            signature: None,
        };
        self.graph.insert(node);
        Ok(id)
    }

    /// Materialize the tree of `change` to the working area, skipping
    /// content `reader` cannot see (ADR 0006).
    fn surface(&self, change: &Oid, reader: &str, now: u64) -> Result<(), RepoError> {
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
        // Full bundle: ship every object referenced by the sent changes.
        self.bundle_impl(have, None)
    }

    fn apply(
        &mut self,
        bundle: &SyncBundle,
        now: u64,
    ) -> Result<BTreeMap<PathBuf, MergeOutcome>, RepoError> {
        // One decode, then dispatch on the typed frame. A relay would call `stow`
        // instead and skip the merge. Sealed-key grants (tag 3) need the caller's
        // unseal closure, so they go through `apply_sealed_grant`, not here.
        match Frame::decode(&bundle.0)? {
            Frame::Sync { purges, body } => self.apply_sync(purges, body, now),
            Frame::Grant { grantee, body } => {
                let BundleBody { objs, keys, escrow, .. } = body;
                // Install objects and, if the grant is addressed to us, its keys.
                for (addr, obj) in objs {
                    let key = keys.get(&addr).copied();
                    // Store the object (may dedup). For grant bundles targeted to us,
                    // file the key directly into the keyring — dedup does not block key
                    // custody since the key is the grant payload, not derived from storage.
                    self.store(addr.clone(), obj, None);
                    if grantee == self.identity {
                        if let Some(k) = key {
                            if !self.keyring.holds(&addr) {
                                self.keyring.insert(addr, k);
                            }
                        }
                    }
                }
                for (oid, (key, reveal_at)) in escrow {
                    if grantee == self.identity && !self.escrow.holds(&oid) && !self.keyring.holds(&oid) {
                        self.escrow.insert(oid, key, reveal_at);
                    }
                }
                Ok(BTreeMap::new())
            }
            Frame::SealedGrant { .. } => Err(RepoError::Backend(
                "sealed-key grant bundle (tag 3) must be applied via apply_sealed_grant".into(),
            )),
        }
    }

    fn heads(&self) -> Vec<Oid> {
        self.graph.heads()
    }

    fn flush_embargo(&mut self, now: u64) {
        self.flush_escrow(now);
    }
}

impl DagRepo {
    /// Returns `true` if the repo has any authored-but-unsigned change (a working
    /// change the author has not yet signed). Such changes are excluded from
    /// bundles (ADR 0018), so a push while one exists silently transfers nothing.
    pub fn has_unsigned_tip(&self) -> bool {
        self.graph
            .in_order()
            .into_iter()
            .any(|c| c.author.is_some() && c.signature.is_none())
    }

    /// Object addresses in the closure of the changes this repo would send for
    /// `have` — the objects a recipient may be missing (S5). Only addresses of
    /// objects we actually hold are offered. Zero-knowledge: addresses only,
    /// never keys or plaintext (the relay already sees content addresses).
    pub fn offered_objects(&self, have: &[Oid]) -> Vec<Oid> {
        let have_set: std::collections::BTreeSet<&Oid> = have.iter().collect();
        let mut addrs: std::collections::BTreeSet<Oid> = std::collections::BTreeSet::new();
        for c in self.graph.in_order() {
            if have_set.contains(&c.id) || (c.author.is_some() && c.signature.is_none()) {
                continue;
            }
            for (oid, _vis) in c.tree.values() {
                if self.object(oid).is_ok() {
                    addrs.insert(oid.clone());
                }
            }
        }
        addrs.into_iter().collect()
    }

    /// The subset of `offered` addresses this repo does NOT already hold — the
    /// "wants" a receiver replies with (S5).
    pub fn missing_objects(&self, offered: &[Oid]) -> Vec<Oid> {
        offered
            .iter()
            .filter(|oid| self.object(oid).is_err())
            .cloned()
            .collect()
    }

    /// A sync bundle for `have` whose object *bytes* are limited to `wants` (S5).
    /// Changes, keys, escrow, and attestations ride as in a normal bundle (they
    /// are tiny); only the negotiated object ciphertext is filtered, so a peer
    /// never re-downloads objects it already holds.
    pub fn bundle_wanted(&self, have: &[Oid], wants: &[Oid]) -> Result<SyncBundle, RepoError> {
        let wants_set: std::collections::BTreeSet<Oid> = wants.iter().cloned().collect();
        self.bundle_impl(have, Some(&wants_set))
    }

    /// Split `wants` into batches and produce one `SyncBundle` per batch (S6).
    ///
    /// The change delta, keys, escrow, and attestations are computed once and
    /// cloned into each bundle; only the object ciphertext subset differs per
    /// batch. This is O(graph_size + N*batch_payload) rather than the
    /// O(N*graph_size) cost of calling `bundle_wanted` N times in a loop.
    ///
    /// When `wants` is empty one bundle is returned (carrying the change delta
    /// and attestations with no object bytes) so the caller always makes at
    /// least one network round-trip to propagate metadata.
    pub fn bundle_wanted_batched(
        &self,
        have: &[Oid],
        wants: &[Oid],
        batch_size: usize,
    ) -> Result<Vec<SyncBundle>, RepoError> {
        // Compute the shared payload (send-set, keys, escrow, attestations) once.
        let (shared_changes, shared_keys, shared_escrow, shared_attestations, all_objects) =
            self.bundle_shared(have)?;

        let make_bundle = |batch_wants: Option<&[Oid]>| -> SyncBundle {
            let needed: BTreeMap<Oid, SealedObject> = match batch_wants {
                None => all_objects.clone(),
                Some(batch) => {
                    let batch_set: std::collections::BTreeSet<&Oid> = batch.iter().collect();
                    all_objects
                        .iter()
                        .filter(|(oid, _)| batch_set.contains(oid))
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect()
                }
            };
            let body = BundleBody {
                changes: shared_changes.clone(),
                objs: needed,
                keys: shared_keys.clone(),
                escrow: shared_escrow.clone(),
                attestations: shared_attestations.clone(),
            };
            SyncBundle(Frame::Sync { purges: self.purges.clone(), body }.encode())
        };

        if wants.is_empty() {
            return Ok(vec![make_bundle(Some(&[]))]);
        }
        let bundles = wants
            .chunks(batch_size)
            .map(|batch| make_bundle(Some(batch)))
            .collect();
        Ok(bundles)
    }

    /// Compute the shared (non-object) payload for a send relative to `have`:
    /// returns (changes, keys, escrow, attestations, all_objects).
    fn bundle_shared(
        &self,
        have: &[Oid],
    ) -> Result<
        (
            Vec<ChangeNode>,
            BTreeMap<Oid, ContentKey>,
            BTreeMap<Oid, (ContentKey, u64)>,
            Vec<Attestation>,
            BTreeMap<Oid, SealedObject>,
        ),
        RepoError,
    > {
        let have_set: std::collections::BTreeSet<&Oid> = have.iter().collect();
        let send: Vec<&ChangeNode> = self
            .graph
            .in_order()
            .into_iter()
            .filter(|c| !have_set.contains(&c.id) && !(c.author.is_some() && c.signature.is_none()))
            .collect();

        let mut all_objects: BTreeMap<Oid, SealedObject> = BTreeMap::new();
        let mut public_keys: BTreeMap<Oid, ContentKey> = BTreeMap::new();
        let mut escrow_entries: BTreeMap<Oid, (ContentKey, u64)> = BTreeMap::new();
        for c in &send {
            for (oid, vis) in c.tree.values() {
                if let Ok(obj) = self.object(oid) {
                    all_objects.entry(oid.clone()).or_insert_with(|| obj.clone());
                    if obj.grant_ids.iter().any(|g| g == ANYONE) {
                        if let Visibility::Embargoed { reveal_at } = vis {
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

        let sent_ids: std::collections::BTreeSet<&Oid> = send.iter().map(|c| &c.id).collect();
        let attestations: Vec<Attestation> = self
            .attestations
            .iter()
            .filter(|a| sent_ids.contains(&a.change_id))
            .cloned()
            .collect();

        Ok((
            send.into_iter().cloned().collect(),
            public_keys,
            escrow_entries,
            attestations,
            all_objects,
        ))
    }

    /// Shared bundle builder. `wants = None` ships every referenced object;
    /// `wants = Some(set)` ships only those object *bytes* (S5 negotiation).
    fn bundle_impl(
        &self,
        have: &[Oid],
        wants: Option<&std::collections::BTreeSet<Oid>>,
    ) -> Result<SyncBundle, RepoError> {
        // Changes reachable here but not already known to the recipient. For
        // now, "reachable-not-have" = every change id not in `have`.
        let have_set: std::collections::BTreeSet<&Oid> = have.iter().collect();
        let send: Vec<&ChangeNode> = self
            .graph
            .in_order()
            .into_iter()
            // Skip changes the recipient has, and any authored-but-unsigned
            // working change: only finalized, signed history travels (ADR 0018).
            // Legacy unauthored changes still travel, so keyless repos are unaffected.
            .filter(|c| !have_set.contains(&c.id) && !(c.author.is_some() && c.signature.is_none()))
            .collect();

        // Ship SealedObjects (ciphertext, no keys) plus:
        //   - Public content keys -> plain keyring section (ANYONE-granted, not embargoed)
        //   - Embargoed content keys -> escrow section (ANYONE-granted, time-gated)
        //   - Restricted keys NEVER travel (ADR 0003)
        let mut needed: BTreeMap<Oid, SealedObject> = BTreeMap::new();
        let mut public_keys: BTreeMap<Oid, ContentKey> = BTreeMap::new();
        let mut escrow_entries: BTreeMap<Oid, (ContentKey, u64)> = BTreeMap::new();
        for c in &send {
            for (oid, vis) in c.tree.values() {
                if let Ok(obj) = self.object(oid) {
                    // Object bytes: when negotiating (S5), ship only wanted addrs;
                    // keys/escrow below always ride (tiny, and a peer may hold the
                    // ciphertext but not the key).
                    if wants.map_or(true, |w| w.contains(oid)) {
                        needed.entry(oid.clone()).or_insert_with(|| obj.clone());
                    }
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

        // Only ship attestations for changes actually in this bundle's send set
        // (#42/#48). An attestation for a change the recipient is not receiving
        // would leak that change's existence and its reviewers, so attestations
        // ride strictly with their change.
        let sent_ids: std::collections::BTreeSet<&Oid> = send.iter().map(|c| &c.id).collect();
        let attestations: Vec<Attestation> = self
            .attestations
            .iter()
            .filter(|a| sent_ids.contains(&a.change_id))
            .cloned()
            .collect();

        let body = BundleBody {
            changes: send.into_iter().cloned().collect(),
            objs: needed,
            keys: public_keys,
            escrow: escrow_entries,
            attestations,
        };
        Ok(SyncBundle(Frame::Sync { purges: self.purges.clone(), body }.encode()))
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

// --- local persistence helpers for manifest, purges, conflicts ---
// These use the same hand-rolled length-prefixed format as the other codecs.

/// Reject an authored change whose signature is missing or does not verify over
/// its id (S3, ADR 0018). Legacy/unauthored changes (`author == None`) predate
/// signing and are accepted. Called inside `apply`/`stow` so validity is
/// enforced structurally — never a toggle a caller can skip. loot-core is
/// verify-only here; signing and key custody live in loot-identity.
fn verify_authored_change(node: &ChangeNode) -> Result<(), RepoError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let Some(author) = node.author else {
        return Ok(());
    };
    let Some(sig) = node.signature else {
        return Err(RepoError::BadChangeSignature(node.id.clone()));
    };
    let vk = VerifyingKey::from_bytes(&author)
        .map_err(|_| RepoError::BadChangeSignature(node.id.clone()))?;
    vk.verify(&node.id.0, &Signature::from_bytes(&sig))
        .map_err(|_| RepoError::BadChangeSignature(node.id.clone()))
}

fn encode_attestations(log: &AttestationLog) -> Vec<u8> {
    use crate::bundle_codec::{put_attestation, put_u32};
    let mut out = Vec::new();
    crate::format::put_version(&mut out);
    let entries: Vec<_> = log.iter().collect();
    put_u32(&mut out, entries.len());
    for a in entries {
        put_attestation(&mut out, a);
    }
    out
}

fn decode_attestations(b: &[u8]) -> Result<AttestationLog, RepoError> {
    use crate::bundle_codec::Cursor;
    let mut c = Cursor { b, i: 0 };
    crate::format::read_version(&mut c)?;
    let mut log = AttestationLog::new();
    let n = c.u32()?;
    for _ in 0..n {
        let att = c.attestation()?;
        // Re-verify on load: the on-disk log is untrusted (it can be edited or
        // corrupted between runs), so we hold it to the same verify-and-drop bar
        // as bundle ingest — an invalid attestation is silently discarded rather
        // than trusted just because it was on disk (S4, ADR 0018).
        if att.verify() {
            log.insert(att);
        }
    }
    Ok(log)
}

fn encode_manifest(manifest: &Manifest) -> Vec<u8> {
    use crate::bundle_codec::{put_bytes, put_u32};
    let mut out = Vec::new();
    crate::format::put_version(&mut out);
    let entries: Vec<_> = manifest.iter().collect();
    put_u32(&mut out, entries.len());
    for e in entries {
        out.extend_from_slice(&e.oid.0);
        put_bytes(&mut out, e.grantee.as_bytes());
        out.extend_from_slice(&e.grantee_pubkey);
        out.extend_from_slice(&e.grantor_pubkey);
        out.extend_from_slice(&e.granted_at.to_le_bytes());
    }
    out
}

fn decode_manifest(b: &[u8]) -> Result<Manifest, RepoError> {
    use crate::format::Cursor;
    let mut c = Cursor { b, i: 0 };
    crate::format::read_version(&mut c)?;
    let mut m = Manifest::new();
    let n = c.u32()?;
    for _ in 0..n {
        let oid = Oid(c.arr32()?);
        let grantee = c.string()?;
        let grantee_pubkey = c.arr32()?;
        let grantor_pubkey = c.arr32()?;
        let granted_at = c.u64()?;
        m.record(oid, grantee, grantee_pubkey, grantor_pubkey, granted_at);
    }
    Ok(m)
}

fn encode_purges(purges: &[(Oid, String)]) -> Vec<u8> {
    use crate::bundle_codec::{put_bytes, put_u32};
    let mut out = Vec::new();
    crate::format::put_version(&mut out);
    put_u32(&mut out, purges.len());
    for (oid, identity) in purges {
        out.extend_from_slice(&oid.0);
        put_bytes(&mut out, identity.as_bytes());
    }
    out
}

fn decode_purges(b: &[u8]) -> Result<Vec<(Oid, String)>, RepoError> {
    use crate::format::Cursor;
    let mut c = Cursor { b, i: 0 };
    crate::format::read_version(&mut c)?;
    let n = c.u32()?;
    let mut purges = Vec::with_capacity(n);
    for _ in 0..n {
        let oid = Oid(c.arr32()?);
        let identity = c.string()?;
        purges.push((oid, identity));
    }
    Ok(purges)
}

fn encode_conflicts(conflicts: &BTreeMap<PathBuf, (Oid, Oid)>) -> Vec<u8> {
    use crate::bundle_codec::{put_bytes, put_u32};
    let mut out = Vec::new();
    crate::format::put_version(&mut out);
    put_u32(&mut out, conflicts.len());
    for (path, (ours, theirs)) in conflicts {
        put_bytes(&mut out, path.to_string_lossy().as_bytes());
        out.extend_from_slice(&ours.0);
        out.extend_from_slice(&theirs.0);
    }
    out
}

fn decode_conflicts(b: &[u8]) -> Result<BTreeMap<PathBuf, (Oid, Oid)>, RepoError> {
    use crate::format::Cursor;
    let mut c = Cursor { b, i: 0 };
    crate::format::read_version(&mut c)?;
    let n = c.u32()?;
    let mut conflicts = BTreeMap::new();
    for _ in 0..n {
        let path = PathBuf::from(c.string()?);
        let ours = Oid(c.arr32()?);
        let theirs = Oid(c.arr32()?);
        conflicts.insert(path, (ours, theirs));
    }
    Ok(conflicts)
}

#[cfg(test)]
mod tests {
    //! White-box guards that need engine internals (`keyring`, `bundle_codec::decode`).
    //! The black-box bake-off scenarios live in the `spike-dag` shim crate,
    //! driving the engine through the public `Repo` interface (ADR 0002).
    use super::*;
    // White-box tests reach into the low-level body codec directly.
    use crate::bundle_codec;

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
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "m".into(), tree })
            .unwrap();

        let restricted_key = alice.keyring.key_for(&secret_oid).expect("alice holds her key");
        let public_key = alice.keyring.key_for(&pub_oid).expect("alice holds public key");

        let bundle = alice.bundle(&[]).unwrap();
        let payload = extract_sync_payload(&bundle.0);

        assert!(
            !contains_window(&payload, &restricted_key),
            "restricted content key leaked into the sync bundle"
        );
        assert!(
            contains_window(&payload, &public_key),
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
            repo.record(Change { id: Oid([0; 32]), parents: vec![], message: "m".into(), tree })
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
        let payload = extract_sync_payload(bundle);
        let (_changes, objs, _keys, _escrow, _attestations) =
            bundle_codec::decode(&payload, crate::format::FORMAT_MAJOR).unwrap();
        assert_eq!(objs.len(), 1, "test fixture commits exactly one object");
        objs.into_iter().next().unwrap().1.ciphertext
    }

    fn contains_window(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Decode a sync bundle through `Frame::decode` and re-encode just the body
    /// payload for ADR 0003/0004 leak-guard inspection. This approach is immune
    /// to future Frame header changes (S2 compression flags, etc.) — the frame
    /// decoder handles whatever is in front of the body.
    fn extract_sync_payload(bundle: &[u8]) -> Vec<u8> {
        let frame = bundle_codec::Frame::decode(bundle).expect("valid sync bundle");
        let bundle_codec::Frame::Sync { body, .. } = frame else {
            panic!("expected sync bundle (tag 0)");
        };
        let changes: Vec<&ChangeNode> = body.changes.iter().collect();
        bundle_codec::encode(&changes, &body.objs, &body.keys, &body.escrow, &body.attestations)
    }

    /// S1/S2 compatibility: a v1-format sync bundle (marker `[1,0]`, no
    /// `compressed` flag in inline objects) applies cleanly through the full
    /// engine stack. Exercises `Frame::decode -> decode_body(major=1)` on `apply`.
    ///
    /// We hand-serialize the v1 wire layout using the public body-codec helpers
    /// so the test is coupled to the same field encoding as the real codec, not
    /// to internal byte offsets.
    #[test]
    fn v1_bundle_applies_through_engine() {
        use crate::bundle_codec::{put_bytes, put_u32, put_vis};

        // Produce a real bundle so we have live object/key/change data to work with.
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice.put(b"public\n", Visibility::Public).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("f.txt"), (oid.clone(), Visibility::Public));
        let change_id = alice
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "init".into(), tree })
            .unwrap();

        let v2_bundle = alice.bundle(&[]).unwrap();
        let frame = bundle_codec::Frame::decode(&v2_bundle.0).expect("valid v2 bundle");
        let bundle_codec::Frame::Sync { body, .. } = frame else { panic!("expected sync frame") };

        // Hand-serialize the v1 wire layout:
        //   [major=1][minor=0][tag=0][purge_count=0 u32le]
        //   [obj_count u32le]
        //     per object: [addr 32][nonce 12][ciphertext len+bytes][vis][grant_ids]
        //     note: v1 has NO `compressed` flag byte between nonce and ciphertext
        //   [key_count u32le][addr 32][key 32] ...
        //   [escrow_count u32le] ...
        //   [change_count u32le][change ...] ...
        let mut wire = Vec::new();
        wire.push(1u8); // major = 1
        wire.push(0u8); // minor = 0
        wire.push(0u8); // tag = Sync
        put_u32(&mut wire, 0); // no purges

        put_u32(&mut wire, body.objs.len());
        for (addr, obj) in &body.objs {
            wire.extend_from_slice(&addr.0);
            wire.extend_from_slice(&obj.nonce);
            // v1: no compressed flag byte here
            put_bytes(&mut wire, &obj.ciphertext);
            put_vis(&mut wire, &obj.vis);
            put_u32(&mut wire, obj.grant_ids.len());
            for id in &obj.grant_ids {
                put_bytes(&mut wire, id.as_bytes());
            }
        }
        put_u32(&mut wire, body.keys.len());
        for (addr, key) in &body.keys {
            wire.extend_from_slice(&addr.0);
            wire.extend_from_slice(key);
        }
        put_u32(&mut wire, body.escrow.len());
        for (addr, (key, reveal_at)) in &body.escrow {
            wire.extend_from_slice(&addr.0);
            wire.extend_from_slice(key);
            wire.extend_from_slice(&reveal_at.to_le_bytes());
        }
        put_u32(&mut wire, body.changes.len());
        for c in &body.changes {
            wire.extend_from_slice(&c.id.0);
            put_u32(&mut wire, c.parents.len());
            for p in &c.parents {
                wire.extend_from_slice(&p.0);
            }
            put_bytes(&mut wire, c.message.as_bytes());
            put_u32(&mut wire, c.tree.len());
            for (path, (o, vis)) in &c.tree {
                put_bytes(&mut wire, path.to_string_lossy().as_bytes());
                wire.extend_from_slice(&o.0);
                put_vis(&mut wire, vis);
            }
        }

        // apply() must succeed: the v1 major is accepted, the body parses without
        // the compressed flag, and the change is integrated.
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        bob.apply(&SyncBundle(wire), 0).expect("v1 bundle must apply through engine");
        assert!(bob.heads().contains(&change_id), "change must be tracked after v1 apply");
    }

    /// S2 (ADR 0020): a public file compresses on seal and round-trips
    /// byte-identical through bundle -> apply -> read on a peer that receives the
    /// public key. Exercises compress-then-encrypt over the full sync path.
    #[test]
    fn public_content_round_trips_compressed_through_bundle_apply() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let doc = b"fn main() { println!(\"hi\"); }\n".repeat(64);
        let oid = alice.put(&doc, Visibility::Public).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("main.rs"), (oid.clone(), Visibility::Public));
        alice
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "add main".into(), tree })
            .unwrap();
        // Reads back verbatim locally (decompress-on-open).
        assert_eq!(alice.get(&oid, "alice", 0).unwrap(), doc);
        // A peer receives the bundle (public key rides along) and reads identical bytes.
        let bundle = alice.bundle(&[]).unwrap();
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        bob.apply(&bundle, 0).unwrap();
        assert_eq!(
            bob.get(&oid, "bob", 0).unwrap(),
            doc,
            "public content must round-trip byte-identical through bundle/apply"
        );
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
                .record(Change { id: Oid([0; 32]), parents: vec![], message: "init".into(), tree })
                .unwrap();
            repo.save(&dir).unwrap();
        }

        let loaded = DagRepo::load(&dir, dir.join("work")).unwrap();
        // Identity preserved -> alice can still decrypt her restricted content.
        assert_eq!(loaded.get(&secret_oid, "alice", 0).unwrap(), b"TOKEN=abc\n");
        // A peer that never received the key cannot read — confirmed by checking
        // that a fresh repo without the key returns NotFound for the oid.
        // (Under ADR 0008 semantics, holding the key IS authorization; an identity
        // that was never granted the key simply won't have it in their keyring.)
        let mallory_repo = DagRepo::init(dir.join("mallory"), "mallory").unwrap();
        assert!(matches!(
            mallory_repo.get(&secret_oid, "mallory", 0),
            Err(RepoError::NotFound(_))
        ));
        // History preserved.
        assert!(loaded.heads().contains(&change_id));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_writes_objects_as_loose_immutable_files() {
        // ADR 0012: each object is its own content-addressed file, written once.
        // A second save after adding one object writes only the new file and
        // leaves existing object files byte-identical (immutable, incremental).
        let dir = std::env::temp_dir().join(format!("loot-loose-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
        let a = repo.put(b"first\n", Visibility::Public).unwrap();
        repo.save(&dir).unwrap();

        let obj_dir = dir.join("objects");
        let path_a = obj_dir.join(crate::hex::encode(&a.0));
        assert!(path_a.exists(), "object A should be a loose file named by its address");
        let a_bytes_first = std::fs::read(&path_a).unwrap();

        // Add a second object and save again.
        let b = repo.put(b"second\n", Visibility::Public).unwrap();
        repo.save(&dir).unwrap();

        // A's file is untouched (immutable); B's file now exists.
        assert_eq!(std::fs::read(&path_a).unwrap(), a_bytes_first, "existing object file must not be rewritten");
        assert!(obj_dir.join(crate::hex::encode(&b.0)).exists(), "new object B should have its own file");

        // No leftover temp files from the atomic write.
        let leftover_tmp = std::fs::read_dir(&obj_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().ends_with(".tmp"));
        assert!(!leftover_tmp, "atomic write should leave no .tmp files");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- multi-head log display (ADR 0001, issue #18) ---

    fn empty_change(parents: Vec<Oid>, message: &str) -> Change {
        Change { id: Oid([0; 32]), parents, message: message.into(), tree: BTreeMap::new() }
    }

    #[test]
    fn log_graph_single_head_is_linear() {
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let root = repo.record(empty_change(vec![], "root")).unwrap();
        let tip = repo.record(empty_change(vec![root.clone()], "tip")).unwrap();

        let g = repo.log_graph();
        assert_eq!(g.heads, vec![tip.clone()], "one head: the tip");
        // Every change is reachable from the single head (index 0).
        for node in &g.changes {
            assert_eq!(node.reachable_from, vec![0]);
        }
        // Children-first ordering: the tip precedes its ancestor.
        let ids: Vec<&Oid> = g.changes.iter().map(|n| &n.id).collect();
        assert_eq!(ids, vec![&tip, &root]);
    }

    #[test]
    fn log_graph_shows_two_diverged_heads() {
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let root = repo.record(empty_change(vec![], "root")).unwrap();
        let a = repo.record(empty_change(vec![root.clone()], "head A")).unwrap();
        let b = repo.record(empty_change(vec![root.clone()], "head B")).unwrap();

        let g = repo.log_graph();
        assert_eq!(g.heads.len(), 2);
        assert!(g.heads.contains(&a) && g.heads.contains(&b));

        let find = |id: &Oid| g.changes.iter().find(|n| &n.id == id).unwrap();
        // Root is shared by both heads; each tip is unique to one head.
        assert_eq!(find(&root).reachable_from.len(), 2, "root shared across the divergence");
        assert_eq!(find(&a).reachable_from.len(), 1);
        assert_eq!(find(&b).reachable_from.len(), 1);
        assert_ne!(
            find(&a).reachable_from,
            find(&b).reachable_from,
            "the two tips belong to different heads"
        );
    }

    #[test]
    fn log_graph_shows_three_diverged_heads() {
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let root = repo.record(empty_change(vec![], "root")).unwrap();
        let a = repo.record(empty_change(vec![root.clone()], "head A")).unwrap();
        let b = repo.record(empty_change(vec![root.clone()], "head B")).unwrap();
        let c = repo.record(empty_change(vec![root.clone()], "head C")).unwrap();

        let g = repo.log_graph();
        assert_eq!(g.heads.len(), 3);
        for h in [&a, &b, &c] {
            assert!(g.heads.contains(h), "each tip is a head");
        }
        let find = |id: &Oid| g.changes.iter().find(|n| &n.id == id).unwrap();
        assert_eq!(find(&root).reachable_from.len(), 3, "root shared by all three heads");
        assert_eq!(find(&a).reachable_from.len(), 1);
        assert_eq!(find(&b).reachable_from.len(), 1);
        assert_eq!(find(&c).reachable_from.len(), 1);
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
        alice.record(Change { id: Oid([0; 32]), parents: vec![], message: "cve".into(), tree }).unwrap();

        let bundle = alice.bundle(&[]).unwrap();

        // The raw wire must have the key in the escrow section, not the keyring.
        let payload = extract_sync_payload(&bundle.0);
        let (_changes, _objs, plain_keys, escrow_entries, _attestations) =
            bundle_codec::decode(&payload, crate::format::FORMAT_MAJOR).unwrap();
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

    /// Manifest persists across save/load.
    #[test]
    fn manifest_survives_save_load() {
        let dir = std::env::temp_dir().join(format!("loot-manifest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let oid;
        {
            let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
            oid = repo.put(b"shared data", Visibility::Restricted(vec!["alice".into(), "bob".into()])).unwrap();
            repo.manifest.record(oid.clone(), "bob".to_string(), [0u8;32], [0u8;32], 42);
            repo.save(&dir).unwrap();
        }

        let loaded = DagRepo::load(&dir, dir.join("work")).unwrap();
        let grants = loaded.manifest.grants_for(&oid);
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].grantee, "bob");
        assert_eq!(grants[0].granted_at, 42);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Purge events persist across save/load.
    #[test]
    fn purge_events_survive_save_load() {
        let dir = std::env::temp_dir().join(format!("loot-purges-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let oid;
        {
            let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
            oid = repo.put(b"data", Visibility::Restricted(vec!["alice".into()])).unwrap();
            repo.purges.push((oid.clone(), "bob".to_string()));
            repo.save(&dir).unwrap();
        }

        let loaded = DagRepo::load(&dir, dir.join("work")).unwrap();
        assert_eq!(loaded.purges.len(), 1);
        assert_eq!(loaded.purges[0].0, oid);
        assert_eq!(loaded.purges[0].1, "bob");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- grant / manifest (ADR 0008) ---

    #[test]
    fn grant_gives_grantee_the_key_and_records_in_manifest() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice.put(b"secret data", Visibility::Restricted(vec!["alice".into()])).unwrap();

        let bundle = alice.grant(&oid, "bob", 100).unwrap();

        // Manifest should record the grant.
        let grants = alice.manifest.grants_for(&oid);
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].grantee, "bob");
        assert_eq!(grants[0].granted_at, 100);

        // Bob applies the grant bundle.
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        // Also give bob the object (normally via regular bundle).
        let obj = alice.objects.get(&oid).unwrap().clone();
        bob.objects.put(oid.clone(), obj);

        bob.apply(&bundle, 0).unwrap();
        assert!(bob.keyring.holds(&oid), "bob must hold the key after applying grant");
        assert_eq!(bob.get(&oid, "bob", 0).unwrap(), b"secret data");
    }

    #[test]
    fn grant_requires_caller_to_hold_key() {
        let alice = DagRepo::init(tmp(), "alice").unwrap();
        let unknown_oid = Oid([99; 32]);
        let mut repo = alice;
        let result = repo.grant(&unknown_oid, "bob", 0);
        assert!(matches!(result, Err(RepoError::Unauthorized(_))), "must fail without key");
    }

    #[test]
    fn manifest_accumulates_across_bundles() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid1 = alice.put(b"data1", Visibility::Restricted(vec!["alice".into()])).unwrap();
        let oid2 = alice.put(b"data2", Visibility::Restricted(vec!["alice".into()])).unwrap();

        alice.grant(&oid1, "bob", 10).unwrap();
        alice.grant(&oid2, "carol", 20).unwrap();

        assert_eq!(alice.manifest.grants_for(&oid1).len(), 1);
        assert_eq!(alice.manifest.grants_for(&oid2).len(), 1);
        assert_eq!(alice.manifest.iter().count(), 2);
    }

    // --- forward maroon (ADR 0009/0010) ---

    #[test]
    fn forward_maroon_cuts_future_access() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice.put(b"secret", Visibility::Restricted(vec!["alice".into(), "bob".into()])).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("secret.txt"), (oid.clone(), Visibility::Restricted(vec!["alice".into(), "bob".into()])));
        alice.record(Change { id: Oid([0; 32]), parents: vec![], message: "add secret".into(), tree }).unwrap();

        let result = alice.maroon(Path::new("secret.txt"), "bob", 0).unwrap();

        // The new oid is different (re-sealed without bob).
        assert_ne!(result.new_oid, oid, "re-sealed content must have new oid");

        // Alice can still read the new object.
        let plaintext = alice.get(&result.new_oid, "alice", 0).unwrap();
        assert_eq!(plaintext, b"secret");
    }

    #[test]
    fn forward_maroon_re_grants_remaining_identities() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice.put(b"secret", Visibility::Restricted(vec!["alice".into(), "bob".into(), "carol".into()])).unwrap();
        // Record grant of old oid to bob and carol so maroon can find them.
        alice.manifest.record(oid.clone(), "bob".to_string(), [0u8;32], [0u8;32], 1);
        alice.manifest.record(oid.clone(), "carol".to_string(), [0u8;32], [0u8;32], 1);
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("s.txt"), (oid.clone(), Visibility::Restricted(vec!["alice".into(), "bob".into(), "carol".into()])));
        alice.record(Change { id: Oid([0; 32]), parents: vec![], message: "add".into(), tree }).unwrap();

        let result = alice.maroon(Path::new("s.txt"), "bob", 0).unwrap();

        // Carol should get a grant bundle (bob was marooned, carol remains).
        assert!(
            result.grants.iter().any(|(g, _)| g == "carol"),
            "carol must receive a re-grant bundle"
        );
        assert!(
            !result.grants.iter().any(|(g, _)| g == "bob"),
            "bob must not receive a re-grant bundle"
        );
    }

    #[test]
    fn forward_maroon_unknown_path_is_not_found() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let result = alice.maroon(Path::new("nonexistent.txt"), "bob", 0);
        assert!(matches!(result, Err(RepoError::NotFound(_))));
    }

    #[test]
    fn forward_maroon_requires_keyholder() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice.put(b"secret", Visibility::Restricted(vec!["alice".into()])).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("s.txt"), (oid.clone(), Visibility::Restricted(vec!["alice".into()])));
        alice.record(Change { id: Oid([0; 32]), parents: vec![], message: "add".into(), tree }).unwrap();

        let bundle = alice.bundle(&[]).unwrap();
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        bob.apply(&bundle, 0).unwrap();

        // Bob cannot maroon alice (he doesn't hold the key).
        let result = bob.maroon(Path::new("s.txt"), "alice", 0);
        assert!(matches!(result, Err(RepoError::Unauthorized(_))));
    }

    // --- hard maroon (ADR 0009) ---

    #[test]
    fn hard_maroon_purges_old_key_on_apply() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice.put(b"secret", Visibility::Restricted(vec!["alice".into(), "bob".into()])).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("s.txt"), (oid.clone(), Visibility::Restricted(vec!["alice".into(), "bob".into()])));
        alice.record(Change { id: Oid([0; 32]), parents: vec![], message: "add".into(), tree }).unwrap();

        // Give bob his own copy with the key.
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        let init_bundle = alice.bundle(&[]).unwrap();
        bob.apply(&init_bundle, 0).unwrap();
        // Manually insert bob's key for testing purposes.
        let key = alice.keyring.key_for(&oid).unwrap();
        bob.keyring.insert(oid.clone(), key);
        assert!(bob.keyring.holds(&oid), "bob should have the key before maroon");

        // Alice hard-marooned bob.
        alice.maroon_hard(Path::new("s.txt"), "bob", 0).unwrap();

        // Alice ships a new bundle to bob (with the purge event).
        let purge_bundle = alice.bundle(&[]).unwrap();
        bob.apply(&purge_bundle, 0).unwrap();

        // Bob's old key should be purged.
        assert!(!bob.keyring.holds(&oid), "bob's old key must be removed after hard maroon");
    }

    #[test]
    fn hard_maroon_does_not_purge_other_identities() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice.put(b"secret", Visibility::Restricted(vec!["alice".into(), "bob".into(), "carol".into()])).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("s.txt"), (oid.clone(), Visibility::Restricted(vec!["alice".into(), "bob".into(), "carol".into()])));
        alice.record(Change { id: Oid([0; 32]), parents: vec![], message: "add".into(), tree }).unwrap();

        alice.maroon_hard(Path::new("s.txt"), "bob", 0).unwrap();
        let purge_bundle = alice.bundle(&[]).unwrap();

        // Carol applies — her key must NOT be removed (purge is only for bob).
        let mut carol = DagRepo::init(tmp(), "carol").unwrap();
        let init_bundle = alice.bundle(&[]).unwrap();
        carol.apply(&init_bundle, 0).unwrap();
        let key = alice.keyring.key_for(&oid).unwrap();
        carol.keyring.insert(oid.clone(), key);

        carol.apply(&purge_bundle, 0).unwrap();
        assert!(carol.keyring.holds(&oid), "carol's key must NOT be purged");
    }

    // --- migrate (ADR 0010) ---

    #[test]
    fn migrate_restricted_to_public_drops_key_guard() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice.put(b"was secret", Visibility::Restricted(vec!["alice".into()])).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("f.txt"), (oid.clone(), Visibility::Restricted(vec!["alice".into()])));
        alice.record(Change { id: Oid([0; 32]), parents: vec![], message: "add".into(), tree }).unwrap();

        let result = alice.migrate(Path::new("f.txt"), Visibility::Public, 0).unwrap();
        let new_oid = result.new_oid;

        // The re-sealed content should be readable by anyone holding the key.
        let plaintext = alice.get(&new_oid, "alice", 0).unwrap();
        assert_eq!(plaintext, b"was secret");
    }

    #[test]
    fn migrate_public_to_restricted_gates_access() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice.put(b"now secret", Visibility::Public).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("f.txt"), (oid.clone(), Visibility::Public));
        alice.record(Change { id: Oid([0; 32]), parents: vec![], message: "add".into(), tree }).unwrap();

        let result = alice.migrate(Path::new("f.txt"), Visibility::Restricted(vec!["alice".into()]), 0).unwrap();
        let new_oid = result.new_oid;

        // Alice can read.
        assert_eq!(alice.get(&new_oid, "alice", 0).unwrap(), b"now secret");
    }

    #[test]
    fn migrate_produces_grants_for_restricted_identities() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice.put(b"data", Visibility::Public).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("f.txt"), (oid.clone(), Visibility::Public));
        alice.record(Change { id: Oid([0; 32]), parents: vec![], message: "add".into(), tree }).unwrap();

        let result = alice.migrate(
            Path::new("f.txt"),
            Visibility::Restricted(vec!["alice".into(), "bob".into()]),
            0,
        ).unwrap();

        // bob should receive a grant bundle.
        assert!(result.grants.iter().any(|(g, _)| g == "bob"), "bob must receive a grant bundle");
    }

    #[test]
    fn migrate_unknown_path_is_not_found() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let result = alice.migrate(Path::new("nonexistent.txt"), Visibility::Public, 0);
        assert!(matches!(result, Err(RepoError::NotFound(_))));
    }

    // --- conflicts (ADR 0001) ---

    #[test]
    fn conflicts_recorded_on_apply() {
        // Two peers both edit the same public file (both are keyholders) with
        // divergent content, so the classifier produces Conflict.
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();

        // Shared base.
        let oid_base = alice.put(b"base\n", Visibility::Public).unwrap();
        let mut base_tree = BTreeMap::new();
        base_tree.insert(PathBuf::from("f.txt"), (oid_base.clone(), Visibility::Public));
        alice.record(Change { id: Oid([0; 32]), parents: vec![], message: "base".into(), tree: base_tree }).unwrap();
        let seed = alice.bundle(&[]).unwrap();
        bob.apply(&seed, 0).unwrap();

        // Divergent edits.
        let oid_alice = alice.put(b"alice edit\n", Visibility::Public).unwrap();
        let mut alice_tree = BTreeMap::new();
        alice_tree.insert(PathBuf::from("f.txt"), (oid_alice, Visibility::Public));
        alice.record(Change { id: Oid([0; 32]), parents: alice.graph.heads(), message: "alice".into(), tree: alice_tree }).unwrap();

        let oid_bob = bob.put(b"bob edit\n", Visibility::Public).unwrap();
        let mut bob_tree = BTreeMap::new();
        bob_tree.insert(PathBuf::from("f.txt"), (oid_bob.clone(), Visibility::Public));
        bob.record(Change { id: Oid([0; 32]), parents: bob.graph.heads(), message: "bob".into(), tree: bob_tree }).unwrap();

        // Bob applies alice's bundle.
        let alice_bundle = alice.bundle(&bob.heads()).unwrap();
        let outcomes = bob.apply(&alice_bundle, 0).unwrap();

        let f_outcome = outcomes.get(Path::new("f.txt"));
        assert!(
            matches!(f_outcome, Some(MergeOutcome::Conflict { .. })),
            "divergent edits must produce Conflict"
        );
        assert!(bob.conflicts.contains_key(Path::new("f.txt")), "conflict must be recorded");
    }

    // --- relay stow (ADR 0011) ---

    #[test]
    fn stow_stores_restricted_ciphertext_without_its_key_and_never_merges() {
        // A relay stows alice's bundle carrying RESTRICTED content. It gains the
        // ciphertext and the change as a tip, but receives no restricted key
        // (those never travel — ADR 0003), so it cannot read it. It also records
        // no conflict and surfaces no working tree: storage + forwarding only.
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let restricted = Visibility::Restricted(vec!["alice".into()]);
        let oid = alice.put(b"secret\n", restricted.clone()).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from(".env"), (oid.clone(), restricted));
        let change_id = alice
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "init".into(), tree })
            .unwrap();
        let bundle = alice.bundle(&[]).unwrap();

        let mut relay = DagRepo::init(tmp(), "relay").unwrap();
        relay.stow(&bundle).unwrap();

        // Object stored as ciphertext; the change is now a tip.
        assert!(relay.object(&oid).is_ok(), "relay must store the ciphertext");
        assert!(relay.heads().contains(&change_id), "relay must hold the change");
        // The relay holds no key for restricted content and cannot read it.
        assert!(!relay.keyring.holds(&oid), "a relay must never hold a restricted key");
        assert!(relay.get(&oid, "relay", 0).is_err(), "relay must not read restricted content");
        // Nothing classified, nothing conflicted.
        assert!(relay.conflicts.is_empty(), "stow must never record a conflict");
    }

    #[test]
    fn stow_forwards_public_keys_so_downstream_peers_can_read() {
        // Public content is ANYONE-granted, so its key travels in every sync
        // bundle (ADR 0003). A relay must retain that key and forward it, or a
        // downstream peer would receive unreadable public ciphertext.
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice.put(b"readme\n", Visibility::Public).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("README"), (oid.clone(), Visibility::Public));
        alice.record(Change { id: Oid([0; 32]), parents: vec![], message: "init".into(), tree }).unwrap();

        let mut relay = DagRepo::init(tmp(), "relay").unwrap();
        relay.stow(&alice.bundle(&[]).unwrap()).unwrap();

        // A fresh peer pulls from the relay and can read the public content.
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        bob.apply(&relay.bundle(&[]).unwrap(), 0).unwrap();
        assert_eq!(bob.get(&oid, "bob", 0).unwrap(), b"readme\n", "public content must survive the relay hop");
    }

    #[test]
    fn stow_accumulates_concurrent_forks_without_conflict() {
        // Two peers fork from a shared base. A relay stows both. The relay's
        // graph holds both tips (a fork) and records no conflict — convergence
        // is the keyholders' job on pull, not the relay's.
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let base_oid = alice.put(b"base\n", Visibility::Public).unwrap();
        let mut base_tree = BTreeMap::new();
        base_tree.insert(PathBuf::from("f.txt"), (base_oid, Visibility::Public));
        alice.record(Change { id: Oid([0; 32]), parents: vec![], message: "base".into(), tree: base_tree }).unwrap();

        let mut relay = DagRepo::init(tmp(), "relay").unwrap();
        relay.stow(&alice.bundle(&[]).unwrap()).unwrap();

        // Bob clones the base off the relay's state by applying the same seed.
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        bob.apply(&alice.bundle(&[]).unwrap(), 0).unwrap();

        // Divergent edits on the same path.
        let a_oid = alice.put(b"alice\n", Visibility::Public).unwrap();
        let mut a_tree = BTreeMap::new();
        a_tree.insert(PathBuf::from("f.txt"), (a_oid, Visibility::Public));
        alice.record(Change { id: Oid([0; 32]), parents: alice.graph.heads(), message: "a".into(), tree: a_tree }).unwrap();

        let b_oid = bob.put(b"bob\n", Visibility::Public).unwrap();
        let mut b_tree = BTreeMap::new();
        b_tree.insert(PathBuf::from("f.txt"), (b_oid, Visibility::Public));
        bob.record(Change { id: Oid([0; 32]), parents: bob.graph.heads(), message: "b".into(), tree: b_tree }).unwrap();

        // Relay stows both pushes. No merge, no conflict — just two tips.
        relay.stow(&alice.bundle(&[]).unwrap()).unwrap();
        relay.stow(&bob.bundle(&[]).unwrap()).unwrap();

        assert!(relay.conflicts.is_empty(), "relay must never manufacture a conflict");
        assert!(relay.heads().len() >= 2, "relay must hold the forked tips, uncollapsed");
    }

    #[test]
    fn stow_rejects_grant_bundles() {
        // A grant bundle (tag 1) is a targeted key handoff — meaningless to a
        // keyless relay. Stow rejects it rather than silently dropping it.
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice.put(b"secret\n", Visibility::Restricted(vec!["alice".into()])).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from(".env"), (oid.clone(), Visibility::Restricted(vec!["alice".into()])));
        alice.record(Change { id: Oid([0; 32]), parents: vec![], message: "init".into(), tree }).unwrap();
        let grant = alice.grant(&oid, "bob", 0).unwrap();

        let mut relay = DagRepo::init(tmp(), "relay").unwrap();
        assert!(matches!(relay.stow(&grant), Err(RepoError::Backend(_))), "relay must reject grant bundles");
    }

    #[test]
    fn stow_forwards_purges_downstream() {
        // A hard-maroon purge event rides a sync bundle. A relay stows it,
        // holds no keyring entry to remove, but re-emits the purge in its own
        // bundle so a downstream marooned peer still receives it.
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice.put(b"code\n", Visibility::Restricted(vec!["alice".into(), "bob".into()])).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("src.rs"), (oid.clone(), Visibility::Restricted(vec!["alice".into(), "bob".into()])));
        alice.record(Change { id: Oid([0; 32]), parents: vec![], message: "init".into(), tree }).unwrap();
        // Grant bob so the manifest knows him, then hard-maroon him.
        alice.grant(&oid, "bob", 0).unwrap();
        alice.maroon_hard(Path::new("src.rs"), "bob", 1).unwrap();

        let mut relay = DagRepo::init(tmp(), "relay").unwrap();
        relay.stow(&alice.bundle(&[]).unwrap()).unwrap();

        // The relay re-emits the purge in its own outgoing bundle.
        let relay_out = relay.bundle(&[]).unwrap();
        let purges = match bundle_codec::Frame::decode(&relay_out.0).unwrap() {
            bundle_codec::Frame::Sync { purges, .. } => purges,
            _ => panic!("relay bundle must be a sync frame"),
        };
        assert!(
            purges.iter().any(|(o, who)| *o == oid && who == "bob"),
            "relay must forward the purge event downstream"
        );
    }

    #[test]
    fn resolve_clears_conflict_and_updates_tree() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();

        // Shared base.
        let oid_base = alice.put(b"base\n", Visibility::Public).unwrap();
        let mut base_tree = BTreeMap::new();
        base_tree.insert(PathBuf::from("f.txt"), (oid_base.clone(), Visibility::Public));
        alice.record(Change { id: Oid([0; 32]), parents: vec![], message: "base".into(), tree: base_tree }).unwrap();
        let seed = alice.bundle(&[]).unwrap();
        bob.apply(&seed, 0).unwrap();

        // Divergent edits.
        let oid_alice = alice.put(b"alice\n", Visibility::Public).unwrap();
        let mut alice_tree = BTreeMap::new();
        alice_tree.insert(PathBuf::from("f.txt"), (oid_alice, Visibility::Public));
        alice.record(Change { id: Oid([0; 32]), parents: alice.graph.heads(), message: "alice".into(), tree: alice_tree }).unwrap();

        let oid_bob_edit = bob.put(b"bob\n", Visibility::Public).unwrap();
        let mut bob_tree = BTreeMap::new();
        bob_tree.insert(PathBuf::from("f.txt"), (oid_bob_edit.clone(), Visibility::Public));
        bob.record(Change { id: Oid([0; 32]), parents: bob.graph.heads(), message: "bob".into(), tree: bob_tree }).unwrap();

        let alice_bundle = alice.bundle(&bob.heads()).unwrap();
        bob.apply(&alice_bundle, 0).unwrap();

        // Ensure conflict is recorded.
        assert!(bob.conflicts.contains_key(Path::new("f.txt")));

        // Resolve.
        let resolution = b"resolved content\n";
        let new_oid = bob.resolve(Path::new("f.txt"), resolution, Visibility::Public, 0).unwrap();

        // Conflict cleared.
        assert!(!bob.conflicts.contains_key(Path::new("f.txt")), "conflict must be cleared after resolve");

        // Tree updated.
        let tree = bob.graph.current_tree();
        assert_eq!(tree[Path::new("f.txt")].0, new_oid, "tree must point to resolution oid");
    }

    #[test]
    fn resolve_unknown_path_errors() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let result = alice.resolve(Path::new("no-conflict.txt"), b"resolution", Visibility::Public, 0);
        assert!(matches!(result, Err(RepoError::Backend(_))), "unknown path must error");
    }

    // --- golden-byte fixtures + major-rejection for manifest, purges, conflicts (ADR 0019) ---

    // manifest: one entry — oid=[1;32], grantee="bob", grantee_pubkey=[2;32],
    //           grantor_pubkey=[3;32], granted_at=42.
    // Layout: [major=1][minor=0][count=1 u32le][oid 32][put_bytes("bob")=7][grantee_pk 32][grantor_pk 32][granted_at u64le]
    const GOLDEN_MANIFEST_V1: [u8; 117] = [
        1, 0, 1, 0, 0, 0,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // oid=[1;32]
        3, 0, 0, 0, 98, 111, 98,  // put_bytes("bob")
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // grantee_pk=[2;32]
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // grantor_pk=[3;32]
        42, 0, 0, 0, 0, 0, 0, 0, // granted_at=42
    ];

    // purges: one entry — oid=[6;32], identity="eve".
    // Layout: [major=1][minor=0][count=1 u32le][oid 32][put_bytes("eve")=7]
    const GOLDEN_PURGES_V1: [u8; 45] = [
        1, 0, 1, 0, 0, 0,
        6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, // oid=[6;32]
        3, 0, 0, 0, 101, 118, 101, // put_bytes("eve")
    ];

    // conflicts: one entry — path="f.txt", ours=[7;32], theirs=[8;32].
    // Layout: [major=1][minor=0][count=1 u32le][put_bytes("f.txt")=9][ours 32][theirs 32]
    const GOLDEN_CONFLICTS_V1: [u8; 79] = [
        1, 0, 1, 0, 0, 0,
        5, 0, 0, 0, 102, 46, 116, 120, 116, // put_bytes("f.txt")
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, // ours=[7;32]
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, // theirs=[8;32]
    ];

    // v2 goldens (current format, FORMAT_MAJOR = 2, ADR 0020). These layouts are
    // unchanged from v1; only the marker byte differs.
    const GOLDEN_MANIFEST_V2: [u8; 117] = [
        2, 0, 1, 0, 0, 0,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        3, 0, 0, 0, 98, 111, 98,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        42, 0, 0, 0, 0, 0, 0, 0,
    ];
    const GOLDEN_PURGES_V2: [u8; 45] = [
        2, 0, 1, 0, 0, 0,
        6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
        3, 0, 0, 0, 101, 118, 101,
    ];
    const GOLDEN_CONFLICTS_V2: [u8; 79] = [
        2, 0, 1, 0, 0, 0,
        5, 0, 0, 0, 102, 46, 116, 120, 116,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    ];

    // v3 goldens (current format, FORMAT_MAJOR = 3, ADR 0018). None of these
    // artifacts contain changes, so their layouts are unchanged from v2 — only
    // the marker byte differs.
    const GOLDEN_MANIFEST_V3: [u8; 117] = [
        3, 0, 1, 0, 0, 0,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        3, 0, 0, 0, 98, 111, 98,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        42, 0, 0, 0, 0, 0, 0, 0,
    ];
    const GOLDEN_PURGES_V3: [u8; 45] = [
        3, 0, 1, 0, 0, 0,
        6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
        3, 0, 0, 0, 101, 118, 101,
    ];
    const GOLDEN_CONFLICTS_V3: [u8; 79] = [
        3, 0, 1, 0, 0, 0,
        5, 0, 0, 0, 102, 46, 116, 120, 116,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    ];

    // v4 goldens (FORMAT_MAJOR = 4). manifest/purges/conflicts layouts unchanged
    // in S4 — only the marker. The attestation log is new in v4.
    const GOLDEN_MANIFEST_V4: [u8; 117] = [
        4, 0, 1, 0, 0, 0,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        3, 0, 0, 0, 98, 111, 98,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        42, 0, 0, 0, 0, 0, 0, 0,
    ];
    const GOLDEN_PURGES_V4: [u8; 45] = [
        4, 0, 1, 0, 0, 0,
        6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
        3, 0, 0, 0, 101, 118, 101,
    ];
    const GOLDEN_CONFLICTS_V4: [u8; 79] = [
        4, 0, 1, 0, 0, 0,
        5, 0, 0, 0, 102, 46, 116, 120, 116,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    ];
    // attestation log: 1 entry — change_id=[1;32], attester=[7;32], role="reviewed", sig=[9;64].
    const GOLDEN_ATTEST_V4: [u8; 146] = [
        4, 0, 1, 0, 0, 0,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        8, 0, 0, 0, 114, 101, 118, 105, 101, 119, 101, 100,
        9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
        9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    ];

    fn sample_manifest() -> Manifest {
        let mut m = Manifest::new();
        m.record(Oid([1; 32]), "bob".to_string(), [2u8; 32], [3u8; 32], 42);
        m
    }

    #[test]
    fn v1_manifest_still_decodes() {
        // Layout unchanged since v1; a v2 build still reads a v1 manifest.
        let back = decode_manifest(&GOLDEN_MANIFEST_V1).unwrap();
        let entries = back.grants_for(&Oid([1; 32]));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].grantee, "bob");
        assert_eq!(entries[0].granted_at, 42);
    }

    #[test]
    fn v2_manifest_still_decodes() {
        assert_eq!(decode_manifest(&GOLDEN_MANIFEST_V2).unwrap().grants_for(&Oid([1; 32])).len(), 1);
    }

    #[test]
    fn v3_manifest_still_decodes() {
        assert_eq!(decode_manifest(&GOLDEN_MANIFEST_V3).unwrap().grants_for(&Oid([1; 32])).len(), 1);
    }

    #[test]
    fn golden_v4_manifest_matches_and_round_trips() {
        assert_eq!(encode_manifest(&sample_manifest()), GOLDEN_MANIFEST_V4, "v4 manifest layout must not drift");
        assert_eq!(decode_manifest(&GOLDEN_MANIFEST_V4).unwrap().grants_for(&Oid([1; 32])).len(), 1);
    }

    #[test]
    fn v1_purges_still_decodes() {
        let back = decode_purges(&GOLDEN_PURGES_V1).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].0, Oid([6; 32]));
        assert_eq!(back[0].1, "eve");
    }

    #[test]
    fn v2_purges_still_decodes() {
        assert_eq!(decode_purges(&GOLDEN_PURGES_V2).unwrap().len(), 1);
    }

    #[test]
    fn v3_purges_still_decodes() {
        assert_eq!(decode_purges(&GOLDEN_PURGES_V3).unwrap().len(), 1);
    }

    #[test]
    fn golden_v4_purges_matches_and_round_trips() {
        let purges = vec![(Oid([6; 32]), "eve".to_string())];
        assert_eq!(encode_purges(&purges), GOLDEN_PURGES_V4, "v4 purges layout must not drift");
        assert_eq!(decode_purges(&GOLDEN_PURGES_V4).unwrap().len(), 1);
    }

    #[test]
    fn v1_conflicts_still_decodes() {
        let back = decode_conflicts(&GOLDEN_CONFLICTS_V1).unwrap();
        let (ours, theirs) = &back[Path::new("f.txt")];
        assert_eq!(*ours, Oid([7; 32]));
        assert_eq!(*theirs, Oid([8; 32]));
    }

    #[test]
    fn v2_conflicts_still_decodes() {
        assert!(decode_conflicts(&GOLDEN_CONFLICTS_V2).unwrap().contains_key(Path::new("f.txt")));
    }

    #[test]
    fn v3_conflicts_still_decodes() {
        assert!(decode_conflicts(&GOLDEN_CONFLICTS_V3).unwrap().contains_key(Path::new("f.txt")));
    }

    #[test]
    fn golden_v4_conflicts_matches_and_round_trips() {
        let mut conflicts = BTreeMap::new();
        conflicts.insert(PathBuf::from("f.txt"), (Oid([7; 32]), Oid([8; 32])));
        assert_eq!(encode_conflicts(&conflicts), GOLDEN_CONFLICTS_V4, "v4 conflicts layout must not drift");
        assert!(decode_conflicts(&GOLDEN_CONFLICTS_V4).unwrap().contains_key(Path::new("f.txt")));
    }

    #[test]
    fn golden_v4_attestations_layout_matches() {
        // Encode-direction golden: fixed bytes (with a placeholder signature)
        // lock the durable *layout* so it cannot drift. Decode is not exercised
        // here — `decode_attestations` now re-verifies and would drop this
        // placeholder signature; disk decode is covered by the round-trip tests.
        let mut log = AttestationLog::new();
        log.insert(Attestation {
            change_id: Oid([1; 32]),
            attester: [7; 32],
            role: "reviewed".into(),
            signature: [9; 64],
        });
        assert_eq!(encode_attestations(&log), GOLDEN_ATTEST_V4, "v4 attestation layout must not drift");
    }

    #[test]
    fn valid_attestations_survive_disk_round_trip() {
        let (sk, pk) = test_signer(9);
        let mut log = AttestationLog::new();
        log.insert(make_attestation(&sk, pk, Oid([1; 32]), "reviewed"));
        let back = decode_attestations(&encode_attestations(&log)).unwrap();
        assert_eq!(back.for_change(&Oid([1; 32])).len(), 1, "valid attestation survives disk load");
    }

    #[test]
    fn invalid_attestation_dropped_on_disk_load() {
        // A tampered on-disk log must not be trusted just because it was on disk.
        let (sk, pk) = test_signer(9);
        let mut att = make_attestation(&sk, pk, Oid([1; 32]), "reviewed");
        att.signature[0] ^= 0xff; // corrupt after signing
        let mut log = AttestationLog::new();
        log.insert(att);
        let back = decode_attestations(&encode_attestations(&log)).unwrap();
        assert!(back.is_empty(), "invalid on-disk attestation is dropped on load");
    }

    // ---- S3: authored, signed history (ADR 0018) ----

    /// A deterministic ed25519 test keypair (seeded, no RNG needed).
    fn test_signer(seed: u8) -> (ed25519_dalek::SigningKey, [u8; 32]) {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn authored_change(id: Oid, author: [u8; 32], signature: Option<[u8; 64]>) -> ChangeNode {
        ChangeNode {
            id,
            parents: vec![],
            message: "m".into(),
            tree: BTreeMap::new(),
            author: Some(author),
            signature,
        }
    }

    fn bundle_of(node: ChangeNode) -> SyncBundle {
        let body = BundleBody {
            changes: vec![node],
            objs: BTreeMap::new(),
            keys: BTreeMap::new(),
            escrow: BTreeMap::new(),
            attestations: vec![],
        };
        SyncBundle(Frame::Sync { purges: vec![], body }.encode())
    }

    #[test]
    fn author_is_part_of_change_id() {
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("f"), (Oid([9; 32]), Visibility::Public));
        let change = Change { id: Oid([0; 32]), parents: vec![], message: "m".into(), tree };
        let (_s1, pk1) = test_signer(1);
        let (_s2, pk2) = test_signer(2);
        let id_legacy = compute_change_id(None, &change);
        let id1 = compute_change_id(Some(&pk1), &change);
        let id2 = compute_change_id(Some(&pk2), &change);
        assert_ne!(id1, id2, "same edit by two authors must yield different ids");
        assert_ne!(id1, id_legacy, "authored id must differ from the legacy (unauthored) id");
    }

    #[test]
    fn signed_change_verifies_through_apply() {
        use ed25519_dalek::Signer;
        let (sk, pk) = test_signer(7);
        let id = Oid([5; 32]);
        let node = authored_change(id.clone(), pk, Some(sk.sign(&id.0).to_bytes()));
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        assert!(bob.apply(&bundle_of(node), 0).is_ok(), "a validly signed change must apply");
    }

    #[test]
    fn apply_rejects_missing_forged_and_tampered_signatures() {
        use ed25519_dalek::Signer;
        let (sk, pk) = test_signer(7);
        let id = Oid([5; 32]);

        // Names an author but carries no signature — a stripped signature.
        let missing = authored_change(id.clone(), pk, None);
        assert!(matches!(
            DagRepo::init(tmp(), "bob").unwrap().apply(&bundle_of(missing), 0),
            Err(RepoError::BadChangeSignature(_))
        ));

        // Signature is valid ed25519 but over a different message (forged/tampered).
        let forged = authored_change(id.clone(), pk, Some(sk.sign(b"not the id").to_bytes()));
        assert!(matches!(
            DagRepo::init(tmp(), "bob").unwrap().apply(&bundle_of(forged), 0),
            Err(RepoError::BadChangeSignature(_))
        ));

        // Signature by the wrong key (author claims pk but a different key signed).
        let (other, _) = test_signer(8);
        let wrong_key = authored_change(id.clone(), pk, Some(other.sign(&id.0).to_bytes()));
        assert!(matches!(
            DagRepo::init(tmp(), "bob").unwrap().apply(&bundle_of(wrong_key), 0),
            Err(RepoError::BadChangeSignature(_))
        ));
    }

    #[test]
    fn relay_stow_preserves_author_and_signature() {
        use ed25519_dalek::Signer;
        let (sk, pk) = test_signer(7);
        let id = Oid([5; 32]);
        let node = authored_change(id.clone(), pk, Some(sk.sign(&id.0).to_bytes()));

        // A keyless relay verifies then stows, and re-bundles downstream with the
        // author + signature intact — authorship survives the relay hop (ADR 0018).
        let mut relay = DagRepo::init(tmp(), "relay").unwrap();
        relay.stow(&bundle_of(node)).unwrap();
        let out = relay.bundle(&[]).unwrap();
        match Frame::decode(&out.0).unwrap() {
            Frame::Sync { body, .. } => {
                let c = body.changes.iter().find(|c| c.id == id).expect("change survived the relay");
                assert_eq!(c.author, Some(pk), "author must survive the relay hop");
                assert!(c.signature.is_some(), "signature must survive the relay hop");
            }
            _ => panic!("expected Sync"),
        }
    }

    // ---- S4: attestation lane (ADR 0018) ----

    fn make_attestation(sk: &ed25519_dalek::SigningKey, pk: [u8; 32], change: Oid, role: &str) -> Attestation {
        use ed25519_dalek::Signer;
        let signature = sk.sign(&crate::attestation::signing_bytes(&change, &pk, role)).to_bytes();
        Attestation { change_id: change, attester: pk, role: role.into(), signature }
    }

    fn attestation_bundle(atts: Vec<Attestation>) -> SyncBundle {
        let body = BundleBody {
            changes: vec![],
            objs: BTreeMap::new(),
            keys: BTreeMap::new(),
            escrow: BTreeMap::new(),
            attestations: atts,
        };
        SyncBundle(Frame::Sync { purges: vec![], body }.encode())
    }

    #[test]
    fn attestation_round_trips_through_apply() {
        let (sk, pk) = test_signer(9);
        let att = make_attestation(&sk, pk, Oid([5; 32]), "reviewed");
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        bob.apply(&attestation_bundle(vec![att]), 0).unwrap();
        let got = bob.attestations_for(&Oid([5; 32]));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].role, "reviewed");
        assert_eq!(got[0].attester, pk);
    }

    #[test]
    fn invalid_attestation_is_dropped_not_fatal() {
        let (sk, pk) = test_signer(9);
        let good = make_attestation(&sk, pk, Oid([6; 32]), "kept");
        let mut bad = make_attestation(&sk, pk, Oid([5; 32]), "reviewed");
        bad.signature[0] ^= 0xff; // corrupt the signature

        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        // apply must NOT fail on a bad attestation (advisory, unlike change sigs).
        bob.apply(&attestation_bundle(vec![bad, good]), 0).unwrap();
        assert!(bob.attestations_for(&Oid([5; 32])).is_empty(), "invalid attestation dropped");
        assert_eq!(bob.attestations_for(&Oid([6; 32])).len(), 1, "valid attestation kept");
    }

    #[test]
    fn attestation_does_not_change_change_id() {
        let (sk, pk) = test_signer(9);
        let mut repo = DagRepo::init(tmp(), "alice").unwrap();
        repo.set_author(pk);
        let oid = repo.put(b"x", Visibility::Public).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("f"), (oid, Visibility::Public));
        let id = repo
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "m".into(), tree })
            .unwrap();
        let heads_before = repo.heads();
        assert!(repo.add_attestation(make_attestation(&sk, pk, id.clone(), "reviewed")));
        assert_eq!(repo.heads(), heads_before, "attesting must not touch the graph or ids");
        assert_eq!(repo.attestations_for(&id).len(), 1);
    }

    /// A legacy (unauthored) change with an arbitrary id — travels through a
    /// relay, so an attestation over it can ride along.
    fn carried_change(id: Oid) -> ChangeNode {
        ChangeNode {
            id,
            parents: vec![],
            message: "m".into(),
            tree: BTreeMap::new(),
            author: None,
            signature: None,
        }
    }

    #[test]
    fn relay_preserves_attestations_for_changes_it_carries() {
        // Strict send-set filtering (#42/#48): an attestation rides only with its
        // change. A relay that carries the change also forwards its attestation.
        let (sk, pk) = test_signer(9);
        let att = make_attestation(&sk, pk, Oid([5; 32]), "reviewed");
        let body = BundleBody {
            changes: vec![carried_change(Oid([5; 32]))],
            objs: BTreeMap::new(),
            keys: BTreeMap::new(),
            escrow: BTreeMap::new(),
            attestations: vec![att],
        };
        let bundle = SyncBundle(Frame::Sync { purges: vec![], body }.encode());
        let mut relay = DagRepo::init(tmp(), "relay").unwrap();
        relay.stow(&bundle).unwrap();
        match Frame::decode(&relay.bundle(&[]).unwrap().0).unwrap() {
            Frame::Sync { body, .. } => {
                assert_eq!(body.attestations.len(), 1, "attestation rides with its carried change");
                assert_eq!(body.attestations[0].attester, pk);
            }
            _ => panic!("expected Sync"),
        }
    }

    #[test]
    fn bundle_omits_attestations_for_changes_not_sent() {
        // The change is NOT in the send set, so its attestation must not ship —
        // shipping it would leak the change's existence and reviewers (#42).
        let (sk, pk) = test_signer(9);
        let att = make_attestation(&sk, pk, Oid([5; 32]), "reviewed");
        let mut relay = DagRepo::init(tmp(), "relay").unwrap();
        relay.stow(&attestation_bundle(vec![att])).unwrap(); // attestation only, no change
        match Frame::decode(&relay.bundle(&[]).unwrap().0).unwrap() {
            Frame::Sync { body, .. } => {
                assert!(body.attestations.is_empty(), "orphan attestation must not be shipped");
            }
            _ => panic!("expected Sync"),
        }
    }

    #[test]
    fn stow_rejects_authored_change_with_missing_or_bad_signature() {
        use ed25519_dalek::Signer;
        let (sk, pk) = test_signer(7);
        let id = Oid([5; 32]);

        let missing_sig = authored_change(id.clone(), pk, None);
        assert!(
            matches!(
                DagRepo::init(tmp(), "relay").unwrap().stow(&bundle_of(missing_sig)),
                Err(RepoError::BadChangeSignature(_))
            ),
            "stow must reject authored change with no signature"
        );

        let forged = authored_change(id.clone(), pk, Some(sk.sign(b"wrong").to_bytes()));
        assert!(
            matches!(
                DagRepo::init(tmp(), "relay").unwrap().stow(&bundle_of(forged)),
                Err(RepoError::BadChangeSignature(_))
            ),
            "stow must reject authored change with a forged signature"
        );
    }

    // ---- S5: object-level "wants" negotiation ----

    fn objs_in(bundle: &SyncBundle) -> BTreeMap<Oid, SealedObject> {
        match Frame::decode(&bundle.0).unwrap() {
            Frame::Sync { body, .. } => body.objs,
            _ => panic!("expected Sync"),
        }
    }

    #[test]
    fn negotiation_transfers_only_missing_objects() {
        // Alice: two changes, each adding one public object (A then B).
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let a = alice.put(b"aaaa", Visibility::Public).unwrap();
        let mut t1 = BTreeMap::new();
        t1.insert(PathBuf::from("a"), (a.clone(), Visibility::Public));
        let c1 = alice
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "c1".into(), tree: t1 })
            .unwrap();
        let b = alice.put(b"bbbb", Visibility::Public).unwrap();
        let mut t2 = BTreeMap::new();
        t2.insert(PathBuf::from("b"), (b.clone(), Visibility::Public));
        let c2 = alice
            .record(Change { id: Oid([0; 32]), parents: vec![c1.clone()], message: "c2".into(), tree: t2 })
            .unwrap();

        // Bob receives only change1 (+ object A) via a partial bundle (have=[c2]).
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        bob.apply(&alice.bundle(&[c2]).unwrap(), 0).unwrap();
        assert!(bob.object(&a).is_ok(), "bob has A");
        assert!(bob.object(&b).is_err(), "bob lacks B");

        // Negotiate: alice offers the closure, bob replies with the subset it lacks.
        let have = bob.heads();
        let offered = alice.offered_objects(&have);
        let wants = bob.missing_objects(&offered);
        assert_eq!(wants, vec![b.clone()], "bob wants only the object it is missing");

        // Alice ships only the wanted object bytes; the already-held one is not re-sent.
        let bundle = alice.bundle_wanted(&have, &wants).unwrap();
        let objs = objs_in(&bundle);
        assert_eq!(objs.len(), 1);
        assert!(objs.contains_key(&b) && !objs.contains_key(&a));
        bob.apply(&bundle, 0).unwrap();
        assert!(bob.object(&b).is_ok(), "bob now holds B");
    }

    #[test]
    fn re_pull_with_nothing_new_transfers_zero_objects() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let a = alice.put(b"data", Visibility::Public).unwrap();
        let mut t = BTreeMap::new();
        t.insert(PathBuf::from("f"), (a, Visibility::Public));
        alice
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "c".into(), tree: t })
            .unwrap();

        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        bob.apply(&alice.bundle(&[]).unwrap(), 0).unwrap();

        // Re-pull: bob already holds everything, so wants is empty and no object
        // bytes move (AC: a re-pull with nothing new transfers ~0 object bytes).
        let have = bob.heads();
        let offered = alice.offered_objects(&have);
        let wants = bob.missing_objects(&offered);
        assert!(wants.is_empty(), "nothing new to want");
        assert!(objs_in(&alice.bundle_wanted(&have, &wants).unwrap()).is_empty());
    }

    // ---- S6: resumable transfer ----

    #[test]
    fn interrupted_push_resumes_transferring_only_remaining() {
        // Alice: two changes, objects A then B.
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let a = alice.put(b"aaaa", Visibility::Public).unwrap();
        let mut t1 = BTreeMap::new();
        t1.insert(PathBuf::from("a"), (a.clone(), Visibility::Public));
        let c1 = alice
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "c1".into(), tree: t1 })
            .unwrap();
        let b = alice.put(b"bbbb", Visibility::Public).unwrap();
        let mut t2 = BTreeMap::new();
        t2.insert(PathBuf::from("b"), (b.clone(), Visibility::Public));
        alice
            .record(Change { id: Oid([0; 32]), parents: vec![c1], message: "c2".into(), tree: t2 })
            .unwrap();

        let mut relay = DagRepo::init(tmp(), "relay").unwrap();

        // "Interrupted" push: only the first batch (object A) reaches the relay and
        // is stowed. `stow` is append-only + idempotent, so this partial progress
        // is durable.
        relay.stow(&alice.bundle_wanted(&[], &[a.clone()]).unwrap()).unwrap();
        assert!(relay.object(&a).is_ok(), "A delivered");
        assert!(relay.object(&b).is_err(), "B not yet delivered");

        // Resume: re-negotiate. The relay already holds A, so only B is wanted.
        let wants = relay.missing_objects(&alice.offered_objects(&[]));
        assert_eq!(wants, vec![b.clone()], "resume sends only the remaining object");
        relay.stow(&alice.bundle_wanted(&[], &wants).unwrap()).unwrap();
        assert!(relay.object(&b).is_ok(), "B delivered on resume");

        // Re-run a completed push: nothing left to want (idempotent no-op).
        assert!(relay.missing_objects(&alice.offered_objects(&[])).is_empty());
    }

    #[test]
    fn re_stowing_a_delivered_bundle_is_idempotent() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let a = alice.put(b"data", Visibility::Public).unwrap();
        let mut t = BTreeMap::new();
        t.insert(PathBuf::from("f"), (a.clone(), Visibility::Public));
        alice
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "c".into(), tree: t })
            .unwrap();
        let bundle = alice.bundle(&[]).unwrap();

        let mut relay = DagRepo::init(tmp(), "relay").unwrap();
        relay.stow(&bundle).unwrap();
        relay.stow(&bundle).unwrap(); // re-run of a completed transfer
        assert!(relay.object(&a).is_ok());
        assert_eq!(relay.offered_objects(&[]).len(), 1, "no duplication on re-stow");
    }

    #[test]
    fn decode_manifest_rejects_incompatible_future_major() {
        let mut bytes = encode_manifest(&sample_manifest());
        bytes[0] = crate::format::FORMAT_MAJOR + 1;
        assert!(matches!(decode_manifest(&bytes), Err(RepoError::UnsupportedFormat { .. })));
    }

    #[test]
    fn decode_purges_rejects_incompatible_future_major() {
        let mut bytes = encode_purges(&[(Oid([6; 32]), "eve".to_string())]);
        bytes[0] = crate::format::FORMAT_MAJOR + 1;
        assert!(matches!(decode_purges(&bytes), Err(RepoError::UnsupportedFormat { .. })));
    }

    #[test]
    fn decode_conflicts_rejects_incompatible_future_major() {
        let mut conflicts = BTreeMap::new();
        conflicts.insert(PathBuf::from("f.txt"), (Oid([7; 32]), Oid([8; 32])));
        let mut bytes = encode_conflicts(&conflicts);
        bytes[0] = crate::format::FORMAT_MAJOR + 1;
        assert!(matches!(decode_conflicts(&bytes), Err(RepoError::UnsupportedFormat { .. })));
    }

    #[test]
    fn conflicts_survive_save_load() {
        let dir = std::env::temp_dir().join(format!("loot-conflicts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        {
            let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
            // Manually insert a conflict to test persistence.
            repo.conflicts.insert(
                PathBuf::from("f.txt"),
                (Oid([1; 32]), Oid([2; 32])),
            );
            repo.save(&dir).unwrap();
        }

        let loaded = DagRepo::load(&dir, dir.join("work")).unwrap();
        assert!(loaded.conflicts.contains_key(Path::new("f.txt")), "conflict must survive save/load");
        let (ours, theirs) = &loaded.conflicts[Path::new("f.txt")];
        assert_eq!(*ours, Oid([1; 32]));
        assert_eq!(*theirs, Oid([2; 32]));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
