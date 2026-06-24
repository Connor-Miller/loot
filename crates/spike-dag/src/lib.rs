//! Spike A: encrypted content-addressed DAG.
//!
//! Thesis being proven out:
//!   - each object is encrypted independently; visibility == key possession
//!   - addressing is by CIPHERTEXT hash only; there is no plaintext-derived
//!     identity, so the store leaks no plaintext-equality oracle (ADR 0004)
//!   - storage is log-structured / packed (one append-only `Vec` + in-memory
//!     index), NOT git-style loose files, so we don't reproduce the APFS
//!     small-file perf disaster
//!   - runs fully in-memory; `checkout` is the only thing that touches disk
//!
//! Encryption, visibility, and embargo are NOT implemented here — they live in
//! the deep `loot_core::sealed` module (ADR 0003). This backend stores
//! [`SealedObject`]s (ciphertext, no keys) in its packed log and holds content
//! keys in a separate [`Keyring`]. It calls `sealed::seal`/`sealed::open` and
//! never touches crypto directly. Because keys live only in the keyring, a sync
//! bundle cannot leak them: it ships SealedObjects, plus keys for `ANYONE`-
//! granted (Public/Embargoed) content only — Restricted keys never travel.

mod change_graph;
mod object_store;

use change_graph::{compute_change_id, ChangeGraph, ChangeNode};
use loot_core::sealed::{self, ContentKey, Keyring, SealedObject, ANYONE};
use loot_core::{converge, Change, MergeOutcome, Oid, Repo, RepoError, SyncBundle, Visibility};
use object_store::{ObjectStore, Stored};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// The DAG backend: a thin composition of an [`ObjectStore`] (content-addressed
/// ciphertext), a [`ChangeGraph`] (history), a [`Keyring`] (this identity's key
/// custody), and calls into `loot_core::sealed`/`converge` for policy. DagRepo
/// itself holds no storage or merge logic — it wires the modules to the `Repo`
/// seam.
pub struct DagRepo {
    root: PathBuf,
    identity: String,
    /// This identity's private key custody. Keys live here and only here.
    keyring: Keyring,
    objects: ObjectStore,
    graph: ChangeGraph,
}

impl DagRepo {
    /// Whether this identity is entitled to hold the key for content with these
    /// grant ids — used to decide what to file into the local keyring.
    fn entitled(&self, grant_ids: &[String]) -> bool {
        grant_ids.iter().any(|g| g == ANYONE || g == &self.identity)
    }

    /// Store a SealedObject, then file `key` into the keyring iff this identity
    /// is entitled AND the key actually seals what we stored. If dedup collapsed
    /// us onto a different existing address, the minted key is for ciphertext we
    /// discarded, so it must not be filed (it would corrupt the keyring).
    fn store(&mut self, addr: Oid, obj: SealedObject, key: Option<ContentKey>) -> Oid {
        let entitled = self.entitled(&obj.grant_ids);
        let stored = self.objects.put(addr, obj);
        let stored_addr = stored.addr().clone();
        if let Some(k) = key {
            if matches!(stored, Stored::New(_)) && entitled && !self.keyring.holds(&stored_addr) {
                self.keyring.insert(stored_addr.clone(), k);
            }
        }
        stored_addr
    }

    fn object(&self, oid: &Oid) -> Result<&SealedObject, RepoError> {
        self.objects.get(oid)
    }
}

impl Repo for DagRepo {
    fn init(path: PathBuf, identity: &str) -> Result<Self, RepoError> {
        Ok(DagRepo {
            root: path,
            identity: identity.to_string(),
            keyring: Keyring::new(),
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
        // the spike, "reachable-not-have" = every change id not in `have`.
        let have_set: std::collections::BTreeSet<&Oid> = have.iter().collect();
        let send: Vec<&ChangeNode> = self
            .graph
            .in_order()
            .into_iter()
            .filter(|c| !have_set.contains(&c.id))
            .collect();

        // Ship SealedObjects (ciphertext, no keys) plus the keys for ANYONE-
        // granted (Public/Embargoed) content ONLY. Restricted keys NEVER travel
        // (ADR 0003): a peer without them becomes a relay, by construction.
        let mut needed: BTreeMap<Oid, &SealedObject> = BTreeMap::new();
        let mut public_keys: BTreeMap<Oid, ContentKey> = BTreeMap::new();
        for c in &send {
            for (oid, _vis) in c.tree.values() {
                if let Ok(obj) = self.object(oid) {
                    needed.insert(oid.clone(), obj);
                    if obj.grant_ids.iter().any(|g| g == ANYONE) {
                        if let Some(k) = self.keyring.key_for(oid) {
                            public_keys.insert(oid.clone(), k);
                        }
                    }
                }
            }
        }

        Ok(SyncBundle(wire::encode(&send, &needed, &public_keys)))
    }

    fn apply(
        &mut self,
        bundle: &SyncBundle,
        now: u64,
    ) -> Result<BTreeMap<PathBuf, MergeOutcome>, RepoError> {
        let (incoming_changes, incoming_objs, incoming_keys) = wire::decode(&bundle.0)?;

        // Our tree before applying, used to detect concurrent same-path edits.
        let local_before = self.graph.current_tree();

        // Ingest SealedObjects, filing only the public keys that rode along
        // (entitlement still enforced in `store`). No Restricted key can be
        // here to file, so a relay structurally cannot gain one.
        for (addr, obj) in incoming_objs {
            let key = incoming_keys.get(&addr).copied();
            self.store(addr, obj, key);
        }

        // Classify every incoming change against our pre-apply tree using the
        // shared ADR 0001 classifier (loot_core::converge). We are the KeyOracle:
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
}

/// The repo answers the convergence classifier's content questions (ADR 0001).
/// `open` returns plaintext iff our own identity may read it now; `None` is the
/// relay role. The classifier owns the merge rule; we own crypto + storage.
impl converge::KeyOracle for DagRepo {
    fn open(&self, oid: &Oid, now: u64) -> Option<Vec<u8>> {
        self.get(oid, &self.identity, now).ok()
    }
}

/// Minimal length-prefixed binary wire format for `SyncBundle`, hand-rolled to
/// keep spike-dag dependency-light (no serde/bincode). The format is internal:
/// bundles produced by `bundle` are only ever read by `apply`.
mod wire {
    use super::ChangeNode;
    use loot_core::sealed::{ContentKey, SealedObject};
    use loot_core::{Oid, RepoError, Visibility};
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

        // Keys for ANYONE-granted content only (ADR 0003). The caller guarantees
        // no Restricted key is present here; this section can carry only the
        // keys a relay is already entitled to as a repo reader.
        put_u32(&mut out, public_keys.len());
        for (addr, key) in public_keys {
            out.extend_from_slice(&addr.0);
            out.extend_from_slice(key);
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

        Ok((changes, objs, public_keys))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loot_bench::{
        scenario_concurrent_converge, scenario_embargo, scenario_same_file_concurrent,
        scenario_scale_and_transfer, scenario_write_and_checkout, small_file_workload,
    };
    use std::time::Instant;

    fn tmp() -> PathBuf {
        tempfile::tempdir().unwrap().keep()
    }

    #[test]
    fn write_and_checkout_passes() {
        let mut repo = DagRepo::init(tmp(), "alice").unwrap();
        let blobs = small_file_workload(50, "alice");
        let res =
            scenario_write_and_checkout(&mut repo, &blobs, "alice", "mallory", 1000).unwrap();
        assert!(res.all_passed(), "checks: {:?}", res.checks);
    }

    #[test]
    fn embargo_passes() {
        let mut repo = DagRepo::init(tmp(), "alice").unwrap();
        let res = scenario_embargo(&mut repo, 5000, "anyone").unwrap();
        assert!(res.all_passed(), "checks: {:?}", res.checks);
    }

    #[test]
    fn concurrent_converge_passes() {
        let base = tmp();
        let res =
            scenario_concurrent_converge::<DagRepo>(&base, "alice", "relaybob", 9999).unwrap();
        assert!(res.all_passed(), "checks: {:?}", res.checks);
    }

    /// Perf signal: ~2000 small files, time commit + checkout for both readers.
    #[test]
    fn perf_signal_2000_files() {
        let mut repo = DagRepo::init(tmp(), "alice").unwrap();
        let blobs = small_file_workload(2000, "alice");

        let t = Instant::now();
        let res =
            scenario_write_and_checkout(&mut repo, &blobs, "alice", "mallory", 1000).unwrap();
        let elapsed = t.elapsed();

        assert!(res.all_passed(), "checks: {:?}", res.checks);
        println!(
            "[spike-dag] write+checkout of 2000 files (encrypt + 2-reader checkout): {elapsed:?}"
        );
    }

    /// VERDICT TEST: 4 keyholders edit the SAME public file concurrently, then
    /// converge. The DAG uses 3-way merge, so conflicts are expected here.
    #[test]
    fn same_file_concurrent_conflict_rate() {
        let base = tmp();
        let res = scenario_same_file_concurrent::<DagRepo>(&base, 4, 9999).unwrap();
        println!(
            "[spike-dag] same-file concurrent (4 peers): conflicts={:?} merged={:?} converged={:?} relayed={:?} surviving={:?}/{:?}",
            res.metric_value("conflicts"),
            res.metric_value("merged"),
            res.metric_value("converged"),
            res.metric_value("relayed"),
            res.metric_value("surviving_peer_edits"),
            res.metric_value("total_peer_edits"),
        );
        assert!(res.all_passed(), "checks: {:?}", res.checks);
    }

    /// Scale + transfer: 50k files, report sync bundle size.
    #[test]
    fn scale_and_transfer_50k() {
        let base = tmp();
        let t = Instant::now();
        let res = scenario_scale_and_transfer::<DagRepo>(&base, 50_000, 1000).unwrap();
        println!(
            "[spike-dag] 50k files: bundle_bytes={:?} elapsed={:?}",
            res.metric_value("bundle_bytes"),
            t.elapsed(),
        );
        assert!(res.all_passed(), "checks: {:?}", res.checks);
    }

    /// ADR 0003 leak guard: a Restricted content key must NEVER appear in a sync
    /// bundle. We mint a restricted blob, capture the actual content key from
    /// the producer's keyring, and assert its raw bytes are absent from the
    /// bundle. Public keys may ride along; restricted ones may not.
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
        let cid = alice
            .commit(Change { id: Oid([0; 32]), parents: vec![], message: "m".into(), tree })
            .unwrap();
        let _ = cid;

        let restricted_key = alice.keyring.key_for(&secret_oid).expect("alice holds her key");
        let public_key = alice.keyring.key_for(&pub_oid).expect("alice holds public key");

        let bundle = alice.bundle(&[]).unwrap();

        // The restricted key's 32 raw bytes must not occur anywhere in the wire.
        assert!(
            !contains_window(&bundle.0, &restricted_key),
            "restricted content key leaked into the sync bundle"
        );
        // The public key is allowed to travel (relay is a repo reader).
        assert!(
            contains_window(&bundle.0, &public_key),
            "public content key should ride along for ANYONE-granted content"
        );
    }

    /// ADR 0004 leak guard: the sync wire must carry no plaintext-equality
    /// oracle. We commit the SAME restricted plaintext into two separate repos
    /// and bundle each. The bundles must not share any plaintext-derived marker:
    /// specifically, blake3(plaintext) must appear in neither bundle.
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

        // The plaintext hash must not be present in either bundle: there is no
        // plaintext-derived field on the wire, so a relay cannot recompute or
        // match it.
        assert!(!contains_window(&a, &plaintext_hash));
        assert!(!contains_window(&b, &plaintext_hash));

        // And the same plaintext yields different ciphertext in each repo
        // (random key+nonce per seal), so the ciphertext blocks don't match
        // either — a relay holding both bundles cannot link them by content.
        let ct_a = single_ciphertext(&a);
        let ct_b = single_ciphertext(&b);
        assert_ne!(ct_a, ct_b, "same plaintext must not produce equal ciphertext on the wire");
    }

    /// Decode a bundle and return its single object's ciphertext, for asserting
    /// that equal plaintext does not yield equal ciphertext.
    fn single_ciphertext(bundle: &[u8]) -> Vec<u8> {
        let (_changes, objs, _keys) = wire::decode(bundle).unwrap();
        assert_eq!(objs.len(), 1, "test fixture commits exactly one object");
        objs.into_iter().next().unwrap().1.ciphertext
    }

    fn contains_window(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
