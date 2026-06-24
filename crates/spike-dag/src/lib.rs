//! Spike A: encrypted content-addressed DAG.
//!
//! Thesis being proven out:
//!   - each object is encrypted independently; visibility == key possession
//!   - addressing is by CIPHERTEXT hash (the content address), with a separate
//!     plaintext identity hash used only for dedup (the known sharp edge)
//!   - storage is log-structured / packed (one append-only `Vec` + in-memory
//!     indexes), NOT git-style loose files, so we don't reproduce the APFS
//!     small-file perf disaster
//!   - runs fully in-memory; `checkout` is the only thing that touches disk
//!
//! Crypto is honest but simple: a fresh AES-256-GCM content key per object
//! (RustCrypto `aes-gcm`, a vetted impl — no novel crypto). "Holding a key"
//! is modelled by an in-object grant map: an authorized identity has the
//! content key, an outsider does not and literally cannot decrypt. Embargo =
//! the grant exists for everyone but is withheld until `now >= reveal_at`.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use loot_core::{Change, MergeOutcome, Oid, Repo, RepoError, SyncBundle, Visibility};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Wildcard grant key id — content readable by anyone who can read the repo.
const ANYONE: &str = "*";

type ContentKey = [u8; 32];

/// One encrypted object in the packed log. Addressed by the blake3 hash of its
/// ciphertext (`Oid`). The plaintext `identity_hash` is kept ONLY for dedup —
/// deliberately a different value from the address (the sharp edge: two repos
/// that encrypt the same plaintext under different keys produce different
/// addresses but the same identity hash, so dedup must key on identity hash).
#[derive(Clone)]
struct StoredObject {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    vis: Visibility,
    /// identity -> content key. `ANYONE` for Public/Embargoed; the listed
    /// identities for Restricted. A repo that lacks an entry for its own
    /// identity (and for `ANYONE`) cannot decrypt — it can only relay bytes.
    grants: BTreeMap<String, ContentKey>,
    /// blake3(plaintext) — dedup identity, NOT the address.
    identity_hash: [u8; 32],
}

/// A change node in the DAG.
#[derive(Clone)]
struct ChangeNode {
    id: Oid,
    parents: Vec<Oid>,
    message: String,
    tree: BTreeMap<PathBuf, (Oid, Visibility)>,
}

pub struct DagRepo {
    root: PathBuf,
    identity: String,
    /// Append-only packed object log. Indexes point into this.
    log: Vec<StoredObject>,
    /// content address -> position in `log`.
    by_addr: BTreeMap<Oid, usize>,
    /// plaintext identity hash -> content address (dedup).
    by_identity: BTreeMap<[u8; 32], Oid>,
    /// change id -> change node.
    changes: BTreeMap<Oid, ChangeNode>,
    /// current DAG heads (change ids that are nobody's parent).
    heads: Vec<Oid>,
}

impl DagRepo {
    fn random_bytes<const N: usize>() -> Result<[u8; N], RepoError> {
        let mut buf = [0u8; N];
        getrandom::getrandom(&mut buf).map_err(|e| RepoError::Backend(e.to_string()))?;
        Ok(buf)
    }

    /// Authorized grant key ids for a visibility policy.
    fn grant_ids(vis: &Visibility) -> Vec<String> {
        match vis {
            Visibility::Public | Visibility::Embargoed { .. } => vec![ANYONE.to_string()],
            Visibility::Restricted(ids) => ids.clone(),
        }
    }

    /// Encrypt `bytes` under a fresh content key and build a `StoredObject`
    /// plus its content address. Pure — no store mutation — so it's reused for
    /// both `put` and (re-)sealing is unnecessary on bundle ingest.
    fn seal(bytes: &[u8], vis: &Visibility) -> Result<(Oid, StoredObject), RepoError> {
        let key_bytes: ContentKey = Self::random_bytes()?;
        let nonce_bytes: [u8; 12] = Self::random_bytes()?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), bytes)
            .map_err(|e| RepoError::Backend(format!("encrypt: {e}")))?;

        // Address = hash of ciphertext (+ nonce). Identity hash = hash of
        // plaintext, used for dedup only.
        let mut addr_hasher = blake3::Hasher::new();
        addr_hasher.update(&nonce_bytes);
        addr_hasher.update(&ciphertext);
        let addr = Oid(*addr_hasher.finalize().as_bytes());
        let identity_hash = *blake3::hash(bytes).as_bytes();

        let grants = Self::grant_ids(vis)
            .into_iter()
            .map(|id| (id, key_bytes))
            .collect();

        Ok((
            addr,
            StoredObject {
                nonce: nonce_bytes,
                ciphertext,
                vis: vis.clone(),
                grants,
                identity_hash,
            },
        ))
    }

    /// Insert an object into the packed log + indexes, deduping on identity
    /// hash. Returns the address actually stored (an existing one on a hit).
    fn store(&mut self, addr: Oid, obj: StoredObject) -> Oid {
        if self.by_addr.contains_key(&addr) {
            return addr;
        }
        // Dedup: same plaintext already present under another address. Merge
        // any new grants in so newly-authorized identities gain the key.
        if let Some(existing) = self.by_identity.get(&obj.identity_hash).cloned() {
            let pos = self.by_addr[&existing];
            for (id, k) in &obj.grants {
                self.log[pos].grants.entry(id.clone()).or_insert(*k);
            }
            return existing;
        }
        let pos = self.log.len();
        self.by_identity.insert(obj.identity_hash, addr.clone());
        self.log.push(obj);
        self.by_addr.insert(addr.clone(), pos);
        addr
    }

    fn object(&self, oid: &Oid) -> Result<&StoredObject, RepoError> {
        self.by_addr
            .get(oid)
            .map(|&pos| &self.log[pos])
            .ok_or_else(|| RepoError::NotFound(oid.clone()))
    }

    /// The content key `reader` can obtain for `obj` at time `now`, enforcing
    /// the visibility policy. Single chokepoint for authorization. Returns
    /// `Embargoed` if sealed, `Unauthorized` if no grant, else the key.
    fn resolve_key(
        obj: &StoredObject,
        oid: &Oid,
        reader: &str,
        now: u64,
    ) -> Result<ContentKey, RepoError> {
        // Embargo: the key is withheld until reveal time, for everyone.
        if let Visibility::Embargoed { reveal_at } = obj.vis {
            if now < reveal_at {
                return Err(RepoError::Embargoed(reveal_at));
            }
        }
        // A grant for ANYONE means anyone who can read the repo holds the key.
        if let Some(k) = obj.grants.get(ANYONE) {
            return Ok(*k);
        }
        // Otherwise the reader must be an explicitly authorized keyholder.
        obj.grants
            .get(reader)
            .copied()
            .ok_or_else(|| RepoError::Unauthorized(oid.clone()))
    }

    fn decrypt(obj: &StoredObject, key: &ContentKey) -> Result<Vec<u8>, RepoError> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        cipher
            .decrypt(Nonce::from_slice(&obj.nonce), obj.ciphertext.as_ref())
            .map_err(|e| RepoError::Backend(format!("decrypt: {e}")))
    }

    /// Whether this repo's own identity can obtain the key for `oid` right now.
    /// Used to decide merger vs relay role during `apply` (ADR 0001).
    fn can_decrypt(&self, oid: &Oid, now: u64) -> bool {
        match self.object(oid) {
            Ok(obj) => Self::resolve_key(obj, oid, &self.identity, now).is_ok(),
            Err(_) => false,
        }
    }

    fn compute_change_id(change: &Change) -> Oid {
        let mut h = blake3::Hasher::new();
        h.update(change.message.as_bytes());
        for p in &change.parents {
            h.update(&p.0);
        }
        for (path, (oid, _vis)) in &change.tree {
            h.update(path.to_string_lossy().as_bytes());
            h.update(&[0]);
            h.update(&oid.0);
        }
        Oid(*h.finalize().as_bytes())
    }

    fn insert_change(&mut self, node: ChangeNode) {
        let id = node.id.clone();
        if self.changes.contains_key(&id) {
            return;
        }
        // Maintain heads: drop any parent that was a head, add this node.
        self.heads.retain(|h| !node.parents.contains(h));
        self.changes.insert(id.clone(), node);
        if !self.heads.contains(&id) {
            self.heads.push(id);
        }
    }

    /// Latest-known content address per path (later writes win), using a topo
    /// order so parents are applied before children.
    fn current_tree(&self) -> BTreeMap<PathBuf, (Oid, Visibility)> {
        let mut tree: BTreeMap<PathBuf, (Oid, Visibility)> = BTreeMap::new();
        for node in self.changes_in_order() {
            for (path, entry) in &node.tree {
                tree.insert(path.clone(), entry.clone());
            }
        }
        tree
    }

    /// Changes ordered so parents precede children (topo sort via DFS).
    fn changes_in_order(&self) -> Vec<&ChangeNode> {
        fn visit<'a>(
            id: &Oid,
            changes: &'a BTreeMap<Oid, ChangeNode>,
            visited: &mut BTreeMap<Oid, bool>,
            out: &mut Vec<&'a ChangeNode>,
        ) {
            if visited.get(id).copied().unwrap_or(false) {
                return;
            }
            visited.insert(id.clone(), true);
            if let Some(node) = changes.get(id) {
                for p in &node.parents {
                    visit(p, changes, visited, out);
                }
                out.push(node);
            }
        }
        let mut ordered = Vec::with_capacity(self.changes.len());
        let mut visited: BTreeMap<Oid, bool> = BTreeMap::new();
        for id in self.changes.keys() {
            visit(id, &self.changes, &mut visited, &mut ordered);
        }
        ordered
    }
}

impl Repo for DagRepo {
    fn init(path: PathBuf, identity: &str) -> Result<Self, RepoError> {
        Ok(DagRepo {
            root: path,
            identity: identity.to_string(),
            log: Vec::new(),
            by_addr: BTreeMap::new(),
            by_identity: BTreeMap::new(),
            changes: BTreeMap::new(),
            heads: Vec::new(),
        })
    }

    fn put(&mut self, bytes: &[u8], vis: Visibility) -> Result<Oid, RepoError> {
        let (addr, obj) = Self::seal(bytes, &vis)?;
        Ok(self.store(addr, obj))
    }

    fn get(&self, oid: &Oid, reader: &str, now: u64) -> Result<Vec<u8>, RepoError> {
        let obj = self.object(oid)?;
        let key = Self::resolve_key(obj, oid, reader, now)?;
        Self::decrypt(obj, &key)
    }

    fn commit(&mut self, change: Change) -> Result<Oid, RepoError> {
        let id = Self::compute_change_id(&change);
        let node = ChangeNode {
            id: id.clone(),
            parents: change.parents,
            message: change.message,
            tree: change.tree,
        };
        self.insert_change(node);
        Ok(id)
    }

    fn checkout(&self, change: &Oid, reader: &str, now: u64) -> Result<(), RepoError> {
        let node = self
            .changes
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
        // Content stays encrypted; we ship ciphertext + grants so a keyholder
        // peer can decrypt and a relay can only forward.
        let have_set: std::collections::BTreeSet<&Oid> = have.iter().collect();
        let send: Vec<&ChangeNode> = self
            .changes_in_order()
            .into_iter()
            .filter(|c| !have_set.contains(&c.id))
            .collect();

        let mut needed: BTreeMap<Oid, &StoredObject> = BTreeMap::new();
        for c in &send {
            for (oid, _vis) in c.tree.values() {
                if let Ok(obj) = self.object(oid) {
                    needed.insert(oid.clone(), obj);
                }
            }
        }

        Ok(SyncBundle(wire::encode(&send, &needed)))
    }

    fn apply(
        &mut self,
        bundle: &SyncBundle,
        now: u64,
    ) -> Result<BTreeMap<PathBuf, MergeOutcome>, RepoError> {
        let (incoming_changes, incoming_objs) = wire::decode(&bundle.0)?;

        // Our tree before applying, used to detect concurrent same-path edits.
        let local_before = self.current_tree();

        // Ingest objects first (dedup handles overlap).
        for (addr, obj) in incoming_objs {
            self.store(addr, obj);
        }

        let mut outcomes: BTreeMap<PathBuf, MergeOutcome> = BTreeMap::new();
        for node in &incoming_changes {
            for (path, (their_oid, _vis)) in &node.tree {
                let outcome = match local_before.get(path) {
                    // Path we never had -> disjoint, converges.
                    None => MergeOutcome::Converged,
                    // Same content address -> identical, converges.
                    Some((our_oid, _)) if our_oid == their_oid => MergeOutcome::Converged,
                    // Concurrent same-path edit: role depends on key (ADR 0001).
                    Some((our_oid, _)) => {
                        let we_have_key =
                            self.can_decrypt(our_oid, now) && self.can_decrypt(their_oid, now);
                        if we_have_key {
                            three_way(self, our_oid, their_oid, now)
                        } else {
                            // Non-keyholder: relay ciphertext, defer the merge.
                            MergeOutcome::RelayedUnmerged
                        }
                    }
                };
                let entry = outcomes
                    .entry(path.clone())
                    .or_insert(MergeOutcome::Converged);
                *entry = worst(entry.clone(), outcome);
            }
        }

        for node in incoming_changes {
            self.insert_change(node);
        }

        Ok(outcomes)
    }

    fn heads(&self) -> Vec<Oid> {
        self.heads.clone()
    }
}

/// Order merge outcomes by "how much human attention is needed" so a repeated
/// path keeps its worst result.
fn worst(a: MergeOutcome, b: MergeOutcome) -> MergeOutcome {
    fn rank(o: &MergeOutcome) -> u8 {
        match o {
            MergeOutcome::Converged => 0,
            MergeOutcome::Merged => 1,
            MergeOutcome::RelayedUnmerged => 2,
            MergeOutcome::Conflict => 3,
        }
    }
    if rank(&a) >= rank(&b) {
        a
    } else {
        b
    }
}

/// Spike 3-way merge of two blobs a keyholder can decrypt. Without a stored
/// common base we approximate: identical plaintext converges; if one side's
/// line set subsumes the other it merges cleanly; otherwise it's a genuine
/// conflict. Crude on purpose — the point the DAG model makes here is that
/// merging *requires plaintext access*, which is the thesis tension.
fn three_way(repo: &DagRepo, ours: &Oid, theirs: &Oid, now: u64) -> MergeOutcome {
    let id = repo.identity.clone();
    let (a, b) = match (repo.get(ours, &id, now), repo.get(theirs, &id, now)) {
        (Ok(a), Ok(b)) => (a, b),
        // Thought we had keys but couldn't read -> relay instead.
        _ => return MergeOutcome::RelayedUnmerged,
    };
    if a == b {
        return MergeOutcome::Merged;
    }
    let al: std::collections::BTreeSet<&[u8]> = a.split(|&c| c == b'\n').collect();
    let bl: std::collections::BTreeSet<&[u8]> = b.split(|&c| c == b'\n').collect();
    if al.is_subset(&bl) || bl.is_subset(&al) {
        MergeOutcome::Merged
    } else {
        MergeOutcome::Conflict
    }
}

/// Minimal length-prefixed binary wire format for `SyncBundle`, hand-rolled to
/// keep spike-dag dependency-light (no serde/bincode). The format is internal:
/// bundles produced by `bundle` are only ever read by `apply`.
mod wire {
    use super::{ChangeNode, StoredObject};
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

    pub fn encode(changes: &[&ChangeNode], objs: &BTreeMap<Oid, &StoredObject>) -> Vec<u8> {
        let mut out = Vec::new();

        put_u32(&mut out, objs.len());
        for (addr, obj) in objs {
            out.extend_from_slice(&addr.0);
            out.extend_from_slice(&obj.nonce);
            put_bytes(&mut out, &obj.ciphertext);
            put_vis(&mut out, &obj.vis);
            out.extend_from_slice(&obj.identity_hash);
            put_u32(&mut out, obj.grants.len());
            for (id, key) in &obj.grants {
                put_bytes(&mut out, id.as_bytes());
                out.extend_from_slice(key);
            }
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
    pub fn decode(b: &[u8]) -> Result<(Vec<ChangeNode>, Vec<(Oid, StoredObject)>), RepoError> {
        let mut c = Cursor { b, i: 0 };

        let n_objs = c.u32()?;
        let mut objs = Vec::with_capacity(n_objs);
        for _ in 0..n_objs {
            let addr = Oid(c.arr32()?);
            let nonce = c.arr12()?;
            let ciphertext = c.bytes()?;
            let vis = c.vis()?;
            let identity_hash = c.arr32()?;
            let n_grants = c.u32()?;
            let mut grants = BTreeMap::new();
            for _ in 0..n_grants {
                let id = c.string()?;
                let key = c.arr32()?;
                grants.insert(id, key);
            }
            objs.push((
                addr,
                StoredObject {
                    nonce,
                    ciphertext,
                    vis,
                    grants,
                    identity_hash,
                },
            ));
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

        Ok((changes, objs))
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
}
