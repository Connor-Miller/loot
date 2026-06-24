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
//! Encryption, visibility, and embargo are NOT implemented here — they live in
//! the deep `loot_core::sealed` module (ADR 0003). This backend stores
//! [`SealedObject`]s (ciphertext, no keys) in its packed log and holds content
//! keys in a separate [`Keyring`]. It calls `sealed::seal`/`sealed::open` and
//! never touches crypto directly. Because keys live only in the keyring, a sync
//! bundle cannot leak them: it ships SealedObjects, plus keys for `ANYONE`-
//! granted (Public/Embargoed) content only — Restricted keys never travel.

use loot_core::sealed::{self, ContentKey, Keyring, SealedObject, ANYONE};
use loot_core::{Change, MergeOutcome, Oid, Repo, RepoError, SyncBundle, Visibility};
use std::collections::BTreeMap;
use std::path::PathBuf;

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
    /// This identity's private key custody. Keys live here and only here.
    keyring: Keyring,
    /// Append-only packed object log of SealedObjects. Indexes point into this.
    log: Vec<SealedObject>,
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
    /// Whether this identity is entitled to hold the key for content with these
    /// grant ids — used to decide what to file into the local keyring.
    fn entitled(&self, grant_ids: &[String]) -> bool {
        grant_ids.iter().any(|g| g == ANYONE || g == &self.identity)
    }

    /// Store a SealedObject in the packed log + indexes, deduping on identity
    /// hash. If `key` is supplied AND this identity is entitled, file it into
    /// the keyring. Returns the address actually stored (existing one on a hit).
    fn store(&mut self, addr: Oid, obj: SealedObject, key: Option<ContentKey>) -> Oid {
        let stored_addr = if self.by_addr.contains_key(&addr) {
            addr.clone()
        } else if let Some(existing) = self.by_identity.get(&obj.identity_hash).cloned() {
            // Same plaintext already present under another address (dedup).
            existing
        } else {
            let pos = self.log.len();
            self.by_identity.insert(obj.identity_hash, addr.clone());
            self.log.push(obj.clone());
            self.by_addr.insert(addr.clone(), pos);
            addr.clone()
        };
        // A content key belongs to a specific ciphertext (address). Only file it
        // when the address we stored IS the one this key seals; if dedup
        // collapsed us onto a different existing address, the minted key is for
        // ciphertext we discarded and would corrupt the keyring. Don't overwrite
        // a key already filed for this address either.
        if let Some(k) = key {
            if stored_addr == addr && self.entitled(&obj.grant_ids) && !self.keyring.holds(&addr) {
                self.keyring.insert(stored_addr.clone(), k);
            }
        }
        stored_addr
    }

    fn object(&self, oid: &Oid) -> Result<&SealedObject, RepoError> {
        self.by_addr
            .get(oid)
            .map(|&pos| &self.log[pos])
            .ok_or_else(|| RepoError::NotFound(oid.clone()))
    }

    /// Whether this repo's own identity can open `oid` right now (authorized,
    /// holds the key, and not embargoed). Decides merger vs relay (ADR 0001).
    fn can_decrypt(&self, oid: &Oid, now: u64) -> bool {
        match self.object(oid) {
            Ok(obj) => sealed::open(obj, oid, &self.identity, &self.keyring, now).is_ok(),
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
            keyring: Keyring::new(),
            log: Vec::new(),
            by_addr: BTreeMap::new(),
            by_identity: BTreeMap::new(),
            changes: BTreeMap::new(),
            heads: Vec::new(),
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
        let have_set: std::collections::BTreeSet<&Oid> = have.iter().collect();
        let send: Vec<&ChangeNode> = self
            .changes_in_order()
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
        let local_before = self.current_tree();

        // Ingest SealedObjects, filing only the public keys that rode along
        // (entitlement still enforced in `store`). No Restricted key can be
        // here to file, so a relay structurally cannot gain one.
        for (addr, obj) in incoming_objs {
            let key = incoming_keys.get(&addr).copied();
            self.store(addr, obj, key);
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

        // SealedObjects: ciphertext + policy + grant_ids (NAMES), never keys.
        put_u32(&mut out, objs.len());
        for (addr, obj) in objs {
            out.extend_from_slice(&addr.0);
            out.extend_from_slice(&obj.nonce);
            put_bytes(&mut out, &obj.ciphertext);
            put_vis(&mut out, &obj.vis);
            out.extend_from_slice(&obj.identity_hash);
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
            let identity_hash = c.arr32()?;
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
                    identity_hash,
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

    fn contains_window(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
