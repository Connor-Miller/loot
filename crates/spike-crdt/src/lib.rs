//! Spike B: CRDT document store, filesystem as a projection.
//!
//! NON-CANONICAL (ADR 0002). The bake-off chose the encrypted DAG. This crate
//! is retained only as the reproducible benchmark record behind that decision
//! (`cargo test --release`). It is NOT part of the product. The deciding
//! finding: under per-content encryption, Automerge cannot character-merge
//! ciphertext, so concurrent same-file edits resolve last-writer-wins and are
//! silently dropped (0 of 4 survived) — the CRDT's one advantage is
//! structurally unavailable under loot's encryption thesis.
//!
//! The repo is a single Automerge document (the source of truth); the working
//! tree is a *projection* of that document. Two repos converge by merging
//! their Automerge docs — automerge gives us conflict-free convergence of
//! concurrent offline edits for free, which is this model's whole pitch.
//!
//! The two honest tensions this spike exists to probe (answered in the
//! crate-level report, summarized here):
//!
//! (a) DISCRETE, REVIEWABLE, EMBARGOABLE CHANGE vs. a CRDT that converges
//!     *state*. A CRDT has no native notion of a reviewable commit — it has a
//!     soup of operations. We recover a discrete Change by writing an explicit
//!     `changes/<id>` record into the document: id (blake3 of message + tree),
//!     parents, message, and the path->oid tree it touched. The CRDT still
//!     converges state underneath; the Change record is a first-class node we
//!     layer on top so review/embargo/permissions have something to attach to.
//!     This is *bolted on*, not native — see the report.
//!
//! (b) PER-UNIT ENCRYPTION vs. the merge function. A CRDT merges by SEEING
//!     content; encrypted content can't be seen by a peer without the key.
//!     We resolve this exactly as ADR 0001 dictates: content is stored in the
//!     doc as ciphertext only. A keyholder can decrypt -> merge -> Merged /
//!     Converged. A non-keyholder can only relay the ciphertext bytes ->
//!     RelayedUnmerged; it must NOT auto-merge plaintext it cannot read.

use automerge::transaction::Transactable;
use automerge::{AutoCommit, ObjType, ReadDoc, ScalarValue, Value};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use loot_core::{
    Change, MergeOutcome, Oid, Repo, RepoError, SyncBundle, Visibility,
};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

const PATHS: &str = "paths";
const CHANGES: &str = "changes";

/// In-memory keyring: OID -> the per-content symmetric key. In a real system
/// these keys would be wrapped to each authorized identity's public key; for a
/// spike we keep a flat per-identity table and decide membership by policy.
type ContentKey = [u8; 32];

/// Per-path record we materialize from the Automerge doc.
struct PathEntry {
    oid: Oid,
    vis: Visibility,
    nonce: [u8; 12],
    ct: Vec<u8>,
}

pub struct CrdtRepo {
    root: PathBuf,
    identity: String,
    /// The CRDT document: the single source of truth. The FS is a projection.
    doc: AutoCommit,
    /// What this identity can decrypt. Keyed by OID. A repo whose identity is
    /// not authorized for a unit of content simply has no entry here and thus
    /// can only relay its ciphertext (ADR 0001).
    keyring: HashMap<Oid, ContentKey>,
}

impl CrdtRepo {
    /// Deterministic content key for a unit of content. In a spike we derive it
    /// from the plaintext so identical content dedups to the same key; a real
    /// system would generate a random key and wrap it per identity. Keeping it
    /// deterministic keeps the spike honest about *merge* behavior without a
    /// key-distribution layer.
    fn derive_content_key(bytes: &[u8]) -> ContentKey {
        let mut h = blake3::Hasher::new();
        h.update(b"loot-crdt-content-key-v1");
        h.update(bytes);
        *h.finalize().as_bytes()
    }

    /// Stable OID = blake3 of the plaintext (identity hash). Equal plaintext
    /// dedups regardless of who encrypted it.
    fn oid_of(bytes: &[u8]) -> Oid {
        Oid(*blake3::hash(bytes).as_bytes())
    }

    fn nonce_for(oid: &Oid) -> [u8; 12] {
        let mut n = [0u8; 12];
        n.copy_from_slice(&oid.0[..12]);
        n
    }

    /// Does this repo's identity hold the key for `oid`?
    fn holds_key(&self, oid: &Oid) -> bool {
        self.keyring.contains_key(oid)
    }

    /// Is `identity` authorized to read content under `vis`?
    fn authorized(identity: &str, vis: &Visibility) -> bool {
        match vis {
            Visibility::Public => true,
            Visibility::Restricted(ids) => ids.iter().any(|i| i == identity),
            // Embargoed content is encrypted to all; the gate is *time*, not
            // identity, so anyone is "authorized" once revealed.
            Visibility::Embargoed { .. } => true,
        }
    }

    fn encrypt(key: &ContentKey, nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, RepoError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        cipher
            .encrypt(Nonce::from_slice(nonce), plaintext)
            .map_err(|e| RepoError::Backend(format!("encrypt: {e}")))
    }

    fn decrypt(key: &ContentKey, nonce: &[u8; 12], ct: &[u8]) -> Result<Vec<u8>, RepoError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        cipher
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|e| RepoError::Backend(format!("decrypt: {e}")))
    }

    // --- visibility (de)serialization into the CRDT doc ---

    fn encode_vis(vis: &Visibility) -> String {
        match vis {
            Visibility::Public => "public".to_string(),
            Visibility::Restricted(ids) => format!("restricted:{}", ids.join(",")),
            Visibility::Embargoed { reveal_at } => format!("embargoed:{reveal_at}"),
        }
    }

    fn decode_vis(s: &str) -> Visibility {
        if s == "public" {
            Visibility::Public
        } else if let Some(rest) = s.strip_prefix("restricted:") {
            let ids = if rest.is_empty() {
                vec![]
            } else {
                rest.split(',').map(|x| x.to_string()).collect()
            };
            Visibility::Restricted(ids)
        } else if let Some(rest) = s.strip_prefix("embargoed:") {
            Visibility::Embargoed {
                reveal_at: rest.parse().unwrap_or(0),
            }
        } else {
            Visibility::Public
        }
    }

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    fn unhex(s: &str) -> Option<[u8; 32]> {
        if s.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(out)
    }

    /// Ensure the root `paths` and `changes` maps exist.
    fn ensure_roots(doc: &mut AutoCommit) -> Result<(), RepoError> {
        let backend = |e: automerge::AutomergeError| RepoError::Backend(e.to_string());
        if doc.get(automerge::ROOT, PATHS).map_err(backend)?.is_none() {
            doc.put_object(automerge::ROOT, PATHS, ObjType::Map)
                .map_err(backend)?;
        }
        if doc.get(automerge::ROOT, CHANGES).map_err(backend)?.is_none() {
            doc.put_object(automerge::ROOT, CHANGES, ObjType::Map)
                .map_err(backend)?;
        }
        Ok(())
    }

    /// Read a path entry out of the CRDT doc.
    fn read_entry(&self, path: &str) -> Result<Option<PathEntry>, RepoError> {
        let backend = |e: automerge::AutomergeError| RepoError::Backend(e.to_string());
        let (_, paths_id) = match self.doc.get(automerge::ROOT, PATHS).map_err(backend)? {
            Some((Value::Object(_), id)) => ((), id),
            _ => return Ok(None),
        };
        let entry_id = match self.doc.get(&paths_id, path).map_err(backend)? {
            Some((Value::Object(_), id)) => id,
            _ => return Ok(None),
        };

        let get_str = |k: &str| -> Result<Option<String>, RepoError> {
            Ok(match self.doc.get(&entry_id, k).map_err(backend)? {
                Some((Value::Scalar(s), _)) => match s.as_ref() {
                    ScalarValue::Str(v) => Some(v.to_string()),
                    _ => None,
                },
                _ => None,
            })
        };
        let get_bytes = |k: &str| -> Result<Option<Vec<u8>>, RepoError> {
            Ok(match self.doc.get(&entry_id, k).map_err(backend)? {
                Some((Value::Scalar(s), _)) => match s.as_ref() {
                    ScalarValue::Bytes(v) => Some(v.clone()),
                    _ => None,
                },
                _ => None,
            })
        };

        let oid_hex = match get_str("oid")? {
            Some(s) => s,
            None => return Ok(None),
        };
        let oid = match Self::unhex(&oid_hex) {
            Some(b) => Oid(b),
            None => return Ok(None),
        };
        let vis = Self::decode_vis(&get_str("vis")?.unwrap_or_default());
        let ct = get_bytes("ct")?.unwrap_or_default();
        let nonce_v = get_bytes("nonce")?.unwrap_or_default();
        let mut nonce = [0u8; 12];
        if nonce_v.len() == 12 {
            nonce.copy_from_slice(&nonce_v);
        }
        Ok(Some(PathEntry { oid, vis, nonce, ct }))
    }

    /// Build the human-path -> (oid, vis) projection by walking every change
    /// record's tree. Later changes win for a given path (last write per path
    /// in iteration order; automerge converges the underlying records).
    fn projected_tree(&self) -> Result<BTreeMap<String, (Oid, Visibility)>, RepoError> {
        let backend = |e: automerge::AutomergeError| RepoError::Backend(e.to_string());
        let mut out = BTreeMap::new();
        let changes_id = match self.doc.get(automerge::ROOT, CHANGES).map_err(backend)? {
            Some((Value::Object(_), id)) => id,
            _ => return Ok(out),
        };
        for change_key in self.doc.keys(&changes_id) {
            let change_obj = match self.doc.get(&changes_id, &change_key).map_err(backend)? {
                Some((Value::Object(_), id)) => id,
                _ => continue,
            };
            let tree_obj = match self.doc.get(&change_obj, "tree").map_err(backend)? {
                Some((Value::Object(_), id)) => id,
                _ => continue,
            };
            for path in self.doc.keys(&tree_obj) {
                if let Some((Value::Scalar(s), _)) =
                    self.doc.get(&tree_obj, &path).map_err(backend)?
                {
                    if let ScalarValue::Str(v) = s.as_ref() {
                        let mut parts = v.splitn(2, '|');
                        let oid_hex = parts.next().unwrap_or("");
                        let vis = Self::decode_vis(parts.next().unwrap_or("public"));
                        if let Some(b) = Self::unhex(oid_hex) {
                            out.insert(path, (Oid(b), vis));
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    /// All path entries currently in the doc.
    fn all_entries(&self) -> Result<BTreeMap<String, PathEntry>, RepoError> {
        let backend = |e: automerge::AutomergeError| RepoError::Backend(e.to_string());
        let mut out = BTreeMap::new();
        let paths_id = match self.doc.get(automerge::ROOT, PATHS).map_err(backend)? {
            Some((Value::Object(_), id)) => id,
            _ => return Ok(out),
        };
        for key in self.doc.keys(&paths_id) {
            if let Some(entry) = self.read_entry(&key)? {
                out.insert(key, entry);
            }
        }
        Ok(out)
    }

    /// Decrypt one entry for `reader` at time `now`, enforcing visibility.
    fn decrypt_entry(&self, entry: &PathEntry, reader: &str, now: u64) -> Result<Vec<u8>, RepoError> {
        match &entry.vis {
            Visibility::Embargoed { reveal_at } if now < *reveal_at => {
                return Err(RepoError::Embargoed(*reveal_at));
            }
            _ => {}
        }
        if !Self::authorized(reader, &entry.vis) {
            return Err(RepoError::Unauthorized(entry.oid.clone()));
        }
        // ADR 0001: convergence/read requires the key. A reader who is policy-
        // authorized but lacks the key (relay role) cannot decrypt.
        let key = self
            .keyring
            .get(&entry.oid)
            .ok_or_else(|| RepoError::Unauthorized(entry.oid.clone()))?;
        Self::decrypt(key, &entry.nonce, &entry.ct)
    }
}

/// Wire format for a SyncBundle: the saved Automerge document plus a side
/// table of content keys for the *publicly readable* content, so a fresh peer
/// can project public files. Restricted/embargoed keys are NOT shipped here —
/// that is the whole point of the relay role (ADR 0001).
fn encode_bundle(doc_bytes: &[u8], public_keys: &[(Oid, ContentKey)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(public_keys.len() as u32).to_le_bytes());
    for (oid, key) in public_keys {
        out.extend_from_slice(&oid.0);
        out.extend_from_slice(key);
    }
    out.extend_from_slice(&(doc_bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(doc_bytes);
    out
}

/// Decoded bundle: the saved Automerge doc bytes plus the public content keys
/// the peer was willing to share.
type DecodedBundle = (Vec<u8>, Vec<(Oid, ContentKey)>);

fn decode_bundle(bytes: &[u8]) -> Result<DecodedBundle, RepoError> {
    let err = || RepoError::Backend("malformed bundle".to_string());
    if bytes.len() < 4 {
        return Err(err());
    }
    let n = u32::from_le_bytes(bytes[0..4].try_into().map_err(|_| err())?) as usize;
    let mut off = 4;
    let mut keys = Vec::with_capacity(n);
    for _ in 0..n {
        if bytes.len() < off + 64 {
            return Err(err());
        }
        let mut oid = [0u8; 32];
        oid.copy_from_slice(&bytes[off..off + 32]);
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[off + 32..off + 64]);
        keys.push((Oid(oid), key));
        off += 64;
    }
    if bytes.len() < off + 8 {
        return Err(err());
    }
    let len = u64::from_le_bytes(bytes[off..off + 8].try_into().map_err(|_| err())?) as usize;
    off += 8;
    if bytes.len() < off + len {
        return Err(err());
    }
    Ok((bytes[off..off + len].to_vec(), keys))
}

impl Repo for CrdtRepo {
    fn init(path: PathBuf, identity: &str) -> Result<Self, RepoError> {
        // Distinct, stable actor per identity so concurrent repos never collide
        // on (actor, seq). Roots are created lazily on first write, NOT here:
        // a fresh repo that immediately merges a peer's doc must ADOPT the
        // peer's root maps rather than create competing ones under its own
        // actor (which produced "duplicate seq" divergence).
        let mut actor = blake3::hash(identity.as_bytes()).as_bytes()[..16].to_vec();
        actor[0] |= 1; // avoid all-zero edge
        let doc = AutoCommit::new().with_actor(automerge::ActorId::from(actor.as_slice()));
        Ok(CrdtRepo {
            root: path,
            identity: identity.to_string(),
            doc,
            keyring: HashMap::new(),
        })
    }

    fn put(&mut self, bytes: &[u8], vis: Visibility) -> Result<Oid, RepoError> {
        let backend = |e: automerge::AutomergeError| RepoError::Backend(e.to_string());
        let oid = Self::oid_of(bytes);
        let key = Self::derive_content_key(bytes);
        let nonce = Self::nonce_for(&oid);
        let ct = Self::encrypt(&key, &nonce, bytes)?;

        // This repo's identity learns the key iff it is authorized to read.
        // (Embargoed: it holds the key but `get` time-gates it via the policy.)
        if Self::authorized(&self.identity, &vis) {
            self.keyring.insert(oid.clone(), key);
        }
        self.put_in_doc(&oid, &vis, &nonce, &ct).map_err(backend)?;
        // Flush pending ops into a committed change immediately. This keeps
        // `&self` clones (bundle/heads) from ever diverging from the original
        // under the same (actor, seq) — the "duplicate seq" trap.
        self.doc.commit();
        Ok(oid)
    }

    fn get(&self, oid: &Oid, reader: &str, now: u64) -> Result<Vec<u8>, RepoError> {
        // Find any path entry carrying this oid (content-addressed).
        for entry in self.all_entries()?.into_values() {
            if &entry.oid == oid {
                return self.decrypt_entry(&entry, reader, now);
            }
        }
        Err(RepoError::NotFound(oid.clone()))
    }

    fn record(&mut self, change: Change) -> Result<Oid, RepoError> {
        let backend = |e: automerge::AutomergeError| RepoError::Backend(e.to_string());

        // The path content was already placed in the doc by `put`/`put_in_doc`.
        // Here we record the DISCRETE, reviewable Change node (answer to qa):
        // a CRDT converges state, so we layer an explicit change record with a
        // content-derived id, parents, message, and the touched tree.
        let mut hasher = blake3::Hasher::new();
        hasher.update(change.message.as_bytes());
        for (path, (oid, vis)) in &change.tree {
            hasher.update(path.to_string_lossy().as_bytes());
            hasher.update(&oid.0);
            hasher.update(Self::encode_vis(vis).as_bytes());
        }
        for p in &change.parents {
            hasher.update(&p.0);
        }
        let change_id = Oid(*hasher.finalize().as_bytes());
        let change_hex = Self::hex(&change_id.0);

        let changes_id = match self.doc.get(automerge::ROOT, CHANGES).map_err(backend)? {
            Some((Value::Object(_), id)) => id,
            _ => {
                Self::ensure_roots(&mut self.doc)?;
                match self.doc.get(automerge::ROOT, CHANGES).map_err(backend)? {
                    Some((Value::Object(_), id)) => id,
                    _ => return Err(RepoError::Backend("changes map missing".into())),
                }
            }
        };
        let change_obj = self
            .doc
            .put_object(&changes_id, &change_hex, ObjType::Map)
            .map_err(backend)?;
        self.doc
            .put(&change_obj, "message", change.message.clone())
            .map_err(backend)?;
        let parents_str = change
            .parents
            .iter()
            .map(|p| Self::hex(&p.0))
            .collect::<Vec<_>>()
            .join(",");
        self.doc
            .put(&change_obj, "parents", parents_str)
            .map_err(backend)?;
        // Record the tree as path -> oid:vis pairs.
        let tree_obj = self
            .doc
            .put_object(&change_obj, "tree", ObjType::Map)
            .map_err(backend)?;
        for (path, (oid, vis)) in &change.tree {
            let v = format!("{}|{}", Self::hex(&oid.0), Self::encode_vis(vis));
            self.doc
                .put(&tree_obj, path.to_string_lossy().to_string(), v)
                .map_err(backend)?;
        }
        self.doc.commit(); // flush pending ops; keep &self clones safe
        Ok(change_id)
    }

    fn surface(&self, change: &Oid, reader: &str, now: u64) -> Result<(), RepoError> {
        let backend = |e: automerge::AutomergeError| RepoError::Backend(e.to_string());
        // Find the change record and project its tree to the working area,
        // skipping content the reader can't see (visibility or missing key).
        let changes_id = match self.doc.get(automerge::ROOT, CHANGES).map_err(backend)? {
            Some((Value::Object(_), id)) => id,
            _ => return Err(RepoError::NotFound(change.clone())),
        };
        let change_hex = Self::hex(&change.0);
        let change_obj = match self.doc.get(&changes_id, &change_hex).map_err(backend)? {
            Some((Value::Object(_), id)) => id,
            _ => return Err(RepoError::NotFound(change.clone())),
        };
        let tree_obj = match self.doc.get(&change_obj, "tree").map_err(backend)? {
            Some((Value::Object(_), id)) => id,
            _ => return Err(RepoError::NotFound(change.clone())),
        };

        // Entries are addressed by oid-hex; the change tree maps human path ->
        // "oid|vis". Resolve each human path to its entry via the oid.
        let entries = self.all_entries()?;
        let by_oid: BTreeMap<Oid, &PathEntry> =
            entries.values().map(|e| (e.oid.clone(), e)).collect();
        for path in self.doc.keys(&tree_obj) {
            let tree_val = match self.doc.get(&tree_obj, &path).map_err(backend)? {
                Some((Value::Scalar(s), _)) => match s.as_ref() {
                    ScalarValue::Str(v) => v.to_string(),
                    _ => continue,
                },
                _ => continue,
            };
            let oid_hex = tree_val.split('|').next().unwrap_or("");
            let oid = match Self::unhex(oid_hex) {
                Some(b) => Oid(b),
                None => continue,
            };
            let entry = match by_oid.get(&oid) {
                Some(e) => *e,
                None => continue,
            };
            // Project only content this reader can actually materialize.
            let plaintext = match self.decrypt_entry(entry, reader, now) {
                Ok(pt) => pt,
                // Not visible / embargoed / no key -> skip (projection is
                // partial by design; that is the thesis).
                Err(_) => continue,
            };
            let dest = self.root.join(&path);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| RepoError::Backend(format!("mkdir: {e}")))?;
            }
            std::fs::write(&dest, &plaintext)
                .map_err(|e| RepoError::Backend(format!("write {dest:?}: {e}")))?;
        }
        Ok(())
    }

    fn bundle(&self, _have: &[Oid]) -> Result<SyncBundle, RepoError> {
        // Automerge's save is already a compact, mergeable delta of the whole
        // document. A peer applies it via `merge` regardless of `have`, so we
        // ship the saved doc. (A production system would use automerge's sync
        // protocol with `have` heads; for the spike, whole-doc save converges
        // identically and keeps the bundle self-contained.)
        let mut doc = self.doc.clone();
        let doc_bytes = doc.save();

        // Ship keys ONLY for public content. Restricted/embargoed keys stay
        // home: a peer without them becomes a relay (ADR 0001).
        let mut public_keys = Vec::new();
        for entry in self.all_entries()?.into_values() {
            if matches!(entry.vis, Visibility::Public) {
                if let Some(k) = self.keyring.get(&entry.oid) {
                    public_keys.push((entry.oid.clone(), *k));
                }
            }
        }
        Ok(SyncBundle(encode_bundle(&doc_bytes, &public_keys)))
    }

    fn apply(
        &mut self,
        bundle: &SyncBundle,
        _now: u64,
    ) -> Result<BTreeMap<PathBuf, MergeOutcome>, RepoError> {
        let backend = |e: automerge::AutomergeError| RepoError::Backend(e.to_string());
        let (doc_bytes, public_keys) = decode_bundle(&bundle.0)?;

        // Snapshot our pre-merge projection (human path -> oid) so we can
        // classify each path's outcome after the CRDT merge.
        let before = self.projected_tree()?;

        // Learn any public content keys the peer shared.
        for (oid, key) in &public_keys {
            self.keyring.entry(oid.clone()).or_insert(*key);
        }

        // CRDT-native convergence: merge the peer's document into ours.
        let mut incoming = AutoCommit::load(&doc_bytes).map_err(backend)?;
        self.doc.merge(&mut incoming).map_err(backend)?;

        // Classify every human path the peer touched (per ADR 0001).
        let after = self.projected_tree()?;
        let mut outcomes = BTreeMap::new();
        for (path, (oid, vis)) in &after {
            let touched_by_peer = match before.get(path) {
                None => true,                       // new path from peer
                Some((prev_oid, _)) => prev_oid != oid,
            };
            if !touched_by_peer {
                continue;
            }
            let both_sides = before.contains_key(path);
            let can_read = self.holds_key(oid) || matches!(vis, Visibility::Public);
            let outcome = if !can_read {
                // Encrypted content we lack the key for: ADR 0001 -> we may
                // only relay the ciphertext (which `merge` already carried in
                // the doc), never auto-merge plaintext we can't read. This
                // holds whether or not it overlaps a path we already had.
                MergeOutcome::RelayedUnmerged
            } else if !both_sides {
                // Disjoint, readable: peer introduced a path we didn't have.
                MergeOutcome::Converged
            } else {
                // Same path, we hold the key (or it's public): the CRDT merged
                // it conflict-free. This is where the model shines.
                MergeOutcome::Merged
            };
            outcomes.insert(PathBuf::from(path), outcome);
        }
        Ok(outcomes)
    }

    fn heads(&self) -> Vec<Oid> {
        // Map automerge change hashes (20 bytes) into our 32-byte Oid space.
        let mut doc = self.doc.clone();
        doc.get_heads()
            .into_iter()
            .map(|h| {
                let mut b = [0u8; 32];
                let src = h.0;
                let n = src.len().min(32);
                b[..n].copy_from_slice(&src[..n]);
                Oid(b)
            })
            .collect()
    }
}

impl CrdtRepo {
    /// Write/overwrite a path entry in the CRDT doc. Path defaults to the
    /// stringified oid so content-addressed `put` (without an explicit path)
    /// is still findable by `get`; `commit` records the human path mapping.
    fn put_in_doc(
        &mut self,
        oid: &Oid,
        vis: &Visibility,
        nonce: &[u8; 12],
        ct: &[u8],
    ) -> Result<(), automerge::AutomergeError> {
        let paths_id = match self.doc.get(automerge::ROOT, PATHS)? {
            Some((Value::Object(_), id)) => id,
            _ => self.doc.put_object(automerge::ROOT, PATHS, ObjType::Map)?,
        };
        // Address entries by oid hex; commit() ties human paths to these via
        // the change tree, and checkout reads them back out.
        let key = Self::hex(&oid.0);
        let entry = self.doc.put_object(&paths_id, &key, ObjType::Map)?;
        self.doc.put(&entry, "oid", Self::hex(&oid.0))?;
        self.doc.put(&entry, "vis", Self::encode_vis(vis))?;
        self.doc
            .put(&entry, "nonce", ScalarValue::Bytes(nonce.to_vec()))?;
        self.doc.put(&entry, "ct", ScalarValue::Bytes(ct.to_vec()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::CrdtRepo;
    use loot_bench::{
        scenario_concurrent_converge, scenario_embargo, scenario_same_file_concurrent,
        scenario_scale_and_transfer, scenario_write_and_checkout, small_file_workload,
    };
    use loot_core::Repo;
    use std::time::Instant;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("loot-crdt-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn write_and_checkout_enforces_visibility() {
        let dir = tmpdir("wac");
        let mut repo = CrdtRepo::init(dir, "keyholder").unwrap();
        let blobs = small_file_workload(50, "keyholder");
        let res =
            scenario_write_and_checkout(&mut repo, &blobs, "keyholder", "outsider", 1000).unwrap();
        for (name, ok) in &res.checks {
            println!("  [{}] {name}", if *ok { "PASS" } else { "FAIL" });
        }
        assert!(res.all_passed(), "write_and_checkout checks must pass");
    }

    #[test]
    fn embargo_seals_then_reveals() {
        let dir = tmpdir("embargo");
        let mut repo = CrdtRepo::init(dir, "anyone").unwrap();
        let res = scenario_embargo(&mut repo, 5_000, "anyone").unwrap();
        for (name, ok) in &res.checks {
            println!("  [{}] {name}", if *ok { "PASS" } else { "FAIL" });
        }
        assert!(res.all_passed(), "embargo checks must pass");
    }

    #[test]
    fn concurrent_offline_edits_converge() {
        let base = tmpdir("converge");
        let res =
            scenario_concurrent_converge::<CrdtRepo>(&base, "keyholder", "relay", 1000).unwrap();
        for (name, ok) in &res.checks {
            println!("  [{}] {name}", if *ok { "PASS" } else { "FAIL" });
        }
        assert!(res.all_passed(), "convergence checks must pass");
    }

    #[test]
    fn small_file_workload_timing_2000() {
        let dir = tmpdir("perf");
        let mut repo = CrdtRepo::init(dir, "keyholder").unwrap();
        let blobs = small_file_workload(2000, "keyholder");

        let t0 = Instant::now();
        let res =
            scenario_write_and_checkout(&mut repo, &blobs, "keyholder", "outsider", 1000).unwrap();
        let elapsed = t0.elapsed();

        println!(
            "  2000-file write+checkout (commit + 2x checkout): {:?} ({:.1} files/s)",
            elapsed,
            2000.0 / elapsed.as_secs_f64()
        );
        assert!(res.all_passed(), "2000-file workload checks must pass");
    }

    /// VERDICT TEST (ADR 0002): 4 keyholders edit the SAME public file
    /// concurrently, then converge — the CRDT's supposed best case. The finding
    /// is that under encryption Automerge CANNOT character-merge ciphertext, so
    /// it resolves last-writer-wins and silently drops edits. This test ASSERTS
    /// that documented failure mode, so the evidence is pinned and the suite
    /// stays green. If a future change ever makes the CRDT preserve edits here,
    /// this test will fail loudly and the bake-off must be revisited.
    #[test]
    fn same_file_concurrent_is_silent_data_loss() {
        let base = tmpdir("samefile");
        let res = scenario_same_file_concurrent::<CrdtRepo>(&base, 4, 9999).unwrap();
        let conflicts = res.metric_value("conflicts").unwrap();
        let surviving = res.metric_value("surviving_peer_edits").unwrap();
        let total = res.metric_value("total_peer_edits").unwrap();
        println!(
            "  [spike-crdt] same-file concurrent (4 peers): conflicts={} surviving={}/{} -> silent data loss",
            conflicts, surviving, total
        );
        // The documented bad outcome: zero conflicts AND lost edits.
        assert_eq!(conflicts, 0, "CRDT reports no conflicts (opaque-register LWW)");
        assert!(
            surviving < total,
            "CRDT silently dropped edits: expected <{total} survivors, got {surviving}"
        );
    }

    /// Scale + transfer: 50k files, report sync bundle size.
    #[test]
    fn scale_and_transfer_50k() {
        let base = tmpdir("scale");
        let t = Instant::now();
        let res = scenario_scale_and_transfer::<CrdtRepo>(&base, 50_000, 1000).unwrap();
        println!(
            "  [spike-crdt] 50k files: bundle_bytes={:?} elapsed={:?}",
            res.metric_value("bundle_bytes"),
            t.elapsed(),
        );
        assert!(res.all_passed(), "scale checks must pass");
    }
}
