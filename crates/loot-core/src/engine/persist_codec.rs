//! Persistence encoding and decoding (local file format).
//! Serializes repo state to and from the on-disk `.loot/` files — distinct from
//! the network bundle format.
//!
//! Objects use **loose, content-addressed storage** (ADR 0012): each SealedObject
//! is its own file at `objects/<hex-address>`, written once and immutably. A
//! mutation rewrites only the new object files (O(delta), not O(store)), and
//! idempotency is "does the file already exist" — the filename *is* the content
//! address, so a re-store writes byte-identical content. The small metadata (the
//! change graph, keyring, escrow, manifest, purges, conflicts) stays as whole
//! files, since it is tiny next to object content.

use crate::bundle_codec::{put_bytes, put_u32, put_vis};
use crate::format::Cursor;
use crate::escrow::Escrow;
use crate::format;
use crate::sealed::{Keyring, SealedObject};
use crate::{Oid, RepoError};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::change_graph::{ChangeGraph, ChangeNode};
use super::object_store::ObjectStore;

const OBJECTS_DIR: &str = "objects";

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
    // v3: author pubkey + signature ride beside the change body (ADR 0018).
    format::put_author_sig(out, &c.author, &c.signature);
}

fn encode_object(obj: &SealedObject) -> Vec<u8> {
    // The version marker rides in the FILE bytes only; the content address is
    // blake3(nonce || ciphertext) (SealedObject::address), independent of this
    // encoding, so the object's loose-storage filename is unaffected (ADR 0019).
    let mut out = Vec::new();
    format::put_version(&mut out);
    out.extend_from_slice(&obj.nonce);
    out.push(obj.compressed as u8); // v2: compression flag (ADR 0020)
    put_bytes(&mut out, &obj.ciphertext);
    put_vis(&mut out, &obj.vis);
    put_u32(&mut out, obj.grant_ids.len());
    for id in &obj.grant_ids {
        put_bytes(&mut out, id.as_bytes());
    }
    out
}

fn decode_object(b: &[u8]) -> Result<SealedObject, RepoError> {
    let mut c = Cursor { b, i: 0 };
    let (major, _minor) = format::read_version(&mut c)?;
    let nonce = c.arr12()?;
    // The compression flag exists from v2 on; a v1 object predates it and is
    // uncompressed (newer reads older, ADR 0019/0020).
    let compressed = if major >= 2 { c.take(1)?[0] != 0 } else { false };
    let ciphertext = c.bytes()?;
    let vis = c.vis()?;
    let n_grants = c.u32()?;
    let mut grant_ids = Vec::with_capacity(n_grants);
    for _ in 0..n_grants {
        grant_ids.push(c.string()?);
    }
    Ok(SealedObject {
        nonce,
        ciphertext,
        vis,
        grant_ids,
        compressed,
    })
}

/// Write every object as a loose, content-addressed file under `dir/objects/`.
/// Idempotent and incremental: an object whose file already exists is skipped
/// (its bytes are immutable, keyed by content address), so a save writes only
/// the new objects (ADR 0012). Writes are atomic (temp file + rename).
pub fn save_objects_loose(dir: &Path, objects: &ObjectStore) -> Result<(), RepoError> {
    let io = |e: std::io::Error| RepoError::Backend(e.to_string());
    let obj_dir = dir.join(OBJECTS_DIR);
    std::fs::create_dir_all(&obj_dir).map_err(io)?;
    for (addr, obj) in objects.iter() {
        let dest = obj_dir.join(crate::hex::encode(&addr.0));
        if dest.exists() {
            continue;
        }
        let tmp = obj_dir.join(format!("{}.tmp", crate::hex::encode(&addr.0)));
        std::fs::write(&tmp, encode_object(obj)).map_err(io)?;
        std::fs::rename(&tmp, &dest).map_err(io)?;
    }
    Ok(())
}

/// Load every loose object file under `dir/objects/` back into an ObjectStore.
/// Missing directory yields an empty store (a fresh repo persists nothing until
/// its first object). A file whose name is not a 64-char hex address is skipped.
pub fn load_objects_loose(dir: &Path) -> Result<ObjectStore, RepoError> {
    let mut objects = ObjectStore::new();
    let obj_dir = dir.join(OBJECTS_DIR);
    let entries = match std::fs::read_dir(&obj_dir) {
        Ok(e) => e,
        Err(_) => return Ok(objects),
    };
    for entry in entries {
        let entry = entry.map_err(|e| RepoError::Backend(e.to_string()))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(addr) = crate::hex::decode_array::<32>(&name) else {
            continue; // skip *.tmp and anything not a content address
        };
        let bytes = std::fs::read(entry.path()).map_err(|e| RepoError::Backend(e.to_string()))?;
        objects.put(Oid(addr), decode_object(&bytes)?);
    }
    Ok(objects)
}

pub fn encode_graph(graph: &ChangeGraph) -> Vec<u8> {
    let mut out = Vec::new();
    format::put_version(&mut out);
    // Changes in topo order so decode can replay them parents-first.
    let changes = graph.in_order();
    put_u32(&mut out, changes.len());
    for c in changes {
        put_change(&mut out, c);
    }
    out
}

pub fn decode_graph(b: &[u8]) -> Result<ChangeGraph, RepoError> {
    let mut c = Cursor { b, i: 0 };
    let (major, _minor) = format::read_version(&mut c)?;
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
        let (author, signature) = format::read_author_sig(&mut c, major)?;
        graph.insert(ChangeNode {
            id,
            parents,
            message,
            tree,
            author,
            signature,
        });
    }
    Ok(graph)
}

pub fn encode_keyring(keyring: &Keyring) -> Vec<u8> {
    let mut out = Vec::new();
    format::put_version(&mut out);
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
    format::read_version(&mut c)?;
    let mut keyring = Keyring::new();
    let n = c.u32()?;
    for _ in 0..n {
        let oid = Oid(c.arr32()?);
        let key = c.arr32()?;
        keyring.insert(oid, key);
    }
    Ok(keyring)
}

pub fn encode_escrow(escrow: &Escrow) -> Vec<u8> {
    let mut out = Vec::new();
    format::put_version(&mut out);
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
    format::read_version(&mut c)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Visibility;

    // Golden v1 bytes locking the durable on-disk layouts (ADR 0019). If an
    // encoder drifts, these fail and the change must bump FORMAT_MAJOR.

    // graph: one change id=[1;32], parents=[], message="first",
    //        tree={"a.txt": (oid=[2;32], Public)}.
    const GOLDEN_GRAPH_V1: [u8; 97] = [
        1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 5, 0, 0, 0, 102, 105, 114, 115, 116, 1, 0, 0, 0, 5, 0,
        0, 0, 97, 46, 116, 120, 116, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0,
    ];

    // sealed object: nonce=[9;12], ciphertext=[0xAB,0xCD], Public, grant_ids=["*"].
    const GOLDEN_OBJECT_V1: [u8; 30] = [
        1, 0, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 2, 0, 0, 0, 171, 205, 0, 1, 0, 0, 0, 1, 0, 0, 0,
        42,
    ];

    // keyring: one entry (Oid([4;32]), key=[7;32]).
    // Layout: [major=1][minor=0][count=1 u32le][oid 32 bytes][key 32 bytes] = 70 bytes.
    const GOLDEN_KEYRING_V1: [u8; 70] = {
        let mut b = [0u8; 70];
        b[0] = 1; b[1] = 0;          // version marker
        b[2] = 1;                      // count = 1 (LE u32, low byte)
        let mut i = 6;
        while i < 6 + 32 { b[i] = 4; i += 1; }   // oid = [4;32]
        while i < 6 + 64 { b[i] = 7; i += 1; }   // key = [7;32]
        b
    };

    // escrow: one entry (Oid([5;32]), key=[8;32], reveal_at=1_800_000_000).
    // 1_800_000_000 LE u64 = [0, 210, 73, 107, 0, 0, 0, 0].
    // Layout: [major=1][minor=0][count=1 u32le][oid 32][key 32][reveal_at u64le] = 78 bytes.
    const GOLDEN_ESCROW_V1: [u8; 78] = {
        let mut b = [0u8; 78];
        b[0] = 1; b[1] = 0;           // version marker
        b[2] = 1;                       // count = 1 (LE u32, low byte)
        let mut i = 6;
        while i < 6 + 32 { b[i] = 5; i += 1; }    // oid = [5;32]
        while i < 6 + 64 { b[i] = 8; i += 1; }    // key = [8;32]
        // reveal_at = 1_800_000_000 little-endian u64
        b[70] = 0; b[71] = 210; b[72] = 73; b[73] = 107;
        b[74] = 0; b[75] = 0;   b[76] = 0; b[77] = 0;
        b
    };

    // ---- v2 goldens (current format, FORMAT_MAJOR = 2, ADR 0020) ----
    // Graph/keyring/escrow layouts are unchanged from v1; only the marker byte
    // differs. The sealed object gains a one-byte `compressed` flag after the
    // nonce, so its v2 golden is one byte longer than v1.

    // graph: identical body to GOLDEN_GRAPH_V1, marker [2,0].
    const GOLDEN_GRAPH_V2: [u8; 97] = [
        2, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 5, 0, 0, 0, 102, 105, 114, 115, 116, 1, 0, 0, 0, 5, 0,
        0, 0, 97, 46, 116, 120, 116, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0,
    ];

    // sealed object: nonce=[9;12], compressed=0, ciphertext=[0xAB,0xCD], Public,
    // grant_ids=["*"]. The compressed flag sits right after the nonce.
    const GOLDEN_OBJECT_V2: [u8; 31] = [
        2, 0, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 0, 2, 0, 0, 0, 171, 205, 0, 1, 0, 0, 0, 1, 0, 0,
        0, 42,
    ];

    // keyring: same body as GOLDEN_KEYRING_V1, marker [2,0].
    const GOLDEN_KEYRING_V2: [u8; 70] = {
        let mut b = [0u8; 70];
        b[0] = 2; b[1] = 0;
        b[2] = 1;
        let mut i = 6;
        while i < 6 + 32 { b[i] = 4; i += 1; }
        while i < 6 + 64 { b[i] = 7; i += 1; }
        b
    };

    // escrow: same body as GOLDEN_ESCROW_V1, marker [2,0].
    const GOLDEN_ESCROW_V2: [u8; 78] = {
        let mut b = [0u8; 78];
        b[0] = 2; b[1] = 0;
        b[2] = 1;
        let mut i = 6;
        while i < 6 + 32 { b[i] = 5; i += 1; }
        while i < 6 + 64 { b[i] = 8; i += 1; }
        b[70] = 0; b[71] = 210; b[72] = 73; b[73] = 107;
        b[74] = 0; b[75] = 0;   b[76] = 0; b[77] = 0;
        b
    };

    // ---- v3 goldens (current format, FORMAT_MAJOR = 3, ADR 0018) ----
    // S3 changed only the *change* layout (per-change author + signature), so the
    // graph golden grows by 2 bytes (author-absent, sig-absent for this sample
    // unauthored change). Object/keyring/escrow layouts are unchanged; only the
    // marker byte differs.
    const GOLDEN_GRAPH_V3: [u8; 99] = [
        3, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 5, 0, 0, 0, 102, 105, 114, 115, 116, 1, 0, 0, 0, 5, 0,
        0, 0, 97, 46, 116, 120, 116, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0,
    ];
    const GOLDEN_OBJECT_V3: [u8; 31] = [
        3, 0, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 0, 2, 0, 0, 0, 171, 205, 0, 1, 0, 0, 0, 1, 0, 0,
        0, 42,
    ];
    const GOLDEN_KEYRING_V3: [u8; 70] = {
        let mut b = [0u8; 70];
        b[0] = 3; b[1] = 0;
        b[2] = 1;
        let mut i = 6;
        while i < 6 + 32 { b[i] = 4; i += 1; }
        while i < 6 + 64 { b[i] = 7; i += 1; }
        b
    };
    const GOLDEN_ESCROW_V3: [u8; 78] = {
        let mut b = [0u8; 78];
        b[0] = 3; b[1] = 0;
        b[2] = 1;
        let mut i = 6;
        while i < 6 + 32 { b[i] = 5; i += 1; }
        while i < 6 + 64 { b[i] = 8; i += 1; }
        b[70] = 0; b[71] = 210; b[72] = 73; b[73] = 107;
        b[74] = 0; b[75] = 0;   b[76] = 0; b[77] = 0;
        b
    };

    // ---- v4 goldens (current format, FORMAT_MAJOR = 4, ADR 0018). None of these
    // artifacts changed layout in S4 (attestations are separate); only the marker.
    const GOLDEN_GRAPH_V4: [u8; 99] = [
        4, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 5, 0, 0, 0, 102, 105, 114, 115, 116, 1, 0, 0, 0, 5, 0,
        0, 0, 97, 46, 116, 120, 116, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0,
    ];
    const GOLDEN_OBJECT_V4: [u8; 31] = [
        4, 0, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 0, 2, 0, 0, 0, 171, 205, 0, 1, 0, 0, 0, 1, 0, 0,
        0, 42,
    ];
    const GOLDEN_KEYRING_V4: [u8; 70] = {
        let mut b = [0u8; 70];
        b[0] = 4; b[1] = 0;
        b[2] = 1;
        let mut i = 6;
        while i < 6 + 32 { b[i] = 4; i += 1; }
        while i < 6 + 64 { b[i] = 7; i += 1; }
        b
    };
    const GOLDEN_ESCROW_V4: [u8; 78] = {
        let mut b = [0u8; 78];
        b[0] = 4; b[1] = 0;
        b[2] = 1;
        let mut i = 6;
        while i < 6 + 32 { b[i] = 5; i += 1; }
        while i < 6 + 64 { b[i] = 8; i += 1; }
        b[70] = 0; b[71] = 210; b[72] = 73; b[73] = 107;
        b[74] = 0; b[75] = 0;   b[76] = 0; b[77] = 0;
        b
    };

    fn one_change_graph() -> ChangeGraph {
        let mut g = ChangeGraph::new();
        let mut tree = BTreeMap::new();
        tree.insert(
            PathBuf::from("a.txt"),
            (Oid([2; 32]), Visibility::Public),
        );
        g.insert(ChangeNode {
            id: Oid([1; 32]),
            parents: vec![],
            message: "first".into(),
            tree,
            author: None,
            signature: None,
        });
        g
    }

    // A hand-built fixture object. `compressed: false` keeps its bytes
    // deterministic (the codec round-trips the flag verbatim; actual zstd lives
    // in seal/open, tested in the sealed module).
    fn sample_object() -> SealedObject {
        SealedObject {
            nonce: [9; 12],
            ciphertext: vec![0xAB, 0xCD],
            vis: Visibility::Public,
            grant_ids: vec!["*".into()],
            compressed: false,
        }
    }

    #[test]
    fn graph_encode_leads_with_version_and_round_trips() {
        let g = one_change_graph();
        let bytes = encode_graph(&g);
        assert_eq!(&bytes[..2], &[format::FORMAT_MAJOR, format::FORMAT_MINOR]);
        let back = decode_graph(&bytes).unwrap();
        assert_eq!(back.in_order().len(), 1);
    }

    #[test]
    fn v1_graph_still_decodes() {
        // A v2 build still reads a committed v1 graph (newer reads older).
        let g = decode_graph(&GOLDEN_GRAPH_V1).unwrap();
        let changes = g.in_order();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].message, "first");
        assert_eq!(changes[0].id, Oid([1; 32]));
    }

    #[test]
    fn v2_graph_still_decodes() {
        // A v3 build still reads a v2 graph; its change predates authorship.
        let g = decode_graph(&GOLDEN_GRAPH_V2).unwrap();
        assert_eq!(g.in_order().len(), 1);
        assert!(g.in_order()[0].author.is_none(), "v2 change is unauthored");
    }

    #[test]
    fn v3_graph_still_decodes() {
        assert_eq!(decode_graph(&GOLDEN_GRAPH_V3).unwrap().in_order().len(), 1);
    }

    #[test]
    fn golden_v4_graph_matches_and_round_trips() {
        assert_eq!(encode_graph(&one_change_graph()), GOLDEN_GRAPH_V4, "v4 graph layout must not drift");
        assert_eq!(decode_graph(&GOLDEN_GRAPH_V4).unwrap().in_order().len(), 1);
    }

    #[test]
    fn object_encode_leads_with_version_and_round_trips() {
        let obj = sample_object();
        let bytes = encode_object(&obj);
        assert_eq!(&bytes[..2], &[format::FORMAT_MAJOR, format::FORMAT_MINOR]);
        // The content address is derived from nonce+ciphertext, not the file
        // bytes, so it is unchanged by the version prefix (ADR 0012/0019).
        let before = obj.address();
        let back = decode_object(&bytes).unwrap();
        assert_eq!(back, obj);
        assert_eq!(back.address(), before);
    }

    #[test]
    fn v1_object_still_decodes_as_uncompressed() {
        // A v1 object predates the compressed flag; a v2 build reads it and
        // defaults compressed=false (newer reads older, ADR 0020).
        let obj = decode_object(&GOLDEN_OBJECT_V1).unwrap();
        assert_eq!(obj, sample_object());
        assert!(!obj.compressed);
    }

    #[test]
    fn v2_object_still_decodes() {
        // The object layout is unchanged in v3; a v3 build still reads a v2 object.
        assert_eq!(decode_object(&GOLDEN_OBJECT_V2).unwrap(), sample_object());
    }

    #[test]
    fn v3_object_still_decodes() {
        assert_eq!(decode_object(&GOLDEN_OBJECT_V3).unwrap(), sample_object());
    }

    #[test]
    fn golden_v4_object_matches_and_round_trips() {
        assert_eq!(encode_object(&sample_object()), GOLDEN_OBJECT_V4, "v4 object layout must not drift");
        assert_eq!(decode_object(&GOLDEN_OBJECT_V4).unwrap(), sample_object());
    }

    #[test]
    fn object_compressed_flag_round_trips() {
        let mut obj = sample_object();
        obj.compressed = true;
        let back = decode_object(&encode_object(&obj)).unwrap();
        assert!(back.compressed, "compressed flag must survive encode/decode");
    }

    #[test]
    fn decode_graph_rejects_incompatible_future_major() {
        let mut bytes = encode_graph(&one_change_graph());
        bytes[0] = format::FORMAT_MAJOR + 1;
        assert!(matches!(
            decode_graph(&bytes),
            Err(RepoError::UnsupportedFormat { .. })
        ));
    }

    #[test]
    fn decode_object_rejects_incompatible_future_major() {
        let mut bytes = encode_object(&sample_object());
        bytes[0] = format::FORMAT_MAJOR + 1;
        assert!(matches!(
            decode_object(&bytes),
            Err(RepoError::UnsupportedFormat { .. })
        ));
    }

    fn sample_keyring() -> Keyring {
        let mut kr = Keyring::new();
        kr.insert(Oid([4; 32]), [7; 32]);
        kr
    }

    fn sample_escrow() -> Escrow {
        let mut es = Escrow::new();
        es.insert(Oid([5; 32]), [8; 32], 1_800_000_000);
        es
    }

    #[test]
    fn v1_keyring_still_decodes() {
        // Layout unchanged since v1; a v2 build still reads a v1 keyring.
        assert!(decode_keyring(&GOLDEN_KEYRING_V1).unwrap().holds(&Oid([4; 32])));
    }

    #[test]
    fn v2_keyring_still_decodes() {
        assert!(decode_keyring(&GOLDEN_KEYRING_V2).unwrap().holds(&Oid([4; 32])));
    }

    #[test]
    fn v3_keyring_still_decodes() {
        assert!(decode_keyring(&GOLDEN_KEYRING_V3).unwrap().holds(&Oid([4; 32])));
    }

    #[test]
    fn golden_v4_keyring_matches_and_round_trips() {
        assert_eq!(encode_keyring(&sample_keyring()), GOLDEN_KEYRING_V4, "v4 keyring layout must not drift");
        assert!(decode_keyring(&GOLDEN_KEYRING_V4).unwrap().holds(&Oid([4; 32])));
    }

    #[test]
    fn v1_escrow_still_decodes() {
        // Layout unchanged since v1; a v2 build still reads a v1 escrow.
        assert!(decode_escrow(&GOLDEN_ESCROW_V1).unwrap().holds(&Oid([5; 32])));
    }

    #[test]
    fn v2_escrow_still_decodes() {
        assert!(decode_escrow(&GOLDEN_ESCROW_V2).unwrap().holds(&Oid([5; 32])));
    }

    #[test]
    fn v3_escrow_still_decodes() {
        assert!(decode_escrow(&GOLDEN_ESCROW_V3).unwrap().holds(&Oid([5; 32])));
    }

    #[test]
    fn golden_v4_escrow_matches_and_round_trips() {
        assert_eq!(encode_escrow(&sample_escrow()), GOLDEN_ESCROW_V4, "v4 escrow layout must not drift");
        assert!(decode_escrow(&GOLDEN_ESCROW_V4).unwrap().holds(&Oid([5; 32])));
    }

    #[test]
    fn decode_keyring_rejects_incompatible_future_major() {
        let mut bytes = encode_keyring(&sample_keyring());
        bytes[0] = format::FORMAT_MAJOR + 1;
        assert!(matches!(
            decode_keyring(&bytes),
            Err(RepoError::UnsupportedFormat { .. })
        ));
    }

    #[test]
    fn decode_escrow_rejects_incompatible_future_major() {
        let mut bytes = encode_escrow(&sample_escrow());
        bytes[0] = format::FORMAT_MAJOR + 1;
        assert!(matches!(
            decode_escrow(&bytes),
            Err(RepoError::UnsupportedFormat { .. })
        ));
    }
}
