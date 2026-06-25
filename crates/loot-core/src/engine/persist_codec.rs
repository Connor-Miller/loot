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

use crate::bundle_codec::{put_bytes, put_u32, put_vis, Cursor};
use crate::escrow::Escrow;
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
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = (bytes[2 * i] as char).to_digit(16)?;
        let lo = (bytes[2 * i + 1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

fn encode_object(obj: &SealedObject) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&obj.nonce);
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
    let nonce = c.arr12()?;
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
        let dest = obj_dir.join(hex(&addr.0));
        if dest.exists() {
            continue;
        }
        let tmp = obj_dir.join(format!("{}.tmp", hex(&addr.0)));
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
        let Some(addr) = unhex32(&name) else {
            continue; // skip *.tmp and anything not a content address
        };
        let bytes = std::fs::read(entry.path()).map_err(|e| RepoError::Backend(e.to_string()))?;
        objects.put(Oid(addr), decode_object(&bytes)?);
    }
    Ok(objects)
}

pub fn encode_graph(graph: &ChangeGraph) -> Vec<u8> {
    let mut out = Vec::new();
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
    Ok(graph)
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
