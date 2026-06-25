//! Sync-bundle encoding and decoding (network protocol).
//! Owns the shared low-level binary primitives and the `SyncBundle` wire format
//! consumed by `engine::DagRepo::bundle` and `engine::DagRepo::apply`.

use crate::engine::ChangeNode;
use crate::sealed::{ContentKey, SealedObject};
use crate::{Oid, RepoError, Visibility};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub fn put_u32(out: &mut Vec<u8>, n: usize) {
    out.extend_from_slice(&(n as u32).to_le_bytes());
}
pub fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u32(out, b.len());
    out.extend_from_slice(b);
}
pub fn put_vis(out: &mut Vec<u8>, vis: &Visibility) {
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

pub struct Cursor<'a> {
    pub b: &'a [u8],
    pub i: usize,
}
impl<'a> Cursor<'a> {
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], RepoError> {
        if self.i + n > self.b.len() {
            return Err(RepoError::Backend("bundle truncated".into()));
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    pub fn u32(&mut self) -> Result<usize, RepoError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize)
    }
    pub fn u64(&mut self) -> Result<u64, RepoError> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_le_bytes(a))
    }
    pub fn arr32(&mut self) -> Result<[u8; 32], RepoError> {
        let s = self.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(s);
        Ok(a)
    }
    pub fn arr12(&mut self) -> Result<[u8; 12], RepoError> {
        let s = self.take(12)?;
        let mut a = [0u8; 12];
        a.copy_from_slice(s);
        Ok(a)
    }
    pub fn bytes(&mut self) -> Result<Vec<u8>, RepoError> {
        let n = self.u32()?;
        Ok(self.take(n)?.to_vec())
    }
    pub fn string(&mut self) -> Result<String, RepoError> {
        String::from_utf8(self.bytes()?).map_err(|e| RepoError::Backend(e.to_string()))
    }
    pub fn vis(&mut self) -> Result<Visibility, RepoError> {
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

pub fn encode_grant(
    changes: &[&ChangeNode],
    objs: &BTreeMap<Oid, &SealedObject>,
    public_keys: &BTreeMap<Oid, ContentKey>,
    escrow_entries: &BTreeMap<Oid, (ContentKey, u64)>,
) -> Vec<u8> {
    encode(changes, objs, public_keys, escrow_entries)
}

#[allow(clippy::type_complexity)]
pub fn decode_grant(
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
    decode(b)
}
