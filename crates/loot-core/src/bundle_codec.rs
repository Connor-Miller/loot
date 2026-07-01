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
    objs: &BTreeMap<Oid, SealedObject>,
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

/// The decoded payload every bundle carries: changes plus the sealed objects,
/// public keys, and embargoed escrow entries riding with them. This is exactly
/// what the low-level [`encode`]/[`decode`] body codec moves; `Frame` wraps it
/// with the per-kind header.
#[derive(Clone)]
pub struct BundleBody {
    pub changes: Vec<ChangeNode>,
    /// Keyed by content address so `encode_body` can borrow directly into
    /// `encode()` without rebuilding a map.
    pub objs: BTreeMap<Oid, SealedObject>,
    pub keys: BTreeMap<Oid, ContentKey>,
    pub escrow: BTreeMap<Oid, (ContentKey, u64)>,
}

/// A whole bundle on the wire, tag already resolved: the one value callers match
/// on. The leading tag byte, the Sync purge prefix, the Grant grantee prefix,
/// and the SealedGrant `[pubkey·wrapped·oid]` header all live behind
/// [`Frame::decode`]/[`Frame::encode`] and never escape this module (arch
/// review C1). The engine stops doing offset math.
///
/// A `SealedGrant`'s `wrapped_key` is surfaced verbatim and never unwrapped
/// here — unsealing is the caller's job (identity crypto stays out of loot-core,
/// ADR 0014/0015).
pub enum Frame {
    /// tag 0. Produced by `bundle`; consumed by `apply` (merge) and `stow` (relay).
    Sync {
        purges: Vec<(Oid, String)>,
        body: BundleBody,
    },
    /// tag 1. A targeted key handoff whose key rides in `body.keys`.
    Grant {
        grantee: String,
        body: BundleBody,
    },
    /// tag 3. A sealed-key grant: the content key is ECIES-wrapped to the
    /// recipient's pubkey and carried in `wrapped_key`, not `body`.
    SealedGrant {
        grantee_pubkey: [u8; 32],
        wrapped_key: [u8; 80],
        oid: Oid,
        body: BundleBody,
    },
}

/// Serialize a `BundleBody` via the low-level body codec, reusing [`encode`] so
/// there is exactly one definition of the payload layout.
fn encode_body(body: &BundleBody) -> Vec<u8> {
    let changes: Vec<&ChangeNode> = body.changes.iter().collect();
    encode(&changes, &body.objs, &body.keys, &body.escrow)
}

fn decode_body(b: &[u8]) -> Result<BundleBody, RepoError> {
    let (changes, objs_vec, keys, escrow) = decode(b)?;
    let objs = objs_vec.into_iter().collect();
    Ok(BundleBody { changes, objs, keys, escrow })
}

impl Frame {
    /// Serialize to the exact bytes the old hand-rolled framing emitted —
    /// byte-identical, so the ADR 0003/0004/0007 leak-guards still pass.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Frame::Sync { purges, body } => {
                let mut out = vec![0u8];
                put_u32(&mut out, purges.len());
                for (oid, marooned) in purges {
                    out.extend_from_slice(&oid.0);
                    put_bytes(&mut out, marooned.as_bytes());
                }
                out.extend_from_slice(&encode_body(body));
                out
            }
            Frame::Grant { grantee, body } => {
                let mut out = vec![1u8];
                put_bytes(&mut out, grantee.as_bytes());
                out.extend_from_slice(&encode_body(body));
                out
            }
            Frame::SealedGrant { grantee_pubkey, wrapped_key, oid, body } => {
                let mut out = vec![3u8];
                out.extend_from_slice(grantee_pubkey);
                out.extend_from_slice(wrapped_key);
                out.extend_from_slice(&oid.0);
                out.extend_from_slice(&encode_body(body));
                out
            }
        }
    }

    /// Decode a whole bundle. Pure and total: no keys, no I/O, no crypto — so it
    /// serves both `apply` (keyholder) and `stow` (relay). Errors on empty input,
    /// an unknown tag, or any truncation.
    pub fn decode(bytes: &[u8]) -> Result<Frame, RepoError> {
        let Some((&tag, rest)) = bytes.split_first() else {
            return Err(RepoError::Backend("empty bundle".into()));
        };
        match tag {
            0 => {
                let mut c = Cursor { b: rest, i: 0 };
                let purge_count = c.u32()?;
                let mut purges = Vec::with_capacity(purge_count);
                for _ in 0..purge_count {
                    let oid = Oid(c.arr32()?);
                    let marooned = c.string()?;
                    purges.push((oid, marooned));
                }
                let body = decode_body(&c.b[c.i..])?;
                Ok(Frame::Sync { purges, body })
            }
            1 => {
                let mut c = Cursor { b: rest, i: 0 };
                let grantee = c.string()?;
                let body = decode_body(&c.b[c.i..])?;
                Ok(Frame::Grant { grantee, body })
            }
            // tag 2: reserved — do not assign (the Visibility codec uses 2 for Embargoed
            // in its own sub-stream; assigning it as a bundle tag would be ambiguous
            // to any reader that sees both streams).
            3 => {
                let mut c = Cursor { b: rest, i: 0 };
                let grantee_pubkey = c.arr32()?;
                let mut wrapped_key = [0u8; 80];
                wrapped_key.copy_from_slice(c.take(80)?);
                let oid = Oid(c.arr32()?);
                let body = decode_body(&c.b[c.i..])?;
                Ok(Frame::SealedGrant { grantee_pubkey, wrapped_key, oid, body })
            }
            t => Err(RepoError::Backend(format!("unknown bundle tag {t}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_body() -> BundleBody {
        BundleBody { changes: vec![], objs: BTreeMap::new(), keys: BTreeMap::new(), escrow: BTreeMap::new() }
    }

    #[test]
    fn sync_frame_round_trips_with_purges() {
        let f = Frame::Sync {
            purges: vec![(Oid([7; 32]), "bob".into())],
            body: empty_body(),
        };
        let bytes = f.encode();
        assert_eq!(bytes[0], 0, "sync tag");
        match Frame::decode(&bytes).unwrap() {
            Frame::Sync { purges, body } => {
                assert_eq!(purges, vec![(Oid([7; 32]), "bob".to_string())]);
                assert!(body.objs.is_empty() && body.changes.is_empty());
            }
            _ => panic!("expected Sync"),
        }
    }

    #[test]
    fn grant_frame_round_trips_grantee() {
        let f = Frame::Grant { grantee: "alice".into(), body: empty_body() };
        let bytes = f.encode();
        assert_eq!(bytes[0], 1, "grant tag");
        match Frame::decode(&bytes).unwrap() {
            Frame::Grant { grantee, .. } => assert_eq!(grantee, "alice"),
            _ => panic!("expected Grant"),
        }
    }

    #[test]
    fn sealed_grant_frame_round_trips_header() {
        let f = Frame::SealedGrant {
            grantee_pubkey: [1; 32],
            wrapped_key: [2; 80],
            oid: Oid([3; 32]),
            body: empty_body(),
        };
        let bytes = f.encode();
        assert_eq!(bytes[0], 3, "sealed-grant tag");
        match Frame::decode(&bytes).unwrap() {
            Frame::SealedGrant { grantee_pubkey, wrapped_key, oid, .. } => {
                assert_eq!(grantee_pubkey, [1; 32]);
                assert_eq!(wrapped_key, [2; 80]);
                assert_eq!(oid, Oid([3; 32]));
            }
            _ => panic!("expected SealedGrant"),
        }
    }

    #[test]
    fn decode_rejects_empty_and_unknown_tag() {
        assert!(Frame::decode(&[]).is_err(), "empty input");
        assert!(Frame::decode(&[9]).is_err(), "unknown tag");
    }
}
