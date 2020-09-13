//! Sync-bundle encoding and decoding (network protocol).
//! Owns the shared low-level binary primitives and the `SyncBundle` wire format
//! consumed by `engine::DagRepo::bundle` and `engine::DagRepo::apply`.

use crate::attestation::Attestation;
use crate::engine::ChangeNode;
use crate::format;
pub use crate::format::Cursor;
use crate::sealed::{ContentKey, SealedObject};
use crate::{Oid, RepoError, Visibility};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub fn put_u32(out: &mut Vec<u8>, n: usize) {
    // Every length/count prefix in the format is 32-bit. Truncating a larger
    // usize would silently corrupt the stream (a huge count wrapping to a small
    // one); fail loudly instead — no real artifact carries >4B of anything.
    let n = u32::try_from(n).expect("count exceeds u32::MAX — loot wire format uses 32-bit length prefixes");
    out.extend_from_slice(&n.to_le_bytes());
}
pub fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u32(out, b.len());
    out.extend_from_slice(b);
}
/// Write a single attestation record: `change_id ‖ attester ‖ role ‖ signature`.
/// The one definition of the attestation byte layout — shared by the bundle body
/// (`encode`) and the durable `.loot/attestations` log (S4, ADR 0018).
pub fn put_attestation(out: &mut Vec<u8>, a: &Attestation) {
    out.extend_from_slice(&a.change_id.0);
    out.extend_from_slice(&a.attester);
    put_bytes(out, a.role.as_bytes());
    out.extend_from_slice(&a.signature);
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

impl<'a> Cursor<'a> {
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
    /// Read a single attestation record written by [`put_attestation`]. The one
    /// reader for the attestation byte layout — shared by the bundle body and the
    /// durable `.loot/attestations` log (S4, ADR 0018).
    pub fn attestation(&mut self) -> Result<Attestation, RepoError> {
        let change_id = Oid(self.arr32()?);
        let attester = self.arr32()?;
        let role = self.string()?;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(self.take(64)?);
        Ok(Attestation { change_id, attester, role, signature })
    }
}

/// Encode the bundle body payload (objects, keys, changes).
/// This is the raw body — no version marker or frame tag. Use `Frame::encode`
/// for the complete on-wire format; call this directly only when re-encoding a
/// decoded body for inspection (e.g. in test helpers).
pub fn encode(
    changes: &[&ChangeNode],
    objs: &BTreeMap<Oid, SealedObject>,
    public_keys: &BTreeMap<Oid, ContentKey>,
    attestations: &[Attestation],
) -> Vec<u8> {
    let mut out = Vec::new();

    // SealedObjects: ciphertext + policy + grant_ids (NAMES), never keys,
    // and no plaintext-derived field — so the wire leaks no equality signal
    // to a relay (ADR 0004).
    put_u32(&mut out, objs.len());
    for (addr, obj) in objs {
        out.extend_from_slice(&addr.0);
        out.extend_from_slice(&obj.nonce);
        out.push(obj.compressed as u8); // v2: compression flag (ADR 0020)
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

    // v5 (ADR 0027): the plaintext escrow section is GONE. Embargoed keys
    // never ride in a bundle — they travel only as relay-withheld timed
    // SealedGrants. v1–v4 wrote `[count][addr·key·reveal_at]...` here.

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
        // v3: author pubkey + signature ride beside the change body (ADR 0018).
        format::put_author_sig(&mut out, &c.author, &c.signature);
        // v6: the durable change_id travels with the change (ADR 0029), so peers
        // agree on it by receipt — no id-allocation protocol.
        format::put_change_id(&mut out, &c.change_id);
        // v7: the versions this one supersedes travel with it (ADR 0032), so a
        // solo amend arrives at every peer as a clean replacement, not a fork.
        format::put_predecessors(&mut out, &c.predecessors);
    }

    // v4: detachable attestations ride after the changes (S4, ADR 0018).
    put_u32(&mut out, attestations.len());
    for a in attestations {
        put_attestation(&mut out, a);
    }
    out
}

/// Decode the bundle body payload (no version marker or frame tag).
/// Use `Frame::decode` for the complete on-wire format; call this directly only
/// when parsing a body slice that was already extracted by `Frame::decode`.
/// `major` is the format major from the frame's version marker: it selects
/// whether inline objects carry the v2 `compressed` flag (ADR 0019/0020) and
/// whether a v1–v4 plaintext escrow section must be parsed — parsed for cursor
/// correctness only; its raw keys are DROPPED, never surfaced (ADR 0027, #14).
#[allow(clippy::type_complexity)]
pub fn decode(
    b: &[u8],
    major: u8,
) -> Result<
    (
        Vec<ChangeNode>,
        Vec<(Oid, SealedObject)>,
        BTreeMap<Oid, ContentKey>,
        Vec<Attestation>,
    ),
    RepoError,
> {
    let mut c = Cursor { b, i: 0 };

    let n_objs = c.u32()?;
    let mut objs = Vec::with_capacity(n_objs);
    for _ in 0..n_objs {
        let addr = Oid(c.arr32()?);
        let nonce = c.arr12()?;
        // Compression flag exists from v2 on; v1 bundles predate it (uncompressed).
        let compressed = if major >= 2 { c.take(1)?[0] != 0 } else { false };
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
                compressed,
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

    // v1–v4 carried a plaintext escrow section here (`[addr·key·reveal_at]`).
    // Parse it to keep the cursor in sync, then DROP it: filing those raw keys
    // is the pre-reveal read hard embargo exists to close (ADR 0027).
    if major <= 4 {
        let n_escrow = c.u32()?;
        for _ in 0..n_escrow {
            let _addr = c.arr32()?;
            let _key = c.arr32()?;
            let _reveal_at = c.u64()?;
        }
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
        let (author, signature) = format::read_author_sig(&mut c, major)?;
        let change_id = format::read_change_id(&mut c, major)?;
        let predecessors = format::read_predecessors(&mut c, major)?;
        changes.push(ChangeNode {
            id,
            parents,
            message,
            tree,
            author,
            signature,
            change_id,
            predecessors,
        });
    }

    // v4: detachable attestations after the changes (S4, ADR 0018). Older
    // bundles predate them, so a pre-v4 reader/body yields none.
    let attestations = if major >= 4 {
        let n = c.u32()?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(c.attestation()?);
        }
        v
    } else {
        Vec::new()
    };

    Ok((changes, objs, public_keys, attestations))
}

/// The decoded payload every bundle carries: changes plus the sealed objects
/// and public keys riding with them. This is exactly what the low-level
/// [`encode`]/[`decode`] body codec moves; `Frame` wraps it with the per-kind
/// header. Embargoed keys deliberately have no lane here (ADR 0027): they
/// travel only as relay-withheld timed SealedGrants.
#[derive(Clone)]
pub struct BundleBody {
    pub changes: Vec<ChangeNode>,
    /// Keyed by content address so `encode_body` can borrow directly into
    /// `encode()` without rebuilding a map.
    pub objs: BTreeMap<Oid, SealedObject>,
    pub keys: BTreeMap<Oid, ContentKey>,
    /// Detachable, advisory attestations over changes (S4, ADR 0018). Carried
    /// with the bundle; verified and dropped-if-invalid on ingest.
    pub attestations: Vec<Attestation>,
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
    /// recipient's pubkey and carried in `wrapped_key`, not `body`. `reveal_at`
    /// (v5, ADR 0027) makes it a *timed* grant: the relay withholds it from the
    /// mailbox until its own clock passes `reveal_at`; `0` means untimed
    /// (deliver immediately). It rides inside the grantor-signed envelope, so a
    /// recipient cannot alter it without breaking the signature.
    SealedGrant {
        grantee_pubkey: [u8; 32],
        wrapped_key: [u8; 80],
        oid: Oid,
        reveal_at: u64,
        body: BundleBody,
    },
}

/// Serialize a `BundleBody` via the low-level body codec, reusing [`encode`] so
/// there is exactly one definition of the payload layout.
fn encode_body(body: &BundleBody) -> Vec<u8> {
    let changes: Vec<&ChangeNode> = body.changes.iter().collect();
    encode(&changes, &body.objs, &body.keys, &body.attestations)
}

fn decode_body(b: &[u8], major: u8) -> Result<BundleBody, RepoError> {
    let (changes, objs_vec, keys, attestations) = decode(b, major)?;
    let objs = objs_vec.into_iter().collect();
    Ok(BundleBody { changes, objs, keys, attestations })
}

impl Frame {
    /// Serialize a bundle: a two-byte format marker (`[major][minor]`, ADR 0019)
    /// followed by the tagged body. The body after the marker is byte-identical
    /// to the old hand-rolled framing, so the ADR 0003/0004/0007 leak-guards
    /// still pass.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        format::put_version(&mut out);
        match self {
            Frame::Sync { purges, body } => {
                out.push(0);
                put_u32(&mut out, purges.len());
                for (oid, marooned) in purges {
                    out.extend_from_slice(&oid.0);
                    put_bytes(&mut out, marooned.as_bytes());
                }
                out.extend_from_slice(&encode_body(body));
            }
            Frame::Grant { grantee, body } => {
                out.push(1);
                put_bytes(&mut out, grantee.as_bytes());
                out.extend_from_slice(&encode_body(body));
            }
            Frame::SealedGrant { grantee_pubkey, wrapped_key, oid, reveal_at, body } => {
                out.push(3);
                out.extend_from_slice(grantee_pubkey);
                out.extend_from_slice(wrapped_key);
                out.extend_from_slice(&oid.0);
                out.extend_from_slice(&reveal_at.to_le_bytes()); // v5 (ADR 0027)
                out.extend_from_slice(&encode_body(body));
            }
        }
        out
    }

    /// Decode a whole bundle. Pure and total: no keys, no I/O, no crypto — so it
    /// serves both `apply` (keyholder) and `stow` (relay). The format marker is
    /// checked first, so a bundle from an incompatible future major is rejected
    /// with a clear error (ADR 0019). Errors on empty input, an unsupported
    /// version, an unknown tag, or any truncation.
    pub fn decode(bytes: &[u8]) -> Result<Frame, RepoError> {
        let mut head = Cursor { b: bytes, i: 0 };
        let (major, _minor) = format::read_version(&mut head)?;
        let tag = head.take(1)?[0];
        let rest = &bytes[head.i..];
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
                let body = decode_body(&c.b[c.i..], major)?;
                Ok(Frame::Sync { purges, body })
            }
            1 => {
                let mut c = Cursor { b: rest, i: 0 };
                let grantee = c.string()?;
                let body = decode_body(&c.b[c.i..], major)?;
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
                // v5 (ADR 0027): timed grants carry reveal_at in the header.
                // Pre-v5 sealed grants predate it — untimed (0).
                let reveal_at = if major >= 5 { c.u64()? } else { 0 };
                let body = decode_body(&c.b[c.i..], major)?;
                Ok(Frame::SealedGrant { grantee_pubkey, wrapped_key, oid, reveal_at, body })
            }
            t => Err(RepoError::Backend(format!("unknown bundle tag {t}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_body() -> BundleBody {
        BundleBody { changes: vec![], objs: BTreeMap::new(), keys: BTreeMap::new(), attestations: vec![] }
    }

    // Golden wire bytes for `Frame::Sync { purges: [], body: empty }`:
    // v1–v4: [major][minor][tag=0][purge_count=0][objs=0][keys=0][escrow=0][changes=0]
    // (+ attestation count from v4). These lock the wire layout; a drift fails
    // here and must bump FORMAT_MAJOR (ADR 0019/0020).
    const GOLDEN_SYNC_V1: [u8; 23] =
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    const GOLDEN_SYNC_V2: [u8; 23] =
        [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    const GOLDEN_SYNC_V3: [u8; 23] =
        [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    // v4 grew by the attestation-count section (S4): empty bundle is 27 bytes.
    const GOLDEN_SYNC_V4: [u8; 27] =
        [4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    // v5 dropped the plaintext escrow section (ADR 0027): back to 23 bytes —
    // [5][0][tag=0][purges=0][objs=0][keys=0][changes=0][attestations=0].
    const GOLDEN_SYNC_V5: [u8; 23] =
        [5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    // v6 (ADR 0029) added the durable change_id, but it rides *per change*, so an
    // empty bundle is byte-identical to v5 apart from the marker — still 23 bytes.
    const GOLDEN_SYNC_V6: [u8; 23] =
        [6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    // v7 (ADR 0032) added per-change `predecessors`, also *per change*, so an
    // empty bundle again differs from v6 only in the marker.
    const GOLDEN_SYNC_V7: [u8; 23] =
        [7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    // v4 bundle with one authored+signed change (no tree, no objects, no attestations).
    // Kept as a decode-compat fixture: a v5 reader must still read it (and drop
    // its empty escrow section). Pins the put_author_sig layout.
    const GOLDEN_SYNC_V4_AUTHORED: [u8; 177] = [
        4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 0, 0, 0, 5, 5, 5, 5, 5, 5, 5, 5, 5,
        5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
        5, 5, 5, 5, 5, 5, 5, 0, 0, 0, 0, 8, 0, 0, 0, 97,
        117, 116, 104, 111, 114, 101, 100, 0, 0, 0, 0, 1, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 9, 9, 9,
        9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
        9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
        9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
        9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 0, 0, 0,
        0,
    ];
    // v5 equivalent of the authored-change fixture: no escrow section (4 bytes
    // shorter). Pins the current writer's layout.
    const GOLDEN_SYNC_V5_AUTHORED: [u8; 173] = [
        5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
        5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
        5, 5, 5, 0, 0, 0, 0, 8, 0, 0, 0, 97, 117, 116, 104, 111,
        114, 101, 100, 0, 0, 0, 0, 1, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 1, 9, 9, 9, 9, 9, 9, 9,
        9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
        9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
        9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
        9, 9, 9, 9, 9, 9, 9, 9, 9, 0, 0, 0, 0,
    ];

    fn object(compressed: bool) -> SealedObject {
        SealedObject {
            nonce: [1; 12],
            ciphertext: vec![9, 9, 9],
            vis: Visibility::Public,
            grant_ids: vec!["*".into()],
            compressed,
        }
    }

    #[test]
    fn encoded_bundle_leads_with_version_marker() {
        let bytes = Frame::Sync { purges: vec![], body: empty_body() }.encode();
        assert_eq!(&bytes[..2], &[format::FORMAT_MAJOR, format::FORMAT_MINOR]);
    }

    #[test]
    fn v1_sync_bundle_still_decodes() {
        // A v2 build still reads the committed v1 wire bytes (newer reads older).
        assert!(matches!(Frame::decode(&GOLDEN_SYNC_V1).unwrap(), Frame::Sync { .. }));
    }

    #[test]
    fn v2_sync_bundle_still_decodes() {
        // A v3 build still reads the committed v2 wire bytes (newer reads older).
        assert!(matches!(Frame::decode(&GOLDEN_SYNC_V2).unwrap(), Frame::Sync { .. }));
    }

    #[test]
    fn v3_sync_bundle_still_decodes() {
        // A v4 build still reads the committed v3 wire bytes (newer reads older).
        assert!(matches!(Frame::decode(&GOLDEN_SYNC_V3).unwrap(), Frame::Sync { .. }));
    }

    #[test]
    fn v4_sync_bundle_still_decodes() {
        // A v5 build still reads the committed v4 wire bytes, dropping the
        // (empty) plaintext escrow section (newer reads older, ADR 0027).
        assert!(matches!(Frame::decode(&GOLDEN_SYNC_V4).unwrap(), Frame::Sync { .. }));
    }

    #[test]
    fn golden_v7_sync_bundle_matches_and_round_trips() {
        let bytes = Frame::Sync { purges: vec![], body: empty_body() }.encode();
        assert_eq!(bytes, GOLDEN_SYNC_V7, "v7 wire layout must not drift");
        assert!(matches!(Frame::decode(&GOLDEN_SYNC_V7).unwrap(), Frame::Sync { .. }));
        // A v7 build still reads the committed v6/v5 empty bundles (newer reads older).
        assert!(matches!(Frame::decode(&GOLDEN_SYNC_V6).unwrap(), Frame::Sync { .. }));
        assert!(matches!(Frame::decode(&GOLDEN_SYNC_V5).unwrap(), Frame::Sync { .. }));
    }

    #[test]
    fn golden_v7_authored_change_layout_matches_and_round_trips() {
        // Pins the wire layout for a change: author+sig (put_author_sig), the
        // durable change_id (put_change_id, v6/ADR 0029), then the predecessors
        // count (put_predecessors, v7/ADR 0032). A field-ordering regression
        // must break this test before it breaks interop with peers. The
        // expected v7 bytes are the v5 authored golden with the marker bumped,
        // a change_id-absent byte, and a 4-byte zero predecessors count, all
        // inserted right before the trailing 4-byte attestation count.
        let mut expected = GOLDEN_SYNC_V5_AUTHORED.to_vec();
        expected[0] = format::FORMAT_MAJOR;
        let at = expected.len() - 4;
        expected.splice(at..at, [0, 0, 0, 0, 0]); // change_id absent + preds count 0
        let node = ChangeNode {
            id: Oid([5; 32]),
            parents: vec![],
            message: "authored".into(),
            tree: BTreeMap::new(),
            author: Some([7; 32]),
            signature: Some([9; 64]),
            change_id: None,
            predecessors: Vec::new(),
        };
        let body = BundleBody {
            changes: vec![node],
            objs: BTreeMap::new(),
            keys: BTreeMap::new(),
            attestations: vec![],
        };
        let bytes = Frame::Sync { purges: vec![], body }.encode();
        assert_eq!(bytes, expected, "v7 authored-change wire layout must not drift");
        match Frame::decode(&expected).unwrap() {
            Frame::Sync { body, .. } => {
                assert_eq!(body.changes.len(), 1);
                assert_eq!(body.changes[0].author, Some([7; 32]));
                assert_eq!(body.changes[0].signature, Some([9; 64]));
                assert_eq!(body.changes[0].change_id, None);
                assert!(body.changes[0].predecessors.is_empty());
            }
            _ => panic!("expected Sync"),
        }
        // A v7 build still reads a v6 authored bundle (the v5 golden with the
        // v6 marker + change_id byte) and the committed v5 one, both as
        // predecessors-empty legacy.
        let mut v6 = GOLDEN_SYNC_V5_AUTHORED.to_vec();
        v6[0] = 6;
        v6.insert(v6.len() - 4, 0); // change_id absent
        for fixture in [v6.as_slice(), GOLDEN_SYNC_V5_AUTHORED.as_slice()] {
            match Frame::decode(fixture).unwrap() {
                Frame::Sync { body, .. } => {
                    assert_eq!(body.changes[0].author, Some([7; 32]));
                    assert!(body.changes[0].change_id.is_none(), "pre-v6 change has no change id");
                    assert!(body.changes[0].predecessors.is_empty(), "pre-v7 change has no predecessors");
                }
                _ => panic!("expected Sync"),
            }
        }
    }

    #[test]
    fn v4_authored_fixture_still_decodes_and_drops_escrow() {
        // The committed v4 fixture (which carries an escrow section) must stay
        // readable by a v5 build — and there is structurally nowhere for its
        // plaintext escrow keys to land (BundleBody has no escrow lane).
        match Frame::decode(&GOLDEN_SYNC_V4_AUTHORED).unwrap() {
            Frame::Sync { body, .. } => {
                assert_eq!(body.changes.len(), 1);
                assert_eq!(body.changes[0].author, Some([7; 32]));
            }
            _ => panic!("expected Sync"),
        }
    }

    #[test]
    fn v4_escrow_section_is_parsed_and_dropped() {
        // A v4 bundle whose escrow section actually carries a plaintext key:
        // the v5 reader must parse past it (cursor correctness — the trailing
        // change must decode) and drop the key on the floor.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[4, 0, 0]); // v4 marker + Sync tag
        put_u32(&mut bytes, 0); // purges
        put_u32(&mut bytes, 0); // objs
        put_u32(&mut bytes, 0); // keys
        put_u32(&mut bytes, 1); // ONE escrow entry
        bytes.extend_from_slice(&[6; 32]); // addr
        bytes.extend_from_slice(&[8; 32]); // plaintext content key
        bytes.extend_from_slice(&500u64.to_le_bytes()); // reveal_at
        put_u32(&mut bytes, 1); // one change (unauthored)
        bytes.extend_from_slice(&[5; 32]); // id
        put_u32(&mut bytes, 0); // parents
        put_bytes(&mut bytes, b"after escrow"); // message
        put_u32(&mut bytes, 0); // tree
        format::put_author_sig(&mut bytes, &None, &None);
        put_u32(&mut bytes, 0); // attestations
        match Frame::decode(&bytes).unwrap() {
            Frame::Sync { body, .. } => {
                assert_eq!(body.changes.len(), 1, "cursor must survive the escrow section");
                assert_eq!(body.changes[0].message, "after escrow");
                assert!(body.keys.is_empty(), "the plaintext escrow key must not surface");
            }
            _ => panic!("expected Sync"),
        }
    }

    #[test]
    fn bundle_attestation_round_trips() {
        let att = Attestation {
            change_id: Oid([5; 32]),
            attester: [7; 32],
            role: "reviewed".into(),
            signature: [9; 64],
        };
        let body = BundleBody {
            changes: vec![],
            objs: BTreeMap::new(),
            keys: BTreeMap::new(),
            attestations: vec![att.clone()],
        };
        match Frame::decode(&Frame::Sync { purges: vec![], body }.encode()).unwrap() {
            Frame::Sync { body, .. } => {
                assert_eq!(body.attestations.len(), 1, "attestation must survive the bundle");
                assert_eq!(body.attestations[0], att);
            }
            _ => panic!("expected Sync"),
        }
    }

    #[test]
    fn bundle_change_author_signature_and_change_id_round_trip() {
        let node = ChangeNode {
            id: Oid([5; 32]),
            parents: vec![],
            message: "authored".into(),
            tree: BTreeMap::new(),
            author: Some([7; 32]),
            signature: Some([9; 64]),
            change_id: Some([0xAB; 16]),
            // v7 (ADR 0032): supersession claims must survive the wire too.
            predecessors: vec![Oid([0xCD; 32]), Oid([0xEF; 32])],
        };
        let body = BundleBody {
            changes: vec![node],
            objs: BTreeMap::new(),
            keys: BTreeMap::new(),
            attestations: vec![],
        };
        match Frame::decode(&Frame::Sync { purges: vec![], body }.encode()).unwrap() {
            Frame::Sync { body, .. } => {
                let c = &body.changes[0];
                assert_eq!(c.author, Some([7; 32]), "author must survive the bundle");
                assert_eq!(c.signature, Some([9; 64]), "signature must survive the bundle");
                assert_eq!(
                    c.change_id,
                    Some([0xAB; 16]),
                    "durable change_id must survive the bundle (ADR 0029)"
                );
                assert_eq!(
                    c.predecessors,
                    vec![Oid([0xCD; 32]), Oid([0xEF; 32])],
                    "predecessors must survive the bundle (ADR 0032)"
                );
            }
            _ => panic!("expected Sync"),
        }
    }

    #[test]
    fn bundle_inline_object_compressed_flag_round_trips() {
        let obj = object(true);
        let addr = obj.address();
        let mut objs = BTreeMap::new();
        objs.insert(addr.clone(), obj);
        let body = BundleBody { changes: vec![], objs, keys: BTreeMap::new(), attestations: vec![] };
        match Frame::decode(&Frame::Sync { purges: vec![], body }.encode()).unwrap() {
            Frame::Sync { body, .. } => {
                assert!(
                    body.objs.get(&addr).expect("object present").compressed,
                    "inline object compressed flag must round-trip through the bundle"
                );
            }
            _ => panic!("expected Sync"),
        }
    }

    #[test]
    fn decode_rejects_incompatible_future_major() {
        let mut bytes = Frame::Sync { purges: vec![], body: empty_body() }.encode();
        bytes[0] = format::FORMAT_MAJOR + 1; // pretend a newer major wrote it
        assert!(matches!(
            Frame::decode(&bytes),
            Err(RepoError::UnsupportedFormat { .. })
        ));
    }

    #[test]
    fn sync_frame_round_trips_with_purges() {
        let f = Frame::Sync {
            purges: vec![(Oid([7; 32]), "bob".into())],
            body: empty_body(),
        };
        let bytes = f.encode();
        assert_eq!(bytes[2], 0, "sync tag follows the 2-byte version marker");
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
        assert_eq!(bytes[2], 1, "grant tag follows the 2-byte version marker");
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
            reveal_at: 12345,
            body: empty_body(),
        };
        let bytes = f.encode();
        assert_eq!(bytes[2], 3, "sealed-grant tag follows the 2-byte version marker");
        match Frame::decode(&bytes).unwrap() {
            Frame::SealedGrant { grantee_pubkey, wrapped_key, oid, reveal_at, .. } => {
                assert_eq!(grantee_pubkey, [1; 32]);
                assert_eq!(wrapped_key, [2; 80]);
                assert_eq!(oid, Oid([3; 32]));
                assert_eq!(reveal_at, 12345, "reveal_at must survive the frame (ADR 0027)");
            }
            _ => panic!("expected SealedGrant"),
        }
    }

    #[test]
    fn pre_v5_sealed_grant_decodes_as_untimed() {
        // A v4 sealed grant has no reveal_at in its header; a v5 reader treats
        // it as untimed (0) and keeps the body aligned.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[4, 0, 3]); // v4 marker + SealedGrant tag
        bytes.extend_from_slice(&[1; 32]); // grantee pubkey
        bytes.extend_from_slice(&[2; 80]); // wrapped key
        bytes.extend_from_slice(&[3; 32]); // oid
        // v4 body: objs, keys, escrow, changes (no attestations before... v4 HAS attestations)
        put_u32(&mut bytes, 0); // objs
        put_u32(&mut bytes, 0); // keys
        put_u32(&mut bytes, 0); // escrow (v4)
        put_u32(&mut bytes, 0); // changes
        put_u32(&mut bytes, 0); // attestations (v4)
        match Frame::decode(&bytes).unwrap() {
            Frame::SealedGrant { reveal_at, oid, .. } => {
                assert_eq!(reveal_at, 0, "pre-v5 grants are untimed");
                assert_eq!(oid, Oid([3; 32]));
            }
            _ => panic!("expected SealedGrant"),
        }
    }

    #[test]
    fn decode_rejects_empty_and_unknown_tag() {
        assert!(Frame::decode(&[]).is_err(), "empty input");
        // An unknown tag now sits after the 2-byte version marker.
        assert!(
            Frame::decode(&[format::FORMAT_MAJOR, format::FORMAT_MINOR, 9]).is_err(),
            "unknown tag"
        );
    }
}
