//! Format versioning and the compatibility gate (S1).
//!
//! Every durable and on-wire artifact loot writes begins with a two-byte
//! version marker `[major][minor]`, checked on load and on receive. The marker
//! buys one guarantee, stated plainly: **a newer loot always reads what an
//! older loot wrote.**
//!
//! - `major` — the breaking version. A reader accepts any `major` up to and
//!   including its own [`FORMAT_MAJOR`]; a higher (unknown) major is rejected
//!   with a clear, actionable error instead of a corrupt parse. Bump `major`
//!   only for a change an older reader could not correctly parse.
//! - `minor` — a backward-compatible revision. Older readers of the same major
//!   tolerate a higher minor (they parse the prefix they understand). Bump
//!   `minor` for a purely additive change.
//!
//! `major = 0` is never written and always rejected, so a zeroed or truncated
//! header cannot masquerade as a valid artifact.
//!
//! The push envelope (loot-identity) predates this module and carries its own
//! `0x01` version byte; the durable artifacts (sealed object, repo state) and
//! the sync bundle are brought in line here. See `docs/adr/0019`.
//!
//! This module also owns [`Cursor`], the shared byte-slice reader used by every
//! codec. Keeping it here (rather than in `bundle_codec`) breaks the upward
//! dependency that `bundle_codec` would otherwise create.

use crate::RepoError;

/// A position-tracking read cursor over a byte slice. Owned here so that
/// `format` is a pure foundation module with no upward codec dependencies;
/// `bundle_codec` and `persist_codec` both import from here.
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
}

/// The newest breaking format version this build writes and can read.
///
/// - v2 (S2, ADR 0020) added the per-object `compressed` flag to the sealed-object
///   layout.
/// - v3 (S3, ADR 0018) added the per-change `author` pubkey + `signature` to the
///   change layout (bundle and durable graph).
/// - v4 (S4, ADR 0018) added the detachable attestation section to the bundle
///   body and a durable attestation log.
/// - v5 (ADR 0027, #14) removed the plaintext bundle escrow section (it shipped
///   raw embargoed `ContentKey` bytes to every peer and relay — the exact bypass
///   hard embargo closes) and added `reveal_at` to the SealedGrant frame header.
/// - v6 (ADR 0029, #143) added the durable per-change `change_id` (a random
///   16-byte handle stable across a working change's re-snapshots) beside the
///   change body, and widened the finalize signature to cover
///   `version_id ‖ change_id`. Additive: a legacy change decodes as
///   `change_id = None`, and its signature — over the 32-byte version id alone —
///   still verifies, because the signed message only grows when a change id is
///   present.
/// - v7 (ADR 0032, #171) added the per-change `predecessors` list — the version
///   ids this version **supersedes** (`loot edit`): amending mints a sibling
///   version under the same change id, and supersession travels as signed data.
///   The list is folded into the version-id computation and the finalize
///   signature widens to cover it. Additive: a v≤6 change decodes as
///   predecessors-empty, and an empty list adds nothing to either hash or
///   signature, so every existing id and signature is unchanged.
/// - v8 (#20) added an optional `expires_at` to a grant record — the durable
///   `GrantEntry` (manifest codec) and the SealedGrant frame header (tag 3) —
///   parallel to embargo's `reveal_at` but gating whether the grant is honored
///   at all rather than when its key becomes visible. Additive: a v≤7 manifest
///   entry or SealedGrant decodes with `expires_at = None` (never expires, the
///   pre-#20 behavior), and an unset `expires_at` adds nothing beyond one
///   presence byte, so existing grants are unaffected.
/// - v9 (#400) added the common-ancestor `base` OID to each `.loot/conflicts`
///   entry — the third side a 3-way merge tool (`loot resolve --tool`, #401)
///   needs. The entry layout grew a leading presence byte + optional 32-byte
///   base ahead of the existing ours/theirs pair, so an older reader parsing a
///   v9 conflicts file would mis-frame every entry. The loader migrates a v≤8
///   entry as `base = None` (no ancestor recorded). `.loot/conflicts` is
///   lane-local view state, never shipped on the wire, so no bundle/wire frame
///   changed — only the durable conflicts codec.
///
/// Each was a change an older reader cannot parse, so each bumped the major. A
/// v9 reader still reads v1–v8 artifacts (missing fields default to absent;
/// a v4 escrow section is parsed for cursor correctness but its plaintext keys
/// are DROPPED, never filed); an older reader cleanly rejects a newer major
/// rather than mis-parsing.
pub const FORMAT_MAJOR: u8 = 9;
/// The compatible revision this build writes.
pub const FORMAT_MINOR: u8 = 0;
/// Bytes the version marker occupies at the front of an artifact.
pub const MARKER_LEN: usize = 2;

/// Write the two-byte version marker `[major][minor]` at the front of `out`.
/// Call this before emitting any artifact body.
pub fn put_version(out: &mut Vec<u8>) {
    out.push(FORMAT_MAJOR);
    out.push(FORMAT_MINOR);
}

/// Read and check the two-byte version marker at the cursor.
///
/// Enforces the "newer reads older" rule: an unknown future major (greater than
/// [`FORMAT_MAJOR`]) — or the invalid major `0` — is rejected with
/// [`RepoError::UnsupportedFormat`] rather than misparsed. A known major with
/// any minor is accepted; the parsed `(major, minor)` is returned for callers
/// that wish to branch on it.
pub fn read_version(c: &mut Cursor) -> Result<(u8, u8), RepoError> {
    let marker = c.take(MARKER_LEN)?;
    let (major, minor) = (marker[0], marker[1]);
    if major == 0 || major > FORMAT_MAJOR {
        return Err(RepoError::UnsupportedFormat {
            found: major,
            supported: FORMAT_MAJOR,
        });
    }
    Ok((major, minor))
}

// --- authored-change fields (S3, ADR 0018), shared by the bundle and durable
// graph codecs so the on-wire and on-disk change layouts stay identical. ---

/// Write a change's optional author pubkey then optional signature, each as a
/// presence byte followed by its bytes (32 for the author, 64 for the sig).
pub fn put_author_sig(out: &mut Vec<u8>, author: &Option<[u8; 32]>, signature: &Option<[u8; 64]>) {
    match author {
        Some(a) => {
            out.push(1);
            out.extend_from_slice(a);
        }
        None => out.push(0),
    }
    match signature {
        Some(s) => {
            out.push(1);
            out.extend_from_slice(s);
        }
        None => out.push(0),
    }
}

/// Read a change's optional author pubkey + signature. From v3 on these follow
/// the change body; an older `major` predates them, so both are `None`
/// (unauthored) — this is the "newer reads older" path (ADR 0019/0018).
#[allow(clippy::type_complexity)]
pub fn read_author_sig(
    c: &mut Cursor,
    major: u8,
) -> Result<(Option<[u8; 32]>, Option<[u8; 64]>), RepoError> {
    if major < 3 {
        return Ok((None, None));
    }
    let author = if c.take(1)?[0] != 0 { Some(c.arr32()?) } else { None };
    // Only read the signature bytes when an author is present. If author is
    // absent the sig field has no meaning; skip its presence byte (and any
    // following bytes) so an anomalous author=0/sig=1 payload can't produce a
    // (None, Some(_)) pair that verify_authored_change silently accepts.
    let signature = if author.is_some() {
        if c.take(1)?[0] != 0 {
            let mut s = [0u8; 64];
            s.copy_from_slice(c.take(64)?);
            Some(s)
        } else {
            None
        }
    } else {
        // Consume the sig presence byte to keep the cursor in sync; ignore value.
        let _ = c.take(1)?;
        None
    };
    Ok((author, signature))
}

/// Write a change's optional durable `change_id` (v6, ADR 0029) as a presence
/// byte followed by its 16 bytes when present. Rides after the author+signature,
/// so the two-term (version id + change id) layout stays identical on disk and
/// on the wire.
pub fn put_change_id(out: &mut Vec<u8>, change_id: &Option<[u8; 16]>) {
    match change_id {
        Some(c) => {
            out.push(1);
            out.extend_from_slice(c);
        }
        None => out.push(0),
    }
}

/// Read a change's optional durable `change_id`. From v6 on it follows the
/// author+signature; an older `major` predates it, so the change loads as a
/// legacy change with no durable handle (`None`) — the "newer reads older" path
/// (ADR 0019/0029), with no backfill.
pub fn read_change_id(c: &mut Cursor, major: u8) -> Result<Option<[u8; 16]>, RepoError> {
    if major < 6 {
        return Ok(None);
    }
    if c.take(1)?[0] != 0 {
        let mut id = [0u8; 16];
        id.copy_from_slice(c.take(16)?);
        Ok(Some(id))
    } else {
        Ok(None)
    }
}

/// Write a change's `predecessors` — the version ids it supersedes (v7, ADR
/// 0032) — as a u32 count followed by each 32-byte version id. Rides after the
/// change id, shared by the bundle and durable graph codecs. An ordinary change
/// writes the empty list (count 0).
pub fn put_predecessors(out: &mut Vec<u8>, predecessors: &[crate::Oid]) {
    out.extend_from_slice(&(predecessors.len() as u32).to_le_bytes());
    for p in predecessors {
        out.extend_from_slice(&p.0);
    }
}

/// Read a change's `predecessors` list. From v7 on it follows the change id; an
/// older `major` predates supersession, so the change loads with the empty list
/// — the "newer reads older" path (ADR 0019/0032), with no backfill.
pub fn read_predecessors(c: &mut Cursor, major: u8) -> Result<Vec<crate::Oid>, RepoError> {
    if major < 7 {
        return Ok(Vec::new());
    }
    let n = c.u32()?;
    let mut preds = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        preds.push(crate::Oid(c.arr32()?));
    }
    Ok(preds)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(bytes: &[u8]) -> Result<(u8, u8), RepoError> {
        let mut c = Cursor { b: bytes, i: 0 };
        read_version(&mut c)
    }

    #[test]
    fn current_marker_round_trips() {
        let mut out = Vec::new();
        put_version(&mut out);
        assert_eq!(out, vec![FORMAT_MAJOR, FORMAT_MINOR]);
        assert_eq!(read(&out).unwrap(), (FORMAT_MAJOR, FORMAT_MINOR));
    }

    #[test]
    fn newer_reader_accepts_current_major() {
        // Any major <= ours is readable — this is the "newer reads older" rule.
        assert_eq!(read(&[1, 0]).unwrap(), (1, 0));
    }

    #[test]
    fn older_reader_tolerates_newer_minor() {
        // Same major, higher minor: an additive change stays readable.
        assert_eq!(read(&[FORMAT_MAJOR, 99]).unwrap(), (FORMAT_MAJOR, 99));
    }

    #[test]
    fn rejects_future_major_with_actionable_error() {
        let err = read(&[FORMAT_MAJOR + 1, 0]).unwrap_err();
        assert!(matches!(
            err,
            RepoError::UnsupportedFormat { found, supported }
                if found == FORMAT_MAJOR + 1 && supported == FORMAT_MAJOR
        ));
        assert!(err.to_string().contains("upgrade loot"));
    }

    #[test]
    fn rejects_zero_major() {
        assert!(matches!(
            read(&[0, 0]),
            Err(RepoError::UnsupportedFormat { .. })
        ));
    }

    #[test]
    fn rejects_truncated_marker() {
        assert!(read(&[FORMAT_MAJOR]).is_err(), "one byte is not a marker");
        assert!(read(&[]).is_err(), "empty is not a marker");
    }
}
