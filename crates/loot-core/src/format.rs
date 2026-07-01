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
pub const FORMAT_MAJOR: u8 = 1;
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
