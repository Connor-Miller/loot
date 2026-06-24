//! Sealed content — loot's thesis as one deep module.
//!
//! "Permissioning is key management." This module owns the whole of it:
//! encryption, visibility, and embargo, behind two operations.
//!
//!   - [`seal`] turns plaintext + a [`Visibility`] policy into a
//!     [`SealedObject`] (ciphertext, never a key) plus the freshly-minted
//!     [`ContentKey`]. The caller files the key into a [`Keyring`].
//!   - [`open`] is the single authorization chokepoint. It enforces embargo
//!     (by `now`), then visibility, then decrypts. Nothing else in loot
//!     decides who may read content.
//!
//! Key custody (ADR 0003): content keys live ONLY in a [`Keyring`], never in a
//! [`SealedObject`]. A SealedObject is therefore safe to store and to sync — it
//! cannot leak a key, because it never holds one. A peer lacking a keyring
//! entry simply cannot decrypt, which is exactly the relay role from ADR 0001.

use crate::{Oid, RepoError, Visibility};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use std::collections::BTreeMap;

/// A symmetric content key. Lives in a [`Keyring`], never in a [`SealedObject`].
pub type ContentKey = [u8; 32];

/// Grant id meaning "anyone who can read the repo holds the key" — used for
/// `Public` and `Embargoed` content.
pub const ANYONE: &str = "*";

/// Encrypted content with its access policy — but no key.
///
/// Carries everything needed to *store* and *relay* content, and everything
/// `open` needs to *authorize* a read, while deliberately holding nothing that
/// could decrypt it. `grant_ids` names the identities permitted to hold a key;
/// the keys themselves live in [`Keyring`]s.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedObject {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub vis: Visibility,
    /// Identities permitted to hold this content's key (names, never keys).
    /// `[ANYONE]` for Public/Embargoed; the listed identities for Restricted.
    pub grant_ids: Vec<String>,
    /// `blake3(plaintext)` — dedup identity, deliberately NOT the address.
    pub identity_hash: [u8; 32],
}

impl SealedObject {
    /// The content address: `blake3(nonce || ciphertext)`. Computed, not stored,
    /// so a SealedObject and its address can never drift apart.
    pub fn address(&self) -> Oid {
        let mut h = blake3::Hasher::new();
        h.update(&self.nonce);
        h.update(&self.ciphertext);
        Oid(*h.finalize().as_bytes())
    }
}

/// An identity's private custody of content keys. Keys live here and only here.
///
/// `open` consults a keyring to decrypt; a relay peer simply holds no entry for
/// a given object and so cannot read it. This is the structural reason the sync
/// key-leak is impossible: nothing serializes a keyring.
#[derive(Clone, Debug, Default)]
pub struct Keyring {
    keys: BTreeMap<Oid, ContentKey>,
}

impl Keyring {
    pub fn new() -> Self {
        Self::default()
    }

    /// File a content key under its object address.
    pub fn insert(&mut self, oid: Oid, key: ContentKey) {
        self.keys.insert(oid, key);
    }

    /// Does this keyring hold the key for `oid`?
    pub fn holds(&self, oid: &Oid) -> bool {
        self.keys.contains_key(oid)
    }

    /// A copy of the key for `oid`, if held. Used by a backend to ship keys for
    /// `ANYONE`-granted content during sync; Restricted keys must never be
    /// shipped (ADR 0003), so callers gate on grant ids, not on this accessor.
    pub fn key_for(&self, oid: &Oid) -> Option<ContentKey> {
        self.keys.get(oid).copied()
    }

    fn get(&self, oid: &Oid) -> Option<&ContentKey> {
        self.keys.get(oid)
    }
}

fn random_bytes<const N: usize>() -> Result<[u8; N], RepoError> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|e| RepoError::Backend(e.to_string()))?;
    Ok(buf)
}

/// Grant ids implied by a visibility policy.
pub fn grant_ids(vis: &Visibility) -> Vec<String> {
    match vis {
        Visibility::Public | Visibility::Embargoed { .. } => vec![ANYONE.to_string()],
        Visibility::Restricted(ids) => ids.clone(),
    }
}

/// Encrypt `bytes` under a fresh content key.
///
/// Returns the content address, the [`SealedObject`] (no key inside), and the
/// freshly-minted [`ContentKey`]. The caller is responsible for filing the key
/// into the keyrings of the granted identities (the backend already owns those
/// keyrings); `seal` itself never mutates custody.
pub fn seal(bytes: &[u8], vis: &Visibility) -> Result<(Oid, SealedObject, ContentKey), RepoError> {
    let key: ContentKey = random_bytes()?;
    let nonce: [u8; 12] = random_bytes()?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), bytes)
        .map_err(|e| RepoError::Backend(format!("encrypt: {e}")))?;

    let sealed = SealedObject {
        nonce,
        ciphertext,
        vis: vis.clone(),
        grant_ids: grant_ids(vis),
        identity_hash: *blake3::hash(bytes).as_bytes(),
    };
    Ok((sealed.address(), sealed, key))
}

/// The single authorization chokepoint. Returns the plaintext only if `reader`
/// is allowed to see it *now*.
///
/// Order matters and is part of the interface:
///   1. **embargo** — before `reveal_at`, refuse for everyone (even a keyholder).
///   2. **visibility** — `reader` must be authorized: `ANYONE`-granted content
///      is open to all; `Restricted` content requires `reader` in `grant_ids`.
///   3. **key** — the supplied `keyring` must actually hold the content key.
///
/// Steps 2 and 3 are distinct on purpose: an authorized reader who lacks the
/// key gets `Unauthorized` (they should obtain the key), not a decrypt error.
pub fn open(
    sealed: &SealedObject,
    oid: &Oid,
    reader: &str,
    keyring: &Keyring,
    now: u64,
) -> Result<Vec<u8>, RepoError> {
    // 1. Embargo gate — time, not identity.
    if let Visibility::Embargoed { reveal_at } = sealed.vis {
        if now < reveal_at {
            return Err(RepoError::Embargoed(reveal_at));
        }
    }

    // 2. Visibility gate.
    let authorized = sealed.grant_ids.iter().any(|g| g == ANYONE || g == reader);
    if !authorized {
        return Err(RepoError::Unauthorized(oid.clone()));
    }

    // 3. Key custody gate.
    let key = keyring
        .get(oid)
        .ok_or_else(|| RepoError::Unauthorized(oid.clone()))?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(&sealed.nonce), sealed.ciphertext.as_ref())
        .map_err(|e| RepoError::Backend(format!("decrypt: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyring_with(oid: Oid, key: ContentKey) -> Keyring {
        let mut k = Keyring::new();
        k.insert(oid, key);
        k
    }

    #[test]
    fn public_round_trips_for_any_reader() {
        let (oid, sealed, key) = seal(b"hello", &Visibility::Public).unwrap();
        let kr = keyring_with(oid.clone(), key);
        assert_eq!(open(&sealed, &oid, "anyone", &kr, 0).unwrap(), b"hello");
    }

    #[test]
    fn restricted_denies_unlisted_reader_before_touching_key() {
        let (oid, sealed, key) =
            seal(b"secret", &Visibility::Restricted(vec!["alice".into()])).unwrap();
        // Even a keyring holding the key must not help an unauthorized reader.
        let kr = keyring_with(oid.clone(), key);
        assert!(matches!(
            open(&sealed, &oid, "mallory", &kr, 0),
            Err(RepoError::Unauthorized(_))
        ));
        assert_eq!(open(&sealed, &oid, "alice", &kr, 0).unwrap(), b"secret");
    }

    #[test]
    fn authorized_reader_without_key_is_unauthorized_not_decrypt_error() {
        let (oid, sealed, _key) =
            seal(b"secret", &Visibility::Restricted(vec!["alice".into()])).unwrap();
        let empty = Keyring::new();
        assert!(matches!(
            open(&sealed, &oid, "alice", &empty, 0),
            Err(RepoError::Unauthorized(_))
        ));
    }

    #[test]
    fn embargo_seals_before_reveal_then_opens() {
        let (oid, sealed, key) = seal(b"cve fix", &Visibility::Embargoed { reveal_at: 100 }).unwrap();
        let kr = keyring_with(oid.clone(), key);
        assert!(matches!(
            open(&sealed, &oid, "anyone", &kr, 99),
            Err(RepoError::Embargoed(100))
        ));
        assert_eq!(open(&sealed, &oid, "anyone", &kr, 100).unwrap(), b"cve fix");
    }

    #[test]
    fn sealed_object_holds_no_key_material() {
        // Structural guarantee behind ADR 0003: nothing in a SealedObject is
        // the content key. We assert the key is unequal to every field's bytes.
        let (_oid, sealed, key) = seal(b"x", &Visibility::Public).unwrap();
        assert_ne!(&sealed.ciphertext[..], &key[..]);
        assert_ne!(&sealed.nonce[..], &key[..12]);
        assert_ne!(sealed.identity_hash, key);
    }

    #[test]
    fn address_is_ciphertext_hash_identity_is_plaintext_hash() {
        let (oid, sealed, _) = seal(b"abc", &Visibility::Public).unwrap();
        assert_eq!(oid, sealed.address());
        assert_eq!(sealed.identity_hash, *blake3::hash(b"abc").as_bytes());
        assert_ne!(oid.0, sealed.identity_hash);
    }
}
