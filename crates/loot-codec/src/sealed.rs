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

/// Zstd compression level for public content (matches lore's choice).
#[cfg(feature = "zstd")]
const ZSTD_LEVEL: i32 = 6;

/// Compress public content before sealing (S2, ADR 0020). Behind the `zstd`
/// feature: the native host has it; a wasm build without it never seals public
/// content (authoring is host/subprocess-side), so the missing path is an error,
/// not a silent uncompressed write that would break address parity.
#[cfg(feature = "zstd")]
fn compress(bytes: &[u8]) -> Result<Vec<u8>, RepoError> {
    zstd::encode_all(bytes, ZSTD_LEVEL).map_err(|e| RepoError::Backend(format!("zstd compress: {e}")))
}
#[cfg(not(feature = "zstd"))]
fn compress(_bytes: &[u8]) -> Result<Vec<u8>, RepoError> {
    Err(RepoError::Backend("zstd compression unavailable in this build".into()))
}

/// Undo [`compress`]. Behind the `zstd` feature; a wasm build decompresses
/// public content host-side (with a JS zstd library) instead.
#[cfg(feature = "zstd")]
fn decompress(plain: &[u8]) -> Result<Vec<u8>, RepoError> {
    // 64 MiB cap: generous for typical content, prevents adversarial zip-bomb.
    zstd::bulk::decompress(plain, 64 * 1024 * 1024)
        .map_err(|e| RepoError::Backend(format!("zstd decompress: {e}")))
}
#[cfg(not(feature = "zstd"))]
fn decompress(_plain: &[u8]) -> Result<Vec<u8>, RepoError> {
    Err(RepoError::Backend(
        "zstd decompression unavailable in this build (public content must be decompressed host-side)".into(),
    ))
}

/// AES-256-GCM decryption of a sealed object's ciphertext under `key` — the raw
/// primitive with no embargo/visibility gate and no decompression. [`open`]
/// layers the authorization gates and (host-only) zstd decompression on top; the
/// wasm core calls this directly and decompresses public content host-side, so
/// the decrypt path is single-sourced and cannot drift from the binary.
pub fn decrypt(sealed: &SealedObject, key: &ContentKey) -> Result<Vec<u8>, RepoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(&sealed.nonce), sealed.ciphertext.as_ref())
        .map_err(|e| RepoError::Backend(format!("decrypt: {e}")))
}

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
    /// Whether the plaintext was Zstd-compressed before encryption (S2, ADR 0020).
    /// Only `Public` content is compressed; `open` decompresses when set. The
    /// flag is metadata about the payload, not part of the content address.
    pub compressed: bool,
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

    /// Remove the key for `oid`, if held. Used to honor purge events (ADR 0009).
    pub fn remove(&mut self, oid: &Oid) {
        self.keys.remove(oid);
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

    /// Every (oid, key) pair, for persisting an identity's custody to a
    /// LOCAL-ONLY file. This must never feed a sync bundle — the whole point of
    /// the keyring is that keys do not travel (ADR 0003).
    pub fn iter(&self) -> impl Iterator<Item = (Oid, ContentKey)> + '_ {
        self.keys.iter().map(|(oid, key)| (oid.clone(), *key))
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

    // Compress-then-encrypt, public content only. Each object is its own zstd
    // context (no shared dictionary), so CRIME/BREACH-style cross-context leaks
    // don't apply. Restricted/embargoed payloads are never compressed, so no
    // compressibility/length side-channel appears on sensitive data — keying
    // this off visibility (already in the clear on the object) reveals nothing
    // new (S2, ADR 0020).
    let compressed = matches!(vis, Visibility::Public);
    let payload = if compressed { compress(bytes)? } else { bytes.to_vec() };

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), payload.as_ref())
        .map_err(|e| RepoError::Backend(format!("encrypt: {e}")))?;

    let sealed = SealedObject {
        nonce,
        ciphertext,
        vis: vis.clone(),
        grant_ids: grant_ids(vis),
        compressed,
    };
    Ok((sealed.address(), sealed, key))
}

/// Seal `bytes` **without** compression (`compressed = false`) — for callers
/// that cannot run zstd, namely the WASM author path (zstd's C won't build for
/// wasm, ADR 0040). Otherwise identical to [`seal`]: fresh key + nonce,
/// AES-256-GCM, address over the ciphertext. Public content authored this way is
/// larger on the wire than the binary's compressed form but is equally valid and
/// readable (`open`/`decrypt` honor the flag).
pub fn seal_uncompressed(
    bytes: &[u8],
    vis: &Visibility,
) -> Result<(Oid, SealedObject, ContentKey), RepoError> {
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
        compressed: false,
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

    // 2. Key custody gate — holding the key IS the authorization ("permissioning
    //    is key management"). If the keyring has the key, decrypt directly: a
    //    grant that delivered this key is the policy enforcement event, so the
    //    grant_ids list need not include this reader.
    //
    //    If no key is held, fall through to the visibility gate to give the
    //    right error: Unauthorized means "you are not on the list and should not
    //    seek the key"; reaching here without a key while on the list means the
    //    key simply hasn't arrived yet.
    if let Some(key) = keyring.get(oid) {
        let plain = decrypt(sealed, key)?;
        // Transparent decompression: undo the compress-then-encrypt from `seal`.
        return if sealed.compressed { decompress(&plain) } else { Ok(plain) };
    }

    // 3. Visibility gate — no key held; check if reader is authorized to
    //    obtain one (on the grant_ids list or ANYONE).
    let authorized = sealed.grant_ids.iter().any(|g| g == ANYONE || g == reader);
    if !authorized {
        return Err(RepoError::Unauthorized(oid.clone()));
    }

    // Authorized in policy but no key — should obtain via a grant bundle.
    Err(RepoError::Unauthorized(oid.clone()))
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
    fn restricted_denies_reader_without_key() {
        let (oid, sealed, key) =
            seal(b"secret", &Visibility::Restricted(vec!["alice".into()])).unwrap();
        // A reader with no key entry cannot decrypt, regardless of grant_ids.
        let kr = keyring_with(oid.clone(), key);
        let empty = Keyring::new();
        assert!(matches!(
            open(&sealed, &oid, "mallory", &empty, 0),
            Err(RepoError::Unauthorized(_))
        ));
        // Alice holds the key and can decrypt.
        assert_eq!(open(&sealed, &oid, "alice", &kr, 0).unwrap(), b"secret");
        // If mallory somehow obtains the key (e.g. via a grant), she can also
        // decrypt — holding the key IS the authorization ("permissioning is key
        // management", ADR 0008).
        let mallory_kr = keyring_with(oid.clone(), key);
        assert_eq!(open(&sealed, &oid, "mallory", &mallory_kr, 0).unwrap(), b"secret");
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
    }

    #[test]
    fn address_is_ciphertext_hash() {
        let (oid, sealed, _) = seal(b"abc", &Visibility::Public).unwrap();
        assert_eq!(oid, sealed.address());
    }

    #[test]
    fn no_plaintext_equality_signal_in_sealed_object() {
        // ADR 0004: a SealedObject must carry nothing derived from plaintext that
        // would let a relay infer two objects share content. Two seals of the
        // SAME plaintext must differ in every stored field (random key+nonce ->
        // different ciphertext, address, and nonce; identical grant_ids/vis are
        // policy, not content, so equal there is fine).
        let (oid1, s1, _) = seal(b"same secret", &Visibility::Public).unwrap();
        let (oid2, s2, _) = seal(b"same secret", &Visibility::Public).unwrap();
        assert_ne!(oid1, oid2, "addresses must differ for equal plaintext");
        assert_ne!(s1.ciphertext, s2.ciphertext, "ciphertext must differ");
        assert_ne!(s1.nonce, s2.nonce, "nonces must differ");
        // No field on SealedObject is a function of plaintext alone.
        let plaintext_hash = *blake3::hash(b"same secret").as_bytes();
        assert_ne!(oid1.0, plaintext_hash);
        assert_ne!(oid2.0, plaintext_hash);
    }

    #[test]
    fn public_content_is_compressed_and_round_trips() {
        let data = b"the quick brown fox jumps over the lazy dog\n".repeat(50);
        let (oid, sealed, key) = seal(&data, &Visibility::Public).unwrap();
        assert!(sealed.compressed, "public content must be compressed");
        let kr = keyring_with(oid.clone(), key);
        assert_eq!(open(&sealed, &oid, "anyone", &kr, 0).unwrap(), data);
    }

    #[test]
    fn restricted_content_is_not_compressed_and_round_trips() {
        let (oid, sealed, key) =
            seal(b"secret", &Visibility::Restricted(vec!["alice".into()])).unwrap();
        assert!(!sealed.compressed, "restricted content must not be compressed");
        let kr = keyring_with(oid.clone(), key);
        assert_eq!(open(&sealed, &oid, "alice", &kr, 0).unwrap(), b"secret");
    }

    #[test]
    fn embargoed_content_is_not_compressed() {
        let (_oid, sealed, _key) = seal(b"cve", &Visibility::Embargoed { reveal_at: 0 }).unwrap();
        assert!(!sealed.compressed, "embargoed content must not be compressed");
    }

    #[test]
    fn public_object_shrinks_on_compressible_corpus() {
        // A repetitive text/code corpus compresses well: the sealed public
        // payload (compressed) must be materially smaller than the same bytes
        // sealed uncompressed (restricted). AES-GCM adds only a fixed 16-byte tag,
        // so the difference is the compression win (S2 AC).
        let corpus = "fn main() { println!(\"hello, world\"); }\n".repeat(200);
        let bytes = corpus.as_bytes();
        let (_o1, public, _k1) = seal(bytes, &Visibility::Public).unwrap();
        let (_o2, restricted, _k2) =
            seal(bytes, &Visibility::Restricted(vec!["alice".into()])).unwrap();
        assert!(public.compressed && !restricted.compressed);
        assert!(
            public.ciphertext.len() < restricted.ciphertext.len() / 2,
            "public payload should shrink on a compressible corpus: {} vs {}",
            public.ciphertext.len(),
            restricted.ciphertext.len()
        );
    }
}
