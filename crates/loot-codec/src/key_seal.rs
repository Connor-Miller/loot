//! ECIES key wrapping — the pure, wasm-buildable core of sealed grant delivery.
//!
//! Seals a 32-byte [`ContentKey`](crate::sealed::ContentKey) to a recipient's
//! x25519 public key so a grant can travel through a relay without exposing the
//! key. The relay stores the ciphertext but cannot derive the wrapping key —
//! ECDH requires the recipient's private key.
//!
//! Extracted from `loot-identity` into `loot-codec` (ADR: TS SDK bridging, #381)
//! so the in-memory SDK's WASM build can wrap a private content key **to the
//! author's own identity** and unwrap it for same-session read-back — the exact
//! same composition the `loot` binary uses, so the two builds can never drift.
//! `loot-identity::key_seal` now re-exports these (preserving its `IdentityError`
//! surface); `loot-codec` owns the single implementation.
//!
//! ## Wire format (80 bytes)
//!
//! ```text
//! [ ephemeral_pubkey (32) ][ chacha20poly1305 ciphertext (32 plaintext + 16 tag = 48) ]
//! ```
//!
//! ## Protocol (ECIES over X25519 + ChaCha20-Poly1305)
//!
//! Seal:
//! 1. Generate ephemeral x25519 keypair.
//! 2. ECDH: `shared = ephemeral_private * recipient_x25519_pubkey`.
//! 3. Derive 32-byte wrapping key: `blake3_derive("loot grant key wrap 2024", shared || eph_pub)`.
//! 4. Encrypt the 32-byte content key (nonce = 0 — safe since eph key is unique per seal).
//! 5. Transmit `[ephemeral_pubkey (32)][ciphertext (48)]`.
//!
//! Unseal reverses it: derive the x25519 secret from the recipient's ed25519
//! signing key, ECDH with the envelope's ephemeral pubkey, derive the same
//! wrapping key, decrypt.
//!
//! ## ed25519 → x25519 derivation
//!
//! The x25519 secret is the SHA-512 lower half of the ed25519 seed, clamped per
//! RFC 8032 (`to_scalar_bytes`); the matching x25519 PUBLIC key follows from the
//! ed25519 pubkey via the Edwards→Montgomery map (`to_montgomery`). So peers need
//! only share their ed25519 pubkey — the encryption key derives automatically.

use crate::RepoError;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

/// The total size of a wrapped content key on the wire.
pub const WRAPPED_KEY_SIZE: usize = 80; // 32 ephemeral pubkey + 48 ciphertext (32 + 16 tag)

/// Derive an x25519 StaticSecret from an ed25519 signing key.
/// Uses `to_scalar_bytes()` — the SHA-512 lower half of the seed, clamped per
/// RFC 8032. The corresponding x25519 public key is `vk.to_montgomery()`.
/// This is the standard ed25519→x25519 derivation (Signal, WireGuard, etc.).
fn x25519_secret_from_signing_key(signing_key: &SigningKey) -> StaticSecret {
    StaticSecret::from(signing_key.to_scalar_bytes())
}

/// Derive the x25519 public key from an ed25519 verifying key via the
/// standard Edwards→Montgomery birational map. This allows a sender to
/// compute the recipient's x25519 pubkey from their stored ed25519 pubkey
/// (the OpenSSH line) without needing the recipient's private key.
pub fn x25519_pubkey_from_verifying_key(vk: &VerifyingKey) -> [u8; 32] {
    vk.to_montgomery().to_bytes()
}

/// Derive the x25519 public key from raw ed25519 public key bytes (32 bytes,
/// compressed Edwards Y). Returns an error if the bytes are not a valid
/// compressed Edwards point.
pub fn x25519_pubkey_from_ed25519_bytes(ed25519_pub: &[u8; 32]) -> Result<[u8; 32], RepoError> {
    let vk = VerifyingKey::from_bytes(ed25519_pub)
        .map_err(|e| RepoError::Backend(format!("invalid ed25519 pubkey: {e}")))?;
    Ok(x25519_pubkey_from_verifying_key(&vk))
}

/// Seal (wrap) a 32-byte content key to a recipient's x25519 public key.
/// Returns 80 bytes: `[ephemeral_pubkey (32)][ciphertext (48)]`.
pub fn seal_key(
    content_key: &[u8; 32],
    recipient_x25519_pubkey: &[u8; 32],
) -> Result<[u8; WRAPPED_KEY_SIZE], RepoError> {
    let recipient_pub = X25519PublicKey::from(*recipient_x25519_pubkey);
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_pub = X25519PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(&recipient_pub);

    let wrapping_key = derive_wrapping_key(shared.as_bytes(), ephemeral_pub.as_bytes());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&wrapping_key));
    let nonce = Nonce::default(); // all zeros — safe since ephemeral key is unique per seal

    let ct = cipher
        .encrypt(&nonce, content_key.as_ref())
        .map_err(|e| RepoError::Backend(format!("key seal encrypt: {e}")))?;

    let mut out = [0u8; WRAPPED_KEY_SIZE];
    out[..32].copy_from_slice(ephemeral_pub.as_bytes());
    out[32..].copy_from_slice(&ct);
    Ok(out)
}

/// Unseal (unwrap) a 80-byte wrapped key using the recipient's signing key.
pub fn unseal_key(
    wrapped: &[u8; WRAPPED_KEY_SIZE],
    signing_key: &SigningKey,
) -> Result<[u8; 32], RepoError> {
    let mut ephemeral_pub_bytes = [0u8; 32];
    ephemeral_pub_bytes.copy_from_slice(&wrapped[..32]);
    let ct = &wrapped[32..];

    let ephemeral_pub = X25519PublicKey::from(ephemeral_pub_bytes);
    let recipient_secret = x25519_secret_from_signing_key(signing_key);
    let shared = recipient_secret.diffie_hellman(&ephemeral_pub);

    let wrapping_key = derive_wrapping_key(shared.as_bytes(), &ephemeral_pub_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&wrapping_key));
    let nonce = Nonce::default();

    let plaintext = cipher
        .decrypt(&nonce, ct)
        .map_err(|_| RepoError::Backend("key unseal: wrong recipient or corrupt envelope".into()))?;

    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    Ok(key)
}

fn derive_wrapping_key(shared_secret: &[u8; 32], ephemeral_pub: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("loot grant key wrap 2024");
    h.update(shared_secret);
    h.update(ephemeral_pub);
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signing_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn recipient_x25519(signing_key: &SigningKey) -> [u8; 32] {
        x25519_pubkey_from_verifying_key(&signing_key.verifying_key())
    }

    #[test]
    fn seal_unseal_round_trip() {
        let sk = test_signing_key();
        let x25519_pub = recipient_x25519(&sk);

        let content_key = [0x42u8; 32];
        let wrapped = seal_key(&content_key, &x25519_pub).unwrap();
        let recovered = unseal_key(&wrapped, &sk).unwrap();
        assert_eq!(recovered, content_key);
    }

    #[test]
    fn x25519_pubkey_derived_from_ed25519_pub_matches_private_derivation() {
        let sk = test_signing_key();
        let from_pub = x25519_pubkey_from_verifying_key(&sk.verifying_key());
        let from_priv = *X25519PublicKey::from(&x25519_secret_from_signing_key(&sk)).as_bytes();
        assert_eq!(
            from_pub, from_priv,
            "x25519 pubkey derived from ed25519 pubkey must match private derivation"
        );
    }

    #[test]
    fn x25519_from_bytes_round_trips() {
        let sk = test_signing_key();
        let pub_bytes = sk.verifying_key().to_bytes();
        let x25519 = x25519_pubkey_from_ed25519_bytes(&pub_bytes).unwrap();
        assert_eq!(x25519, x25519_pubkey_from_verifying_key(&sk.verifying_key()));
    }

    #[test]
    fn wrong_recipient_cannot_unseal() {
        let alice = test_signing_key();
        let bob = test_signing_key();
        let alice_x25519 = recipient_x25519(&alice);

        let content_key = [0xABu8; 32];
        let wrapped = seal_key(&content_key, &alice_x25519).unwrap();
        assert!(unseal_key(&wrapped, &bob).is_err(), "wrong recipient must not unseal");
    }

    #[test]
    fn wrapped_key_is_80_bytes() {
        let sk = test_signing_key();
        let x25519_pub = recipient_x25519(&sk);
        let wrapped = seal_key(&[0u8; 32], &x25519_pub).unwrap();
        assert_eq!(wrapped.len(), WRAPPED_KEY_SIZE);
    }
}
