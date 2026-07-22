//! ECIES key wrapping for sealed grant bundle delivery (ADR 0013/0014).
//!
//! The composition (ECDH over X25519 + ChaCha20-Poly1305, the "loot grant key
//! wrap 2024" KDF, the ed25519→x25519 derivation, the 80-byte wire format) now
//! lives in [`loot_codec::key_seal`] so the wasm in-memory SDK builds the exact
//! same code (ADR: TS SDK bridging, #381). This module stays as loot-identity's
//! native surface: thin delegates that preserve the [`IdentityError`] return type
//! its callers (loot-cli, loot-net) already expect. See `loot_codec::key_seal`
//! for the protocol and wire-format documentation.

use ed25519_dalek::{SigningKey, VerifyingKey};
use loot_codec::key_seal as core;
use super::IdentityError;

/// The total size of a wrapped content key on the wire (80 bytes).
pub use core::WRAPPED_KEY_SIZE;

/// Derive the x25519 public key from an ed25519 verifying key
/// (Edwards→Montgomery). Infallible — a re-export of the core primitive.
pub fn x25519_pubkey_from_verifying_key(vk: &VerifyingKey) -> [u8; 32] {
    core::x25519_pubkey_from_verifying_key(vk)
}

/// Derive the x25519 public key from raw ed25519 public key bytes.
pub fn x25519_pubkey_from_ed25519_bytes(ed25519_pub: &[u8; 32]) -> Result<[u8; 32], IdentityError> {
    core::x25519_pubkey_from_ed25519_bytes(ed25519_pub).map_err(codec_err)
}

/// Seal (wrap) a 32-byte content key to a recipient's x25519 public key.
/// Returns 80 bytes: `[ephemeral_pubkey (32)][ciphertext (48)]`.
pub fn seal_key(
    content_key: &[u8; 32],
    recipient_x25519_pubkey: &[u8; 32],
) -> Result<[u8; WRAPPED_KEY_SIZE], IdentityError> {
    core::seal_key(content_key, recipient_x25519_pubkey).map_err(codec_err)
}

/// Unseal (unwrap) a 80-byte wrapped key using the recipient's signing key.
pub fn unseal_key(
    wrapped: &[u8; WRAPPED_KEY_SIZE],
    signing_key: &SigningKey,
) -> Result<[u8; 32], IdentityError> {
    core::unseal_key(wrapped, signing_key).map_err(codec_err)
}

/// Map a `loot-codec` crypto error into loot-identity's error surface. A failed
/// unseal is a wrong-recipient/corrupt-envelope condition — the same class the
/// native path previously reported as `BadSignature`.
fn codec_err(e: loot_codec::RepoError) -> IdentityError {
    IdentityError::Format(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

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
        assert_eq!(unseal_key(&wrapped, &sk).unwrap(), content_key);
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
        let wrapped = seal_key(&[0xABu8; 32], &recipient_x25519(&alice)).unwrap();
        assert!(unseal_key(&wrapped, &bob).is_err(), "wrong recipient must not unseal");
    }

    #[test]
    fn wrapped_key_is_80_bytes() {
        let sk = test_signing_key();
        let wrapped = seal_key(&[0u8; 32], &recipient_x25519(&sk)).unwrap();
        assert_eq!(wrapped.len(), WRAPPED_KEY_SIZE);
    }
}
