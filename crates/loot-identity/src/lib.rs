//! Identity keypairs for loot (ADR 0014).
//!
//! Every loot repo has one ed25519 identity keypair, generated at `loot init`
//! (or backfilled via `loot keygen`). It serves two purposes:
//!
//! - **Signing** — push envelopes carry a detached ed25519 signature so relays
//!   can verify authenticity and log accountability (who pushed what).
//! - **Encryption** — an x25519 key is derived from the ed25519 seed so grant
//!   bundles can be sealed to a recipient's public key rather than traveling as
//!   raw key bytes. This is the seam that makes relay delivery of grant bundles
//!   safe (ADR 0013).
//!
//! On-disk format: OpenSSH (ADR 0014). Private key at `.loot/id` (mode 0600),
//! public key at `.loot/id.pub`. Peer public keys are stored in `.loot/peers`
//! as `name = <openssh-pubkey-line>` pairs.
//!
//! ## Push envelope (ADR 0014, Q7)
//!
//! ```text
//! [ 0x01 ][ 32 bytes pubkey ][ 64 bytes signature ][ bundle bytes ... ]
//! ```
//!
//! The relay's `handle_stow` unwraps the 97-byte header, verifies the
//! signature, then passes the inner bundle bytes to `DagRepo::stow`.

use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use rand::rngs::OsRng;
use ssh_key::{PrivateKey, PublicKey, LineEnding};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

/// Prompt for a passphrase twice (new passphrase), confirming they match.
/// Returns `Err` on mismatch or I/O failure.
pub fn prompt_new_passphrase() -> Result<String, IdentityError> {
    let pass = rpassword::prompt_password("Enter export passphrase: ")
        .map_err(|e| IdentityError::Io(e.to_string()))?;
    let confirm = rpassword::prompt_password("Confirm passphrase: ")
        .map_err(|e| IdentityError::Io(e.to_string()))?;
    if pass != confirm {
        return Err(IdentityError::Format("passphrases do not match".into()));
    }
    if pass.is_empty() {
        return Err(IdentityError::Format("passphrase must not be empty".into()));
    }
    Ok(pass)
}

/// Prompt for an existing passphrase (import).
pub fn prompt_passphrase() -> Result<String, IdentityError> {
    rpassword::prompt_password("Enter passphrase: ")
        .map_err(|e| IdentityError::Io(e.to_string()))
}

mod peers;
pub mod key_seal;
pub use peers::PeerRegistry;
pub use key_seal::{seal_key, unseal_key, x25519_pubkey_from_verifying_key, x25519_pubkey_from_ed25519_bytes, WRAPPED_KEY_SIZE};

/// Version byte for the push envelope.
pub const ENVELOPE_VERSION: u8 = 0x01;
/// Size of the envelope header: version(1) + pubkey(32) + signature(64).
pub const ENVELOPE_HEADER: usize = 97;

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("io error: {0}")]
    Io(String),
    #[error("key format error: {0}")]
    Format(String),
    #[error("signature verification failed")]
    BadSignature,
    #[error("no identity keypair found — run `loot keygen` to generate one")]
    NoKeypair,
    #[error("envelope too short: need at least {ENVELOPE_HEADER} bytes")]
    EnvelopeTooShort,
    #[error("envelope version {0} not supported")]
    UnknownVersion(u8),
}

/// An identity keypair: ed25519 signing key + derived x25519 for encryption.
pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    /// Generate a fresh keypair from OS randomness.
    pub fn generate() -> Self {
        Identity { signing_key: SigningKey::generate(&mut OsRng) }
    }

    /// Load from OpenSSH private key file at `path`.
    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        let pem = std::fs::read_to_string(path)
            .map_err(|e| IdentityError::Io(e.to_string()))?;
        let private = PrivateKey::from_openssh(&pem)
            .map_err(|e| IdentityError::Format(e.to_string()))?;
        let key_data = private.key_data();
        let ed_key = key_data.ed25519()
            .ok_or_else(|| IdentityError::Format("expected ed25519 key".into()))?;
        let bytes: [u8; 32] = ed_key.private.to_bytes();
        Ok(Identity { signing_key: SigningKey::from_bytes(&bytes) })
    }

    /// Save to `.loot/id` (private, mode 0600) and `.loot/id.pub` (public).
    pub fn save(&self, dot: &Path, comment: &str) -> Result<(), IdentityError> {
        let private_path = dot.join("id");
        let public_path = dot.join("id.pub");

        let ed_private = ssh_key::private::Ed25519Keypair {
            public: ssh_key::public::Ed25519PublicKey(self.signing_key.verifying_key().to_bytes()),
            private: ssh_key::private::Ed25519PrivateKey::from_bytes(
                &self.signing_key.to_bytes()
            ),
        };
        let private = PrivateKey::new(
            ssh_key::private::KeypairData::Ed25519(ed_private),
            comment,
        ).map_err(|e| IdentityError::Format(e.to_string()))?;

        let pem = private.to_openssh(LineEnding::LF)
            .map_err(|e| IdentityError::Format(e.to_string()))?;
        std::fs::write(&private_path, pem.as_bytes())
            .map_err(|e| IdentityError::Io(e.to_string()))?;

        // chmod 0600 on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&private_path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| IdentityError::Io(e.to_string()))?;
        }

        let public = private.public_key();
        let pub_line = public.to_openssh()
            .map_err(|e| IdentityError::Format(e.to_string()))?;
        std::fs::write(&public_path, format!("{pub_line}\n"))
            .map_err(|e| IdentityError::Io(e.to_string()))?;

        Ok(())
    }

    /// The ed25519 public key bytes (32 bytes).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// The x25519 public key bytes for sealed grant delivery (ADR 0014).
    pub fn x25519_pubkey_bytes(&self) -> [u8; 32] {
        key_seal::x25519_pubkey_from_verifying_key(&self.signing_key.verifying_key())
    }

    /// Unseal a wrapped content key addressed to this identity.
    pub fn unseal_key(&self, wrapped: &[u8; WRAPPED_KEY_SIZE]) -> Result<[u8; 32], IdentityError> {
        key_seal::unseal_key(wrapped, &self.signing_key)
    }

    /// The OpenSSH public key line (for sharing with peers / `loot whoami`).
    pub fn public_key_openssh(&self, comment: &str) -> Result<String, IdentityError> {
        let pub_key = PublicKey::from_openssh(
            &self.to_openssh_pub_line(comment)?
        ).map_err(|e| IdentityError::Format(e.to_string()))?;
        pub_key.to_openssh().map_err(|e| IdentityError::Format(e.to_string()))
    }

    fn to_openssh_pub_line(&self, comment: &str) -> Result<String, IdentityError> {
        // Build from raw bytes via ssh-key's KeyData
        let key_data = ssh_key::public::KeyData::Ed25519(
            ssh_key::public::Ed25519PublicKey(self.signing_key.verifying_key().to_bytes())
        );
        let pub_key = PublicKey::new(key_data, comment);
        pub_key.to_openssh().map_err(|e| IdentityError::Format(e.to_string()))
    }

    /// Export this keypair to `path`, passphrase-encrypted (OpenSSH native encryption).
    /// The exported file is the highest-risk artifact — always passphrase-wrapped,
    /// unlike the in-repo `.loot/id` which relies on filesystem permissions.
    pub fn export_encrypted(&self, path: &Path, passphrase: &str, comment: &str) -> Result<(), IdentityError> {
        let ed_private = ssh_key::private::Ed25519Keypair {
            public: ssh_key::public::Ed25519PublicKey(self.signing_key.verifying_key().to_bytes()),
            private: ssh_key::private::Ed25519PrivateKey::from_bytes(&self.signing_key.to_bytes()),
        };
        let private = PrivateKey::new(
            ssh_key::private::KeypairData::Ed25519(ed_private),
            comment,
        ).map_err(|e| IdentityError::Format(e.to_string()))?;

        let encrypted = private.encrypt(&mut OsRng, passphrase)
            .map_err(|e| IdentityError::Format(format!("encrypt: {e}")))?;

        let pem = encrypted.to_openssh(LineEnding::LF)
            .map_err(|e| IdentityError::Format(e.to_string()))?;

        std::fs::write(path, pem.as_bytes())
            .map_err(|e| IdentityError::Io(e.to_string()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| IdentityError::Io(e.to_string()))?;
        }

        Ok(())
    }

    /// Load an identity from a passphrase-encrypted export file.
    /// Returns `Err(Format)` if the passphrase is wrong or the file is invalid.
    pub fn import_encrypted(path: &Path, passphrase: &str) -> Result<Self, IdentityError> {
        let pem = std::fs::read_to_string(path)
            .map_err(|e| IdentityError::Io(e.to_string()))?;
        let encrypted = PrivateKey::from_openssh(&pem)
            .map_err(|e| IdentityError::Format(e.to_string()))?;

        if !encrypted.is_encrypted() {
            return Err(IdentityError::Format("export file is not passphrase-encrypted — refusing to import".into()));
        }

        let private = encrypted.decrypt(passphrase)
            .map_err(|_| IdentityError::Format("wrong passphrase or corrupt export file".into()))?;

        let key_data = private.key_data();
        let ed_key = key_data.ed25519()
            .ok_or_else(|| IdentityError::Format("expected ed25519 key in export file".into()))?;
        let bytes: [u8; 32] = ed_key.private.to_bytes();
        Ok(Identity { signing_key: SigningKey::from_bytes(&bytes) })
    }

    /// Sign `message` and return a 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    /// Wrap `bundle_bytes` in a signed push envelope:
    /// `[0x01][pubkey 32][signature 64][bundle...]`
    pub fn wrap_envelope(&self, bundle_bytes: &[u8]) -> Vec<u8> {
        let pubkey = self.public_key_bytes();
        let sig = self.sign(bundle_bytes);
        let mut out = Vec::with_capacity(ENVELOPE_HEADER + bundle_bytes.len());
        out.push(ENVELOPE_VERSION);
        out.extend_from_slice(&pubkey);
        out.extend_from_slice(&sig);
        out.extend_from_slice(bundle_bytes);
        out
    }
}

/// Check whether `dot/.loot/id` exists.
pub fn keypair_exists(dot: &Path) -> bool {
    dot.join("id").exists()
}

/// Unwrap and verify a push envelope. Returns `(pubkey_bytes, bundle_bytes)`.
/// `allowed` — if non-empty, the pubkey must be in the set.
pub fn unwrap_envelope<'a>(
    data: &'a [u8],
    allowed: &[[u8; 32]],
) -> Result<([u8; 32], &'a [u8]), IdentityError> {
    if data.len() < ENVELOPE_HEADER {
        return Err(IdentityError::EnvelopeTooShort);
    }
    let version = data[0];
    if version != ENVELOPE_VERSION {
        return Err(IdentityError::UnknownVersion(version));
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&data[1..33]);
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&data[33..97]);
    let bundle = &data[ENVELOPE_HEADER..];

    let verifying = VerifyingKey::from_bytes(&pubkey)
        .map_err(|_| IdentityError::BadSignature)?;
    let sig = Signature::from_bytes(&sig_bytes);
    verifying.verify(bundle, &sig)
        .map_err(|_| IdentityError::BadSignature)?;

    if !allowed.is_empty() && !allowed.contains(&pubkey) {
        return Err(IdentityError::BadSignature);
    }

    Ok((pubkey, bundle))
}

/// Load the identity from `dot/id`, returning `Err(NoKeypair)` if absent.
pub fn load_or_missing(dot: &Path) -> Result<Identity, IdentityError> {
    let path = dot.join("id");
    if !path.exists() {
        return Err(IdentityError::NoKeypair);
    }
    Identity::load(&path)
}

/// Generate and save a new keypair at `dot/id` and `dot/id.pub`.
/// Fails if a keypair already exists (use `load_or_missing` to check first).
pub fn generate_and_save(dot: &Path, comment: &str) -> Result<Identity, IdentityError> {
    let id = Identity::generate();
    id.save(dot, comment)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir()
            .join(format!("loot-id-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn generate_save_load_round_trips() {
        let dir = tmp("rtrip");
        let id = Identity::generate();
        let pubkey = id.public_key_bytes();
        id.save(&dir, "test@loot").unwrap();

        let loaded = Identity::load(&dir.join("id")).unwrap();
        assert_eq!(loaded.public_key_bytes(), pubkey);
    }

    #[test]
    fn envelope_sign_verify_round_trip() {
        let id = Identity::generate();
        let bundle = b"some sealed bytes";
        let env = id.wrap_envelope(bundle);
        assert_eq!(env.len(), ENVELOPE_HEADER + bundle.len());
        let (pubkey, inner) = unwrap_envelope(&env, &[]).unwrap();
        assert_eq!(pubkey, id.public_key_bytes());
        assert_eq!(inner, bundle);
    }

    #[test]
    fn allowlist_rejects_unknown_key() {
        let id = Identity::generate();
        let other = Identity::generate();
        let env = id.wrap_envelope(b"bundle");
        let allowed = [other.public_key_bytes()];
        assert!(matches!(unwrap_envelope(&env, &allowed), Err(IdentityError::BadSignature)));
    }

    #[test]
    fn allowlist_accepts_known_key() {
        let id = Identity::generate();
        let env = id.wrap_envelope(b"bundle");
        let allowed = [id.public_key_bytes()];
        assert!(unwrap_envelope(&env, &allowed).is_ok());
    }

    #[test]
    fn tampered_bundle_fails_verify() {
        let id = Identity::generate();
        let mut env = id.wrap_envelope(b"bundle");
        // Flip a byte in the bundle portion
        let last = env.len() - 1;
        env[last] ^= 0xff;
        assert!(matches!(unwrap_envelope(&env, &[]), Err(IdentityError::BadSignature)));
    }

    #[test]
    fn id_pub_is_written_as_openssh_line() {
        let dir = tmp("publine");
        let id = Identity::generate();
        id.save(&dir, "alice@loot").unwrap();
        let pub_line = std::fs::read_to_string(dir.join("id.pub")).unwrap();
        assert!(pub_line.starts_with("ssh-ed25519 "), "expected openssh pubkey, got: {pub_line}");
    }

    #[test]
    fn keypair_exists_detects_presence() {
        let dir = tmp("exists");
        assert!(!keypair_exists(&dir));
        let id = Identity::generate();
        id.save(&dir, "test").unwrap();
        assert!(keypair_exists(&dir));
    }

    #[test]
    fn export_import_round_trips_keypair() {
        let dir = tmp("export");
        let id = Identity::generate();
        let pubkey = id.public_key_bytes();
        let export_path = dir.join("id.export");

        id.export_encrypted(&export_path, "hunter2", "alice@loot").unwrap();

        // Exported file must exist and be non-empty.
        let bytes = std::fs::read(&export_path).unwrap();
        assert!(!bytes.is_empty());

        // Round-trip: import recovers the same keypair.
        let imported = Identity::import_encrypted(&export_path, "hunter2").unwrap();
        assert_eq!(imported.public_key_bytes(), pubkey, "import must recover the original keypair");
    }

    #[test]
    fn import_rejects_wrong_passphrase() {
        let dir = tmp("wrongpass");
        let id = Identity::generate();
        let export_path = dir.join("id.export");
        id.export_encrypted(&export_path, "correct", "test@loot").unwrap();

        let result = Identity::import_encrypted(&export_path, "wrong");
        assert!(result.is_err(), "wrong passphrase must fail");
    }

    #[test]
    fn export_file_is_passphrase_encrypted() {
        let dir = tmp("encrypted");
        let id = Identity::generate();
        let export_path = dir.join("id.export");
        id.export_encrypted(&export_path, "passphrase", "test@loot").unwrap();

        // Loading the raw file without decrypting it must report is_encrypted.
        let pem = std::fs::read_to_string(&export_path).unwrap();
        let raw = ssh_key::PrivateKey::from_openssh(&pem).unwrap();
        assert!(raw.is_encrypted(), "export file must be passphrase-encrypted");
    }

    #[test]
    fn import_rejects_unencrypted_file() {
        let dir = tmp("unenc");
        let id = Identity::generate();
        // save() writes unencrypted — import must refuse it
        id.save(&dir, "test@loot").unwrap();
        let result = Identity::import_encrypted(&dir.join("id"), "any-passphrase");
        assert!(result.is_err(), "unencrypted key file must be rejected by import");
    }
}
