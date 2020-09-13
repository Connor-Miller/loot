//! Burn log — signed tombstones for destroyed objects (ADR 0038 §2–4, #344).
//!
//! `loot burn <path>` is the cure for a secret sealed public in finalized
//! history: it **destroys the object's bytes** and records a **signed
//! tombstone** here, while the change graph — every node, change id, signature,
//! and parent edge — is never touched (ADR 0018/0029/0034 invariants hold).
//! Absence then becomes *legible* rather than corruption:
//!
//! - `verify` reads a burn-logged oid's absence as deliberate, not damage;
//! - `surface`/checkout label the path **burned** in old changes;
//! - sync (`apply`/pull negotiation/`stow`) **permanently refuses to re-accept a
//!   burned oid**, closing the resurrection hole where a later pull would quietly
//!   restore the bytes from a relay that still holds them;
//! - `gc` treats a burned oid as already collected.
//!
//! Like the attestation lane (ADR 0018), loot-core is **verify-only** here: the
//! signing happens at the CLI with loot-identity, and a keyless repo records an
//! unauthored (all-zero burner/signature) tombstone. The log is a **shared,
//! append-only** store artifact — a burned oid is burned for every identity —
//! keyed by the burned address so a repeated burn is idempotent.

use crate::bundle_codec::{put_bytes, put_u32};
use crate::format::{self, Cursor};
use crate::{Oid, RepoError};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// The reserved marooned-identity sentinel that marks a **purge event** as a
/// burn tombstone rather than a hard-maroon key revocation (ADR 0038 §3). The
/// post-disclosure ("already pushed") tier deposits `(burned_oid, this)` on the
/// existing purge-event lane (ADR 0009/0010); a cooperating relay/peer that
/// sees it records the burn and stops holding the ciphertext. The control-byte
/// framing makes it impossible to collide with a real identity name.
pub const BURN_PURGE_MARKER: &str = "\u{0}burn\u{0}";

/// Which honesty tier a burn achieved (ADR 0038 §3), decided by whether the
/// object was ever disclosed past a `push` barrier (ADR 0031).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BurnTier {
    /// The only copy was local — destruction is **complete** (the true remedy).
    NeverPushed,
    /// Already disclosed — local destruction **plus** a purge event asking
    /// cooperating relays/peers to destroy their copy (honestly best-effort,
    /// exactly like hard maroon).
    Pushed,
}

impl BurnTier {
    fn tag(self) -> u8 {
        match self {
            BurnTier::NeverPushed => 0,
            BurnTier::Pushed => 1,
        }
    }

    fn from_tag(t: u8) -> Result<Self, RepoError> {
        match t {
            0 => Ok(BurnTier::NeverPushed),
            1 => Ok(BurnTier::Pushed),
            other => Err(RepoError::Backend(format!("unknown burn tier tag {other}"))),
        }
    }

    /// The human label burn prints and the record carries.
    pub fn label(self) -> &'static str {
        match self {
            BurnTier::NeverPushed => "never-pushed",
            BurnTier::Pushed => "pushed",
        }
    }
}

/// A signed tombstone: proof that an object's bytes were deliberately destroyed
/// (ADR 0038 §2). It records the burned address, the path it was burned from
/// (for the record and the git-side guidance), the tier, and — like an
/// [`Attestation`](crate::Attestation) — a detached ed25519 signature by the
/// identity that burned it. An all-zero `burner`/`signature` pair is an
/// *unauthored* tombstone: a keyless repo's own burn, or one **received** as a
/// purge event from a peer (the oid is all a bare purge event carries).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tombstone {
    /// The destroyed content address.
    pub oid: Oid,
    /// The path the object was burned from (empty for a received purge event).
    pub path: PathBuf,
    /// Which honesty tier the burn achieved.
    pub tier: BurnTier,
    /// The burner's ed25519 public key, or all-zero for an unauthored tombstone.
    pub burner: [u8; 32],
    /// Unix seconds the burn was recorded.
    pub burned_at: u64,
    /// ed25519 signature over [`signing_bytes`], or all-zero when unauthored.
    pub signature: [u8; 64],
}

/// Canonical bytes a tombstone signs over: the burned oid, path, tier tag,
/// burner pubkey, then the timestamp. Binding all of them means a tombstone
/// cannot be relabelled to a different oid/path/tier or replayed under a
/// different identity without breaking the signature.
pub fn signing_bytes(
    oid: &Oid,
    path: &std::path::Path,
    tier: BurnTier,
    burner: &[u8; 32],
    burned_at: u64,
) -> Vec<u8> {
    let path = path.to_string_lossy();
    let mut m = Vec::with_capacity(32 + path.len() + 1 + 32 + 8);
    m.extend_from_slice(&oid.0);
    m.extend_from_slice(path.as_bytes());
    m.push(tier.tag());
    m.extend_from_slice(burner);
    m.extend_from_slice(&burned_at.to_le_bytes());
    m
}

impl Tombstone {
    /// A tombstone with no author — a keyless repo's burn, or one received as a
    /// purge event (which carries only the oid). Its absence is still legible;
    /// it simply carries no signed provenance.
    pub fn unauthored(oid: Oid, path: PathBuf, tier: BurnTier, burned_at: u64) -> Self {
        Tombstone { oid, path, tier, burner: [0u8; 32], burned_at, signature: [0u8; 64] }
    }

    /// Whether this tombstone is unauthored (no burner key — a keyless burn or a
    /// received purge event).
    pub fn is_unauthored(&self) -> bool {
        self.burner == [0u8; 32]
    }

    /// Verify the tombstone's signature against its burner pubkey. An unauthored
    /// tombstone (all-zero burner) is valid iff its signature is also all-zero —
    /// there is nothing to forge. Pure and stateless (verify-only ed25519, like
    /// change-signature and attestation checking).
    pub fn verify(&self) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        if self.is_unauthored() {
            return self.signature == [0u8; 64];
        }
        let Ok(vk) = VerifyingKey::from_bytes(&self.burner) else {
            return false;
        };
        vk.verify(
            &signing_bytes(&self.oid, &self.path, self.tier, &self.burner, self.burned_at),
            &Signature::from_bytes(&self.signature),
        )
        .is_ok()
    }
}

/// Append-only set of tombstones, keyed by burned oid so a repeated burn is
/// idempotent (a burned oid is burned for every identity — ADR 0038). Shared,
/// travels in the store's `burn` artifact; consulted by `verify`, `surface`,
/// sync negotiation, `apply`, `stow`, and `gc`.
#[derive(Clone, Debug, Default)]
pub struct BurnLog {
    by_oid: BTreeMap<Oid, Tombstone>,
}

impl BurnLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// File a tombstone, idempotent on its oid. A later burn of the same oid
    /// wins (e.g. an authored tombstone replacing a received unauthored one, or
    /// a Pushed tier superseding a NeverPushed record).
    pub fn insert(&mut self, t: Tombstone) {
        self.by_oid.insert(t.oid.clone(), t);
    }

    /// Merge another log in (idempotent, append-only union).
    pub fn merge(&mut self, other: &BurnLog) {
        for t in other.by_oid.values() {
            // An authored tombstone is more informative than an unauthored one;
            // never let a bare received purge event overwrite signed provenance.
            match self.by_oid.get(&t.oid) {
                Some(existing) if !existing.is_unauthored() && t.is_unauthored() => {}
                _ => self.insert(t.clone()),
            }
        }
    }

    /// Whether `oid` is burned.
    pub fn contains(&self, oid: &Oid) -> bool {
        self.by_oid.contains_key(oid)
    }

    /// The tombstone for `oid`, if burned.
    pub fn get(&self, oid: &Oid) -> Option<&Tombstone> {
        self.by_oid.get(oid)
    }

    /// Every tombstone, for persistence and display.
    pub fn iter(&self) -> impl Iterator<Item = &Tombstone> {
        self.by_oid.values()
    }

    /// The set of burned addresses — what `verify`/`gc`/sync consult.
    pub fn burned_oids(&self) -> BTreeSet<Oid> {
        self.by_oid.keys().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.by_oid.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_oid.is_empty()
    }
}

// --- codec (shared, versioned like every durable artifact) ---

pub fn encode(log: &BurnLog) -> Vec<u8> {
    let mut out = Vec::new();
    format::put_version(&mut out);
    put_u32(&mut out, log.by_oid.len());
    for t in log.by_oid.values() {
        out.extend_from_slice(&t.oid.0);
        put_bytes(&mut out, t.path.to_string_lossy().as_bytes());
        out.push(t.tier.tag());
        out.extend_from_slice(&t.burner);
        out.extend_from_slice(&t.burned_at.to_le_bytes());
        out.extend_from_slice(&t.signature);
    }
    out
}

pub fn decode(b: &[u8]) -> Result<BurnLog, RepoError> {
    let mut c = Cursor { b, i: 0 };
    format::read_version(&mut c)?;
    let n = c.u32()?;
    let mut log = BurnLog::new();
    for _ in 0..n {
        let oid = Oid(c.arr32()?);
        let path = PathBuf::from(c.string()?);
        let tier = BurnTier::from_tag(c.take(1)?[0])?;
        let burner = c.arr32()?;
        let burned_at = c.u64()?;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(c.take(64)?);
        log.insert(Tombstone { oid, path, tier, burner, burned_at, signature });
    }
    Ok(log)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::path::Path;

    fn signer(seed: u8) -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn signed(sk: &SigningKey, pk: [u8; 32], oid: Oid, path: &str, tier: BurnTier) -> Tombstone {
        let p = Path::new(path);
        let sig = sk.sign(&signing_bytes(&oid, p, tier, &pk, 42)).to_bytes();
        Tombstone { oid, path: p.to_path_buf(), tier, burner: pk, burned_at: 42, signature: sig }
    }

    #[test]
    fn signed_tombstone_verifies() {
        let (sk, pk) = signer(7);
        assert!(signed(&sk, pk, Oid([1; 32]), ".env", BurnTier::NeverPushed).verify());
    }

    #[test]
    fn tampered_tier_fails_verify() {
        let (sk, pk) = signer(7);
        let mut t = signed(&sk, pk, Oid([1; 32]), ".env", BurnTier::NeverPushed);
        t.tier = BurnTier::Pushed; // signature covered NeverPushed
        assert!(!t.verify());
    }

    #[test]
    fn tampered_oid_fails_verify() {
        let (sk, pk) = signer(7);
        let mut t = signed(&sk, pk, Oid([1; 32]), ".env", BurnTier::NeverPushed);
        t.oid = Oid([2; 32]);
        assert!(!t.verify());
    }

    #[test]
    fn unauthored_tombstone_is_valid_only_when_unsigned() {
        let t = Tombstone::unauthored(Oid([3; 32]), PathBuf::from(".env"), BurnTier::Pushed, 1);
        assert!(t.verify(), "an all-zero burner/signature tombstone is a valid unauthored record");
        let mut forged = t.clone();
        forged.signature[0] = 1; // a nonzero sig with a zero burner is nonsense
        assert!(!forged.verify());
    }

    #[test]
    fn log_is_idempotent_and_queryable() {
        let (sk, pk) = signer(7);
        let mut log = BurnLog::new();
        log.insert(signed(&sk, pk, Oid([1; 32]), ".env", BurnTier::NeverPushed));
        log.insert(signed(&sk, pk, Oid([1; 32]), ".env", BurnTier::NeverPushed)); // dup
        log.insert(signed(&sk, pk, Oid([2; 32]), "id_rsa", BurnTier::Pushed));
        assert_eq!(log.len(), 2, "a repeated burn of the same oid is idempotent");
        assert!(log.contains(&Oid([1; 32])));
        assert_eq!(log.burned_oids(), BTreeSet::from([Oid([1; 32]), Oid([2; 32])]));
    }

    #[test]
    fn codec_round_trips_authored_and_unauthored() {
        let (sk, pk) = signer(9);
        let mut log = BurnLog::new();
        log.insert(signed(&sk, pk, Oid([5; 32]), "secrets/.env", BurnTier::Pushed));
        log.insert(Tombstone::unauthored(Oid([6; 32]), PathBuf::new(), BurnTier::Pushed, 100));
        let back = decode(&encode(&log)).unwrap();
        assert_eq!(back.len(), 2);
        let a = back.get(&Oid([5; 32])).unwrap();
        assert_eq!(a.path, PathBuf::from("secrets/.env"));
        assert_eq!(a.tier, BurnTier::Pushed);
        assert!(a.verify());
        assert!(back.get(&Oid([6; 32])).unwrap().is_unauthored());
    }

    #[test]
    fn merge_keeps_authored_over_received_unauthored() {
        let (sk, pk) = signer(9);
        let mut log = BurnLog::new();
        log.insert(signed(&sk, pk, Oid([5; 32]), ".env", BurnTier::Pushed));
        // A later received purge event (unauthored) for the same oid must not
        // clobber the signed provenance.
        let mut other = BurnLog::new();
        other.insert(Tombstone::unauthored(Oid([5; 32]), PathBuf::new(), BurnTier::Pushed, 1));
        log.merge(&other);
        assert!(!log.get(&Oid([5; 32])).unwrap().is_unauthored());
        // But a received purge for a NEW oid is filed.
        let mut third = BurnLog::new();
        third.insert(Tombstone::unauthored(Oid([8; 32]), PathBuf::new(), BurnTier::Pushed, 1));
        log.merge(&third);
        assert!(log.contains(&Oid([8; 32])));
    }
}
