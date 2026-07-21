//! Attestation lane — detachable, advisory signatures over a change (S4, ADR 0018).
//!
//! An [`Attestation`] is an extra signature by some identity over an existing
//! change id: a co-author, a reviewer sign-off, a countersignature. Unlike the
//! author signature (ADR 0018), which is folded into the change id and fatal on
//! failure, an attestation is **detachable metadata**: it never enters the change
//! id, never affects convergence, and an invalid one is *dropped* rather than
//! rejecting the whole bundle. Attestations are verified and displayed
//! (`loot log`, `loot manifest`), mirroring how a grant is a fact plus a
//! detachable signed proof (ADR 0015).
//!
//! loot-core is verify-only here (as with change signatures, ADR 0018);
//! attesting — the signing — happens at the CLI with loot-identity.

use crate::Oid;
use std::collections::BTreeMap;

/// A detachable signature over a change id by some identity, with a role tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation {
    /// The change being attested. Never modified by the attestation.
    pub change_id: Oid,
    /// The attester's ed25519 public key.
    pub attester: [u8; 32],
    /// A free-form, advisory role/type tag: "co-author", "reviewed", ...
    pub role: String,
    /// ed25519 signature over [`signing_bytes`]`(change_id, attester, role)`.
    pub signature: [u8; 64],
}

/// Canonical bytes an attestation signs over: the change id, the attester
/// pubkey, then the role tag. Binding the attester and role into the signed
/// message means an attestation cannot be replayed under a different identity
/// or relabelled to a different role without breaking the signature.
pub fn signing_bytes(change_id: &Oid, attester: &[u8; 32], role: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(32 + 32 + role.len());
    m.extend_from_slice(&change_id.0);
    m.extend_from_slice(attester);
    m.extend_from_slice(role.as_bytes());
    m
}

impl Attestation {
    /// Verify this attestation's signature against its attester pubkey. Pure and
    /// stateless (verify-only ed25519, like change-signature checking).
    pub fn verify(&self) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let Ok(vk) = VerifyingKey::from_bytes(&self.attester) else {
            return false;
        };
        vk.verify(
            &signing_bytes(&self.change_id, &self.attester, &self.role),
            &Signature::from_bytes(&self.signature),
        )
        .is_ok()
    }
}

/// Append-only set of attestations, keyed by `(change_id, attester, role)` so a
/// repeated attestation is idempotent. Travels in bundles and persists beside
/// the graph. Advisory only — never affects a change id or convergence.
#[derive(Clone, Debug, Default)]
pub struct AttestationLog {
    entries: BTreeMap<(Oid, [u8; 32], String), Attestation>,
}

impl AttestationLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an attestation, idempotent on `(change_id, attester, role)`.
    pub fn insert(&mut self, att: Attestation) {
        self.entries
            .insert((att.change_id.clone(), att.attester, att.role.clone()), att);
    }

    /// Merge another log in (idempotent).
    pub fn merge(&mut self, other: &AttestationLog) {
        for att in other.entries.values() {
            self.insert(att.clone());
        }
    }

    /// Every attestation, for persistence and display.
    pub fn iter(&self) -> impl Iterator<Item = &Attestation> {
        self.entries.values()
    }

    /// Attestations over a specific change, for display. Entries are keyed by
    /// `(change_id, attester, role)`, so all rows for one change are contiguous:
    /// seek to the change's lower bound and walk while the change id holds — O(log
    /// n + k) instead of a full scan.
    pub fn for_change(&self, change_id: &Oid) -> Vec<&Attestation> {
        use std::ops::Bound;
        let lo = (change_id.clone(), [0u8; 32], String::new());
        self.entries
            .range((Bound::Included(lo), Bound::Unbounded))
            .take_while(|((c, _, _), _)| c == change_id)
            .map(|(_, a)| a)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signer(seed: u8) -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn make(sk: &SigningKey, pk: [u8; 32], change: Oid, role: &str) -> Attestation {
        let signature = sk.sign(&signing_bytes(&change, &pk, role)).to_bytes();
        Attestation { change_id: change, attester: pk, role: role.into(), signature }
    }

    #[test]
    fn valid_attestation_verifies() {
        let (sk, pk) = signer(3);
        assert!(make(&sk, pk, Oid([1; 32]), "reviewed").verify());
    }

    #[test]
    fn tampered_role_fails_verify() {
        let (sk, pk) = signer(3);
        let mut a = make(&sk, pk, Oid([1; 32]), "reviewed");
        a.role = "approved".into(); // signature covers "reviewed"
        assert!(!a.verify());
    }

    #[test]
    fn wrong_attester_fails_verify() {
        let (sk, _pk) = signer(3);
        let (_o, other_pk) = signer(4);
        // Claims other_pk as attester, but sk (pk=3) signed.
        let sig = sk.sign(&signing_bytes(&Oid([1; 32]), &other_pk, "reviewed")).to_bytes();
        let a = Attestation { change_id: Oid([1; 32]), attester: other_pk, role: "reviewed".into(), signature: sig };
        assert!(!a.verify());
    }

    #[test]
    fn log_is_idempotent_and_queryable() {
        let (sk, pk) = signer(3);
        let mut log = AttestationLog::new();
        log.insert(make(&sk, pk, Oid([1; 32]), "reviewed"));
        log.insert(make(&sk, pk, Oid([1; 32]), "reviewed")); // duplicate
        log.insert(make(&sk, pk, Oid([2; 32]), "reviewed"));
        assert_eq!(log.len(), 2, "duplicate (change, attester, role) is idempotent");
        assert_eq!(log.for_change(&Oid([1; 32])).len(), 1);
    }
}
