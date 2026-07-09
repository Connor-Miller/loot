//! Buoy resolver — navigational-role landmark over the attestation lane (CA4,
//! ADR 0025).
//!
//! A buoy is "the newest change attested with role X by a trusted peer," where
//! "newest" is defined topologically: the **maximal elements of the candidate
//! set under the ancestor partial order** of the whole change graph.
//!
//! The resolver is a pure function of five inputs — no disk, no keys, no clock
//! — so it is unit-testable with fakes, exactly like the converge key-oracle
//! seam.

use crate::attestation::Attestation;
use crate::Oid;
use std::collections::{BTreeMap, BTreeSet};

/// The resolved buoy result.
#[derive(Debug, PartialEq, Eq)]
pub enum BuoyResult {
    /// Exactly one maximal role-attested change: the buoy.
    Resolved {
        change: Oid,
        /// The trusted attesters (pubkeys) that back this change for this role.
        attesters: Vec<[u8; 32]>,
    },
    /// More than one maximal candidate — the role is attested on mutually
    /// incomparable (concurrent) changes. List them all; pick none.
    Ambiguous { candidates: Vec<Candidate> },
    /// No trusted, locally-present, signature-valid attestation for the role.
    None,
}

/// A single candidate in an ambiguous result.
#[derive(Debug, PartialEq, Eq)]
pub struct Candidate {
    pub change: Oid,
    pub attesters: Vec<[u8; 32]>,
}

/// Resolve `role` over the whole change graph.
///
/// - `present`: the set of change ids held locally (used to skip attestations
///   that name changes we do not hold).
/// - `parents`: a function from change id to its parent ids; unknown ids return
///   empty (identical to the `ChangeGraph::parents_of` contract).
/// - `attestations`: iterator over every attestation in the log.
/// - `trusted`: a predicate — true iff the given pubkey is trusted (in the
///   peer registry **or** is the local identity's own pubkey).
pub fn resolve<'a>(
    present: &BTreeSet<Oid>,
    parents: &dyn Fn(&Oid) -> Vec<Oid>,
    attestations: impl Iterator<Item = &'a Attestation>,
    trusted: &dyn Fn(&[u8; 32]) -> bool,
    role: &str,
) -> BuoyResult {
    // Collect candidates: changes present locally, with at least one trusted
    // and signature-valid attestation for this role.
    // Map from change_id -> list of attester pubkeys that back it.
    let mut candidates: BTreeMap<Oid, Vec<[u8; 32]>> = BTreeMap::new();
    for att in attestations {
        if att.role != role {
            continue;
        }
        if !att.verify() {
            continue;
        }
        if !trusted(&att.attester) {
            continue;
        }
        if !present.contains(&att.change_id) {
            continue;
        }
        candidates.entry(att.change_id.clone()).or_default().push(att.attester);
    }

    if candidates.is_empty() {
        return BuoyResult::None;
    }

    // Retain only the maximal elements: remove any candidate that is a strict
    // ancestor of another candidate.
    let ids: Vec<Oid> = candidates.keys().cloned().collect();
    let mut is_dominated = BTreeSet::new();
    for candidate in &ids {
        if is_dominated.contains(candidate) {
            continue;
        }
        // Walk the ancestor closure of `candidate`; any other candidate found
        // in there is dominated by `candidate`.
        let mut stack = parents(candidate);
        let mut visited: BTreeSet<Oid> = BTreeSet::new();
        while let Some(anc) = stack.pop() {
            if !visited.insert(anc.clone()) {
                continue;
            }
            if candidates.contains_key(&anc) {
                is_dominated.insert(anc.clone());
            }
            for p in parents(&anc) {
                stack.push(p);
            }
        }
    }

    let mut maximal: Vec<Candidate> = candidates
        .into_iter()
        .filter(|(id, _)| !is_dominated.contains(id))
        .map(|(change, attesters)| Candidate { change, attesters })
        .collect();

    // Sort for deterministic output (change id bytes are unique).
    maximal.sort_by(|a, b| a.change.cmp(&b.change));

    match maximal.len() {
        0 => BuoyResult::None,
        1 => {
            let c = maximal.remove(0);
            BuoyResult::Resolved { change: c.change, attesters: c.attesters }
        }
        _ => BuoyResult::Ambiguous { candidates: maximal },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{Attestation, AttestationLog};
    use ed25519_dalek::{Signer, SigningKey};

    // --- Helpers ---------------------------------------------------------------

    fn oid(b: u8) -> Oid {
        Oid([b; 32])
    }

    fn make_key(seed: u8) -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn attest(sk: &SigningKey, pk: [u8; 32], change: Oid, role: &str) -> Attestation {
        let sig = sk.sign(&crate::attestation::signing_bytes(&change, &pk, role)).to_bytes();
        Attestation { change_id: change, attester: pk, role: role.into(), signature: sig }
    }

    fn trusted_set(keys: &[[u8; 32]]) -> impl Fn(&[u8; 32]) -> bool + '_ {
        |pk: &[u8; 32]| keys.contains(pk)
    }

    /// Build an `AttestationLog` from a slice of `Attestation`s.
    fn log_from(atts: &[Attestation]) -> AttestationLog {
        let mut log = AttestationLog::new();
        for a in atts {
            log.insert(a.clone());
        }
        log
    }

    // A minimal parent-map: map from child oid-byte to list of parent oid-bytes.
    fn make_parents<'a>(edges: &'a [(u8, &'a [u8])]) -> impl Fn(&Oid) -> Vec<Oid> + 'a {
        let map: BTreeMap<u8, Vec<u8>> =
            edges.iter().map(|(c, ps)| (*c, ps.to_vec())).collect();
        move |id: &Oid| {
            map.get(&id.0[0]).map_or(vec![], |ps| ps.iter().map(|&b| oid(b)).collect())
        }
    }

    fn present(ids: &[u8]) -> BTreeSet<Oid> {
        ids.iter().map(|&b| oid(b)).collect()
    }

    // --- Cycle 1: single resolved buoy -----------------------------------------

    #[test]
    fn single_attested_change_resolves_as_buoy() {
        let (sk, pk) = make_key(1);
        let log = log_from(&[attest(&sk, pk, oid(10), "reviewed")]);
        let parents = make_parents(&[]);
        let result = resolve(
            &present(&[10]),
            &parents,
            log.iter(),
            &trusted_set(&[pk]),
            "reviewed",
        );
        assert_eq!(result, BuoyResult::Resolved { change: oid(10), attesters: vec![pk] });
    }

    // --- Cycle 2: no matching attestation → None --------------------------------

    #[test]
    fn no_attestation_returns_none() {
        let log = AttestationLog::new();
        let parents = make_parents(&[]);
        let result = resolve(&present(&[10]), &parents, log.iter(), &trusted_set(&[]), "reviewed");
        assert_eq!(result, BuoyResult::None);
    }

    #[test]
    fn wrong_role_returns_none() {
        let (sk, pk) = make_key(1);
        let log = log_from(&[attest(&sk, pk, oid(10), "base")]);
        let parents = make_parents(&[]);
        let result = resolve(
            &present(&[10]),
            &parents,
            log.iter(),
            &trusted_set(&[pk]),
            "reviewed",
        );
        assert_eq!(result, BuoyResult::None);
    }

    // --- Cycle 3: untrusted attester is ignored ---------------------------------

    #[test]
    fn untrusted_attester_is_ignored() {
        let (sk, pk) = make_key(2);
        let log = log_from(&[attest(&sk, pk, oid(10), "reviewed")]);
        let parents = make_parents(&[]);
        // pk is NOT in the trusted set
        let result = resolve(&present(&[10]), &parents, log.iter(), &trusted_set(&[]), "reviewed");
        assert_eq!(result, BuoyResult::None);
    }

    // --- Cycle 4: bad signature is dropped --------------------------------------

    #[test]
    fn bad_signature_is_dropped() {
        let (sk, pk) = make_key(3);
        let mut att = attest(&sk, pk, oid(10), "reviewed");
        att.signature[0] ^= 0xff; // corrupt
        let log = log_from(&[att]);
        let parents = make_parents(&[]);
        let result = resolve(
            &present(&[10]),
            &parents,
            log.iter(),
            &trusted_set(&[pk]),
            "reviewed",
        );
        assert_eq!(result, BuoyResult::None);
    }

    // --- Cycle 5: missing change excluded from resolution -----------------------

    #[test]
    fn attestation_for_absent_change_is_excluded() {
        let (sk, pk) = make_key(1);
        // Change oid(10) is attested but NOT in present set
        let log = log_from(&[attest(&sk, pk, oid(10), "reviewed")]);
        let parents = make_parents(&[]);
        let result = resolve(
            &present(&[]),  // empty local store
            &parents,
            log.iter(),
            &trusted_set(&[pk]),
            "reviewed",
        );
        assert_eq!(result, BuoyResult::None);
    }

    // --- Cycle 6: ancestor collapsed under descendant ---------------------------

    #[test]
    fn ancestor_is_dominated_by_descendant() {
        let (sk, pk) = make_key(1);
        // Linear chain: 10 <- 11 (11 is child of 10)
        // Both attested — 10 must be dropped (it's an ancestor of 11).
        let log = log_from(&[
            attest(&sk, pk, oid(10), "reviewed"),
            attest(&sk, pk, oid(11), "reviewed"),
        ]);
        let parents = make_parents(&[(11, &[10])]);
        let result = resolve(
            &present(&[10, 11]),
            &parents,
            log.iter(),
            &trusted_set(&[pk]),
            "reviewed",
        );
        assert_eq!(result, BuoyResult::Resolved { change: oid(11), attesters: vec![pk] });
    }

    // --- Cycle 7: concurrent attestations → Ambiguous ---------------------------

    #[test]
    fn concurrent_attestations_are_ambiguous() {
        let (sk, pk) = make_key(1);
        // Forks from a common base (oid(9)): 10 and 11 are incomparable.
        let log = log_from(&[
            attest(&sk, pk, oid(10), "reviewed"),
            attest(&sk, pk, oid(11), "reviewed"),
        ]);
        // Both are children of 9, neither is the other's ancestor.
        let parents = make_parents(&[(10, &[9]), (11, &[9])]);
        let result = resolve(
            &present(&[9, 10, 11]),
            &parents,
            log.iter(),
            &trusted_set(&[pk]),
            "reviewed",
        );
        match result {
            BuoyResult::Ambiguous { candidates } => {
                let ids: Vec<Oid> = candidates.iter().map(|c| c.change.clone()).collect();
                assert!(ids.contains(&oid(10)));
                assert!(ids.contains(&oid(11)));
                assert_eq!(ids.len(), 2);
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    // --- Cycle 8: self-trust (local identity counts as trusted) -----------------

    #[test]
    fn self_attestation_is_trusted() {
        let (sk, pk) = make_key(5);
        let log = log_from(&[attest(&sk, pk, oid(10), "reviewed")]);
        let parents = make_parents(&[]);
        // Self-trust: pk is the local identity's own pubkey.
        let result = resolve(
            &present(&[10]),
            &parents,
            log.iter(),
            &trusted_set(&[pk]),
            "reviewed",
        );
        assert_eq!(result, BuoyResult::Resolved { change: oid(10), attesters: vec![pk] });
    }

    // --- Cycle 9: three-level chain, only grandchild survives -------------------

    #[test]
    fn only_leaf_survives_in_linear_chain() {
        let (sk, pk) = make_key(1);
        // Chain: 10 <- 11 <- 12. All three attested; only 12 is maximal.
        let log = log_from(&[
            attest(&sk, pk, oid(10), "reviewed"),
            attest(&sk, pk, oid(11), "reviewed"),
            attest(&sk, pk, oid(12), "reviewed"),
        ]);
        let parents = make_parents(&[(11, &[10]), (12, &[11])]);
        let result = resolve(
            &present(&[10, 11, 12]),
            &parents,
            log.iter(),
            &trusted_set(&[pk]),
            "reviewed",
        );
        assert_eq!(result, BuoyResult::Resolved { change: oid(12), attesters: vec![pk] });
    }

    // --- Cycle 10: merge node — one candidate, one of its parents attested ------

    #[test]
    fn merge_node_dominates_its_attested_parents() {
        let (sk, pk) = make_key(1);
        // Merge: 12 merges 10 and 11 (10 and 11 are both parents of 12).
        // 10 and 12 both attested; 10 is an ancestor of 12, so only 12 remains.
        let log = log_from(&[
            attest(&sk, pk, oid(10), "reviewed"),
            attest(&sk, pk, oid(12), "reviewed"),
        ]);
        let parents = make_parents(&[(12, &[10, 11])]);
        let result = resolve(
            &present(&[10, 11, 12]),
            &parents,
            log.iter(),
            &trusted_set(&[pk]),
            "reviewed",
        );
        assert_eq!(result, BuoyResult::Resolved { change: oid(12), attesters: vec![pk] });
    }
}
