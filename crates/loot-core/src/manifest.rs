//! Manifest — the append-only audit trail of grant events (ADR 0008, 0015).
//!
//! A Manifest records the *fact* of every key handoff: who granted what to whom,
//! and when. For relay-delivered (sealed) grants both grantor and grantee are
//! identified by **pubkey** (the globally-stable identity, ADR 0015). For
//! file-based (tag-1) grants the grantee name string is preserved for
//! compatibility; pubkey fields are zeroed. Names are resolved at display time
//! via the peer registry.
//!
//! "Who loaded what cargo, and when" — named for a ship's manifest.

use crate::Oid;
use std::collections::BTreeMap;

/// Sentinel 32-byte value meaning "pubkey not recorded" (legacy/file-based grant).
pub const UNKNOWN_PUBKEY: [u8; 32] = [0u8; 32];

/// A single grant event in the audit trail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantEntry {
    /// The content object the grant is for.
    pub oid: Oid,
    /// Grantee identity name (always present; for relay grants also see grantee_pubkey).
    pub grantee: String,
    /// Grantee ed25519 pubkey. `UNKNOWN_PUBKEY` for file-based (tag-1) grants.
    pub grantee_pubkey: [u8; 32],
    /// Grantor ed25519 pubkey, bound by the envelope signature (ADR 0015).
    /// `UNKNOWN_PUBKEY` for file-based (tag-1) grants (no envelope).
    pub grantor_pubkey: [u8; 32],
    /// Unix timestamp when the grant was issued.
    pub granted_at: u64,
}

impl GrantEntry {
    /// True if this entry has a verified grantor pubkey (relay-delivered grant).
    pub fn has_grantor(&self) -> bool {
        self.grantor_pubkey != UNKNOWN_PUBKEY
    }
}

/// Append-only audit trail of grant events. Travels in bundles so every peer
/// has a complete record of who granted what to whom (ADR 0008, 0015).
///
/// Keyed by (oid, grantee) so a second grant of the same key to the same
/// identity is idempotent — the earlier timestamp wins.
#[derive(Clone, Debug, Default)]
pub struct Manifest {
    entries: BTreeMap<(Oid, String), GrantEntry>,
}

impl Manifest {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a grant event. Idempotent: if this (oid, grantee) pair already
    /// exists, the earlier `granted_at` is preserved.
    pub fn record(
        &mut self,
        oid: Oid,
        grantee: String,
        grantee_pubkey: [u8; 32],
        grantor_pubkey: [u8; 32],
        granted_at: u64,
    ) {
        self.entries
            .entry((oid.clone(), grantee.clone()))
            .or_insert(GrantEntry { oid, grantee, grantee_pubkey, grantor_pubkey, granted_at });
    }

    /// Merge another manifest in, preserving the earlier timestamp for any
    /// duplicate (oid, grantee) pairs.
    pub fn merge(&mut self, other: &Manifest) {
        for ((oid, grantee), entry) in &other.entries {
            self.entries
                .entry((oid.clone(), grantee.clone()))
                .and_modify(|e| {
                    if entry.granted_at < e.granted_at {
                        e.granted_at = entry.granted_at;
                    }
                })
                .or_insert(entry.clone());
        }
    }

    /// All entries, for iteration, querying, and persistence.
    pub fn iter(&self) -> impl Iterator<Item = &GrantEntry> {
        self.entries.values()
    }

    /// All grants for a specific object.
    pub fn grants_for(&self, oid: &Oid) -> Vec<&GrantEntry> {
        self.entries
            .iter()
            .filter(|((o, _), _)| o == oid)
            .map(|(_, e)| e)
            .collect()
    }

    /// All grants to a specific identity name.
    pub fn grants_to(&self, grantee: &str) -> Vec<&GrantEntry> {
        self.entries
            .iter()
            .filter(|((_, g), _)| g == grantee)
            .map(|(_, e)| e)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(b: u8) -> Oid {
        Oid([b; 32])
    }

    fn pk(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn record_is_idempotent_earlier_timestamp_wins() {
        let mut m = Manifest::new();
        m.record(oid(1), "alice".into(), pk(0xaa), pk(0xbb), 100);
        m.record(oid(1), "alice".into(), pk(0xaa), pk(0xbb), 50);
        m.record(oid(1), "alice".into(), pk(0xaa), pk(0xbb), 200);

        let entries = m.grants_for(&oid(1));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].granted_at, 100, "first write wins");
    }

    #[test]
    fn merge_preserves_earlier_timestamp() {
        let mut a = Manifest::new();
        a.record(oid(1), "alice".into(), pk(0xaa), pk(0xbb), 100);

        let mut b = Manifest::new();
        b.record(oid(1), "alice".into(), pk(0xaa), pk(0xbb), 50);

        a.merge(&b);
        let entries = a.grants_for(&oid(1));
        assert_eq!(entries[0].granted_at, 50, "merge should take the earlier timestamp");
    }

    #[test]
    fn grants_for_filters_by_oid() {
        let mut m = Manifest::new();
        m.record(oid(1), "alice".into(), pk(0xaa), pk(0xbb), 100);
        m.record(oid(2), "bob".into(), pk(0xcc), pk(0xbb), 200);
        m.record(oid(1), "carol".into(), pk(0xdd), pk(0xbb), 150);

        let for_oid1 = m.grants_for(&oid(1));
        assert_eq!(for_oid1.len(), 2);
        assert!(for_oid1.iter().all(|e| e.oid == oid(1)));
    }

    #[test]
    fn grants_to_filters_by_grantee_name() {
        let mut m = Manifest::new();
        m.record(oid(1), "alice".into(), pk(0xaa), pk(0xbb), 100);
        m.record(oid(2), "alice".into(), pk(0xaa), pk(0xbb), 200);
        m.record(oid(3), "bob".into(), pk(0xcc), pk(0xbb), 300);

        let to_alice = m.grants_to("alice");
        assert_eq!(to_alice.len(), 2);
        assert!(to_alice.iter().all(|e| e.grantee == "alice"));
    }

    #[test]
    fn has_grantor_distinguishes_relay_vs_file_grants() {
        let mut m = Manifest::new();
        m.record(oid(1), "alice".into(), UNKNOWN_PUBKEY, UNKNOWN_PUBKEY, 100);
        m.record(oid(2), "bob".into(), pk(0xaa), pk(0xbb), 200);

        let file_grant = m.grants_for(&oid(1))[0];
        let relay_grant = m.grants_for(&oid(2))[0];
        assert!(!file_grant.has_grantor());
        assert!(relay_grant.has_grantor());
    }

    #[test]
    fn iter_covers_all_entries() {
        let mut m = Manifest::new();
        m.record(oid(1), "alice".into(), pk(0xaa), pk(0xbb), 100);
        m.record(oid(2), "bob".into(), pk(0xcc), pk(0xdd), 200);
        assert_eq!(m.iter().count(), 2);
    }
}
