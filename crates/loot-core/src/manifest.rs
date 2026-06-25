//! Manifest — the append-only audit trail of grant events (ADR 0008).
//!
//! A Manifest records the *fact* of every key handoff: who was granted access
//! to which object, and when. It carries no key material — the key travels
//! separately in a targeted bundle's keyring section. The Manifest travels
//! with every bundle so all peers accumulate a complete audit trail.
//!
//! "Who loaded what cargo, and when" — named for a ship's manifest.

use crate::Oid;
use std::collections::BTreeMap;

/// A single grant event in the audit trail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantEntry {
    /// The content object the grant is for.
    pub oid: Oid,
    /// The identity who received the key.
    pub grantee: String,
    /// Unix timestamp when the grant was issued.
    pub granted_at: u64,
}

/// Append-only audit trail of grant events. Travels in bundles so every peer
/// has a complete record of who was given access to what (ADR 0008).
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
    pub fn record(&mut self, oid: Oid, grantee: String, granted_at: u64) {
        self.entries
            .entry((oid.clone(), grantee.clone()))
            .or_insert(GrantEntry { oid, grantee, granted_at });
    }

    /// Merge another manifest in, preserving the earlier timestamp for any
    /// duplicate (oid, grantee) pairs. Called during `apply` to accumulate
    /// incoming grant history.
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

    /// All grants for a specific object — "who has ever been granted access to
    /// this content?"
    pub fn grants_for(&self, oid: &Oid) -> Vec<&GrantEntry> {
        self.entries
            .iter()
            .filter(|((o, _), _)| o == oid)
            .map(|(_, e)| e)
            .collect()
    }

    /// All grants for a specific identity — "what has this identity ever been
    /// granted access to?"
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

    #[test]
    fn record_is_idempotent_earlier_timestamp_wins() {
        let mut m = Manifest::new();
        m.record(oid(1), "alice".into(), 100);
        m.record(oid(1), "alice".into(), 50); // earlier — should win
        m.record(oid(1), "alice".into(), 200); // later — should be ignored

        let entries: Vec<_> = m.grants_for(&oid(1));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].granted_at, 100, "first write wins, not earliest retroactively");
    }

    #[test]
    fn merge_preserves_earlier_timestamp() {
        let mut a = Manifest::new();
        a.record(oid(1), "alice".into(), 100);

        let mut b = Manifest::new();
        b.record(oid(1), "alice".into(), 50); // earlier

        a.merge(&b);
        let entries: Vec<_> = a.grants_for(&oid(1));
        assert_eq!(entries[0].granted_at, 50, "merge should take the earlier timestamp");
    }

    #[test]
    fn grants_for_filters_by_oid() {
        let mut m = Manifest::new();
        m.record(oid(1), "alice".into(), 100);
        m.record(oid(2), "bob".into(), 200);
        m.record(oid(1), "carol".into(), 150);

        let for_oid1 = m.grants_for(&oid(1));
        assert_eq!(for_oid1.len(), 2);
        assert!(for_oid1.iter().all(|e| e.oid == oid(1)));
    }

    #[test]
    fn grants_to_filters_by_grantee() {
        let mut m = Manifest::new();
        m.record(oid(1), "alice".into(), 100);
        m.record(oid(2), "alice".into(), 200);
        m.record(oid(3), "bob".into(), 300);

        let to_alice = m.grants_to("alice");
        assert_eq!(to_alice.len(), 2);
        assert!(to_alice.iter().all(|e| e.grantee == "alice"));
    }

    #[test]
    fn iter_covers_all_entries() {
        let mut m = Manifest::new();
        m.record(oid(1), "alice".into(), 100);
        m.record(oid(2), "bob".into(), 200);
        assert_eq!(m.iter().count(), 2);
    }
}
