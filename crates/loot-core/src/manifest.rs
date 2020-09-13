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
    /// Unix timestamp after which this grant is no longer honored (`None` =
    /// never expires — the default, and the only behavior before #20).
    /// Parallel to content [`crate::Visibility::Embargoed`], but for the grant
    /// itself: `apply_sealed_grant` rejects a sealed grant once
    /// `now >= expires_at`, and `surface` skips a path once its recorded
    /// grant for the reader has expired.
    pub expires_at: Option<u64>,
}

impl GrantEntry {
    /// True if this entry has a verified grantor pubkey (relay-delivered grant).
    pub fn has_grantor(&self) -> bool {
        self.grantor_pubkey != UNKNOWN_PUBKEY
    }

    /// True once `now` has reached or passed `expires_at`. Always `false` for
    /// an unset `expires_at` — an ordinary, non-expiring grant (#20).
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|t| now >= t)
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
    /// exists, the earlier record (including its `expires_at`) is preserved.
    pub fn record(
        &mut self,
        oid: Oid,
        grantee: String,
        grantee_pubkey: [u8; 32],
        grantor_pubkey: [u8; 32],
        granted_at: u64,
        expires_at: Option<u64>,
    ) {
        self.entries.entry((oid.clone(), grantee.clone())).or_insert(GrantEntry {
            oid,
            grantee,
            grantee_pubkey,
            grantor_pubkey,
            granted_at,
            expires_at,
        });
    }

    /// Merge another manifest in, preserving the earlier grant (timestamp and
    /// its `expires_at`) for any duplicate (oid, grantee) pairs.
    pub fn merge(&mut self, other: &Manifest) {
        for ((oid, grantee), entry) in &other.entries {
            self.entries
                .entry((oid.clone(), grantee.clone()))
                .and_modify(|e| {
                    if entry.granted_at < e.granted_at {
                        e.granted_at = entry.granted_at;
                        e.expires_at = entry.expires_at;
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

    /// The grant recorded for this exact `(oid, grantee)` pair, if any — the
    /// map is keyed by the pair, so there is at most one. Used by `surface`
    /// (#20) to check whether the one grant covering a path for `reader` has
    /// expired; a miss (no matching grant at all — an owner's own content, or
    /// a tag-1 recipient who never separately recorded one) is not an
    /// expiry and must not skip the path.
    pub fn grant_for(&self, oid: &Oid, grantee: &str) -> Option<&GrantEntry> {
        self.entries.get(&(oid.clone(), grantee.to_string()))
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
        m.record(oid(1), "alice".into(), pk(0xaa), pk(0xbb), 100, None);
        m.record(oid(1), "alice".into(), pk(0xaa), pk(0xbb), 50, None);
        m.record(oid(1), "alice".into(), pk(0xaa), pk(0xbb), 200, None);

        let entries = m.grants_for(&oid(1));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].granted_at, 100, "first write wins");
    }

    #[test]
    fn merge_preserves_earlier_timestamp() {
        let mut a = Manifest::new();
        a.record(oid(1), "alice".into(), pk(0xaa), pk(0xbb), 100, None);

        let mut b = Manifest::new();
        b.record(oid(1), "alice".into(), pk(0xaa), pk(0xbb), 50, None);

        a.merge(&b);
        let entries = a.grants_for(&oid(1));
        assert_eq!(entries[0].granted_at, 50, "merge should take the earlier timestamp");
    }

    #[test]
    fn grants_for_filters_by_oid() {
        let mut m = Manifest::new();
        m.record(oid(1), "alice".into(), pk(0xaa), pk(0xbb), 100, None);
        m.record(oid(2), "bob".into(), pk(0xcc), pk(0xbb), 200, None);
        m.record(oid(1), "carol".into(), pk(0xdd), pk(0xbb), 150, None);

        let for_oid1 = m.grants_for(&oid(1));
        assert_eq!(for_oid1.len(), 2);
        assert!(for_oid1.iter().all(|e| e.oid == oid(1)));
    }

    #[test]
    fn grants_to_filters_by_grantee_name() {
        let mut m = Manifest::new();
        m.record(oid(1), "alice".into(), pk(0xaa), pk(0xbb), 100, None);
        m.record(oid(2), "alice".into(), pk(0xaa), pk(0xbb), 200, None);
        m.record(oid(3), "bob".into(), pk(0xcc), pk(0xbb), 300, None);

        let to_alice = m.grants_to("alice");
        assert_eq!(to_alice.len(), 2);
        assert!(to_alice.iter().all(|e| e.grantee == "alice"));
    }

    #[test]
    fn has_grantor_distinguishes_relay_vs_file_grants() {
        let mut m = Manifest::new();
        m.record(oid(1), "alice".into(), UNKNOWN_PUBKEY, UNKNOWN_PUBKEY, 100, None);
        m.record(oid(2), "bob".into(), pk(0xaa), pk(0xbb), 200, None);

        let file_grant = m.grants_for(&oid(1))[0];
        let relay_grant = m.grants_for(&oid(2))[0];
        assert!(!file_grant.has_grantor());
        assert!(relay_grant.has_grantor());
    }

    #[test]
    fn iter_covers_all_entries() {
        let mut m = Manifest::new();
        m.record(oid(1), "alice".into(), pk(0xaa), pk(0xbb), 100, None);
        m.record(oid(2), "bob".into(), pk(0xcc), pk(0xdd), 200, None);
        assert_eq!(m.iter().count(), 2);
    }

    // --- grant expiry (#20) ---

    #[test]
    fn no_expiry_never_expires() {
        let mut m = Manifest::new();
        m.record(oid(1), "alice".into(), pk(0xaa), pk(0xbb), 100, None);
        let e = m.grants_for(&oid(1))[0];
        assert!(!e.is_expired(u64::MAX), "a grant without expires_at never expires");
    }

    #[test]
    fn is_expired_true_once_now_reaches_expires_at() {
        let mut m = Manifest::new();
        m.record(oid(1), "alice".into(), pk(0xaa), pk(0xbb), 100, Some(200));
        let e = m.grants_for(&oid(1))[0];
        assert!(!e.is_expired(199), "not yet expired the moment before expires_at");
        assert!(e.is_expired(200), "expired exactly at expires_at");
        assert!(e.is_expired(201), "expired after expires_at");
    }

    #[test]
    fn record_preserves_expires_at_on_a_re_grant() {
        // #16 (id rotate) needs a re-grant to keep the original expiry: since
        // `record` is idempotent on (oid, grantee) — first write wins — a later
        // call that omits expires_at cannot wipe out an earlier one.
        let mut m = Manifest::new();
        m.record(oid(1), "alice".into(), pk(0xaa), pk(0xbb), 100, Some(999));
        m.record(oid(1), "alice".into(), pk(0xaa), pk(0xbb), 100, None);

        let e = m.grants_for(&oid(1))[0];
        assert_eq!(e.expires_at, Some(999), "the first-recorded expiry survives a re-grant");
    }

    #[test]
    fn merge_carries_expires_at_along_with_the_earlier_timestamp() {
        let mut a = Manifest::new();
        a.record(oid(1), "alice".into(), pk(0xaa), pk(0xbb), 100, None);

        let mut b = Manifest::new();
        b.record(oid(1), "alice".into(), pk(0xaa), pk(0xbb), 50, Some(500));

        a.merge(&b);
        let e = a.grants_for(&oid(1))[0];
        assert_eq!(e.granted_at, 50);
        assert_eq!(e.expires_at, Some(500), "the earlier record's expiry travels with it");
    }

    #[test]
    fn grant_for_finds_the_exact_oid_grantee_pair() {
        let mut m = Manifest::new();
        m.record(oid(1), "alice".into(), pk(0xaa), pk(0xbb), 100, Some(200));
        m.record(oid(1), "bob".into(), pk(0xcc), pk(0xbb), 100, None);

        assert_eq!(m.grant_for(&oid(1), "alice").unwrap().expires_at, Some(200));
        assert_eq!(m.grant_for(&oid(1), "bob").unwrap().expires_at, None);
        assert!(m.grant_for(&oid(2), "alice").is_none(), "no grant recorded for this oid");
        assert!(m.grant_for(&oid(1), "carol").is_none(), "no grant recorded for this grantee");
    }
}
