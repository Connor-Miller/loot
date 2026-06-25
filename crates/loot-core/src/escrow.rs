//! Escrow — the lifecycle stage between `seal` and `Keyring` for embargoed content.
//!
//! When content is sealed as `Embargoed { reveal_at }`, its key is filed here
//! instead of directly into the Keyring. `flush` promotes eligible entries to
//! the Keyring once `now >= reveal_at`. Until flush runs, no Keyring entry
//! exists and `sealed::open` finds nothing to work with — closing the D-threat
//! (a keyholder bypassing embargo by passing a manipulated clock).
//!
//! See ADR 0007.

use crate::{Oid, sealed::{ContentKey, Keyring}};
use std::collections::BTreeMap;

/// A single embargoed key awaiting its reveal time.
#[derive(Clone, Debug)]
pub struct EscrowEntry {
    pub key: ContentKey,
    pub reveal_at: u64,
}

/// Custody of embargoed content keys, held separately from the Keyring until
/// `reveal_at`. See ADR 0007.
#[derive(Clone, Debug, Default)]
pub struct Escrow {
    entries: BTreeMap<Oid, EscrowEntry>,
}

impl Escrow {
    pub fn new() -> Self {
        Self::default()
    }

    /// File an embargoed key under its object address.
    pub fn insert(&mut self, oid: Oid, key: ContentKey, reveal_at: u64) {
        self.entries.insert(oid, EscrowEntry { key, reveal_at });
    }

    /// Promote all entries where `now >= reveal_at` into `keyring`, then remove
    /// them. Call this before any content-reading operation (checkout, snapshot).
    pub fn flush(&mut self, keyring: &mut Keyring, now: u64) {
        let eligible: Vec<Oid> = self
            .entries
            .iter()
            .filter(|(_, e)| now >= e.reveal_at)
            .map(|(oid, _)| oid.clone())
            .collect();
        for oid in eligible {
            let entry = self.entries.remove(&oid).unwrap();
            keyring.insert(oid, entry.key);
        }
    }

    /// Does this escrow hold an entry for `oid`?
    pub fn holds(&self, oid: &Oid) -> bool {
        self.entries.contains_key(oid)
    }

    /// Every entry, for local-only persistence. Must never feed a sync bundle
    /// (bundles carry escrow entries in their own section — this is for
    /// persisting the local escrow state to `.loot/escrow`).
    pub fn iter(&self) -> impl Iterator<Item = (&Oid, &EscrowEntry)> {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(b: u8) -> ContentKey {
        [b; 32]
    }

    fn oid(b: u8) -> Oid {
        Oid([b; 32])
    }

    #[test]
    fn flush_promotes_eligible_entries() {
        let mut escrow = Escrow::new();
        let mut kr = Keyring::new();
        escrow.insert(oid(1), make_key(1), 100);
        escrow.insert(oid(2), make_key(2), 200);

        escrow.flush(&mut kr, 100);
        assert!(kr.holds(&oid(1)), "exactly at reveal_at should promote");
        assert!(!kr.holds(&oid(2)), "not yet due should stay in escrow");
        assert!(!escrow.holds(&oid(1)), "promoted entry should leave escrow");
        assert!(escrow.holds(&oid(2)), "pending entry should remain");
    }

    #[test]
    fn flush_before_reveal_promotes_nothing() {
        let mut escrow = Escrow::new();
        let mut kr = Keyring::new();
        escrow.insert(oid(1), make_key(1), 100);
        escrow.flush(&mut kr, 99);
        assert!(!kr.holds(&oid(1)));
        assert!(escrow.holds(&oid(1)));
    }

    #[test]
    fn flush_after_reveal_clears_escrow() {
        let mut escrow = Escrow::new();
        let mut kr = Keyring::new();
        escrow.insert(oid(1), make_key(1), 100);
        escrow.flush(&mut kr, 101);
        assert!(kr.holds(&oid(1)));
        assert!(!escrow.holds(&oid(1)));
    }

    #[test]
    fn iter_covers_all_pending_entries() {
        let mut escrow = Escrow::new();
        escrow.insert(oid(1), make_key(1), 100);
        escrow.insert(oid(2), make_key(2), 200);
        let pairs: Vec<_> = escrow.iter().collect();
        assert_eq!(pairs.len(), 2);
    }
}
