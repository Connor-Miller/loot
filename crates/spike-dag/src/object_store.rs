//! Content-addressed object storage for the DAG backend (internal seam).
//!
//! A log-structured store of [`SealedObject`]s: one append-only `Vec` plus a
//! single index (content address -> position). It knows nothing about changes,
//! keys, or identities — only how to store ciphertext by address. Dedup is
//! address-only (byte-identical ciphertext); there is deliberately NO
//! plaintext-derived dedup, because that leaked an equality oracle to relays
//! (ADR 0004). Backend-private; a different backend would store bytes
//! differently.

use loot_core::sealed::SealedObject;
use loot_core::{Oid, RepoError};
use std::collections::BTreeMap;

/// What `put` did. The caller (which owns key custody) files a freshly-minted
/// key only on [`Stored::New`]; on a [`Stored::Deduped`] the ciphertext already
/// existed and the minted key seals nothing stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stored {
    /// Object was newly written at this address.
    New(Oid),
    /// Byte-identical ciphertext was already present at this address.
    Deduped(Oid),
}

impl Stored {
    pub fn addr(&self) -> &Oid {
        match self {
            Stored::New(a) | Stored::Deduped(a) => a,
        }
    }
}

#[derive(Default)]
pub struct ObjectStore {
    log: Vec<SealedObject>,
    by_addr: BTreeMap<Oid, usize>,
}

impl ObjectStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store `obj` at `addr`. Dedup is address-only: identical ciphertext maps
    /// to the same address and is stored once (so re-applying a bundle is
    /// idempotent). Distinct ciphertext is always stored, even if its plaintext
    /// happens to match — there is no plaintext comparison (ADR 0004).
    pub fn put(&mut self, addr: Oid, obj: SealedObject) -> Stored {
        if self.by_addr.contains_key(&addr) {
            return Stored::Deduped(addr);
        }
        let pos = self.log.len();
        self.log.push(obj);
        self.by_addr.insert(addr.clone(), pos);
        Stored::New(addr)
    }

    pub fn get(&self, oid: &Oid) -> Result<&SealedObject, RepoError> {
        self.by_addr
            .get(oid)
            .map(|&pos| &self.log[pos])
            .ok_or_else(|| RepoError::NotFound(oid.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loot_core::sealed::seal;
    use loot_core::Visibility;

    #[test]
    fn put_then_get_round_trips() {
        let mut s = ObjectStore::new();
        let (addr, obj, _k) = seal(b"hi", &Visibility::Public).unwrap();
        assert_eq!(s.put(addr.clone(), obj.clone()), Stored::New(addr.clone()));
        assert_eq!(s.get(&addr).unwrap().ciphertext, obj.ciphertext);
    }

    #[test]
    fn same_address_dedups() {
        let mut s = ObjectStore::new();
        let (addr, obj, _k) = seal(b"hi", &Visibility::Public).unwrap();
        s.put(addr.clone(), obj.clone());
        assert_eq!(s.put(addr.clone(), obj), Stored::Deduped(addr));
    }

    #[test]
    fn equal_plaintext_different_seal_is_stored_separately() {
        // ADR 0004: two independent seals of the same plaintext have different
        // addresses (random key+nonce) and MUST be stored as two distinct
        // objects. There is no plaintext comparison, so no equality oracle.
        let mut s = ObjectStore::new();
        let (addr1, obj1, _) = seal(b"same", &Visibility::Public).unwrap();
        let (addr2, obj2, _) = seal(b"same", &Visibility::Public).unwrap();
        assert_ne!(addr1, addr2);
        assert_eq!(s.put(addr1.clone(), obj1), Stored::New(addr1.clone()));
        assert_eq!(s.put(addr2.clone(), obj2), Stored::New(addr2.clone()));
        // Both retrievable independently.
        assert!(s.get(&addr1).is_ok());
        assert!(s.get(&addr2).is_ok());
    }

    #[test]
    fn missing_object_is_not_found() {
        let s = ObjectStore::new();
        assert!(matches!(s.get(&Oid([9; 32])), Err(RepoError::NotFound(_))));
    }
}
