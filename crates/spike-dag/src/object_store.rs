//! Content-addressed object storage for the DAG backend (internal seam).
//!
//! A log-structured store of [`SealedObject`]s: one append-only `Vec` plus two
//! indexes (content address -> position; plaintext identity-hash -> address for
//! dedup). It knows nothing about changes, keys, or identities — only how to
//! store ciphertext by address and dedup equal plaintext. Backend-private; a
//! different backend would store bytes differently.

use loot_core::sealed::SealedObject;
use loot_core::{Oid, RepoError};
use std::collections::BTreeMap;

/// What `put` did, so the caller (which owns key custody) knows whether the
/// freshly-minted key actually seals the stored ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stored {
    /// Object was newly written at exactly the requested address.
    New(Oid),
    /// Address (or equal plaintext) already present; collapsed onto this
    /// existing address. A minted key would be for discarded ciphertext.
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
    by_identity: BTreeMap<[u8; 32], Oid>,
}

impl ObjectStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store `obj` at `addr`, deduping on its plaintext identity hash. Returns
    /// [`Stored::New`] only when the object was actually written at `addr`;
    /// otherwise [`Stored::Deduped`] with the pre-existing address.
    pub fn put(&mut self, addr: Oid, obj: SealedObject) -> Stored {
        if self.by_addr.contains_key(&addr) {
            return Stored::Deduped(addr);
        }
        if let Some(existing) = self.by_identity.get(&obj.identity_hash).cloned() {
            return Stored::Deduped(existing);
        }
        let pos = self.log.len();
        self.by_identity.insert(obj.identity_hash, addr.clone());
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
    fn equal_plaintext_different_seal_dedups_to_first_address() {
        // Two independent seals of the same plaintext have different addresses
        // (random nonce/key) but the same identity hash, so the second dedups
        // onto the first — and reports Deduped, not New.
        let mut s = ObjectStore::new();
        let (addr1, obj1, _) = seal(b"same", &Visibility::Public).unwrap();
        let (addr2, obj2, _) = seal(b"same", &Visibility::Public).unwrap();
        assert_ne!(addr1, addr2);
        s.put(addr1.clone(), obj1);
        assert_eq!(s.put(addr2, obj2), Stored::Deduped(addr1));
    }

    #[test]
    fn missing_object_is_not_found() {
        let s = ObjectStore::new();
        assert!(matches!(s.get(&Oid([9; 32])), Err(RepoError::NotFound(_))));
    }
}
