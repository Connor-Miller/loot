//! Spike A: encrypted content-addressed DAG.
//!
//! Thesis to prove out:
//!   - each object is encrypted independently; visibility == key possession
//!   - addressing is by CIPHERTEXT hash, with a separate plaintext identity
//!     hash for dedup (the known sharp edge from the design discussion)
//!   - storage is log-structured / packed, NOT git-style loose files, so we
//!     don't reproduce the APFS small-file perf disaster Theo ranted about
//!   - can run fully in-memory
//!
//! TODO(spike): implement `Repo` for `DagRepo`, then run `benches/` against it.

use loot_core::{
    Change, MergeOutcome, Oid, Repo, RepoError, SyncBundle, Visibility,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub struct DagRepo {
    _root: PathBuf,
    _identity: String,
    // TODO: packed object store (single append-only file + index), in-memory variant.
    // TODO: per-object content key, wrapped per authorized identity.
}

impl Repo for DagRepo {
    fn init(_path: PathBuf, _identity: &str) -> Result<Self, RepoError> {
        todo!("spike-dag: init packed/in-memory store")
    }
    fn put(&mut self, _bytes: &[u8], _vis: Visibility) -> Result<Oid, RepoError> {
        todo!("spike-dag: encrypt, hash ciphertext for address, record dedup identity")
    }
    fn get(&self, _oid: &Oid, _reader: &str, _now: u64) -> Result<Vec<u8>, RepoError> {
        todo!("spike-dag: enforce visibility, unwrap key, decrypt")
    }
    fn commit(&mut self, _change: Change) -> Result<Oid, RepoError> {
        todo!("spike-dag: append change node to DAG")
    }
    fn checkout(&self, _change: &Oid, _reader: &str, _now: u64) -> Result<(), RepoError> {
        todo!("spike-dag: materialize visible tree; measure small-file write perf")
    }
    fn bundle(&self, _have: &[Oid]) -> Result<SyncBundle, RepoError> {
        todo!("spike-dag: pack reachable-not-have changes as ciphertext bundle")
    }
    fn apply(
        &mut self,
        _bundle: &SyncBundle,
        _now: u64,
    ) -> Result<BTreeMap<PathBuf, MergeOutcome>, RepoError> {
        todo!("spike-dag: 3-way merge per path; relay where no key (ADR 0001)")
    }
    fn heads(&self) -> Vec<Oid> {
        todo!("spike-dag: current change ids")
    }
}
