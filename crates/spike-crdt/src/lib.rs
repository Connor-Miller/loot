//! Spike B: CRDT document store, filesystem as a projection.
//!
//! Thesis to prove out:
//!   - native live sync between machines ("Dropbox for devs")
//!   - in-memory by nature
//! Open questions this spike must answer honestly:
//!   - how do you model a *reviewable, embargoable change* when a CRDT
//!     converges state rather than recording discrete changes?
//!   - per-unit encryption fights the merge function (merge needs to see
//!     content). Where does that leave `.env`-style restricted content?
//!   - git interop story.
//!
//! TODO(spike): implement `Repo` for `CrdtRepo`, then run `benches/` against it.

use loot_core::{Change, Oid, Repo, RepoError, Visibility};
use std::path::PathBuf;

pub struct CrdtRepo {
    _root: PathBuf,
    // TODO: CRDT doc (automerge/yrs) as source of truth; FS = projection.
}

impl Repo for CrdtRepo {
    fn init(_path: PathBuf) -> Result<Self, RepoError> {
        todo!("spike-crdt: init CRDT doc + FS projection")
    }
    fn put(&mut self, _bytes: &[u8], _vis: Visibility) -> Result<Oid, RepoError> {
        todo!("spike-crdt: insert into doc; decide encryption-vs-merge tradeoff")
    }
    fn get(&self, _oid: &Oid, _reader: &str, _now: u64) -> Result<Vec<u8>, RepoError> {
        todo!("spike-crdt: read from doc, enforce visibility")
    }
    fn commit(&mut self, _change: Change) -> Result<Oid, RepoError> {
        todo!("spike-crdt: how is a discrete reviewable change modeled here?")
    }
    fn checkout(&self, _change: &Oid, _reader: &str, _now: u64) -> Result<(), RepoError> {
        todo!("spike-crdt: project doc to working tree; measure write perf")
    }
}
