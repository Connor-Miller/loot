//! loot-core: the shared contract for the two storage spikes.
//!
//! Both `spike-dag` (encrypted content-addressed DAG) and `spike-crdt`
//! (CRDT document store) implement [`Repo`]. The bench harness runs the
//! same workload against each so we can compare speed and feel before
//! locking a foundation. The winner graduates into this crate; the loser
//! is deleted. Nothing downstream has to be refactored.

use std::collections::BTreeMap;
use std::path::PathBuf;

/// Content identity. A stable handle to a unit of content, independent of
/// where (or whether) it is currently materialized on disk.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Oid(pub [u8; 32]);

/// Who may read a unit of content. The whole product thesis lives here:
/// visibility is a property of the *content*, not the repo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Visibility {
    /// Readable by anyone who can read the repo.
    Public,
    /// Readable only by the listed identities (by key id).
    Restricted(Vec<String>),
    /// Encrypted to all, but the decryption key is withheld until `reveal_at`
    /// (unix seconds). Models embargoed security fixes / delayed-reveal merges.
    Embargoed { reveal_at: u64 },
}

/// A change: the reviewable, permission-bearing unit (loot's answer to a commit).
#[derive(Clone, Debug)]
pub struct Change {
    pub id: Oid,
    pub parents: Vec<Oid>,
    pub message: String,
    /// Path -> content, with per-path visibility. This is where `.env`
    /// becomes committable: it lives in the change as `Restricted`/`Embargoed`.
    pub tree: BTreeMap<PathBuf, (Oid, Visibility)>,
}

#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    #[error("object not found: {0:?}")]
    NotFound(Oid),
    #[error("not authorized to read {0:?}")]
    Unauthorized(Oid),
    #[error("content still embargoed until {0}")]
    Embargoed(u64),
    #[error("backend error: {0}")]
    Backend(String),
}

/// The contract under test. Deliberately tiny: just enough to run the
/// workload from Theo's perf rant (write thousands of small objects,
/// read them back, materialize a tree) plus the visibility hook.
pub trait Repo {
    /// Create an empty repo rooted at `path` (a real dir, or in-memory if
    /// the backend ignores it).
    fn init(path: PathBuf) -> Result<Self, RepoError>
    where
        Self: Sized;

    /// Store one unit of content with a visibility policy. Returns its id.
    fn put(&mut self, bytes: &[u8], vis: Visibility) -> Result<Oid, RepoError>;

    /// Read content back, enforcing the visibility policy for `reader`.
    fn get(&self, oid: &Oid, reader: &str, now: u64) -> Result<Vec<u8>, RepoError>;

    /// Record a change over the current set of put() objects.
    fn commit(&mut self, change: Change) -> Result<Oid, RepoError>;

    /// Materialize the tree of `change` to the working area, skipping
    /// content `reader` cannot see. This is the operation APFS makes slow.
    fn checkout(&self, change: &Oid, reader: &str, now: u64) -> Result<(), RepoError>;
}
