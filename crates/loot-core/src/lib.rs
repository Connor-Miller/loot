//! loot-core: the shared contract for the two storage spikes.
//!
//! Both `spike-dag` (encrypted content-addressed DAG) and `spike-crdt`
//! (CRDT document store) implement [`Repo`]. The bench harness runs the
//! same workload against each so we can compare speed and feel before
//! locking a foundation. The winner graduates into this crate; the loser
//! is deleted. Nothing downstream has to be refactored.

use std::collections::BTreeMap;
use std::path::PathBuf;

pub mod converge;
pub mod sealed;

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

/// An opaque, transport-ready bundle of changes produced by one repo and
/// applied by another. Its bytes are ciphertext + metadata: a peer can carry
/// and forward it without holding any key (the *relay* role from ADR 0001).
#[derive(Clone, Debug)]
pub struct SyncBundle(pub Vec<u8>);

/// The outcome of merging a peer's content into ours for a single path.
/// See ADR 0001 (per-content, decrypt-then-merge).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeOutcome {
    /// Disjoint or identical edits; converged with no human needed.
    Converged,
    /// Both sides edited the same content and we hold the key: a fine-grained
    /// merge was performed (this is where the CRDT model should shine).
    Merged,
    /// Both sides edited the same content but we lack the key, so we could only
    /// relay ciphertext, not merge. Records that convergence was deferred to a
    /// keyholder rather than silently dropping a side.
    RelayedUnmerged,
    /// Same content, both sides keyholders, but the edits genuinely conflict
    /// and need a human. Expected for the DAG model's 3-way merge.
    Conflict,
}

/// The contract under test. Covers the three bake-off axes:
///   - thesis fit: `put`/`get`/`commit`/`checkout` with per-path visibility
///   - local perf: write many small objects, materialize a tree (`checkout`)
///   - sync: `bundle` + `apply` with concurrent-offline convergence (ADR 0001)
///
/// Both spikes implement this identically; the bench harness is generic over
/// any `Repo`, so the comparison is apples-to-apples.
pub trait Repo {
    /// Create an empty repo rooted at `path` (a real dir, or in-memory if
    /// the backend ignores it). `identity` is this repo's keyholder identity;
    /// it determines which content this repo can decrypt, and thus whether it
    /// acts as a *merger* or a *relay* during sync.
    fn init(path: PathBuf, identity: &str) -> Result<Self, RepoError>
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

    // --- sync axis (ADR 0001) ---

    /// Produce a transport bundle of every change reachable here but not
    /// implied by `have` (the recipient's known change ids). Content stays
    /// encrypted; this repo need not hold keys to bundle ciphertext it relays.
    fn bundle(&self, have: &[Oid]) -> Result<SyncBundle, RepoError>;

    /// Apply a peer's bundle, converging per path. For each path touched on
    /// both sides, return its [`MergeOutcome`]. Whether this repo *merges* or
    /// merely *relays* a given path depends on whether it holds that content's
    /// key (its `identity` from `init`).
    fn apply(&mut self, bundle: &SyncBundle, now: u64)
        -> Result<BTreeMap<PathBuf, MergeOutcome>, RepoError>;

    /// Change ids this repo currently has — what a peer passes as `have`.
    fn heads(&self) -> Vec<Oid>;
}
