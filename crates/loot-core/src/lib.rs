//! loot-core: the shared contract for the encrypted DAG engine.
//!
//! [`DagRepo`] is the canonical implementation. [`Repo`] is the trait it
//! implements, shared by the spike crates so the bench harness is generic.

use std::collections::BTreeMap;
use std::path::PathBuf;

pub mod attestation;    // detachable advisory signatures over changes (S4, ADR 0018)
pub mod bridge;         // git interop bridge formats: trailers, marks, dates (GB1, ADR 0028)
pub mod burn;           // burn log: signed tombstones for destroyed objects (ADR 0038, #344)
pub mod buoy;           // navigational-role resolver over the attestation lane (CA4, ADR 0025)
pub mod bundle_codec;   // sync bundle wire format (ADR 0003, 0004, 0007)
pub mod converge;
pub mod engine;
pub mod escrow;
pub mod format;         // format version markers + compatibility gate (S1, ADR 0019)
pub mod hex;            // shared byte<->hex conversion (one home for all crates)
pub mod liveness;       // one home for live/superseded/divergent/parked + the head partition (map #215)
pub mod manifest;
pub mod oplog;          // operation log + undo (S4, ADR 0031)
pub mod sealed;
pub mod store;          // the .loot/ on-disk layout (single source of truth)
pub mod verdict;        // machine-facing reconciliation output (CA3, ADR 0023)

pub use attestation::{Attestation, AttestationLog};
pub use burn::{BurnLog, BurnTier, Tombstone};
pub use liveness::{HeadPartition, Liveness};
pub use engine::{
    change_signing_message, DagRepo, GcReport, LogGraph, LogNode, MaroonResult, MigrateResult,
    MissingObject, MissingRef, RotateRegrant, RotateReport, VerifyReport,
};
pub use oplog::{BarrierRefusal, Operation, StepError, Stepped, View};
pub use store::{valid_dock_name, LaneEntry, QuarantinedGrant, RepoStore, HOME_DOCK};
pub use verdict::{PathVerdict, VERDICT_CONTRACT};

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
    /// A grant whose `expires_at` has already passed as of the applying
    /// clock (#20). Parallel to `Embargoed`, but the other direction in time
    /// and a harder stop: an embargoed key merely isn't visible *yet* (it
    /// still stages), whereas an expired grant is rejected outright —
    /// `apply_sealed_grant` installs nothing for it.
    #[error("grant expired at {0}")]
    Expired(u64),
    #[error("unsupported format version v{found} — upgrade loot (this build reads up to v{supported})")]
    UnsupportedFormat { found: u8, supported: u8 },
    #[error("change {0:?} has a missing or invalid author signature")]
    BadChangeSignature(Oid),
    /// A snapshot would re-seal one or more paths *more readably* than the tree
    /// already records (#62, ADR 0030). A typed, matchable outcome carrying the
    /// offending paths so a driver can classify the abort (rather than scrape a
    /// prose string) and re-run with `--allow-demote` for the ones it intends.
    #[error("refusing to demote visibility of {}: an attributes change would re-seal private content more readably; restore the .lootattributes rule, or re-run with `--allow-demote <path>` to demote deliberately", .paths.join(", "))]
    Demotion { paths: Vec<String> },
    /// The mis-seal gate (#63, ADR 0038 §1): a secret-shaped path is being
    /// sealed public for the first time, but resolves Public only by
    /// *fallthrough* — no `.lootattributes` rule names it, so the default (or a
    /// catch-all glob) is what makes it readable. The sibling of `Demotion`: a
    /// typed, matchable refusal carrying the offending paths so a driver can
    /// classify the abort rather than scrape prose, overridable per-path with
    /// `--allow-reveal`. Content is never inspected — only the name and the
    /// resolution provenance.
    #[error("refusing to seal {} publicly: it matches a built-in secret-shaped name and resolves Public only by fallthrough (no .lootattributes rule names it). Name it in .lootattributes — `<path> restricted=<id>` to seal it, or `<path> public` to consent — or re-run with `--allow-reveal <path>` to seal it public deliberately", .paths.join(", "))]
    MisSeal { paths: Vec<String> },
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
    /// and need a human. Carries the OIDs of both sides so the conflict can be
    /// inspected and resolved (ADR 0001).
    Conflict { ours: Oid, theirs: Oid },
}

/// The contract under test. Covers the three bake-off axes:
///   - thesis fit: `put`/`get`/`record`/`surface` with per-path visibility
///   - local perf: write many small objects, materialize a tree (`surface`)
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
    fn record(&mut self, change: Change) -> Result<Oid, RepoError>;

    /// Materialize the tree of `change` to the working area, skipping
    /// content `reader` cannot see. This is the operation APFS makes slow.
    fn surface(&self, change: &Oid, reader: &str, now: u64) -> Result<(), RepoError>;

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

    /// Promote embargoed keys whose reveal time has passed into the keyring.
    /// Default no-op for implementations that don't use the Escrow model
    /// (e.g. the non-canonical spike-crdt). DagRepo overrides this (ADR 0007).
    fn flush_embargo(&mut self, _now: u64) {}
}
