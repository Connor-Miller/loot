//! RepoStore — the single source of truth for a repo's `.loot/` on-disk layout.
//!
//! Before this module the set of files under `.loot/` and their names were
//! spread across three places: the engine's `save`/`load` (identity, graph,
//! keyring, escrow, manifest, purges, conflicts + the loose `objects/` dir), the
//! Workspace (working, tree-hash, config), and loot-identity (id, id.pub, peers).
//! RepoStore concentrates *where every artifact lives* — path construction plus
//! the small process-file encodings — so no caller hardcodes a filename.
//!
//! It owns **layout, not policy**: which identity holds the repo, when a snapshot
//! happens, what a change means — those stay with the engine and the Workspace.
//! RepoStore is only the filesystem adapter between logical artifacts and paths.
//!
//! Full `.loot/` layout (one place to read it):
//!
//! ```text
//! identity     the ambient keyholder name            (engine)
//! objects/     loose content-addressed SealedObjects  (persist_codec, ADR 0012)
//! graph        the change DAG                          (engine)
//! keyring      this identity's content keys (LOCAL)    (engine, ADR 0003)
//! escrow       embargoed keys awaiting reveal          (engine, ADR 0007)
//! manifest     the grant audit trail                   (engine, ADR 0008)
//! purges       pending hard-maroon purge events        (engine, ADR 0009)
//! conflicts    unresolved merge conflicts              (engine, ADR 0001)
//! working      the in-progress working-change id       (Workspace, ADR 0006)
//! tree-hash    last snapshot's tree+message hash        (Workspace)
//! next-change  eagerly-minted next change id (v6)       (Workspace, ADR 0029/0030)
//! config       named remotes                            (Workspace, ADR 0013)
//! ops          local-only operation log for undo (LOCAL) (oplog, ADR 0031)
//! abandoned     local-only set of abandoned version ids (LOCAL) (S3, ADR 0029)
//! lost         acknowledged-lost object addresses (LOCAL)  (#335)
//! quarantine/  grants held back from an unregistered sender (#12, ADR 0015)
//! id, id.pub   the ed25519 keypair                      (loot-identity, ADR 0014)
//! peers        nickname -> pubkey registry              (loot-identity, ADR 0014)
//! ```
//!
//! The `objects/` subdirectory and the keypair/peers files are written by their
//! owning modules (persist_codec and loot-identity); RepoStore names their paths
//! so the layout has one documented home, and owns the read/write of the small
//! process files (`working`, `tree-hash`) whose on-disk encoding is otherwise
//! inlined in the Workspace.
//!
//! **Two roots (ADR 0034).** A RepoStore names paths under *two* directories:
//! the shared store root (`objects/`, `graph`, keyring, config, `git-mirror/`,
//! the `lanes/` registry — everything with one writer or append-only
//! discipline) and the **lane root**, which holds this position's private
//! mutable state (`working`, `working-change`, `tree-hash`, `next-change`,
//! `tip`, `heads`, `ops`, `abandoned`, `conflicts`, and the dock pointer/dirs).
//! For the primary directory — lane #0 — the two roots are the same `.loot/`,
//! so a repo that never spawns a lane is byte-for-byte unchanged on disk. A
//! spawned lane's `.loot/` is a *directory* containing a `store` pointer at the
//! shared root plus every lane-owned file; no mutable file ever has two
//! writers.

use crate::Oid;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

static STORE_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Write `bytes` to `path` atomically: stage to a unique sibling temp file, then
/// rename over `path`. A crash mid-write or a concurrent reader therefore never
/// observes a torn or truncated file — a reader always sees the whole
/// prior-or-next version, never a partial one (#252, extended to the lane-owned
/// process files in #293, and public since #307 for the bridge's spine files
/// under `.loot/git-mirror/`). The temp name is unique per (process, call) so
/// two writers never clobber each other's staging file; staging in the *same*
/// directory keeps the rename atomic.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let n = STORE_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(".{}.{}.{}.tmp", file_name, std::process::id(), n));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

/// True for the transient errors a Windows `rename`-replace produces when a
/// reader opens the destination inside the brief delete-pending / sharing window:
/// `PermissionDenied` (ERROR_ACCESS_DENIED, 5) **and** the raw
/// `ERROR_SHARING_VIOLATION` (os error 32) — which the writer's `MoveFileEx`
/// contention often yields and which Rust surfaces as an *uncategorized* error,
/// not `PermissionDenied`. `NotFound` is deliberately excluded: it keeps meaning
/// "absent", so an absent optional file still reads as empty rather than stalling.
pub(crate) fn is_transient_replace_error(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(32)
}

/// Read `path`, retrying while `retry(err)` holds. The backoff budget (~300ms:
/// 16 attempts, 1ms doubling to a 25ms cap) is enough to slip through a tight
/// writer loop's rename windows under CPU load without stalling a real read.
fn read_retrying(path: &Path, retry: impl Fn(&std::io::Error) -> bool) -> std::io::Result<Vec<u8>> {
    let mut delay = Duration::from_millis(1);
    for _ in 0..16 {
        match std::fs::read(path) {
            Err(e) if retry(&e) => {
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_millis(25));
            }
            other => return other,
        }
    }
    std::fs::read(path)
}

/// Read a file that is replaced via [`atomic_write`]. On Windows the
/// rename-replace leaves a brief window in which opening the destination
/// transiently fails (`PermissionDenied` / `ERROR_SHARING_VIOLATION`) even though
/// the file is never torn (#293 tail, #476). Retry briefly on those transient
/// errors so a reader racing a writer observes whole-old-or-whole-new; `NotFound`
/// still means "absent" (so an optional store file reads as empty), and a
/// persistent error propagates after the budget.
pub fn read_replaced(path: &Path) -> std::io::Result<Vec<u8>> {
    read_retrying(path, is_transient_replace_error)
}

/// Like [`read_replaced`] but for a file the caller knows **must** exist — the
/// graph, identity, and keyring of a keyed store. For those, a `NotFound` cannot
/// mean "absent": it can only be the momentary gap a Windows rename-replace opens
/// as it swaps the target, so it is retried as one more transient window rather
/// than propagated. This closes the last tear a plain [`read_replaced`] leaves,
/// where a required file blinks missing mid-replace under heavy contention (#476).
pub fn read_replaced_required(path: &Path) -> std::io::Result<Vec<u8>> {
    read_retrying(path, |e| {
        is_transient_replace_error(e) || e.kind() == std::io::ErrorKind::NotFound
    })
}

/// A short-lived exclusive lock over a shared store's mutable metadata files
/// (`graph`, `keyring`, `manifest`, …). ADR 0034 makes the shared store
/// append-only, but `save_to` persists it by a **read-modify-write of whole
/// files**; two concurrent writers that both read the same on-disk version and
/// then both write lose one another's appended change/key (#293 — a finalize
/// that "reports success but doesn't stick", and a keyring drop that makes
/// visible content read as "content you can't see"). Holding this lock across
/// that critical section serializes the read-modify-write so each writer merges
/// against the other's already-persisted state.
///
/// The file's *existence* is the lock (we do not keep the handle open), mirroring
/// the harbor lock (ADR 0036). RAII: [`Drop`] removes it. A lock left by a
/// crashed writer past [`Self::STALE`] is broken on sight so the store can never
/// wedge permanently.
#[derive(Debug)]
pub struct StoreLock {
    path: PathBuf,
    held: bool,
}

impl StoreLock {
    /// A lock older than this is treated as a crashed writer's and broken. The
    /// critical section is a handful of small file writes (milliseconds), so a
    /// live lock is never anywhere near this old.
    const STALE: Duration = Duration::from_secs(30);
    const POLL: Duration = Duration::from_millis(2);

    /// Acquire the lock at `path`, spinning until the holder releases (or its
    /// lock goes stale). Never fails: a permanently stuck lock is broken once it
    /// passes [`Self::STALE`], because proceeding un-serialized is worse than the
    /// rare stale-break race, and the caller has no meaningful recovery besides
    /// retrying anyway.
    fn acquire(path: PathBuf) -> Self {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        loop {
            match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_) => return Self { path, held: true },
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Break a stale lock from a crashed writer, then retry at once.
                    let stale = std::fs::metadata(&path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| SystemTime::now().duration_since(t).ok())
                        .is_none_or(|age| age >= Self::STALE);
                    if stale {
                        let _ = std::fs::remove_file(&path);
                        continue;
                    }
                    std::thread::sleep(Self::POLL);
                }
                // A transient error (e.g. a racing stale-break removing the temp)
                // — back off and retry rather than proceed unlocked.
                Err(_) => std::thread::sleep(Self::POLL),
            }
        }
    }

    fn remove(&mut self) {
        if self.held {
            let _ = std::fs::remove_file(&self.path);
            self.held = false;
        }
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        self.remove();
    }
}

const IDENTITY: &str = "identity";
const GRAPH: &str = "graph";
const KEYRING: &str = "keyring";
const ESCROW: &str = "escrow";
const MANIFEST: &str = "manifest";
const PURGES: &str = "purges";
const CONFLICTS: &str = "conflicts";
const ATTESTATIONS: &str = "attestations";
const WORKING: &str = "working";
const WORKING_CHANGE: &str = "working-change";
const HEADS: &str = "heads";
const TREE_HASH: &str = "tree-hash";
const NEXT_CHANGE: &str = "next-change";
const TIP: &str = "tip";
const DOCK: &str = "dock";
const CONFIG: &str = "config";
const GIT_MIRROR: &str = "git-mirror";
const OPS: &str = "ops";
const ABANDONED: &str = "abandoned";
/// The in-progress `loot bisect` session (#390). Lane-owned positional state,
/// like `ops`/`abandoned`: a bisect walk is per-position and never bundled.
const BISECT: &str = "bisect";
/// Acknowledged-lost content addresses (#335). Shared-store-rooted; see
/// [`RepoStore::lost`].
const LOST: &str = "lost";
/// Directory of grants quarantined at `pull-grants` from an unregistered
/// sender (#12). Shared-store-rooted; see [`RepoStore::quarantine_dir`].
const QUARANTINE: &str = "quarantine";
/// The burn log: signed tombstones for destroyed objects (ADR 0038, #344).
/// Shared-store-rooted and append-only — a burned oid is burned for every
/// identity; see [`RepoStore::burn_log`].
const BURN: &str = "burn";
/// The shared-store metadata lock (#293). `save_to` persists the append-only
/// shared surface (graph, keyring, …) by a read-modify-write of whole files;
/// without serialization two concurrent writers lose one another's appends. A
/// process holds this briefly across that critical section. Local-only, like the
/// harbor lock — never bundled.
const STORE_LOCK: &str = "store.lock";

/// The default dock every repo starts on — the primary directory (ADR 0022
/// physical model). Its process files are the root `.loot/working`/`tree-hash`/
/// `tip`, so a repo that never touches docks is byte-for-byte unchanged on disk.
/// Named `.loot/docks/` are retired (#253/ADR 0034): a second position is a
/// sealed lane whose own `.loot/` carries its process files, so every position
/// now resolves against the home selector and the primary is the only dock.
pub const HOME_DOCK: &str = "main";
const OBJECTS: &str = "objects";
const ID: &str = "id";
const ID_PUB: &str = "id.pub";
const PEERS: &str = "peers";
const STORE_POINTER: &str = "store";
const LANE_ID: &str = "lane-id";
/// A position's dot-directory name — the `.loot/` under a repo or lane root.
const DOT_DIR: &str = ".loot";
const LANES: &str = "lanes";
const LANE_PATH: &str = "path";
const LANE_NAME: &str = "name";
const LANE_HEARTBEAT: &str = "heartbeat";
const LANE_LANDED: &str = "landed";

/// Names every artifact under a repo's `.loot/` directory. Cheap to construct
/// (`new` just stores the directories), so callers that only have the `.loot`
/// path can wrap it on demand.
#[derive(Clone, Debug)]
pub struct RepoStore {
    /// The shared store root: append-only / single-writer artifacts.
    dot: PathBuf,
    /// The lane root holding this position's private mutable state (ADR 0034).
    /// Equal to `dot` for the primary directory (lane #0).
    lane: PathBuf,
}

impl RepoStore {
    /// Wrap a repo's `.loot/` directory (the primary: store and lane roots
    /// coincide, the pre-lane on-disk shape).
    pub fn new(dot: impl Into<PathBuf>) -> Self {
        let dot = dot.into();
        Self { lane: dot.clone(), dot }
    }

    /// Wrap a spawned lane: `dot` is the shared store's `.loot/`, `lane` the
    /// lane's own `.loot/` directory carrying every lane-owned file (ADR 0034).
    pub fn for_lane(dot: impl Into<PathBuf>, lane: impl Into<PathBuf>) -> Self {
        Self { dot: dot.into(), lane: lane.into() }
    }

    /// The shared store's `.loot/` directory.
    pub fn dot(&self) -> &Path {
        &self.dot
    }

    /// Whether this store views the repo through a spawned lane (distinct roots).
    pub fn is_lane(&self) -> bool {
        self.dot != self.lane
    }

    /// Acquire the shared-store metadata lock (#293), serializing the
    /// read-modify-write of the append-only shared files in `save_to`. The lock
    /// lives at the *shared* root (`self.dot`), so every lane over one store
    /// contends on the same file. RAII — released when the returned guard drops.
    pub fn lock_shared(&self) -> StoreLock {
        StoreLock::acquire(self.dot.join(STORE_LOCK))
    }

    // --- engine-owned artifacts ---
    pub fn objects_dir(&self) -> PathBuf { self.dot.join(OBJECTS) }
    pub fn identity(&self) -> PathBuf { self.dot.join(IDENTITY) }
    pub fn graph(&self) -> PathBuf { self.dot.join(GRAPH) }
    pub fn keyring(&self) -> PathBuf { self.dot.join(KEYRING) }
    pub fn escrow(&self) -> PathBuf { self.dot.join(ESCROW) }
    pub fn manifest(&self) -> PathBuf { self.dot.join(MANIFEST) }
    pub fn purges(&self) -> PathBuf { self.dot.join(PURGES) }
    /// Unresolved merge conflicts — positional view state, so lane-owned
    /// (ADR 0034): one lane's half-finished merge never blocks another.
    pub fn conflicts(&self) -> PathBuf { self.lane.join(CONFLICTS) }
    pub fn attestations(&self) -> PathBuf { self.dot.join(ATTESTATIONS) }

    // --- Workspace-owned process artifacts (lane-owned, ADR 0034) ---
    //
    // These live at this store instance's *lane root* — `.loot/` on the primary,
    // the lane's own `.loot/` for a spawned lane. The `dock` selector is always
    // the home selector now that named `.loot/docks/` are retired (#253); the
    // parameter survives until the deferred full dissolve (ADR 0034 consequence).
    // The no-arg `config` and the ambient-dock pointer are repo-wide.
    pub fn config(&self) -> PathBuf { self.dot.join(CONFIG) }

    /// Directory a position's process files live in: this store instance's lane
    /// root. Named docks are retired (#253/ADR 0034), so the selector only ever
    /// picks home — on the primary the lane root is `.loot/` itself, the
    /// unchanged pre-lane shape; on a spawned lane it is the lane's own `.loot/`.
    fn dock_dir(&self, dock: Option<&str>) -> PathBuf {
        debug_assert!(dock.is_none(), "named docks are retired (#253); the selector is always home");
        let _ = dock;
        self.lane.clone()
    }

    pub fn working(&self, dock: Option<&str>) -> PathBuf { self.dock_dir(dock).join(WORKING) }
    pub fn tree_hash(&self, dock: Option<&str>) -> PathBuf { self.dock_dir(dock).join(TREE_HASH) }
    pub fn next_change(&self, dock: Option<&str>) -> PathBuf { self.dock_dir(dock).join(NEXT_CHANGE) }
    pub fn tip(&self, dock: Option<&str>) -> PathBuf { self.dock_dir(dock).join(TIP) }

    /// The ambient-dock pointer: names the dock this workspace is currently on.
    /// Absent (or `home`) means the home dock — so pre-dock repos read as home.
    /// Positional, so lane-owned.
    pub fn dock_pointer(&self) -> PathBuf { self.lane.join(DOCK) }

    // --- loot-identity-owned artifacts (named here; written there) ---
    pub fn id(&self) -> PathBuf { self.dot.join(ID) }
    pub fn id_pub(&self) -> PathBuf { self.dot.join(ID_PUB) }
    pub fn peers(&self) -> PathBuf { self.dot.join(PEERS) }

    // --- git interop bridge artifacts (GB1, ADR 0028) ---
    //
    // Local-only, like `keyring`/`escrow` — never synced. `marks` and `state`
    // are rebuildable from commit trailers; the rest is per-machine config.
    pub fn git_mirror_dir(&self) -> PathBuf { self.dot.join(GIT_MIRROR) }
    pub fn git_marks(&self) -> PathBuf { self.git_mirror_dir().join("marks") }
    pub fn git_state(&self) -> PathBuf { self.git_mirror_dir().join("state") }
    pub fn git_identity_map(&self) -> PathBuf { self.git_mirror_dir().join("identity") }
    pub fn git_allowed_signers(&self) -> PathBuf { self.git_mirror_dir().join("allowed-signers") }
    pub fn git_config(&self) -> PathBuf { self.git_mirror_dir().join("config") }
    pub fn git_wip(&self) -> PathBuf { self.git_mirror_dir().join("wip") }
    pub fn git_pr_map(&self) -> PathBuf { self.git_mirror_dir().join("pr-map") }

    /// The **harbor lock** (ADR 0036): the on-demand mutex a `land` holds while
    /// it projects a signed change to git-main and pushes. Shared-store-rooted
    /// (`self.dot`, never the lane) so every lane over one store contends on the
    /// same file — that single-writer window is what serializes N concurrent
    /// agents' lands into a linear git-main. Local-only, like the rest of
    /// `git-mirror/`; never bundled, never pushed.
    pub fn harbor_lock(&self) -> PathBuf { self.git_mirror_dir().join("harbor.lock") }

    /// The **pr-map ledger lock** (#336): held across every read-modify-write
    /// of [`git_pr_map`](Self::git_pr_map), so a `land`'s whole-file rewrite
    /// can never erase rows sibling `review`s recorded after it read.
    /// Deliberately a separate file from the harbor lock: the harbor
    /// serializes the git-main-critical section (seconds, and released before
    /// land's ledger close-out), while this guards a ledger write
    /// (microseconds) — a review recording its row must not queue behind a
    /// land. Shared-store-rooted and local-only, like its ledger.
    pub fn git_pr_map_lock(&self) -> PathBuf { self.git_mirror_dir().join("pr-map.lock") }

    // --- operation log (S4, ADR 0031) ---
    //
    // Local-only, append-only history of view-changing operations backing
    // `loot undo` / `loot op`. Like `keyring`/`escrow`/the git mark map it is
    // per-machine and **never enters a bundle** — losing it loses undo
    // history, not repo data. Lane-owned (ADR 0034): a lane's op views can
    // only capture per-lane state, so undo in one lane cannot rewind another.
    pub fn ops(&self) -> PathBuf { self.lane.join(OPS) }

    // --- divergent-change abandonment (S3, ADR 0029/0030) ---
    //
    // Local-only set of **abandoned version ids** — versions dropped from a
    // divergent change by `loot abandon`. A view-level filter (never deletes the
    // node from the graph or object store), captured by the oplog so abandon is
    // undoable. Never bundled, like `ops`/the git marks. Lane-owned (ADR 0034).
    pub fn abandoned(&self) -> PathBuf { self.lane.join(ABANDONED) }

    // --- bisect session (#390) ---
    //
    // Local-only, lane-owned state for an in-progress `loot bisect` walk: the
    // known-good/known-bad changes, any skipped ones, the midpoint currently
    // materialized, and the change to restore on `reset`. Captured by the oplog
    // (like `abandoned`) so a bisect step is undoable, and never bundled.
    pub fn bisect(&self) -> PathBuf { self.lane.join(BISECT) }

    /// The set of abandoned version ids (each 32 raw bytes), or empty if none.
    /// A malformed/short file reads as empty (best-effort; the oplog can rebuild).
    pub fn read_abandoned(&self) -> std::collections::BTreeSet<Oid> {
        match read_replaced(&self.abandoned()) {
            Ok(b) if b.len() % 32 == 0 => b
                .chunks_exact(32)
                .map(|c| {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(c);
                    Oid(a)
                })
                .collect(),
            _ => std::collections::BTreeSet::new(),
        }
    }

    /// Persist the abandoned-version set as concatenated 32-byte ids, or remove
    /// the file when empty (best-effort removal keeps a pristine repo clean).
    pub fn write_abandoned(&self, set: &std::collections::BTreeSet<Oid>) -> std::io::Result<()> {
        if set.is_empty() {
            let _ = std::fs::remove_file(self.abandoned());
            return Ok(());
        }
        let mut bytes = Vec::with_capacity(set.len() * 32);
        for id in set {
            bytes.extend_from_slice(&id.0);
        }
        atomic_write(&self.abandoned(), &bytes)
    }

    // --- acknowledged object loss (#335) ---
    //
    // Local-only set of **content addresses** an operator has explicitly
    // accepted as lost (`loot verify --accept-loss`): referenced by a change
    // but absent from `objects/` and unrecoverable — the address is
    // `blake3(nonce || ciphertext)` and the nonce lived only inside the
    // deleted file, so not even the original plaintext can rebuild it.
    // `verify` reports acknowledged addresses separately and stops failing on
    // them; NEW damage still fails. Shared-store-rooted (the loss is a fact
    // about this store's disk, the same for every lane); written only by the
    // primary's accept-loss verb under the store lock, so the single-writer
    // rule (ADR 0034) holds. Never bundled — another clone may still hold the
    // bytes.
    pub fn lost(&self) -> PathBuf { self.dot.join(LOST) }

    // --- burn log (ADR 0038, #344) ---
    //
    // Shared-store-rooted, append-only signed tombstones for objects `loot
    // burn` destroyed: a burned oid is burned for every identity, so the record
    // lives with the shared graph, not per-lane. `verify`, `surface`, sync
    // negotiation, `apply`, `stow`, and `gc` all consult it; the burn verb and
    // `save_to`'s append-only union are the only writers. Decoded via
    // [`crate::burn::decode`] — the codec lives with the type, like the
    // manifest/attestation logs.
    pub fn burn_log(&self) -> PathBuf { self.dot.join(BURN) }

    /// The set of acknowledged-lost addresses (each 32 raw bytes), or empty if
    /// none. A malformed file reads as empty — verify then fails on the
    /// addresses again, the safe direction (never silently forgives).
    pub fn read_lost(&self) -> std::collections::BTreeSet<Oid> {
        match read_replaced(&self.lost()) {
            Ok(b) if b.len() % 32 == 0 => b
                .chunks_exact(32)
                .map(|c| {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(c);
                    Oid(a)
                })
                .collect(),
            _ => std::collections::BTreeSet::new(),
        }
    }

    /// Persist the acknowledged-lost set, or remove the file when empty.
    pub fn write_lost(&self, set: &std::collections::BTreeSet<Oid>) -> std::io::Result<()> {
        if set.is_empty() {
            let _ = std::fs::remove_file(self.lost());
            return Ok(());
        }
        let mut bytes = Vec::with_capacity(set.len() * 32);
        for id in set {
            bytes.extend_from_slice(&id.0);
        }
        atomic_write(&self.lost(), &bytes)
    }

    // --- quarantined grants (#12, ADR 0015) ---
    //
    // `pull-grants` quarantines a grant bundle from a pubkey the peer registry
    // doesn't recognize rather than dropping it — the operator can review it
    // (`loot grants --quarantined`) and later trust the sender (`loot grants
    // --trust <pubkey-hex>`), which re-applies every held bundle. Shared-store
    // rooted like `keyring`/`manifest` (one identity's mailbox, not a lane
    // concern), keyed by the sender's pubkey hex and then the grant's target
    // oid hex — disjoint per-(sender, oid) filenames, so concurrent
    // quarantines from different senders (or different grants) are lock-free,
    // the same reasoning as loose object storage (ADR 0012).

    /// The quarantine root: one subdirectory per sender pubkey hex.
    pub fn quarantine_dir(&self) -> PathBuf { self.dot.join(QUARANTINE) }

    /// One sender's quarantined grants.
    pub fn quarantine_sender_dir(&self, sender_hex: &str) -> PathBuf {
        self.quarantine_dir().join(sender_hex)
    }

    /// One quarantined grant bundle: `<sender pubkey hex>/<oid hex>`.
    pub fn quarantine_entry_path(&self, sender_hex: &str, oid_hex: &str) -> PathBuf {
        self.quarantine_sender_dir(sender_hex).join(oid_hex)
    }

    /// Persist one quarantined grant bundle. `received_at` is the injected
    /// clock's reading at receipt (a value, not a call, per the ADR 0006 clock
    /// discipline), stored as an 8-byte little-endian prefix ahead of the raw
    /// bundle bytes so `--trust` can re-apply exactly what arrived.
    pub fn write_quarantine_entry(
        &self,
        sender_hex: &str,
        oid_hex: &str,
        received_at: u64,
        bundle_bytes: &[u8],
    ) -> std::io::Result<()> {
        let path = self.quarantine_entry_path(sender_hex, oid_hex);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut bytes = Vec::with_capacity(8 + bundle_bytes.len());
        bytes.extend_from_slice(&received_at.to_le_bytes());
        bytes.extend_from_slice(bundle_bytes);
        atomic_write(&path, &bytes)
    }

    /// Every quarantined grant across every sender, sorted by sender then oid
    /// hex for deterministic listing. A malformed entry (too short to carry
    /// the 8-byte timestamp header) is skipped rather than failing the whole
    /// listing — best-effort, like `read_abandoned`/`read_lost`.
    pub fn read_quarantine(&self) -> Vec<QuarantinedGrant> {
        let mut out = Vec::new();
        let Ok(senders) = std::fs::read_dir(self.quarantine_dir()) else { return out };
        let mut sender_hexes: Vec<String> = senders
            .flatten()
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        sender_hexes.sort();
        for sender_hex in sender_hexes {
            out.extend(self.read_quarantine_for_sender(&sender_hex));
        }
        out
    }

    /// Every quarantined grant from one sender, sorted by oid hex.
    pub fn read_quarantine_for_sender(&self, sender_hex: &str) -> Vec<QuarantinedGrant> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(self.quarantine_sender_dir(sender_hex)) else {
            return out;
        };
        let mut oid_hexes: Vec<String> = entries
            .flatten()
            .filter(|e| e.path().is_file())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        oid_hexes.sort();
        for oid_hex in oid_hexes {
            let path = self.quarantine_entry_path(sender_hex, &oid_hex);
            let Ok(bytes) = read_replaced(&path) else { continue };
            if bytes.len() < 8 {
                continue;
            }
            let mut ts = [0u8; 8];
            ts.copy_from_slice(&bytes[..8]);
            out.push(QuarantinedGrant {
                sender_hex: sender_hex.to_string(),
                oid_hex,
                received_at: u64::from_le_bytes(ts),
                bundle_bytes: bytes[8..].to_vec(),
            });
        }
        out
    }

    /// Remove one quarantined grant — it has been re-applied (or is being
    /// discarded). Idempotent (a missing entry is not an error). Also removes
    /// the sender's subdirectory once it is empty, so a fully-trusted sender
    /// leaves no trace under `quarantine/`.
    pub fn remove_quarantine_entry(&self, sender_hex: &str, oid_hex: &str) -> std::io::Result<()> {
        let path = self.quarantine_entry_path(sender_hex, oid_hex);
        let _ = std::fs::remove_file(&path);
        // Best-effort: fails (harmlessly) if other entries remain.
        let _ = std::fs::remove_dir(self.quarantine_sender_dir(sender_hex));
        Ok(())
    }

    /// Read the working-change id (32 raw bytes) for `dock` if one is in
    /// progress. An absent or malformed file means finalized history.
    pub fn read_working(&self, dock: Option<&str>) -> Option<Oid> {
        read_oid_file(&self.working(dock))
    }

    /// Persist the working-change id for `dock`, or remove the file when there is
    /// none. Removal failure is ignored (best-effort).
    pub fn write_working(&self, dock: Option<&str>, working: Option<&Oid>) -> std::io::Result<()> {
        write_oid_file(&self.working(dock), working)
    }

    /// The finalized tip `dock` sits on — the change new snapshots fork from
    /// (ADR 0022). Absent means "derive from the graph" (the home dock before any
    /// dock exists, where the single head is unambiguous).
    pub fn read_tip(&self, dock: Option<&str>) -> Option<Oid> {
        read_oid_file(&self.tip(dock))
    }

    /// Record (or clear) the finalized tip for `dock`.
    pub fn write_tip(&self, dock: Option<&str>, tip: Option<&Oid>) -> std::io::Result<()> {
        write_oid_file(&self.tip(dock), tip)
    }

    /// The last snapshot's tree+message hash for `dock`, or empty if never written.
    pub fn read_tree_hash(&self, dock: Option<&str>) -> Vec<u8> {
        read_replaced(&self.tree_hash(dock)).unwrap_or_default()
    }

    /// Record the snapshot hash used for idempotent re-`status`.
    pub fn write_tree_hash(&self, dock: Option<&str>, hash: &[u8]) -> std::io::Result<()> {
        atomic_write(&self.tree_hash(dock), hash)
    }

    /// Forget the snapshot hash so the next snapshot always runs the engine.
    pub fn clear_tree_hash(&self, dock: Option<&str>) {
        let _ = std::fs::remove_file(self.tree_hash(dock));
    }

    /// The durable change id `loot new` minted eagerly for `dock`'s *next*
    /// change (ADR 0029/0030), before any snapshot has recorded it. 16 raw
    /// bytes; absent or malformed means none is pending.
    pub fn read_next_change(&self, dock: Option<&str>) -> Option<[u8; 16]> {
        match read_replaced(&self.next_change(dock)) {
            Ok(b) if b.len() == 16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&b);
                Some(a)
            }
            _ => None,
        }
    }

    /// Record (or clear) the pending next change id for `dock`. Cleared once the
    /// first snapshot has carried it onto the change (best-effort removal).
    pub fn write_next_change(&self, dock: Option<&str>, id: Option<&[u8; 16]>) -> std::io::Result<()> {
        match id {
            Some(id) => atomic_write(&self.next_change(dock), id),
            None => {
                let _ = std::fs::remove_file(self.next_change(dock));
                Ok(())
            }
        }
    }

    /// The name of the ambient dock, or [`HOME_DOCK`] when the pointer is absent
    /// or empty (pre-dock repos, and repos switched back home).
    pub fn read_dock(&self) -> String {
        match std::fs::read_to_string(self.dock_pointer()) {
            Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
            _ => HOME_DOCK.to_string(),
        }
    }

    // Named-dock directory management (`ensure_dock_dir`/`remove_dock_dir`/
    // `dock_exists`/`list_docks`) and the ambient-pointer writer (`write_dock`)
    // are retired with `.loot/docks/` (#253/ADR 0034): the primary is the only
    // dock and every other position is a sealed lane in the registry. `read_dock`
    // survives to read a legacy `.loot/dock` pointer (it returns home otherwise).

    // --- lineage persistence (ADR 0022 physical model) ---
    //
    // A dock's lineage *tips* (`heads`) and its out-of-graph *working change*
    // (`working-change`) persist beside the shared graph, like git's per-worktree
    // HEAD. The engine writes both on `save` and reads them on `load`; a repo with
    // no `heads` file predates this and derives its tips from the whole graph.
    // Both are lane-owned (ADR 0034): each lane's `heads` is its own view
    // frontier, and its unsigned working change never leaves the lane — that is
    // the seal. Only signed changes enter the shared graph, at finalize.

    pub fn heads(&self) -> PathBuf { self.lane.join(HEADS) }
    pub fn working_change(&self) -> PathBuf { self.lane.join(WORKING_CHANGE) }

    /// This dock's lineage tips, or `None` for a legacy repo with no `heads` file
    /// (the loader then derives them from the whole graph). An empty or malformed
    /// file is treated the same as absent.
    pub fn read_heads(&self) -> Option<Vec<Oid>> {
        let bytes = read_replaced(&self.heads()).ok()?;
        if bytes.is_empty() || bytes.len() % 32 != 0 {
            return None;
        }
        Some(
            bytes
                .chunks_exact(32)
                .map(|c| {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(c);
                    Oid(a)
                })
                .collect(),
        )
    }

    /// Persist this dock's lineage tips as concatenated 32-byte ids.
    pub fn write_heads(&self, heads: &[Oid]) -> std::io::Result<()> {
        let mut bytes = Vec::with_capacity(heads.len() * 32);
        for h in heads {
            bytes.extend_from_slice(&h.0);
        }
        atomic_write(&self.heads(), &bytes)
    }

    /// The encoded working-change node blob if one is in progress, else `None`.
    pub fn read_working_change(&self) -> Option<Vec<u8>> {
        read_replaced(&self.working_change()).ok()
    }

    /// Persist the encoded working-change node blob, or remove the file when there
    /// is none (best-effort removal).
    pub fn write_working_change(&self, blob: Option<&[u8]>) -> std::io::Result<()> {
        match blob {
            Some(b) => atomic_write(&self.working_change(), b),
            None => {
                let _ = std::fs::remove_file(self.working_change());
                Ok(())
            }
        }
    }

    // --- lane pointer + registry (ADR 0034, #231) ---
    //
    // A spawned lane's `.loot/` directory carries a `store` file (the absolute
    // path of the shared store's `.loot/`) and a `lane-id` file (its registry
    // entry's id). The shared store carries one registry entry directory per
    // live lane at `.loot/lanes/<id>/` — `path` (the lane's working directory),
    // `name` (present iff the lane was promoted to a dock), `heartbeat` (unix
    // seconds, rewritten on every workspace open from the lane), and `landed`
    // (a marker the land path writes so the gc-sweep can reap without a stale
    // wait). Writer discipline is per-entry single-writer: each entry is
    // written only by its own lane; the reaper is the only deleter. The
    // registry is deliberately **not** captured by the op log — an undo in one
    // lane must never rewind another lane's entry.

    /// The shared-store path a lane's `.loot/` directory points at, if `dot`
    /// is one (it contains a `store` pointer file). The primary's `.loot/` has
    /// no pointer and reads as `None`.
    pub fn read_store_pointer(dot: &Path) -> Option<PathBuf> {
        read_trimmed(&dot.join(STORE_POINTER)).map(PathBuf::from)
    }

    /// Stamp a fresh lane `.loot/` directory: the `store` pointer at the shared
    /// root and the lane's registry id. Creates the directory.
    pub fn write_lane_pointer(dot: &Path, shared: &Path, id: &str) -> std::io::Result<()> {
        std::fs::create_dir_all(dot)?;
        std::fs::write(dot.join(STORE_POINTER), shared.display().to_string())?;
        std::fs::write(dot.join(LANE_ID), id)
    }

    /// The registry id recorded in a lane's `.loot/` directory, if present.
    pub fn read_lane_id(dot: &Path) -> Option<String> {
        read_trimmed(&dot.join(LANE_ID))
    }

    pub fn lanes_dir(&self) -> PathBuf { self.dot.join(LANES) }
    pub fn lane_entry_dir(&self, id: &str) -> PathBuf { self.lanes_dir().join(id) }

    /// The store view a registered lane sees: this shared root plus the lane's
    /// own `.loot/` under its working directory. RepoStore owns the layout, so
    /// the `.loot` name for a lane's dot directory is named here, not by
    /// callers walking the registry (#265's gc walk, the lane peek).
    pub fn lane_view(&self, entry: &LaneEntry) -> RepoStore {
        RepoStore::for_lane(&self.dot, entry.path.join(DOT_DIR))
    }

    /// Whether a registry entry exists for `id`.
    pub fn lane_entry_exists(&self, id: &str) -> bool {
        self.lane_entry_dir(id).is_dir()
    }

    /// Register a spawned lane: its working-directory path, its dock-name if it
    /// was born named, and a first heartbeat.
    pub fn create_lane_entry(
        &self,
        id: &str,
        path: &Path,
        name: Option<&str>,
        now: u64,
    ) -> std::io::Result<()> {
        let dir = self.lane_entry_dir(id);
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join(LANE_PATH), path.display().to_string())?;
        if let Some(n) = name {
            std::fs::write(dir.join(LANE_NAME), n)?;
        }
        std::fs::write(dir.join(LANE_HEARTBEAT), now.to_string())
    }

    /// The registry entry for `id`, or `None` if absent/malformed (no `path`).
    pub fn read_lane_entry(&self, id: &str) -> Option<LaneEntry> {
        let dir = self.lane_entry_dir(id);
        let path = std::fs::read_to_string(dir.join(LANE_PATH)).ok()?;
        let name = std::fs::read_to_string(dir.join(LANE_NAME))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let heartbeat = std::fs::read_to_string(dir.join(LANE_HEARTBEAT))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let landed = dir.join(LANE_LANDED).exists();
        Some(LaneEntry {
            id: id.to_string(),
            path: PathBuf::from(path.trim()),
            name,
            heartbeat,
            landed,
        })
    }

    /// Every registered lane, sorted by id. Entries without a readable `path`
    /// are skipped (malformed; the reaper's concern, not the lister's).
    pub fn list_lane_entries(&self) -> Vec<LaneEntry> {
        let mut ids: Vec<String> = std::fs::read_dir(self.lanes_dir())
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        ids.sort();
        ids.iter().filter_map(|id| self.read_lane_entry(id)).collect()
    }

    /// Promote (name) a lane: record its dock-name in the registry entry.
    pub fn write_lane_name(&self, id: &str, name: &str) -> std::io::Result<()> {
        std::fs::write(self.lane_entry_dir(id).join(LANE_NAME), name)
    }

    /// Refresh a lane's heartbeat. Self-healing: recreates the entry (and its
    /// `path`) if a sweep removed it while the lane was still alive on disk.
    pub fn touch_lane_heartbeat(&self, id: &str, path: &Path, now: u64) -> std::io::Result<()> {
        let dir = self.lane_entry_dir(id);
        std::fs::create_dir_all(&dir)?;
        if !dir.join(LANE_PATH).exists() {
            std::fs::write(dir.join(LANE_PATH), path.display().to_string())?;
        }
        std::fs::write(dir.join(LANE_HEARTBEAT), now.to_string())
    }

    /// Mark a lane's change as landed (the land path writes this; the gc-sweep
    /// reaps landed unnamed lanes without waiting for staleness).
    pub fn mark_lane_landed(&self, id: &str) -> std::io::Result<()> {
        std::fs::write(self.lane_entry_dir(id).join(LANE_LANDED), b"")
    }

    /// Delete a lane's registry entry (the reaper is the only deleter).
    pub fn remove_lane_entry(&self, id: &str) -> std::io::Result<()> {
        std::fs::remove_dir_all(self.lane_entry_dir(id))
    }
}

/// One registered lane, as read from `.loot/lanes/<id>/` (ADR 0034, #231).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneEntry {
    pub id: String,
    /// The lane's working directory (holds its `.loot/` and tree).
    pub path: PathBuf,
    /// The dock-name, present iff the lane was promoted (named lanes persist).
    pub name: Option<String>,
    /// Unix seconds of the lane's last workspace open.
    pub heartbeat: u64,
    /// Whether the land path marked this lane's change landed.
    pub landed: bool,
}

impl LaneEntry {
    /// Whether the heartbeat is older than `stale_secs` at `now` — the gc-sweep
    /// condition for an unnamed lane that never landed.
    pub fn stale(&self, now: u64, stale_secs: u64) -> bool {
        now.saturating_sub(self.heartbeat) > stale_secs
    }
}

/// One grant `pull-grants` quarantined because its sender wasn't a registered
/// peer (#12, ADR 0015), as read back from `.loot/quarantine/<sender_hex>/`.
/// `bundle_bytes` is exactly what arrived — the `Frame::SealedGrant`-encoded
/// bytes `apply_sealed_grant` expects — so `--trust` re-applies it verbatim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuarantinedGrant {
    /// The sender's pubkey, lowercase hex.
    pub sender_hex: String,
    /// The grant's target content oid, lowercase hex.
    pub oid_hex: String,
    /// Unix seconds when this grant was quarantined.
    pub received_at: u64,
    pub bundle_bytes: Vec<u8>,
}

/// Validate a name for a *new* lane or its promoted dock-name (#253/ADR 0034).
/// The charset (ASCII alphanumerics plus `-`/`_`) is deliberately narrow so a
/// name can never traverse or escape a directory when it seeds a lane directory
/// or a registry entry id. Home (`main`) is reserved — the primary always holds
/// it.
pub fn valid_dock_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("dock name cannot be empty".into());
    }
    if name == HOME_DOCK {
        return Err(format!("'{HOME_DOCK}' is the default dock — it always exists"));
    }
    if name.len() > 64 {
        return Err("dock name is too long (max 64 characters)".into());
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(format!(
            "invalid dock name '{name}' — use only letters, digits, '-' and '_'"
        ));
    }
    Ok(())
}

/// Read a small text pointer file, trimmed; absent or blank reads as `None`.
fn read_trimmed(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Read a 32-byte Oid file, or `None` if absent/malformed.
fn read_oid_file(path: &Path) -> Option<Oid> {
    match read_replaced(path) {
        Ok(b) if b.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            Some(Oid(a))
        }
        _ => None,
    }
}

/// Write a 32-byte Oid, or remove the file when `None` (best-effort removal).
fn write_oid_file(path: &Path, oid: Option<&Oid>) -> std::io::Result<()> {
    match oid {
        Some(oid) => atomic_write(path, &oid.0),
        None => {
            let _ = std::fs::remove_file(path);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_replace_errors_are_retried_but_not_found_is_absent() {
        use std::io::{Error, ErrorKind};
        // ERROR_ACCESS_DENIED (5) and ERROR_SHARING_VIOLATION (32) are the two
        // shapes a Windows rename-replace window yields — both retry.
        assert!(is_transient_replace_error(&Error::from(
            ErrorKind::PermissionDenied
        )));
        assert!(is_transient_replace_error(&Error::from_raw_os_error(32)));
        // Absent stays absent (an optional store file reads as empty), and a
        // genuine unrelated error is not silently swallowed by retrying.
        assert!(!is_transient_replace_error(&Error::from(ErrorKind::NotFound)));
        assert!(!is_transient_replace_error(&Error::from(
            ErrorKind::InvalidData
        )));
    }

    #[test]
    fn paths_are_under_dot() {
        let s = RepoStore::new("/tmp/repo/.loot");
        assert!(s.graph().ends_with(".loot/graph"));
        assert!(s.working(None).ends_with(".loot/working"));
        assert!(s.objects_dir().ends_with(".loot/objects"));
        assert!(s.peers().ends_with(".loot/peers"));
    }

    #[test]
    fn home_position_uses_root_files() {
        // The compat guarantee: the primary's process files are the root files,
        // so a repo that never spawns a lane looks exactly as before. Named
        // `.loot/docks/` are retired (#253) — the selector is always home.
        let s = RepoStore::new("/tmp/repo/.loot");
        assert!(s.working(None).ends_with(".loot/working"));
        assert!(s.tip(None).ends_with(".loot/tip"));
    }

    #[test]
    fn working_round_trips_and_clears() {
        let dir = std::env::temp_dir().join(format!("loot-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let s = RepoStore::new(&dir);

        assert_eq!(s.read_working(None), None, "no working file yet");
        s.write_working(None, Some(&Oid([5; 32]))).unwrap();
        assert_eq!(s.read_working(None), Some(Oid([5; 32])));
        s.write_working(None, None).unwrap();
        assert_eq!(s.read_working(None), None, "None removes the file");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tree_hash_round_trips_and_clears() {
        let dir = std::env::temp_dir().join(format!("loot-store-th-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let s = RepoStore::new(&dir);

        assert!(s.read_tree_hash(None).is_empty());
        s.write_tree_hash(None, b"hash-bytes").unwrap();
        assert_eq!(s.read_tree_hash(None), b"hash-bytes");
        s.clear_tree_hash(None);
        assert!(s.read_tree_hash(None).is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_dock_defaults_to_home_without_a_pointer() {
        // The ambient pointer is retired (#253/ADR 0034): nothing writes
        // `.loot/dock` anymore, so a repo always reads as the home dock. A legacy
        // pointer file, if one survives, still reads back for compatibility.
        let dir = std::env::temp_dir().join(format!("loot-store-dock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let s = RepoStore::new(&dir);

        assert_eq!(s.read_dock(), HOME_DOCK, "no pointer reads as home");
        std::fs::write(s.dock_pointer(), "legacy").unwrap();
        assert_eq!(s.read_dock(), "legacy", "a legacy pointer still reads back");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn abandoned_set_round_trips_and_clears() {
        let dir = std::env::temp_dir().join(format!("loot-store-ab-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let s = RepoStore::new(&dir);

        assert!(s.read_abandoned().is_empty(), "no abandoned file yet");
        let set = std::collections::BTreeSet::from([Oid([3; 32]), Oid([9; 32])]);
        s.write_abandoned(&set).unwrap();
        assert_eq!(s.read_abandoned(), set, "round-trips the version-id set");
        // Empty writes remove the file (pristine repo stays clean).
        s.write_abandoned(&std::collections::BTreeSet::new()).unwrap();
        assert!(s.read_abandoned().is_empty());
        assert!(!s.abandoned().exists(), "empty set removes the file");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn quarantine_round_trips_keyed_by_sender_and_oid() {
        let dir = std::env::temp_dir().join(format!("loot-store-qn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let s = RepoStore::new(&dir);

        assert!(s.read_quarantine().is_empty(), "nothing quarantined yet");

        let alice = "aa".repeat(32);
        let bob = "bb".repeat(32);
        let oid1 = "11".repeat(32);
        let oid2 = "22".repeat(32);

        s.write_quarantine_entry(&alice, &oid1, 1_000, b"alice-grant-1").unwrap();
        s.write_quarantine_entry(&alice, &oid2, 2_000, b"alice-grant-2").unwrap();
        s.write_quarantine_entry(&bob, &oid1, 3_000, b"bob-grant-1").unwrap();

        let all = s.read_quarantine();
        assert_eq!(all.len(), 3, "every sender's every grant is listed");
        // Sorted by sender then oid — deterministic listing.
        assert_eq!(all[0].sender_hex, alice);
        assert_eq!(all[0].oid_hex, oid1);
        assert_eq!(all[0].received_at, 1_000);
        assert_eq!(all[0].bundle_bytes, b"alice-grant-1");
        assert_eq!(all[1].sender_hex, alice);
        assert_eq!(all[1].oid_hex, oid2);
        assert_eq!(all[2].sender_hex, bob);

        let alice_only = s.read_quarantine_for_sender(&alice);
        assert_eq!(alice_only.len(), 2, "one sender's grants only");

        // Re-applying one grant removes just that entry.
        s.remove_quarantine_entry(&alice, &oid1).unwrap();
        let after = s.read_quarantine();
        assert_eq!(after.len(), 2, "removed exactly one entry");
        assert!(!after.iter().any(|g| g.sender_hex == alice && g.oid_hex == oid1));

        // Removing the sender's last entry drops the now-empty subdirectory.
        s.remove_quarantine_entry(&alice, &oid2).unwrap();
        assert!(!s.quarantine_sender_dir(&alice).exists(), "empty sender dir is cleaned up");
        assert_eq!(s.read_quarantine().len(), 1, "bob's grant is untouched");

        // Removing an already-gone entry is a no-op, not an error (idempotent).
        s.remove_quarantine_entry(&alice, &oid1).unwrap();

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lane_store_routes_private_state_to_the_lane_root() {
        // The ADR 0034 partition: lane-owned files under the lane's `.loot/`,
        // shared/single-writer artifacts under the store root.
        let s = RepoStore::for_lane("/repo/.loot", "/repo-lanes/l1/.loot");
        assert!(s.is_lane());
        for lane_owned in [
            s.working(None),
            s.working_change(),
            s.tree_hash(None),
            s.next_change(None),
            s.tip(None),
            s.heads(),
            s.ops(),
            s.abandoned(),
            s.conflicts(),
            s.dock_pointer(),
        ] {
            assert!(
                lane_owned.starts_with("/repo-lanes/l1/.loot"),
                "{} must live under the lane root",
                lane_owned.display()
            );
        }
        for shared in [
            s.objects_dir(),
            s.graph(),
            s.identity(),
            s.keyring(),
            s.escrow(),
            s.manifest(),
            s.purges(),
            s.attestations(),
            s.config(),
            s.git_mirror_dir(),
            s.id(),
            s.peers(),
            s.lanes_dir(),
            s.quarantine_dir(),
            s.burn_log(),
        ] {
            assert!(
                shared.starts_with("/repo/.loot"),
                "{} must live under the store root",
                shared.display()
            );
        }
        // The primary is lane #0: equal roots, byte-for-byte the old layout.
        let p = RepoStore::new("/repo/.loot");
        assert!(!p.is_lane());
        assert!(p.heads().starts_with("/repo/.loot"));
    }

    #[test]
    fn lane_pointer_round_trips_and_primary_reads_none() {
        let dir = std::env::temp_dir().join(format!("loot-store-lp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let lane_dot = dir.join("lane").join(".loot");
        RepoStore::write_lane_pointer(&lane_dot, Path::new("/shared/.loot"), "lane-ab12").unwrap();
        assert_eq!(
            RepoStore::read_store_pointer(&lane_dot),
            Some(PathBuf::from("/shared/.loot"))
        );
        assert_eq!(RepoStore::read_lane_id(&lane_dot), Some("lane-ab12".to_string()));
        // A primary `.loot/` (no pointer file) is not a lane.
        let primary = dir.join("primary").join(".loot");
        std::fs::create_dir_all(&primary).unwrap();
        assert_eq!(RepoStore::read_store_pointer(&primary), None);
        assert_eq!(RepoStore::read_lane_id(&primary), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lane_registry_round_trips_names_heartbeats_and_landed() {
        let dir = std::env::temp_dir().join(format!("loot-store-lr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let s = RepoStore::new(&dir);

        assert!(s.list_lane_entries().is_empty(), "no registry yet");
        s.create_lane_entry("lane-a", Path::new("/w/a"), None, 100).unwrap();
        s.create_lane_entry("lane-b", Path::new("/w/b"), Some("feat"), 200).unwrap();

        let a = s.read_lane_entry("lane-a").unwrap();
        assert_eq!(a.path, PathBuf::from("/w/a"));
        assert_eq!(a.name, None, "unnamed by default");
        assert_eq!(a.heartbeat, 100);
        assert!(!a.landed);
        let b = s.read_lane_entry("lane-b").unwrap();
        assert_eq!(b.name.as_deref(), Some("feat"), "born named");

        // Promotion mid-flight, heartbeat refresh, landed marker.
        s.write_lane_name("lane-a", "keeper").unwrap();
        s.touch_lane_heartbeat("lane-a", Path::new("/w/a"), 300).unwrap();
        s.mark_lane_landed("lane-b").unwrap();
        let a = s.read_lane_entry("lane-a").unwrap();
        assert_eq!(a.name.as_deref(), Some("keeper"));
        assert_eq!(a.heartbeat, 300);
        assert!(s.read_lane_entry("lane-b").unwrap().landed);

        // Staleness is a pure threshold over the heartbeat.
        assert!(!a.stale(300, 86_400));
        assert!(a.stale(300 + 86_401, 86_400));

        // List is sorted; removal deletes the entry only.
        let ids: Vec<_> = s.list_lane_entries().into_iter().map(|e| e.id).collect();
        assert_eq!(ids, vec!["lane-a".to_string(), "lane-b".to_string()]);
        s.remove_lane_entry("lane-b").unwrap();
        assert!(s.read_lane_entry("lane-b").is_none());
        assert!(s.lane_entry_exists("lane-a"));

        // Touch is self-healing: a swept entry regrows with its path.
        s.remove_lane_entry("lane-a").unwrap();
        s.touch_lane_heartbeat("lane-a", Path::new("/w/a"), 400).unwrap();
        let a = s.read_lane_entry("lane-a").unwrap();
        assert_eq!((a.path, a.heartbeat), (PathBuf::from("/w/a"), 400));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dock_name_validation_blocks_traversal_and_reserved() {
        assert!(valid_dock_name("feature-1").is_ok());
        assert!(valid_dock_name("feat_2").is_ok());
        assert!(valid_dock_name("").is_err(), "empty rejected");
        assert!(valid_dock_name(HOME_DOCK).is_err(), "home reserved");
        assert!(valid_dock_name("../evil").is_err(), "path traversal rejected");
        assert!(valid_dock_name("a/b").is_err(), "separators rejected");
        assert!(valid_dock_name("has space").is_err(), "whitespace rejected");
    }
}
