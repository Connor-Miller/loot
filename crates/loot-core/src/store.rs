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
//! id, id.pub   the ed25519 keypair                      (loot-identity, ADR 0014)
//! peers        nickname -> pubkey registry              (loot-identity, ADR 0014)
//! ```
//!
//! The `objects/` subdirectory and the keypair/peers files are written by their
//! owning modules (persist_codec and loot-identity); RepoStore names their paths
//! so the layout has one documented home, and owns the read/write of the small
//! process files (`working`, `tree-hash`) whose on-disk encoding is otherwise
//! inlined in the Workspace.

use crate::Oid;
use std::path::{Path, PathBuf};

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
const DOCKS: &str = "docks";
const CONFIG: &str = "config";
const GIT_MIRROR: &str = "git-mirror";
const OPS: &str = "ops";
const ABANDONED: &str = "abandoned";

/// The default dock every repo starts on — the primary directory (ADR 0022
/// physical model). Its process files are the root `.loot/working`/`tree-hash`/
/// `tip`, so a repo that never touches docks is byte-for-byte unchanged on disk.
/// Named docks live under `.loot/docks/<name>/`.
pub const HOME_DOCK: &str = "main";
const OBJECTS: &str = "objects";
const ID: &str = "id";
const ID_PUB: &str = "id.pub";
const PEERS: &str = "peers";

/// Names every artifact under a repo's `.loot/` directory. Cheap to construct
/// (`new` just stores the directory), so callers that only have the `.loot`
/// path can wrap it on demand.
#[derive(Clone, Debug)]
pub struct RepoStore {
    dot: PathBuf,
}

impl RepoStore {
    /// Wrap a repo's `.loot/` directory.
    pub fn new(dot: impl Into<PathBuf>) -> Self {
        Self { dot: dot.into() }
    }

    /// The `.loot/` directory itself.
    pub fn dot(&self) -> &Path {
        &self.dot
    }

    // --- engine-owned artifacts ---
    pub fn objects_dir(&self) -> PathBuf { self.dot.join(OBJECTS) }
    pub fn identity(&self) -> PathBuf { self.dot.join(IDENTITY) }
    pub fn graph(&self) -> PathBuf { self.dot.join(GRAPH) }
    pub fn keyring(&self) -> PathBuf { self.dot.join(KEYRING) }
    pub fn escrow(&self) -> PathBuf { self.dot.join(ESCROW) }
    pub fn manifest(&self) -> PathBuf { self.dot.join(MANIFEST) }
    pub fn purges(&self) -> PathBuf { self.dot.join(PURGES) }
    pub fn conflicts(&self) -> PathBuf { self.dot.join(CONFLICTS) }
    pub fn attestations(&self) -> PathBuf { self.dot.join(ATTESTATIONS) }

    // --- Workspace-owned process artifacts (per-dock, ADR 0022) ---
    //
    // `dock: None` selects the home dock (root files, unchanged on disk); `Some`
    // selects a named dock under `.loot/docks/<name>/`. The no-arg `config` and
    // the ambient-dock pointer are repo-wide, not per-dock.
    pub fn config(&self) -> PathBuf { self.dot.join(CONFIG) }

    /// Directory a dock's process files live in: the repo root for home, else
    /// `.loot/docks/<name>/`.
    fn dock_dir(&self, dock: Option<&str>) -> PathBuf {
        match dock {
            None => self.dot.clone(),
            Some(name) => self.dot.join(DOCKS).join(name),
        }
    }

    pub fn working(&self, dock: Option<&str>) -> PathBuf { self.dock_dir(dock).join(WORKING) }
    pub fn tree_hash(&self, dock: Option<&str>) -> PathBuf { self.dock_dir(dock).join(TREE_HASH) }
    pub fn next_change(&self, dock: Option<&str>) -> PathBuf { self.dock_dir(dock).join(NEXT_CHANGE) }
    pub fn tip(&self, dock: Option<&str>) -> PathBuf { self.dock_dir(dock).join(TIP) }

    /// The ambient-dock pointer: names the dock this workspace is currently on.
    /// Absent (or `home`) means the home dock — so pre-dock repos read as home.
    pub fn dock_pointer(&self) -> PathBuf { self.dot.join(DOCK) }
    pub fn docks_dir(&self) -> PathBuf { self.dot.join(DOCKS) }

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

    // --- operation log (S4, ADR 0031) ---
    //
    // Local-only, repo-wide, append-only history of view-changing operations
    // backing `loot undo` / `loot op`. Like `keyring`/`escrow`/the git mark map
    // it is per-machine and **never enters a bundle** — losing it loses undo
    // history, not repo data.
    pub fn ops(&self) -> PathBuf { self.dot.join(OPS) }

    // --- divergent-change abandonment (S3, ADR 0029/0030) ---
    //
    // Local-only set of **abandoned version ids** — versions dropped from a
    // divergent change by `loot abandon`. A view-level filter (never deletes the
    // node from the graph or object store), captured by the oplog so abandon is
    // undoable. Never bundled, like `ops`/the git marks.
    pub fn abandoned(&self) -> PathBuf { self.dot.join(ABANDONED) }

    /// The set of abandoned version ids (each 32 raw bytes), or empty if none.
    /// A malformed/short file reads as empty (best-effort; the oplog can rebuild).
    pub fn read_abandoned(&self) -> std::collections::BTreeSet<Oid> {
        match std::fs::read(self.abandoned()) {
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
        std::fs::write(self.abandoned(), bytes)
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
        std::fs::read(self.tree_hash(dock)).unwrap_or_default()
    }

    /// Record the snapshot hash used for idempotent re-`status`.
    pub fn write_tree_hash(&self, dock: Option<&str>, hash: &[u8]) -> std::io::Result<()> {
        std::fs::write(self.tree_hash(dock), hash)
    }

    /// Forget the snapshot hash so the next snapshot always runs the engine.
    pub fn clear_tree_hash(&self, dock: Option<&str>) {
        let _ = std::fs::remove_file(self.tree_hash(dock));
    }

    /// The durable change id `loot new` minted eagerly for `dock`'s *next*
    /// change (ADR 0029/0030), before any snapshot has recorded it. 16 raw
    /// bytes; absent or malformed means none is pending.
    pub fn read_next_change(&self, dock: Option<&str>) -> Option<[u8; 16]> {
        match std::fs::read(self.next_change(dock)) {
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
            Some(id) => std::fs::write(self.next_change(dock), id),
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

    /// Point the workspace at `name`. Writing [`HOME_DOCK`] removes the pointer so
    /// the repo returns to its pristine, pre-dock on-disk shape.
    pub fn write_dock(&self, name: &str) -> std::io::Result<()> {
        if name == HOME_DOCK {
            let _ = std::fs::remove_file(self.dock_pointer());
            Ok(())
        } else {
            std::fs::write(self.dock_pointer(), name)
        }
    }

    /// Create a named dock's directory (idempotent). Home needs none.
    pub fn ensure_dock_dir(&self, name: &str) -> std::io::Result<()> {
        std::fs::create_dir_all(self.docks_dir().join(name))
    }

    /// True if `name` is the home dock or an existing named dock.
    pub fn dock_exists(&self, name: &str) -> bool {
        name == HOME_DOCK || self.docks_dir().join(name).is_dir()
    }

    /// Every dock in the repo: home first, then named docks sorted. Home is
    /// always present even before `.loot/docks/` exists.
    pub fn list_docks(&self) -> Vec<String> {
        let mut named: Vec<String> = std::fs::read_dir(self.docks_dir())
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        named.sort();
        let mut out = vec![HOME_DOCK.to_string()];
        out.extend(named);
        out
    }

    // --- lineage persistence (ADR 0022 physical model) ---
    //
    // A dock's lineage *tips* (`heads`) and its out-of-graph *working change*
    // (`working-change`) persist beside the shared graph, like git's per-worktree
    // HEAD. The engine writes both on `save` and reads them on `load`; a repo with
    // no `heads` file predates this and derives its tips from the whole graph.

    pub fn heads(&self) -> PathBuf { self.dot.join(HEADS) }
    pub fn working_change(&self) -> PathBuf { self.dot.join(WORKING_CHANGE) }

    /// This dock's lineage tips, or `None` for a legacy repo with no `heads` file
    /// (the loader then derives them from the whole graph). An empty or malformed
    /// file is treated the same as absent.
    pub fn read_heads(&self) -> Option<Vec<Oid>> {
        let bytes = std::fs::read(self.heads()).ok()?;
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
        std::fs::write(self.heads(), bytes)
    }

    /// The encoded working-change node blob if one is in progress, else `None`.
    pub fn read_working_change(&self) -> Option<Vec<u8>> {
        std::fs::read(self.working_change()).ok()
    }

    /// Persist the encoded working-change node blob, or remove the file when there
    /// is none (best-effort removal).
    pub fn write_working_change(&self, blob: Option<&[u8]>) -> std::io::Result<()> {
        match blob {
            Some(b) => std::fs::write(self.working_change(), b),
            None => {
                let _ = std::fs::remove_file(self.working_change());
                Ok(())
            }
        }
    }
}

/// Validate a name for a *new* named dock. The charset (ASCII alphanumerics plus
/// `-`/`_`) is deliberately narrow so a name can never traverse or escape the
/// `.loot/docks/` directory. Home is reserved — it always exists.
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

/// Read a 32-byte Oid file, or `None` if absent/malformed.
fn read_oid_file(path: &Path) -> Option<Oid> {
    match std::fs::read(path) {
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
        Some(oid) => std::fs::write(path, oid.0),
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
    fn paths_are_under_dot() {
        let s = RepoStore::new("/tmp/repo/.loot");
        assert!(s.graph().ends_with(".loot/graph"));
        assert!(s.working(None).ends_with(".loot/working"));
        assert!(s.objects_dir().ends_with(".loot/objects"));
        assert!(s.peers().ends_with(".loot/peers"));
    }

    #[test]
    fn home_dock_uses_root_files_named_docks_are_nested() {
        // The compat guarantee: home's process files are the root files, so a
        // repo that never docks looks exactly as before.
        let s = RepoStore::new("/tmp/repo/.loot");
        assert!(s.working(None).ends_with(".loot/working"));
        assert!(s.tip(None).ends_with(".loot/tip"));
        assert!(s.working(Some("feat")).ends_with(".loot/docks/feat/working"));
        assert!(s.tip(Some("feat")).ends_with(".loot/docks/feat/tip"));
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
    fn docks_are_isolated_and_listed_home_first() {
        let dir = std::env::temp_dir().join(format!("loot-store-docks-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let s = RepoStore::new(&dir);

        // Ambient defaults to home with no pointer on disk.
        assert_eq!(s.read_dock(), HOME_DOCK);
        assert_eq!(s.list_docks(), vec![HOME_DOCK.to_string()], "home always present");

        // A named dock's tip is independent of home's.
        s.ensure_dock_dir("feat").unwrap();
        s.write_tip(None, Some(&Oid([1; 32]))).unwrap();
        s.write_tip(Some("feat"), Some(&Oid([2; 32]))).unwrap();
        assert_eq!(s.read_tip(None), Some(Oid([1; 32])));
        assert_eq!(s.read_tip(Some("feat")), Some(Oid([2; 32])), "per-dock tips don't collide");

        // Ambient pointer round-trips; writing home clears it back to pristine.
        s.write_dock("feat").unwrap();
        assert_eq!(s.read_dock(), "feat");
        assert!(s.dock_pointer().exists());
        s.write_dock(HOME_DOCK).unwrap();
        assert_eq!(s.read_dock(), HOME_DOCK);
        assert!(!s.dock_pointer().exists(), "home removes the pointer (compat shape)");

        assert_eq!(s.list_docks(), vec![HOME_DOCK.to_string(), "feat".to_string()]);
        assert!(s.dock_exists("feat") && s.dock_exists(HOME_DOCK) && !s.dock_exists("nope"));

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
