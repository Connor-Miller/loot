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
//! config       named remotes                            (Workspace, ADR 0013)
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
const TREE_HASH: &str = "tree-hash";
const CONFIG: &str = "config";
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

    // --- Workspace-owned process artifacts ---
    pub fn working(&self) -> PathBuf { self.dot.join(WORKING) }
    pub fn tree_hash(&self) -> PathBuf { self.dot.join(TREE_HASH) }
    pub fn config(&self) -> PathBuf { self.dot.join(CONFIG) }

    // --- loot-identity-owned artifacts (named here; written there) ---
    pub fn id(&self) -> PathBuf { self.dot.join(ID) }
    pub fn id_pub(&self) -> PathBuf { self.dot.join(ID_PUB) }
    pub fn peers(&self) -> PathBuf { self.dot.join(PEERS) }

    /// Read the working-change id (32 raw bytes) if one is in progress. An
    /// absent or malformed file means finalized history (no working change).
    pub fn read_working(&self) -> Option<Oid> {
        match std::fs::read(self.working()) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                Some(Oid(a))
            }
            _ => None,
        }
    }

    /// Persist the working-change id, or remove the file when there is none.
    /// Removal failure is ignored (best-effort, matches the prior inline logic).
    pub fn write_working(&self, working: Option<&Oid>) -> std::io::Result<()> {
        match working {
            Some(oid) => std::fs::write(self.working(), oid.0),
            None => {
                let _ = std::fs::remove_file(self.working());
                Ok(())
            }
        }
    }

    /// The last snapshot's tree+message hash, or empty if never written.
    pub fn read_tree_hash(&self) -> Vec<u8> {
        std::fs::read(self.tree_hash()).unwrap_or_default()
    }

    /// Record the snapshot hash used for idempotent re-`status`.
    pub fn write_tree_hash(&self, hash: &[u8]) -> std::io::Result<()> {
        std::fs::write(self.tree_hash(), hash)
    }

    /// Forget the snapshot hash so the next snapshot always runs the engine.
    pub fn clear_tree_hash(&self) {
        let _ = std::fs::remove_file(self.tree_hash());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_under_dot() {
        let s = RepoStore::new("/tmp/repo/.loot");
        assert!(s.graph().ends_with(".loot/graph"));
        assert!(s.working().ends_with(".loot/working"));
        assert!(s.objects_dir().ends_with(".loot/objects"));
        assert!(s.peers().ends_with(".loot/peers"));
    }

    #[test]
    fn working_round_trips_and_clears() {
        let dir = std::env::temp_dir().join(format!("loot-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let s = RepoStore::new(&dir);

        assert_eq!(s.read_working(), None, "no working file yet");
        s.write_working(Some(&Oid([5; 32]))).unwrap();
        assert_eq!(s.read_working(), Some(Oid([5; 32])));
        s.write_working(None).unwrap();
        assert_eq!(s.read_working(), None, "None removes the file");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tree_hash_round_trips_and_clears() {
        let dir = std::env::temp_dir().join(format!("loot-store-th-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let s = RepoStore::new(&dir);

        assert!(s.read_tree_hash().is_empty());
        s.write_tree_hash(b"hash-bytes").unwrap();
        assert_eq!(s.read_tree_hash(), b"hash-bytes");
        s.clear_tree_hash();
        assert!(s.read_tree_hash().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
