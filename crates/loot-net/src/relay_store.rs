//! The relay's on-disk store (ADR 0011).
//!
//! A relay reuses the engine's `.loot/` layout but is *keyless*: it never holds
//! a content key, so it can store and forward sealed cargo but cannot read it.
//! A `role` marker file distinguishes a relay store from a working repo so tools
//! don't mistake one for the other. The relay's identity is a fixed sentinel
//! (`RELAY_IDENTITY`); since it is granted nothing, its keyring stays empty by
//! construction.

use loot_core::{DagRepo, Oid, Repo, SyncBundle};
use std::path::Path;

const ROLE_FILE: &str = "role";
const RELAY_ROLE: &str = "relay";
const RELAY_IDENTITY: &str = "@relay";

/// Whether `dir` holds a relay store (as opposed to a working repo), by reading
/// its `role` marker.
pub fn is_relay(dir: &Path) -> bool {
    std::fs::read_to_string(dir.join(ROLE_FILE))
        .map(|s| s.trim() == RELAY_ROLE)
        .unwrap_or(false)
}

/// A relay's persistent store. Wraps a keyless [`DagRepo`] and persists after
/// every mutating `stow`.
pub struct RelayStore {
    repo: DagRepo,
    dir: std::path::PathBuf,
}

impl RelayStore {
    /// Open the relay store at `dir`, creating it (empty keyring + role marker)
    /// if it does not yet exist. Refuses to open a working repo as a relay.
    pub fn open_or_init(dir: &Path) -> Result<Self, super::NetError> {
        let map_io = |e: std::io::Error| super::NetError::Io(e.to_string());
        let map_eng = |e: loot_core::RepoError| super::NetError::Engine(e.to_string());

        if dir.join("identity").exists() {
            if !is_relay(dir) {
                return Err(super::NetError::Io(format!(
                    "{} is a working repo, not a relay; refusing to serve it",
                    dir.display()
                )));
            }
            // The relay materializes nothing, so its working root is irrelevant.
            let repo = DagRepo::load(dir, dir.to_path_buf()).map_err(map_eng)?;
            return Ok(RelayStore { repo, dir: dir.to_path_buf() });
        }

        std::fs::create_dir_all(dir).map_err(map_io)?;
        let repo = DagRepo::init(dir.to_path_buf(), RELAY_IDENTITY).map_err(map_eng)?;
        repo.save(dir).map_err(map_eng)?;
        std::fs::write(dir.join(ROLE_FILE), RELAY_ROLE).map_err(map_io)?;
        Ok(RelayStore { repo, dir: dir.to_path_buf() })
    }

    /// Stow a pushed bundle append-only, then persist. Never merges (ADR 0011).
    pub fn stow(&mut self, bundle: &SyncBundle) -> Result<(), super::NetError> {
        self.repo
            .stow(bundle)
            .map_err(|e| super::NetError::Engine(e.to_string()))?;
        self.repo
            .save(&self.dir)
            .map_err(|e| super::NetError::Engine(e.to_string()))?;
        Ok(())
    }

    /// Produce a bundle of everything the relay holds that the caller lacks.
    pub fn bundle(&self, have: &[Oid]) -> Result<SyncBundle, super::NetError> {
        self.repo
            .bundle(have)
            .map_err(|e| super::NetError::Engine(e.to_string()))
    }
}
