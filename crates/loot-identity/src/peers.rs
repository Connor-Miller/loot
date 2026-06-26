//! Peer public-key registry: `.loot/peers` stores `name = <openssh-pubkey>` pairs.
//!
//! Used by `loot peer add/list/remove` and by the grant flow to look up a
//! recipient's public key for sealed grant bundle delivery (ADR 0013/0014).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use super::IdentityError;

/// Parsed `.loot/peers`: `name -> openssh-pubkey-line`.
pub struct PeerRegistry {
    entries: BTreeMap<String, String>,
    path: PathBuf,
}

impl PeerRegistry {
    /// Load from `dot/peers`. Missing file = empty registry.
    pub fn load(dot: &Path) -> Self {
        let path = dot.join("peers");
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let mut entries = BTreeMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                entries.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
        PeerRegistry { entries, path }
    }

    /// Add or replace a peer. `pubkey_line` is the full OpenSSH pubkey line.
    pub fn add(&mut self, name: &str, pubkey_line: &str) {
        self.entries.insert(name.to_string(), pubkey_line.trim().to_string());
    }

    /// Remove a peer by name. No-ops if absent.
    pub fn remove(&mut self, name: &str) {
        self.entries.remove(name);
    }

    /// Look up a peer's OpenSSH public key line by name.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries.get(name).map(String::as_str)
    }

    /// Return all `(name, pubkey_line)` pairs, sorted by name.
    pub fn list(&self) -> Vec<(&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
    }

    /// Parse a peer's stored public key into raw ed25519 bytes (32 bytes).
    /// Returns `None` if the peer is not registered or the key is not ed25519.
    pub fn pubkey_bytes(&self, name: &str) -> Result<Option<[u8; 32]>, IdentityError> {
        let Some(line) = self.get(name) else {
            return Ok(None);
        };
        let pub_key = ssh_key::PublicKey::from_openssh(line)
            .map_err(|e| IdentityError::Format(e.to_string()))?;
        let ed_key = pub_key.key_data().ed25519()
            .ok_or_else(|| IdentityError::Format(format!("peer '{name}' key is not ed25519")))?;
        Ok(Some(ed_key.0))
    }

    /// Parse an OpenSSH public key *line* (not a peer name) directly into ed25519
    /// bytes. Used when verifying a grantor pubkey against all registered peers.
    pub fn parse_pubkey_bytes_from_line(line: &str) -> Result<[u8; 32], IdentityError> {
        let pub_key = ssh_key::PublicKey::from_openssh(line)
            .map_err(|e| IdentityError::Format(e.to_string()))?;
        let ed_key = pub_key.key_data().ed25519()
            .ok_or_else(|| IdentityError::Format("key is not ed25519".into()))?;
        Ok(ed_key.0)
    }

    /// Persist to disk.
    pub fn save(&self) -> Result<(), IdentityError> {
        let mut out = String::new();
        for (k, v) in &self.entries {
            out.push_str(&format!("{k} = {v}\n"));
        }
        std::fs::write(&self.path, out)
            .map_err(|e| IdentityError::Io(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir()
            .join(format!("loot-peers-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn fake_openssh_line() -> String {
        // Generate a real key and export it so the round-trip test is genuine.
        let id = crate::Identity::generate();
        // Build a throwaway pub line via save/read
        let dir = tmp("fake");
        id.save(&dir, "test@loot").unwrap();
        std::fs::read_to_string(dir.join("id.pub")).unwrap().trim().to_string()
    }

    #[test]
    fn add_list_remove_round_trips() {
        let dir = tmp("rtrip");
        let mut reg = PeerRegistry::load(&dir);
        assert!(reg.list().is_empty());

        let line = fake_openssh_line();
        reg.add("alice", &line);
        reg.save().unwrap();

        let loaded = PeerRegistry::load(&dir);
        assert_eq!(loaded.get("alice"), Some(line.as_str()));
        assert_eq!(loaded.list().len(), 1);

        let mut loaded2 = PeerRegistry::load(&dir);
        loaded2.remove("alice");
        loaded2.save().unwrap();
        let loaded3 = PeerRegistry::load(&dir);
        assert!(loaded3.get("alice").is_none());
    }

    #[test]
    fn pubkey_bytes_extracts_ed25519() {
        let dir = tmp("bytes");
        let id = crate::Identity::generate();
        id.save(&dir, "bob@loot").unwrap();
        let line = std::fs::read_to_string(dir.join("id.pub")).unwrap();

        let mut reg = PeerRegistry::load(&dir);
        reg.add("bob", line.trim());
        let bytes = reg.pubkey_bytes("bob").unwrap().unwrap();
        assert_eq!(bytes, id.public_key_bytes());
    }
}
