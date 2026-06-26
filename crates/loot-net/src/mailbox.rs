//! Grant mailbox: content-addressed loose blobs + recipient index (ADR grilling).
//!
//! Layout under a relay dir:
//! ```text
//! grants/
//!   <blake3-hex>         <- blob file (raw sealed-grant bundle bytes)
//!   index                <- "recipient_name = <hash1>,<hash2>,..." lines
//! ```
//!
//! Blobs are written atomically (temp + rename), same pattern as loose objects
//! (ADR 0012). The index is rewritten on each mutation — it stays tiny (one line
//! per recipient with pending grants).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use super::NetError;

const GRANTS_DIR: &str = "grants";
const INDEX_FILE: &str = "index";

fn grants_dir(relay_dir: &Path) -> PathBuf {
    relay_dir.join(GRANTS_DIR)
}

fn blob_path(relay_dir: &Path, hash_hex: &str) -> PathBuf {
    grants_dir(relay_dir).join(hash_hex)
}

fn index_path(relay_dir: &Path) -> PathBuf {
    grants_dir(relay_dir).join(INDEX_FILE)
}

fn map_io(e: std::io::Error) -> NetError {
    NetError::Io(e.to_string())
}

/// Hash `bytes` with blake3 and return the lowercase hex string.
fn hex_hash(bytes: &[u8]) -> String {
    let h = blake3::hash(bytes);
    h.to_hex().to_string()
}

/// Load the index: `recipient -> [hash_hex]`.
fn load_index(relay_dir: &Path) -> BTreeMap<String, Vec<String>> {
    let text = std::fs::read_to_string(index_path(relay_dir)).unwrap_or_default();
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((name, hashes)) = line.split_once('=') {
            let name = name.trim().to_string();
            let hashes: Vec<String> = hashes
                .split(',')
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty())
                .collect();
            if !hashes.is_empty() {
                map.insert(name, hashes);
            }
        }
    }
    map
}

/// Persist the index.
fn save_index(relay_dir: &Path, index: &BTreeMap<String, Vec<String>>) -> Result<(), NetError> {
    let dir = grants_dir(relay_dir);
    std::fs::create_dir_all(&dir).map_err(map_io)?;
    let mut text = String::new();
    for (name, hashes) in index {
        if !hashes.is_empty() {
            text.push_str(&format!("{name} = {}\n", hashes.join(",")));
        }
    }
    let path = index_path(relay_dir);
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &text).map_err(map_io)?;
    std::fs::rename(&tmp, &path).map_err(map_io)?;
    Ok(())
}

/// Deposit a sealed grant blob for `recipient`. Returns the blob hash.
/// Idempotent: if the blob already exists (same hash), it is not re-written.
pub fn deposit(relay_dir: &Path, recipient: &str, blob: &[u8]) -> Result<String, NetError> {
    let dir = grants_dir(relay_dir);
    std::fs::create_dir_all(&dir).map_err(map_io)?;

    let hash = hex_hash(blob);
    let dest = blob_path(relay_dir, &hash);
    if !dest.exists() {
        let tmp = dest.with_extension("tmp");
        std::fs::write(&tmp, blob).map_err(map_io)?;
        std::fs::rename(&tmp, &dest).map_err(map_io)?;
    }

    let mut index = load_index(relay_dir);
    let entry = index.entry(recipient.to_string()).or_default();
    if !entry.contains(&hash) {
        entry.push(hash.clone());
    }
    save_index(relay_dir, &index)?;
    Ok(hash)
}

/// Return the count of pending grant blobs for `recipient` without fetching or deleting them.
pub fn peek_count(relay_dir: &Path, recipient: &str) -> Result<usize, NetError> {
    let index = load_index(relay_dir);
    Ok(index.get(recipient).map_or(0, |h| h.len()))
}

/// Fetch and delete all pending grant blobs for `recipient`.
/// Returns the raw blob bytes. Missing blob files are silently skipped
/// (may have been partially delivered by a concurrent pull).
pub fn fetch_and_drain(relay_dir: &Path, recipient: &str) -> Result<Vec<Vec<u8>>, NetError> {
    let mut index = load_index(relay_dir);
    let hashes = match index.remove(recipient) {
        Some(h) if !h.is_empty() => h,
        _ => return Ok(vec![]),
    };

    let mut blobs = Vec::new();
    for hash in &hashes {
        let path = blob_path(relay_dir, hash);
        match std::fs::read(&path) {
            Ok(b) => {
                blobs.push(b);
                let _ = std::fs::remove_file(&path);
            }
            Err(_) => {} // already gone — skip
        }
    }

    // Save index with recipient removed (all delivered).
    save_index(relay_dir, &index)?;
    Ok(blobs)
}

/// Encode `blobs` as `[count(4)][len(4)][blob...]...` for wire transmission.
pub fn encode_blobs(blobs: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(blobs.len() as u32).to_le_bytes());
    for b in blobs {
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(b);
    }
    out
}

/// Decode the wire format produced by `encode_blobs`.
pub fn decode_blobs(data: &[u8]) -> Result<Vec<Vec<u8>>, NetError> {
    if data.len() < 4 {
        return Err(NetError::Http("grant response too short".into()));
    }
    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let mut pos = 4;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 4 > data.len() {
            return Err(NetError::Http("grant response truncated at length".into()));
        }
        let len = u32::from_le_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
        pos += 4;
        if pos + len > data.len() {
            return Err(NetError::Http("grant response truncated at blob".into()));
        }
        out.push(data[pos..pos+len].to_vec());
        pos += len;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir()
            .join(format!("loot-mailbox-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn deposit_and_drain() {
        let dir = tmp("drain");
        deposit(&dir, "alice", b"grant blob 1").unwrap();
        deposit(&dir, "alice", b"grant blob 2").unwrap();
        deposit(&dir, "bob", b"grant for bob").unwrap();

        let alice_blobs = fetch_and_drain(&dir, "alice").unwrap();
        assert_eq!(alice_blobs.len(), 2);
        assert!(alice_blobs.contains(&b"grant blob 1".to_vec()));
        assert!(alice_blobs.contains(&b"grant blob 2".to_vec()));

        // alice's blobs are gone; bob's are untouched
        let alice_again = fetch_and_drain(&dir, "alice").unwrap();
        assert!(alice_again.is_empty());
        let bob_blobs = fetch_and_drain(&dir, "bob").unwrap();
        assert_eq!(bob_blobs.len(), 1);
    }

    #[test]
    fn deposit_is_idempotent() {
        let dir = tmp("idem");
        deposit(&dir, "alice", b"same blob").unwrap();
        deposit(&dir, "alice", b"same blob").unwrap();
        let blobs = fetch_and_drain(&dir, "alice").unwrap();
        assert_eq!(blobs.len(), 1);
    }

    #[test]
    fn encode_decode_blobs_round_trip() {
        let blobs = vec![b"hello".to_vec(), b"world!".to_vec()];
        let encoded = encode_blobs(&blobs);
        let decoded = decode_blobs(&encoded).unwrap();
        assert_eq!(decoded, blobs);
    }

    #[test]
    fn empty_mailbox_returns_empty() {
        let dir = tmp("empty");
        let blobs = fetch_and_drain(&dir, "nobody").unwrap();
        assert!(blobs.is_empty());
    }
}
