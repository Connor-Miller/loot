//! Grant mailbox: content-addressed loose blobs + recipient index (ADR grilling).
//!
//! Layout under a relay dir:
//! ```text
//! grants/
//!   <blake3-hex>         <- blob file (raw sealed-grant bundle bytes)
//!   index                <- "recipient_name = <hash1>:<reveal_at1>,..." lines
//! ```
//!
//! Blobs are written atomically (temp + rename), same pattern as loose objects
//! (ADR 0012). The index is rewritten on each mutation — it stays tiny (one line
//! per recipient with pending grants).
//!
//! **Timed grants (hard embargo, ADR 0027/#14):** each entry carries the
//! `reveal_at` the depositor declared inside its grantor-signed frame. `peek`
//! and `fetch` take the RELAY's clock and exclude entries whose `reveal_at`
//! has not passed — withheld entries stay in the mailbox untouched. The relay
//! never trusts a caller-supplied time; the hard guarantee is exactly that the
//! key blob is not on the recipient's machine until this filter releases it.
//! Bare `<hash>` entries (pre-v5) read as `reveal_at = 0` (untimed).

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

/// Content-address `bytes` with blake3 and return the lowercase hex string.
fn hex_hash(bytes: &[u8]) -> String {
    loot_core::hex::encode(blake3::hash(bytes).as_bytes())
}

/// Load the index: `recipient -> [(hash_hex, reveal_at)]`. A bare `<hash>`
/// entry (pre-v5) reads as untimed (`reveal_at = 0`).
fn load_index(relay_dir: &Path) -> BTreeMap<String, Vec<(String, u64)>> {
    let text = std::fs::read_to_string(index_path(relay_dir)).unwrap_or_default();
    let mut map: BTreeMap<String, Vec<(String, u64)>> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((name, hashes)) = line.split_once('=') {
            let name = name.trim().to_string();
            let hashes: Vec<(String, u64)> = hashes
                .split(',')
                .map(|h| h.trim())
                .filter(|h| !h.is_empty())
                .map(|h| match h.split_once(':') {
                    Some((hash, at)) => (hash.to_string(), at.parse().unwrap_or(0)),
                    None => (h.to_string(), 0),
                })
                .collect();
            if !hashes.is_empty() {
                map.insert(name, hashes);
            }
        }
    }
    map
}

/// Persist the index.
fn save_index(
    relay_dir: &Path,
    index: &BTreeMap<String, Vec<(String, u64)>>,
) -> Result<(), NetError> {
    let dir = grants_dir(relay_dir);
    std::fs::create_dir_all(&dir).map_err(map_io)?;
    let mut text = String::new();
    for (name, hashes) in index {
        if !hashes.is_empty() {
            let joined: Vec<String> =
                hashes.iter().map(|(h, at)| format!("{h}:{at}")).collect();
            text.push_str(&format!("{name} = {}\n", joined.join(",")));
        }
    }
    let path = index_path(relay_dir);
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &text).map_err(map_io)?;
    std::fs::rename(&tmp, &path).map_err(map_io)?;
    Ok(())
}

/// Deposit a sealed grant blob for `recipient`, withheld until `reveal_at`
/// (`0` = deliver immediately). Returns the blob hash.
/// Idempotent: if the blob already exists (same hash), it is not re-written.
pub fn deposit(
    relay_dir: &Path,
    recipient: &str,
    blob: &[u8],
    reveal_at: u64,
) -> Result<String, NetError> {
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
    if !entry.iter().any(|(h, _)| h == &hash) {
        entry.push((hash.clone(), reveal_at));
    }
    save_index(relay_dir, &index)?;
    Ok(hash)
}

/// Count the grant blobs for `recipient` that are DUE at `now` (the relay's
/// clock) without fetching or deleting them. Withheld timed grants are
/// invisible here — a peek must not reveal an embargo's existence early.
pub fn peek_count(relay_dir: &Path, recipient: &str, now: u64) -> Result<usize, NetError> {
    let index = load_index(relay_dir);
    Ok(index
        .get(recipient)
        .map_or(0, |h| h.iter().filter(|(_, at)| *at <= now).count()))
}

/// Fetch and delete the grant blobs for `recipient` that are DUE at `now`
/// (the relay's clock). Timed grants whose `reveal_at` has not passed stay in
/// the mailbox — blob and index entry untouched — until a fetch after reveal.
/// Missing blob files are silently skipped (may have been partially delivered
/// by a concurrent pull).
pub fn fetch_and_drain(
    relay_dir: &Path,
    recipient: &str,
    now: u64,
) -> Result<Vec<Vec<u8>>, NetError> {
    let mut index = load_index(relay_dir);
    let hashes = match index.remove(recipient) {
        Some(h) if !h.is_empty() => h,
        _ => return Ok(vec![]),
    };

    let (due, withheld): (Vec<_>, Vec<_>) = hashes.into_iter().partition(|(_, at)| *at <= now);
    if !withheld.is_empty() {
        index.insert(recipient.to_string(), withheld);
    }

    let mut blobs = Vec::new();
    for (hash, _) in &due {
        let path = blob_path(relay_dir, hash);
        match std::fs::read(&path) {
            Ok(b) => {
                blobs.push(b);
                let _ = std::fs::remove_file(&path);
            }
            Err(_) => {} // already gone — skip
        }
    }

    // Save index with the due entries removed; withheld ones remain.
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
        deposit(&dir, "alice", b"grant blob 1", 0).unwrap();
        deposit(&dir, "alice", b"grant blob 2", 0).unwrap();
        deposit(&dir, "bob", b"grant for bob", 0).unwrap();

        let alice_blobs = fetch_and_drain(&dir, "alice", 0).unwrap();
        assert_eq!(alice_blobs.len(), 2);
        assert!(alice_blobs.contains(&b"grant blob 1".to_vec()));
        assert!(alice_blobs.contains(&b"grant blob 2".to_vec()));

        // alice's blobs are gone; bob's are untouched
        let alice_again = fetch_and_drain(&dir, "alice", 0).unwrap();
        assert!(alice_again.is_empty());
        let bob_blobs = fetch_and_drain(&dir, "bob", 0).unwrap();
        assert_eq!(bob_blobs.len(), 1);
    }

    #[test]
    fn deposit_is_idempotent() {
        let dir = tmp("idem");
        deposit(&dir, "alice", b"same blob", 0).unwrap();
        deposit(&dir, "alice", b"same blob", 0).unwrap();
        let blobs = fetch_and_drain(&dir, "alice", 0).unwrap();
        assert_eq!(blobs.len(), 1);
    }

    #[test]
    fn timed_grant_is_withheld_until_reveal_then_delivered() {
        // ADR 0027/#14: the relay's clock, not the caller's, gates release.
        let dir = tmp("timed");
        deposit(&dir, "alice", b"embargoed grant", 100).unwrap();
        deposit(&dir, "alice", b"ordinary grant", 0).unwrap();

        // Pre-reveal: only the untimed grant is visible or fetchable.
        assert_eq!(peek_count(&dir, "alice", 50).unwrap(), 1, "withheld grant must not be counted");
        let pre = fetch_and_drain(&dir, "alice", 50).unwrap();
        assert_eq!(pre, vec![b"ordinary grant".to_vec()]);

        // Still withheld on a repeat pre-reveal fetch (blob + index survive).
        assert!(fetch_and_drain(&dir, "alice", 99).unwrap().is_empty());
        assert_eq!(peek_count(&dir, "alice", 99).unwrap(), 0);

        // At/after reveal: delivered, then drained.
        assert_eq!(peek_count(&dir, "alice", 100).unwrap(), 1);
        let post = fetch_and_drain(&dir, "alice", 100).unwrap();
        assert_eq!(post, vec![b"embargoed grant".to_vec()]);
        assert!(fetch_and_drain(&dir, "alice", 200).unwrap().is_empty());
    }

    #[test]
    fn pre_v5_bare_hash_index_reads_as_untimed() {
        let dir = tmp("legacy-index");
        // Write a blob + an old-format index line (no `:reveal_at`).
        let hash = deposit(&dir, "alice", b"old grant", 0).unwrap();
        std::fs::write(grants_dir(&dir).join(INDEX_FILE), format!("alice = {hash}\n")).unwrap();
        assert_eq!(peek_count(&dir, "alice", 0).unwrap(), 1);
        assert_eq!(fetch_and_drain(&dir, "alice", 0).unwrap(), vec![b"old grant".to_vec()]);
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
        let blobs = fetch_and_drain(&dir, "nobody", 0).unwrap();
        assert!(blobs.is_empty());
    }
}
