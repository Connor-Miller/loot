//! The change-id fold and finalize-signature message (ADR 0018/0029/0032).
//!
//! Extracted from the engine so the WASM core can author a change whose id and
//! signature are **bit-identical** to the binary's (#381/#424). These are pure
//! over the leaf types; the engine's `compute_change_id(&Change, …)` delegates
//! to [`compute_change_id_raw`].

use crate::{Oid, Visibility};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Canonicalize a predecessors list for hashing/signing (ADR 0032): sorted,
/// deduplicated. Both the id computation and the signing message consume the
/// canonical form, so two writers naming the same set agree byte-for-byte.
pub fn canonical_predecessors(predecessors: &[Oid]) -> Vec<Oid> {
    let mut p = predecessors.to_vec();
    p.sort();
    p.dedup();
    p
}

/// Content-and-author-derived change id: hash of the author pubkey (when
/// present), message, parents, the path/address tree, and — when non-empty —
/// the `predecessors` it supersedes (v7, ADR 0032). Pure; identical inputs get
/// identical ids (idempotent commit/apply). `author = None` reproduces the
/// pre-authorship id exactly (legacy/unauthored changes unchanged).
pub fn compute_change_id_raw(
    author: Option<&[u8; 32]>,
    message: &str,
    parents: &[Oid],
    tree: &BTreeMap<PathBuf, (Oid, Visibility)>,
    predecessors: &[Oid],
) -> Oid {
    let mut h = blake3::Hasher::new();
    if let Some(a) = author {
        h.update(a);
    }
    h.update(message.as_bytes());
    for p in parents {
        h.update(&p.0);
    }
    for (path, (oid, _vis)) in tree {
        h.update(path.to_string_lossy().as_bytes());
        h.update(&[0]);
        h.update(&oid.0);
    }
    if !predecessors.is_empty() {
        h.update(b"\0predecessors\0");
        for p in canonical_predecessors(predecessors) {
            h.update(&p.0);
        }
    }
    Oid(*h.finalize().as_bytes())
}

/// Mint a fresh random 16-byte durable change id (v6, ADR 0029), called when a
/// change begins. Random — not derived from content — so it survives the rewrite
/// churn that content-addressed ids cannot.
pub fn mint_change_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id).expect("OS RNG unavailable while minting a change id");
    id
}

/// The message the finalize signature covers (ADR 0029/0032): the **version id**,
/// the **change id** when present, then the **predecessors** when any (v7). A
/// legacy change (`change_id = None`) signs over the 32-byte version id alone, so
/// its pre-v6 signature still verifies unchanged.
pub fn change_signing_message(
    version_id: &Oid,
    change_id: &Option<[u8; 16]>,
    predecessors: &[Oid],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(48 + 32 * predecessors.len());
    msg.extend_from_slice(&version_id.0);
    if let Some(cid) = change_id {
        msg.extend_from_slice(cid);
    }
    for p in canonical_predecessors(predecessors) {
        msg.extend_from_slice(&p.0);
    }
    msg
}
