//! Network transport for loot sync (ADR 0011, 0014).
//!
//! A loot **relay** is a node that holds ciphertext but no keys — and **a host
//! is a relay that never sleeps**. This crate is the always-on incarnation: an
//! HTTP server (`serve`) that `stow`s pushed bundles append-only and answers
//! pulls by negotiating bundles, plus the blocking `push`/`pull` client the CLI
//! drives. It is the ONE crate that pulls in the async/HTTP dependency tree, so
//! `loot-core` stays pure-sync.
//!
//! Four endpoints:
//! - `POST /stow` — push sync bundle: signed envelope `[0x01][pubkey 32][sig 64][bundle...]`.
//!   Relay verifies signature, checks allowlist, stows append-only.
//! - `POST /negotiate` — pull sync: body is caller's `have` change-ids; relay returns bundle.
//! - `POST /grant` — deposit a sealed grant blob for a named recipient. Body:
//!   `[recipient_len(4)][recipient][blob...]`. No auth — blob is ECIES-sealed.
//! - `POST /pull-grants` — fetch mailbox: body is `[name_len(4)][name]`; relay returns
//!   `[count(4)][len(4)][blob...]...` and deletes delivered blobs.
//!
//! Content is sealed end-to-end, so the relay learns nothing it could not relay
//! anyway; transport security (TLS, when added) protects metadata and integrity,
//! not content secrecy.

use loot_core::{DagRepo, Oid, Repo, SyncBundle};
use loot_identity as identity;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

mod relay_store;
mod mailbox;
pub use relay_store::{is_relay, RelayStore};

/// Maximum request body the relay buffers, replacing axum's implicit 2 MiB
/// `DefaultBodyLimit` that 413'd any push batch over it (#309). Push batches
/// are byte-capped client-side well below this (an eighth), so the limit only
/// refuses a single object too large to batch around — the one case that
/// would need a chunked-object protocol. Exported so the client cap derives
/// from it and the two can never drift apart.
pub const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug)]
pub enum NetError {
    Io(String),
    Http(String),
    Engine(String),
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::Io(e) => write!(f, "io: {e}"),
            NetError::Http(e) => write!(f, "http: {e}"),
            NetError::Engine(e) => write!(f, "engine: {e}"),
        }
    }
}
impl std::error::Error for NetError {}

/// Encode a `have` list (change-ids the caller already holds) as the negotiate
/// request body: a flat run of 32-byte addresses. The relay decodes it and ships
/// every change not in the set (change-id-level negotiation, ADR 0011 / Q1).
pub fn encode_have(have: &[Oid]) -> Vec<u8> {
    let mut out = Vec::with_capacity(have.len() * 32);
    for oid in have {
        out.extend_from_slice(&oid.0);
    }
    out
}

fn decode_have(body: &[u8]) -> Result<Vec<Oid>, NetError> {
    if !body.len().is_multiple_of(32) {
        return Err(NetError::Http(format!(
            "negotiate body must be a multiple of 32 bytes, got {}",
            body.len()
        )));
    }
    let mut have = Vec::with_capacity(body.len() / 32);
    for chunk in body.chunks_exact(32) {
        let mut a = [0u8; 32];
        a.copy_from_slice(chunk);
        have.push(Oid(a));
    }
    Ok(have)
}

// --- S5: object-level "wants" negotiation wire messages ---
//
// The negotiation exchanges content addresses (already relay-visible), never
// keys or plaintext — the zero-knowledge posture is preserved. Each message
// leads with the S1 format marker so the wire protocol is version-gated (a peer
// on an incompatible future major is rejected, not mis-parsed).

/// Encode a version-marked list of content addresses (the `/offer` and `/wants`
/// message shape).
pub fn encode_addrs(oids: &[Oid]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + oids.len() * 32);
    loot_core::format::put_version(&mut out);
    for oid in oids {
        out.extend_from_slice(&oid.0);
    }
    out
}

fn decode_addrs(body: &[u8]) -> Result<Vec<Oid>, NetError> {
    let mut c = loot_core::format::Cursor { b: body, i: 0 };
    loot_core::format::read_version(&mut c).map_err(|e| NetError::Http(e.to_string()))?;
    let rest = &body[c.i..];
    if !rest.len().is_multiple_of(32) {
        return Err(NetError::Http(format!(
            "address list must be a multiple of 32 bytes after the marker, got {}",
            rest.len()
        )));
    }
    let mut oids = Vec::with_capacity(rest.len() / 32);
    for chunk in rest.chunks_exact(32) {
        let mut a = [0u8; 32];
        a.copy_from_slice(chunk);
        oids.push(Oid(a));
    }
    Ok(oids)
}

/// Encode the `/fetch` request: version marker, the caller's `have` change-ids,
/// then the `wants` object addresses (each a length-prefixed list).
pub fn encode_have_wants(have: &[Oid], wants: &[Oid]) -> Vec<u8> {
    let mut out = Vec::new();
    loot_core::format::put_version(&mut out);
    out.extend_from_slice(&(have.len() as u32).to_le_bytes());
    for o in have {
        out.extend_from_slice(&o.0);
    }
    out.extend_from_slice(&(wants.len() as u32).to_le_bytes());
    for o in wants {
        out.extend_from_slice(&o.0);
    }
    out
}

fn decode_have_wants(body: &[u8]) -> Result<(Vec<Oid>, Vec<Oid>), NetError> {
    let mut c = loot_core::format::Cursor { b: body, i: 0 };
    loot_core::format::read_version(&mut c).map_err(|e| NetError::Http(e.to_string()))?;
    // Cap capacity by remaining body bytes so an attacker-controlled count cannot
    // trigger a multi-GB Vec::with_capacity before the loop's arr32() fires.
    let hn = c.u32().map_err(|e| NetError::Http(e.to_string()))?;
    let max_oids = (body.len() - c.i) / 32;
    let mut have = Vec::with_capacity(hn.min(max_oids));
    for _ in 0..hn {
        have.push(Oid(c.arr32().map_err(|e| NetError::Http(e.to_string()))?));
    }
    let wn = c.u32().map_err(|e| NetError::Http(e.to_string()))?;
    let max_oids = (body.len() - c.i) / 32;
    let mut wants = Vec::with_capacity(wn.min(max_oids));
    for _ in 0..wn {
        wants.push(Oid(c.arr32().map_err(|e| NetError::Http(e.to_string()))?));
    }
    Ok((have, wants))
}

// --- server (`loot serve`) ---

#[derive(Clone)]
struct ServerState {
    relay: Arc<Mutex<RelayStore>>,
    /// Root directory of the relay store (for mailbox access).
    relay_dir: Arc<PathBuf>,
    /// Allowed pusher public keys. Empty = open relay (any valid signature accepted).
    allowed_keys: Arc<Vec<[u8; 32]>>,
}

/// Run the relay HTTP server on `addr` (e.g. `0.0.0.0:4000`), serving a relay
/// store rooted at `dir`. Blocks until the process is killed. Creates the relay
/// store (empty keyring + role marker) if `dir` is fresh.
///
/// `allowed_keys` — ed25519 public keys (32 bytes each) permitted to push. An
/// empty slice means open relay: any valid signature is accepted.
pub fn serve(dir: PathBuf, addr: &str, allowed_keys: Vec<[u8; 32]>) -> Result<(), NetError> {
    let store = RelayStore::open_or_init(&dir)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| NetError::Io(e.to_string()))?;
    rt.block_on(serve_async(store, dir, addr, allowed_keys))
}

async fn serve_async(store: RelayStore, dir: PathBuf, addr: &str, allowed_keys: Vec<[u8; 32]>) -> Result<(), NetError> {
    use axum::routing::post;
    use axum::Router;

    let state = ServerState {
        relay: Arc::new(Mutex::new(store)),
        relay_dir: Arc::new(dir),
        allowed_keys: Arc::new(allowed_keys),
    };
    let app = Router::new()
        .route("/stow", post(handle_stow))
        .route("/negotiate", post(handle_negotiate))
        .route("/offer", post(handle_offer))
        .route("/fetch", post(handle_fetch))
        .route("/wants", post(handle_wants))
        .route("/grant", post(handle_deposit_grant))
        .route("/pull-grants", post(handle_pull_grants))
        .route("/grants/peek", post(handle_peek_grants))
        // Every endpoint buffers its body whole; without this layer axum's
        // implicit 2 MiB default applied and large stows 413'd forever (#309).
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| NetError::Io(format!("bind {addr}: {e}")))?;
    println!("loot relay listening on {addr}");
    axum::serve(listener, app)
        .await
        .map_err(|e| NetError::Http(e.to_string()))
}

async fn handle_stow(
    axum::extract::State(state): axum::extract::State<ServerState>,
    body: axum::body::Bytes,
) -> Result<String, (axum::http::StatusCode, String)> {
    let (_, bundle_bytes) = identity::unwrap_envelope(&body, &state.allowed_keys)
        .map_err(|e| (axum::http::StatusCode::UNAUTHORIZED, e.to_string()))?;
    let bundle = SyncBundle(bundle_bytes.to_vec());
    let mut relay = state.relay.lock().await;
    relay
        .stow(&bundle)
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok("stowed".into())
}

async fn handle_negotiate(
    axum::extract::State(state): axum::extract::State<ServerState>,
    body: axum::body::Bytes,
) -> Result<Vec<u8>, (axum::http::StatusCode, String)> {
    let have = decode_have(&body).map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?;
    let relay = state.relay.lock().await;
    let bundle = relay
        .bundle(&have)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(bundle.0)
}

// S5 pull round 1: caller sends its `have` change-ids; relay offers the object
// addresses in the closure of what it would send.
async fn handle_offer(
    axum::extract::State(state): axum::extract::State<ServerState>,
    body: axum::body::Bytes,
) -> Result<Vec<u8>, (axum::http::StatusCode, String)> {
    let have = decode_addrs(&body).map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?;
    let relay = state.relay.lock().await;
    Ok(encode_addrs(&relay.offered_objects(&have)))
}

// S5 pull round 2: caller sends `have` + the `wants` subset it is missing; relay
// returns a bundle whose object bytes are limited to `wants`.
async fn handle_fetch(
    axum::extract::State(state): axum::extract::State<ServerState>,
    body: axum::body::Bytes,
) -> Result<Vec<u8>, (axum::http::StatusCode, String)> {
    let (have, wants) =
        decode_have_wants(&body).map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?;
    let relay = state.relay.lock().await;
    let bundle = relay
        .bundle_wanted(&have, &wants)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(bundle.0)
}

// S5 push round 1: caller offers the object addresses it would push; relay
// replies with the subset it is missing (so only those bytes are stowed).
async fn handle_wants(
    axum::extract::State(state): axum::extract::State<ServerState>,
    body: axum::body::Bytes,
) -> Result<Vec<u8>, (axum::http::StatusCode, String)> {
    let offered =
        decode_addrs(&body).map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?;
    let relay = state.relay.lock().await;
    Ok(encode_addrs(&relay.missing_objects(&offered)))
}

/// The relay's own clock (unix seconds) — the ONLY time source grant
/// withholding trusts (ADR 0027). Never derived from a request.
fn relay_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The `reveal_at` a grant blob declares (ADR 0027, #14). The blob is a
/// grantor-signed envelope around a `Frame`; the signature is verified here,
/// so a tampered `reveal_at` (it rides inside the signed bytes) makes the
/// whole deposit unparseable rather than an earlier-revealing copy. Anything
/// that does not parse as a signed SealedGrant deposits as untimed (0): a
/// malformed blob cannot be a *valid* timed grant — its wrapped key would
/// never unseal — so delivering garbage early reveals nothing.
fn grant_reveal_at(blob: &[u8]) -> u64 {
    let Ok((_grantor, bundle)) = identity::unwrap_envelope(blob, &[]) else {
        return 0;
    };
    match loot_core::bundle_codec::Frame::decode(bundle) {
        Ok(loot_core::bundle_codec::Frame::SealedGrant { reveal_at, .. }) => reveal_at,
        _ => 0,
    }
}

async fn handle_deposit_grant(
    axum::extract::State(state): axum::extract::State<ServerState>,
    body: axum::body::Bytes,
) -> Result<String, (axum::http::StatusCode, String)> {
    if body.len() < 4 {
        return Err((axum::http::StatusCode::BAD_REQUEST, "body too short".into()));
    }
    let name_len = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
    if body.len() < 4 + name_len {
        return Err((axum::http::StatusCode::BAD_REQUEST, "recipient name truncated".into()));
    }
    let recipient = std::str::from_utf8(&body[4..4 + name_len])
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?;
    let blob = &body[4 + name_len..];
    let reveal_at = grant_reveal_at(blob);
    mailbox::deposit(&state.relay_dir, recipient, blob, reveal_at)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok("deposited".into())
}

async fn handle_peek_grants(
    axum::extract::State(state): axum::extract::State<ServerState>,
    body: axum::body::Bytes,
) -> Result<Vec<u8>, (axum::http::StatusCode, String)> {
    if body.len() < 4 {
        return Err((axum::http::StatusCode::BAD_REQUEST, "body too short".into()));
    }
    let name_len = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
    if body.len() < 4 + name_len {
        return Err((axum::http::StatusCode::BAD_REQUEST, "recipient name truncated".into()));
    }
    let recipient = std::str::from_utf8(&body[4..4 + name_len])
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?;
    let count = mailbox::peek_count(&state.relay_dir, recipient, relay_now())
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok((count as u32).to_le_bytes().to_vec())
}

async fn handle_pull_grants(
    axum::extract::State(state): axum::extract::State<ServerState>,
    body: axum::body::Bytes,
) -> Result<Vec<u8>, (axum::http::StatusCode, String)> {
    if body.len() < 4 {
        return Err((axum::http::StatusCode::BAD_REQUEST, "body too short".into()));
    }
    let name_len = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
    if body.len() < 4 + name_len {
        return Err((axum::http::StatusCode::BAD_REQUEST, "recipient name truncated".into()));
    }
    let recipient = std::str::from_utf8(&body[4..4 + name_len])
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?;
    let blobs = mailbox::fetch_and_drain(&state.relay_dir, recipient, relay_now())
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(mailbox::encode_blobs(&blobs))
}

// --- client (`loot push` / `loot pull`) ---

/// Build the error for a non-success relay response, attaching an actionable
/// hint for the failure shapes an operator can act on. Centralizing it keeps the
/// hint identical across every client verb (push, wants, offer, fetch, …) rather
/// than re-deriving it at each call site.
fn relay_rejected(verb: &str, code: reqwest::StatusCode, msg: &str) -> NetError {
    let hint = if code == reqwest::StatusCode::PAYLOAD_TOO_LARGE {
        // 413: one bundle exceeded the relay's request-body buffer. Batches are
        // byte-capped below MAX_BODY_BYTES, so either the relay predates the
        // raised limit (#309) or a single object outgrows it.
        "\n  the relay's body limit is smaller than this bundle — upgrade the relay \
         (a pre-#309 build caps at 2 MiB), or a single object exceeds its limit"
    } else if msg.contains("unsupported format version") {
        // The relay could not read the format version this build wrote (#361,
        // #431). Every client verb here sends bytes marked with the *current*
        // FORMAT_MAJOR, so a version rejection means the relay is behind — not
        // that this build is stale. The wire message says "upgrade loot", which
        // is right for a too-new local artifact but misleading over the wire:
        // the fix is to redeploy the relay.
        "\n  the relay is behind on loot's format version and cannot read what this \
         build wrote — redeploy the relay (`npm run setup:loot` from the scripts repo)"
    } else {
        ""
    };
    NetError::Http(format!("relay rejected {verb} ({code}): {msg}{hint}"))
}

/// Push raw sync-bundle bytes to a relay's `/stow` endpoint. The bundle is
/// wrapped in a signed envelope (ADR 0014) so the relay can verify authenticity.
/// A deliberate disclosure act: it publishes sealed content to a node that
/// persists it.
pub fn push(base_url: &str, bundle_bytes: Vec<u8>, id: &identity::Identity) -> Result<(), NetError> {
    let url = format!("{}/stow", base_url.trim_end_matches('/'));
    let envelope = id.wrap_envelope(&bundle_bytes);
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
        .body(envelope)
        .send()
        .map_err(|e| NetError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(relay_rejected("push", resp.status(), &resp.text().unwrap_or_default()));
    }
    Ok(())
}

/// Pull from a relay's `/negotiate` endpoint: send the change-ids we already
/// hold, receive a bundle of everything the relay has that we lack. Returns the
/// raw bundle bytes for the caller to `apply`.
pub fn pull(base_url: &str, have: &[Oid]) -> Result<Vec<u8>, NetError> {
    let url = format!("{}/negotiate", base_url.trim_end_matches('/'));
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
        .body(encode_have(have))
        .send()
        .map_err(|e| NetError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(relay_rejected("pull", resp.status(), &resp.text().unwrap_or_default()));
    }
    let bytes = resp.bytes().map_err(|e| NetError::Http(e.to_string()))?;
    Ok(bytes.to_vec())
}

/// S5 pull round 1: ask the relay which object addresses it would offer for our
/// `have` change-ids. Returns the offered content addresses.
pub fn offer(base_url: &str, have: &[Oid]) -> Result<Vec<Oid>, NetError> {
    let url = format!("{}/offer", base_url.trim_end_matches('/'));
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
        .body(encode_addrs(have))
        .send()
        .map_err(|e| NetError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(relay_rejected("offer", resp.status(), &resp.text().unwrap_or_default()));
    }
    let bytes = resp.bytes().map_err(|e| NetError::Http(e.to_string()))?;
    decode_addrs(&bytes)
}

/// S5 pull round 2: fetch a bundle whose object bytes are limited to the
/// addresses we `want`. Returns the raw bundle bytes for the caller to `apply`.
pub fn fetch(base_url: &str, have: &[Oid], wants: &[Oid]) -> Result<Vec<u8>, NetError> {
    let url = format!("{}/fetch", base_url.trim_end_matches('/'));
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
        .body(encode_have_wants(have, wants))
        .send()
        .map_err(|e| NetError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(relay_rejected("fetch", resp.status(), &resp.text().unwrap_or_default()));
    }
    let bytes = resp.bytes().map_err(|e| NetError::Http(e.to_string()))?;
    Ok(bytes.to_vec())
}

/// S5 push round 1: offer the relay our object addresses; it replies with the
/// subset it is missing — the only object bytes we then need to stow.
pub fn wants(base_url: &str, offered: &[Oid]) -> Result<Vec<Oid>, NetError> {
    let url = format!("{}/wants", base_url.trim_end_matches('/'));
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
        .body(encode_addrs(offered))
        .send()
        .map_err(|e| NetError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(relay_rejected("wants", resp.status(), &resp.text().unwrap_or_default()));
    }
    let bytes = resp.bytes().map_err(|e| NetError::Http(e.to_string()))?;
    decode_addrs(&bytes)
}

/// Helper: load a working repo's heads for the pull `have` list, given its
/// `.loot/` dir and working root.
pub fn heads_of(dot: &Path, root: PathBuf) -> Result<Vec<Oid>, NetError> {
    let repo = DagRepo::load(dot, root).map_err(|e| NetError::Engine(e.to_string()))?;
    Ok(repo.heads())
}

/// Deposit a sealed grant blob for the recipient identified by `recipient_pubkey`
/// at the relay's `/grant` mailbox. No signing required — the blob is ECIES-sealed
/// to the recipient's key. The mailbox is addressed by the pubkey's hex, resolved
/// here so the relay never sees a name (ADR 0015); callers pass raw key bytes.
pub fn deliver_grant(base_url: &str, recipient_pubkey: &[u8; 32], blob: &[u8]) -> Result<(), NetError> {
    let url = format!("{}/grant", base_url.trim_end_matches('/'));
    let recipient = loot_core::hex::encode(recipient_pubkey);
    let rb = recipient.as_bytes();
    let mut body = Vec::with_capacity(4 + rb.len() + blob.len());
    body.extend_from_slice(&(rb.len() as u32).to_le_bytes());
    body.extend_from_slice(rb);
    body.extend_from_slice(blob);
    let client = reqwest::blocking::Client::new();
    let resp = client.post(&url).body(body).send()
        .map_err(|e| NetError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(relay_rejected("grant deposit", resp.status(), &resp.text().unwrap_or_default()));
    }
    Ok(())
}

/// Peek the pending grant count for `recipient_pubkey` without fetching or
/// draining. Addressed by the pubkey's hex (resolved here), never by name.
pub fn peek_grants(base_url: &str, recipient_pubkey: &[u8; 32]) -> Result<usize, NetError> {
    let url = format!("{}/grants/peek", base_url.trim_end_matches('/'));
    let recipient = loot_core::hex::encode(recipient_pubkey);
    let rb = recipient.as_bytes();
    let mut body = Vec::with_capacity(4 + rb.len());
    body.extend_from_slice(&(rb.len() as u32).to_le_bytes());
    body.extend_from_slice(rb);
    let client = reqwest::blocking::Client::new();
    let resp = client.post(&url).body(body).send()
        .map_err(|e| NetError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(relay_rejected("peek", resp.status(), &resp.text().unwrap_or_default()));
    }
    let bytes = resp.bytes().map_err(|e| NetError::Http(e.to_string()))?;
    if bytes.len() < 4 {
        return Err(NetError::Http("peek response too short".into()));
    }
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize)
}

/// Fetch and drain all sealed grant blobs addressed to `recipient_pubkey`.
/// Returns raw blob bytes; caller is responsible for unsealing and applying.
/// Blobs are deleted from the relay on delivery. Addressed by the pubkey's hex
/// (resolved here), never by name.
pub fn fetch_grants(base_url: &str, recipient_pubkey: &[u8; 32]) -> Result<Vec<Vec<u8>>, NetError> {
    let url = format!("{}/pull-grants", base_url.trim_end_matches('/'));
    let recipient = loot_core::hex::encode(recipient_pubkey);
    let rb = recipient.as_bytes();
    let mut body = Vec::with_capacity(4 + rb.len());
    body.extend_from_slice(&(rb.len() as u32).to_le_bytes());
    body.extend_from_slice(rb);
    let client = reqwest::blocking::Client::new();
    let resp = client.post(&url).body(body).send()
        .map_err(|e| NetError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(relay_rejected("pull-grants", resp.status(), &resp.text().unwrap_or_default()));
    }
    let bytes = resp.bytes().map_err(|e| NetError::Http(e.to_string()))?;
    mailbox::decode_blobs(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(b: u8) -> Oid {
        Oid([b; 32])
    }

    #[test]
    fn addrs_round_trip_and_carry_version_marker() {
        let list = vec![oid(1), oid(2), oid(3)];
        let enc = encode_addrs(&list);
        assert_eq!(
            &enc[..2],
            &[loot_core::format::FORMAT_MAJOR, loot_core::format::FORMAT_MINOR],
            "negotiation messages are versioned under S1"
        );
        assert_eq!(decode_addrs(&enc).unwrap(), list);
    }

    #[test]
    fn empty_addrs_round_trip() {
        assert!(decode_addrs(&encode_addrs(&[])).unwrap().is_empty());
    }

    #[test]
    fn have_wants_round_trip() {
        let have = vec![oid(1), oid(2)];
        let wants = vec![oid(9)];
        let (h, w) = decode_have_wants(&encode_have_wants(&have, &wants)).unwrap();
        assert_eq!(h, have);
        assert_eq!(w, wants);
    }

    #[test]
    fn decode_rejects_incompatible_version() {
        let mut enc = encode_addrs(&[oid(1)]);
        enc[0] = loot_core::format::FORMAT_MAJOR + 1; // pretend a newer major wrote it
        assert!(decode_addrs(&enc).is_err(), "an unknown future major is rejected");
    }

    #[test]
    fn rejection_hints_relay_redeploy_on_format_skew() {
        // A relay too old to read our FORMAT_MAJOR returns the reader-centric
        // "upgrade loot" text. On push the client always writes the *current*
        // major, so a version rejection means the relay is behind, not that this
        // build is stale — the client must point at a relay redeploy (#361/#431),
        // not at upgrading the local loot.
        let e = relay_rejected(
            "wants",
            reqwest::StatusCode::BAD_REQUEST,
            "unsupported format version v8 — upgrade loot (this build reads up to v7)",
        );
        let s = e.to_string();
        assert!(s.contains("redeploy the relay"), "expected redeploy hint, got: {s}");
        assert!(s.contains("setup:loot"), "expected the concrete command, got: {s}");
    }

    #[test]
    fn rejection_hints_body_limit_on_413() {
        let e = relay_rejected("push", reqwest::StatusCode::PAYLOAD_TOO_LARGE, "too big");
        assert!(e.to_string().contains("body limit"), "expected 413 hint");
    }

    #[test]
    fn rejection_plain_error_carries_no_spurious_hint() {
        let e = relay_rejected("pull", reqwest::StatusCode::INTERNAL_SERVER_ERROR, "boom");
        let s = e.to_string();
        assert!(s.contains("relay rejected pull"), "keeps the base message: {s}");
        assert!(!s.contains("redeploy"), "no spurious redeploy hint: {s}");
        assert!(!s.contains("body limit"), "no spurious 413 hint: {s}");
    }

    #[test]
    fn decode_have_wants_rejects_count_larger_than_body() {
        // Craft a body with version marker + hn=1000 but zero actual Oid bytes.
        // The capacity guard must clamp to 0; the first arr32() in the loop must
        // then return an error rather than a panic or a silent over-allocation.
        let mut body = Vec::new();
        loot_core::format::put_version(&mut body);
        body.extend_from_slice(&1000u32.to_le_bytes()); // hn = 1000
        // no oid bytes follow
        assert!(
            decode_have_wants(&body).is_err(),
            "truncated body with oversized count must be rejected"
        );
    }
}
