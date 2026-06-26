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
        .route("/grant", post(handle_deposit_grant))
        .route("/pull-grants", post(handle_pull_grants))
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
    mailbox::deposit(&state.relay_dir, recipient, blob)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok("deposited".into())
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
    let blobs = mailbox::fetch_and_drain(&state.relay_dir, recipient)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(mailbox::encode_blobs(&blobs))
}

// --- client (`loot push` / `loot pull`) ---

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
        let code = resp.status();
        let msg = resp.text().unwrap_or_default();
        return Err(NetError::Http(format!("relay rejected push ({code}): {msg}")));
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
        let code = resp.status();
        let msg = resp.text().unwrap_or_default();
        return Err(NetError::Http(format!("relay rejected pull ({code}): {msg}")));
    }
    let bytes = resp.bytes().map_err(|e| NetError::Http(e.to_string()))?;
    Ok(bytes.to_vec())
}

/// Helper: load a working repo's heads for the pull `have` list, given its
/// `.loot/` dir and working root.
pub fn heads_of(dot: &Path, root: PathBuf) -> Result<Vec<Oid>, NetError> {
    let repo = DagRepo::load(dot, root).map_err(|e| NetError::Engine(e.to_string()))?;
    Ok(repo.heads())
}

/// Deposit a sealed grant blob for `recipient` at the relay's `/grant` mailbox.
/// No signing required — the blob is ECIES-sealed to the recipient's key.
pub fn deliver_grant(base_url: &str, recipient: &str, blob: &[u8]) -> Result<(), NetError> {
    let url = format!("{}/grant", base_url.trim_end_matches('/'));
    let rb = recipient.as_bytes();
    let mut body = Vec::with_capacity(4 + rb.len() + blob.len());
    body.extend_from_slice(&(rb.len() as u32).to_le_bytes());
    body.extend_from_slice(rb);
    body.extend_from_slice(blob);
    let client = reqwest::blocking::Client::new();
    let resp = client.post(&url).body(body).send()
        .map_err(|e| NetError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        let code = resp.status();
        let msg = resp.text().unwrap_or_default();
        return Err(NetError::Http(format!("relay rejected grant deposit ({code}): {msg}")));
    }
    Ok(())
}

/// Fetch and drain all sealed grant blobs addressed to `recipient`.
/// Returns raw blob bytes; caller is responsible for unsealing and applying.
/// Blobs are deleted from the relay on delivery.
pub fn fetch_grants(base_url: &str, recipient: &str) -> Result<Vec<Vec<u8>>, NetError> {
    let url = format!("{}/pull-grants", base_url.trim_end_matches('/'));
    let rb = recipient.as_bytes();
    let mut body = Vec::with_capacity(4 + rb.len());
    body.extend_from_slice(&(rb.len() as u32).to_le_bytes());
    body.extend_from_slice(rb);
    let client = reqwest::blocking::Client::new();
    let resp = client.post(&url).body(body).send()
        .map_err(|e| NetError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        let code = resp.status();
        let msg = resp.text().unwrap_or_default();
        return Err(NetError::Http(format!("relay rejected pull-grants ({code}): {msg}")));
    }
    let bytes = resp.bytes().map_err(|e| NetError::Http(e.to_string()))?;
    mailbox::decode_blobs(&bytes)
}
