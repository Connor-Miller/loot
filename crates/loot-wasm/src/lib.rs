//! loot-wasm: the in-memory SDK's WASM core.
//!
//! `wasm-bindgen` exports over [`loot_codec`]'s crypto/codec so the TypeScript
//! in-memory mode can decode a sync bundle, AES-decrypt a sealed object, and
//! address content — all bit-identical to the `loot` binary, because both build
//! the same `loot-codec` source (ADR: TS SDK bridging, #381). Plus the minimal
//! diskless identity surface (#383): generate / from-seed / public-key over
//! ed25519 — no OpenSSH file, no passphrase.
//!
//! Structure: a pure, native-testable [`core`] module holds all the logic; the
//! `#[wasm_bindgen]` items in this file are a thin ABI shell that adapts
//! `core`'s plain Rust types to `JsError`/`Vec<u8>`. The golden-parity harness
//! (`tests/parity.rs`) exercises `core` natively and the exported shell under
//! `wasm-pack test --node`, so the two builds can never drift.
//!
//! What deliberately does NOT cross this boundary:
//!   - **zstd** — `loot-codec` is built `default-features = false`, so public
//!     content comes back still-compressed and JS inflates it host-side.
//!   - **transport** — TS speaks the relay's HTTP wire via `fetch()` directly.

use wasm_bindgen::prelude::*;

pub mod core {
    //! Pure logic, no `wasm-bindgen` — callable natively and from the shell.

    use ed25519_dalek::{Signer, SigningKey};
    use loot_codec::bundle_codec::{BundleBody, Frame};
    use loot_codec::change_id;
    use loot_codec::sealed::{self, ContentKey, SealedObject};
    use loot_codec::{ChangeNode, Oid, Visibility};
    use serde::Serialize;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    /// ENVELOPE_VERSION (loot-identity): the leading byte of a `/stow` envelope.
    const ENVELOPE_VERSION: u8 = 0x01;

    fn visibility_from(tag: &str) -> Result<Visibility, String> {
        match tag {
            "public" => Ok(Visibility::Public),
            // A carried path may be private; slice 2 authors public content only,
            // so `put` rejects non-public, but `carry` must preserve the tag.
            "private" => Ok(Visibility::Restricted(Vec::new())),
            other => Err(format!("unknown visibility {other:?}")),
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The content address of a sealed object: `blake3(nonce ‖ ciphertext)` —
    /// the exact function the binary uses to name content.
    pub fn address(nonce: &[u8; 12], ciphertext: &[u8]) -> [u8; 32] {
        let obj = SealedObject {
            nonce: *nonce,
            ciphertext: ciphertext.to_vec(),
            vis: Visibility::Public,
            grant_ids: Vec::new(),
            compressed: false,
        };
        obj.address().0
    }

    /// Encode a relay `/fetch` request body: the `[major][minor]` format marker,
    /// then the caller's `have` change-ids and `wants` object addresses, each a
    /// length-prefixed list — byte-identical to `loot-net`'s `encode_have_wants`.
    /// `have`/`wants` are flat concatenations of 32-byte ids. Kept in the wasm
    /// core so the version marker can never drift from the binary's.
    pub fn encode_fetch_request(have: &[u8], wants: &[u8]) -> Result<Vec<u8>, String> {
        if have.len() % 32 != 0 || wants.len() % 32 != 0 {
            return Err("have/wants must each be a multiple of 32 bytes".into());
        }
        let mut out = Vec::new();
        loot_codec::format::put_version(&mut out);
        out.extend_from_slice(&((have.len() / 32) as u32).to_le_bytes());
        out.extend_from_slice(have);
        out.extend_from_slice(&((wants.len() / 32) as u32).to_le_bytes());
        out.extend_from_slice(wants);
        Ok(out)
    }

    /// AES-256-GCM decrypt under `key` — the raw open primitive (no gates, no
    /// decompression). For compressed public content the plaintext is still
    /// zstd-deflated; the host inflates it.
    pub fn decrypt(nonce: &[u8; 12], ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
        let obj = SealedObject {
            nonce: *nonce,
            ciphertext: ciphertext.to_vec(),
            vis: Visibility::Public,
            grant_ids: Vec::new(),
            compressed: false,
        };
        sealed::decrypt(&obj, key).map_err(|e| e.to_string())
    }

    #[derive(Serialize)]
    struct TreeEntryView {
        path: String,
        oid: String,
        visibility: &'static str,
    }

    #[derive(Serialize)]
    struct ChangeView {
        id: String,
        message: String,
        parents: Vec<String>,
        tree: Vec<TreeEntryView>,
    }

    fn vis_tag(v: &Visibility) -> &'static str {
        match v {
            Visibility::Public => "public",
            Visibility::Restricted(_) => "restricted",
            Visibility::Embargoed { .. } => "embargoed",
        }
    }

    /// A decoded sync bundle: change-graph metadata plus the sealed object bytes
    /// and openly-shared content keys that ride with it. The TS SDK path-scopes
    /// a read by resolving a path to its oid in the changes, then fetching and
    /// decrypting the object.
    pub struct DecodedBundle {
        changes: Vec<ChangeView>,
        objects: BTreeMap<[u8; 32], SealedObject>,
        public_keys: BTreeMap<[u8; 32], [u8; 32]>,
    }

    impl DecodedBundle {
        /// Decode relay `/fetch` bytes. Only a `Sync` frame carries a repo
        /// bundle; a Grant/SealedGrant frame is rejected.
        pub fn decode(bytes: &[u8]) -> Result<DecodedBundle, String> {
            let frame = Frame::decode(bytes).map_err(|e| e.to_string())?;
            let body = match frame {
                Frame::Sync { body, .. } => body,
                _ => return Err("not a Sync bundle frame".into()),
            };
            let changes = body
                .changes
                .iter()
                .map(|c| ChangeView {
                    id: hex(&c.id.0),
                    message: c.message.clone(),
                    parents: c.parents.iter().map(|p| hex(&p.0)).collect(),
                    tree: c
                        .tree
                        .iter()
                        .map(|(path, (oid, vis))| TreeEntryView {
                            path: path.to_string_lossy().into_owned(),
                            oid: hex(&oid.0),
                            visibility: vis_tag(vis),
                        })
                        .collect(),
                })
                .collect();
            let objects = body.objs.into_iter().map(|(k, v)| (k.0, v)).collect();
            let public_keys = body.keys.into_iter().map(|(k, v)| (k.0, v)).collect();
            Ok(DecodedBundle { changes, objects, public_keys })
        }

        pub fn changes_json(&self) -> String {
            serde_json::to_string(&self.changes).unwrap_or_else(|_| "[]".into())
        }

        fn key(addr: &[u8]) -> Result<[u8; 32], String> {
            addr.try_into().map_err(|_| "address must be 32 bytes".to_string())
        }

        pub fn object(&self, addr: &[u8]) -> Result<Option<Vec<u8>>, String> {
            Ok(self.objects.get(&Self::key(addr)?).map(|o| o.ciphertext.clone()))
        }
        pub fn nonce(&self, addr: &[u8]) -> Result<Option<Vec<u8>>, String> {
            Ok(self.objects.get(&Self::key(addr)?).map(|o| o.nonce.to_vec()))
        }
        pub fn compressed(&self, addr: &[u8]) -> Result<Option<bool>, String> {
            Ok(self.objects.get(&Self::key(addr)?).map(|o| o.compressed))
        }
        pub fn public_key(&self, addr: &[u8]) -> Result<Option<Vec<u8>>, String> {
            Ok(self.public_keys.get(&Self::key(addr)?).map(|k| k.to_vec()))
        }
    }

    /// A loot authorship identity held entirely in memory (#383).
    pub struct Identity {
        signing_key: SigningKey,
    }

    impl Identity {
        pub fn generate() -> Result<Identity, String> {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(|e| e.to_string())?;
            Ok(Identity { signing_key: SigningKey::from_bytes(&seed) })
        }
        pub fn from_seed(seed: &[u8]) -> Result<Identity, String> {
            let seed: [u8; 32] = seed.try_into().map_err(|_| "seed must be 32 bytes".to_string())?;
            Ok(Identity { signing_key: SigningKey::from_bytes(&seed) })
        }
        pub fn public_key(&self) -> Vec<u8> {
            self.author().to_vec()
        }

        fn author(&self) -> [u8; 32] {
            self.signing_key.verifying_key().to_bytes()
        }

        /// Sign `message` with this identity's ed25519 key (64-byte signature) —
        /// the primitive both the change finalize-signature and the `/stow`
        /// envelope are built from.
        pub fn sign(&self, message: &[u8]) -> Vec<u8> {
            self.signing_key.sign(message).to_bytes().to_vec()
        }

        /// Wrap `bundle` in a signed `/stow` envelope: `[0x01][pubkey 32][sig 64]
        /// [bundle]`, the signature over `bundle` — byte-identical to
        /// loot-identity's `wrap_envelope`.
        pub fn wrap_envelope(&self, bundle: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(97 + bundle.len());
            out.push(ENVELOPE_VERSION);
            out.extend_from_slice(&self.author());
            out.extend_from_slice(&self.sign(bundle));
            out.extend_from_slice(bundle);
            out
        }
    }

    /// The outcome of [`ChangeBuilder::finish`]: the `/stow` envelope to POST,
    /// plus the durable `change_id` and the content-derived `version_id`.
    pub struct AuthoredChange {
        pub envelope: Vec<u8>,
        pub change_id: [u8; 16],
        pub version_id: Oid,
    }

    /// Composes a signed, full-tree change entirely in Rust (#381): the caller
    /// `carry`s each unchanged path (its existing address) and `put`s each edited
    /// path (sealed here), then `finish` folds the change-id, signs the finalize
    /// message, encodes the `Sync` bundle, and wraps the envelope. The TS side
    /// owns only the overlay bookkeeping — never the composition.
    pub struct ChangeBuilder {
        signing_key: SigningKey,
        author: [u8; 32],
        message: String,
        parents: Vec<Oid>,
        tree: BTreeMap<PathBuf, (Oid, Visibility)>,
        objs: BTreeMap<Oid, SealedObject>,
        keys: BTreeMap<Oid, ContentKey>,
    }

    impl ChangeBuilder {
        pub fn new(identity: &Identity, message: String) -> Self {
            ChangeBuilder {
                signing_key: identity.signing_key.clone(),
                author: identity.author(),
                message,
                parents: Vec::new(),
                tree: BTreeMap::new(),
                objs: BTreeMap::new(),
                keys: BTreeMap::new(),
            }
        }

        pub fn set_parent(&mut self, parent: &[u8]) -> Result<(), String> {
            let p: [u8; 32] = parent.try_into().map_err(|_| "parent id must be 32 bytes".to_string())?;
            self.parents.push(Oid(p));
            Ok(())
        }

        /// An unchanged path keeps its existing content address (the relay
        /// already holds the object) — carried into the full-tree manifest.
        pub fn carry(&mut self, path: &str, oid: &[u8], visibility: &str) -> Result<(), String> {
            let o: [u8; 32] = oid.try_into().map_err(|_| "oid must be 32 bytes".to_string())?;
            self.tree.insert(PathBuf::from(path), (Oid(o), visibility_from(visibility)?));
            Ok(())
        }

        /// An edited/new path: seal the plaintext (uncompressed public content,
        /// ADR 0040), record its object + public key, and place it in the tree.
        pub fn put(&mut self, path: &str, plaintext: &[u8], visibility: &str) -> Result<(), String> {
            let vis = visibility_from(visibility)?;
            if !matches!(vis, Visibility::Public) {
                return Err("slice 2 authors public content only (private needs a grant, slice 4)".into());
            }
            let (oid, sealed, key) = sealed::seal_uncompressed(plaintext, &vis).map_err(|e| e.to_string())?;
            self.keys.insert(oid.clone(), key);
            self.objs.insert(oid.clone(), sealed);
            self.tree.insert(PathBuf::from(path), (oid, vis));
            Ok(())
        }

        pub fn finish(self) -> AuthoredChange {
            let author = Some(&self.author);
            let version_id =
                change_id::compute_change_id_raw(author, &self.message, &self.parents, &self.tree, &[]);
            let change_id = change_id::mint_change_id();
            let sign_msg = change_id::change_signing_message(&version_id, &Some(change_id), &[]);
            let signature: [u8; 64] = self.signing_key.sign(&sign_msg).to_bytes();

            let node = ChangeNode {
                id: version_id.clone(),
                parents: self.parents,
                message: self.message,
                tree: self.tree,
                author: Some(self.author),
                signature: Some(signature),
                change_id: Some(change_id),
                predecessors: Vec::new(),
            };
            let body =
                BundleBody { changes: vec![node], objs: self.objs, keys: self.keys, attestations: Vec::new() };
            let bundle = Frame::Sync { purges: Vec::new(), body }.encode();

            let mut envelope = Vec::with_capacity(97 + bundle.len());
            envelope.push(ENVELOPE_VERSION);
            envelope.extend_from_slice(&self.author);
            envelope.extend_from_slice(&self.signing_key.sign(&bundle).to_bytes());
            envelope.extend_from_slice(&bundle);

            AuthoredChange { envelope, change_id, version_id }
        }
    }
}

// ---------------------------------------------------------------------------
// wasm-bindgen ABI shell — thin adapters over `core`
// ---------------------------------------------------------------------------

fn js(e: String) -> JsError {
    JsError::new(&e)
}

fn nonce12(nonce: &[u8]) -> Result<[u8; 12], JsError> {
    nonce.try_into().map_err(|_| JsError::new("nonce must be 12 bytes"))
}

/// The content address of a sealed object: `blake3(nonce ‖ ciphertext)`.
#[wasm_bindgen]
pub fn blake3_address(nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
    Ok(core::address(&nonce12(nonce)?, ciphertext).to_vec())
}

/// Encode a relay `/fetch` request body (format marker + `have` + `wants`).
/// `have`/`wants` are flat concatenations of 32-byte ids.
#[wasm_bindgen(js_name = encodeFetchRequest)]
pub fn encode_fetch_request(have: &[u8], wants: &[u8]) -> Result<Vec<u8>, JsError> {
    core::encode_fetch_request(have, wants).map_err(js)
}

/// AES-256-GCM decrypt of a sealed object's ciphertext under `key`.
#[wasm_bindgen]
pub fn decrypt(nonce: &[u8], ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, JsError> {
    let key: [u8; 32] = key.try_into().map_err(|_| JsError::new("key must be 32 bytes"))?;
    core::decrypt(&nonce12(nonce)?, ciphertext, &key).map_err(js)
}

/// A decoded sync bundle (see [`core::DecodedBundle`]).
#[wasm_bindgen]
pub struct WasmBundle(core::DecodedBundle);

#[wasm_bindgen]
impl WasmBundle {
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<WasmBundle, JsError> {
        core::DecodedBundle::decode(bytes).map(WasmBundle).map_err(js)
    }
    #[wasm_bindgen(js_name = changesJson)]
    pub fn changes_json(&self) -> String {
        self.0.changes_json()
    }
    #[wasm_bindgen]
    pub fn object(&self, addr: &[u8]) -> Result<Option<Vec<u8>>, JsError> {
        self.0.object(addr).map_err(js)
    }
    #[wasm_bindgen]
    pub fn nonce(&self, addr: &[u8]) -> Result<Option<Vec<u8>>, JsError> {
        self.0.nonce(addr).map_err(js)
    }
    #[wasm_bindgen]
    pub fn compressed(&self, addr: &[u8]) -> Result<Option<bool>, JsError> {
        self.0.compressed(addr).map_err(js)
    }
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self, addr: &[u8]) -> Result<Option<Vec<u8>>, JsError> {
        self.0.public_key(addr).map_err(js)
    }
}

/// A loot authorship identity held entirely in memory: an ed25519 keypair with
/// no `.loot/` on disk. Generate / from-seed / sign / envelope (#383/#424).
#[wasm_bindgen]
pub struct Identity(core::Identity);

#[wasm_bindgen]
impl Identity {
    #[wasm_bindgen]
    pub fn generate() -> Result<Identity, JsError> {
        core::Identity::generate().map(Identity).map_err(js)
    }
    #[wasm_bindgen(js_name = fromSeed)]
    pub fn from_seed(seed: &[u8]) -> Result<Identity, JsError> {
        core::Identity::from_seed(seed).map(Identity).map_err(js)
    }
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.0.public_key()
    }
    /// Sign `message` (64-byte ed25519 signature).
    #[wasm_bindgen]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.0.sign(message)
    }
    /// Wrap `bundle` in a signed `/stow` envelope (`[0x01][pubkey][sig][bundle]`).
    #[wasm_bindgen(js_name = wrapEnvelope)]
    pub fn wrap_envelope(&self, bundle: &[u8]) -> Vec<u8> {
        self.0.wrap_envelope(bundle)
    }
}

/// The outcome of [`ChangeBuilder::finish`] — the envelope to POST to `/stow`
/// plus the change's ids.
#[wasm_bindgen]
pub struct AuthoredChange(core::AuthoredChange);

#[wasm_bindgen]
impl AuthoredChange {
    #[wasm_bindgen(getter)]
    pub fn envelope(&self) -> Vec<u8> {
        self.0.envelope.clone()
    }
    #[wasm_bindgen(getter, js_name = changeId)]
    pub fn change_id(&self) -> Vec<u8> {
        self.0.change_id.to_vec()
    }
    #[wasm_bindgen(getter, js_name = versionId)]
    pub fn version_id(&self) -> Vec<u8> {
        self.0.version_id.0.to_vec()
    }
}

/// Composes a signed, full-tree change in Rust (#381). `carry` each unchanged
/// path, `put` each edited path, then `finish` to get the `/stow` envelope.
#[wasm_bindgen]
pub struct ChangeBuilder(core::ChangeBuilder);

#[wasm_bindgen]
impl ChangeBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(identity: &Identity, message: String) -> ChangeBuilder {
        ChangeBuilder(core::ChangeBuilder::new(&identity.0, message))
    }
    #[wasm_bindgen(js_name = setParent)]
    pub fn set_parent(&mut self, parent: &[u8]) -> Result<(), JsError> {
        self.0.set_parent(parent).map_err(js)
    }
    pub fn carry(&mut self, path: &str, oid: &[u8], visibility: &str) -> Result<(), JsError> {
        self.0.carry(path, oid, visibility).map_err(js)
    }
    pub fn put(&mut self, path: &str, plaintext: &[u8], visibility: &str) -> Result<(), JsError> {
        self.0.put(path, plaintext, visibility).map_err(js)
    }
    pub fn finish(self) -> AuthoredChange {
        AuthoredChange(self.0.finish())
    }
}
