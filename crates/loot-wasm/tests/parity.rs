//! Golden parity for the WASM core (Seam 2, #423).
//!
//! Every assertion compares loot-wasm's output against an **independent**
//! reference computation, plus a frozen constant produced by the native
//! `loot-codec`. The *same* assertions run two ways:
//!   - `cargo test -p loot-wasm` — natively against the pure `core` module.
//!   - `wasm-pack test --node`   — against the exported `#[wasm_bindgen]` shell,
//!     proving the actual wasm build reproduces the same bytes (catches
//!     wasm-specific miscompilation / feature-flag drift).
//!
//! The native and wasm entry points call the same reference helpers, so the two
//! builds can never silently diverge.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use loot_codec::bundle_codec::{BundleBody, Frame};
use loot_codec::sealed::SealedObject;
use loot_codec::{ChangeNode, Oid, Visibility};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Independent blake3 of nonce ‖ ciphertext — must match the address export.
fn ref_address(nonce: &[u8; 12], ciphertext: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(nonce);
    h.update(ciphertext);
    *h.finalize().as_bytes()
}

/// Frozen sample: a one-change, one-object Sync bundle encoded with native
/// `loot-codec`, returned as (wire bytes, object, its address, content key).
fn sample_bundle() -> (Vec<u8>, SealedObject, Oid, [u8; 32]) {
    let obj = SealedObject {
        nonce: [0x42; 12],
        ciphertext: vec![0x42; 16],
        vis: Visibility::Public,
        grant_ids: vec!["*".into()],
        compressed: false,
    };
    let addr = obj.address();
    let content_key = [5u8; 32];

    let mut tree = BTreeMap::new();
    tree.insert(PathBuf::from("readme.md"), (addr.clone(), Visibility::Public));
    let change = ChangeNode {
        id: Oid([1u8; 32]),
        parents: vec![],
        message: "first change".into(),
        tree,
        author: None,
        signature: None,
        change_id: None,
        predecessors: vec![],
    };
    let mut objs = BTreeMap::new();
    objs.insert(addr.clone(), obj.clone());
    let mut keys = BTreeMap::new();
    keys.insert(addr.clone(), content_key);
    let body = BundleBody { changes: vec![change], objs, keys, attestations: vec![] };
    (Frame::Sync { purges: vec![], body }.encode(), obj, addr, content_key)
}

// --- The two entry points: they share the reference helpers above but call the
// --- system-under-test through the surface that build can reach.

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn parity_native() {
    use loot_wasm::core::{address, decrypt, DecodedBundle};

    // Address: export == independent blake3, and == frozen native vector.
    let nonce = [3u8; 12];
    let ct = [1u8, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(address(&nonce, &ct).to_vec(), ref_address(&nonce, &ct).to_vec());
    assert_eq!(hex(&address(&nonce, &ct)), FROZEN_ADDRESS);

    // Decrypt: recovers an independently-encrypted plaintext; wrong key errors.
    let key = [7u8; 32];
    let dn = [9u8; 12];
    let plaintext = b"loot slice 1 tracer bullet".to_vec();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let ciphertext = cipher.encrypt(Nonce::from_slice(&dn), plaintext.as_ref()).unwrap();
    assert_eq!(decrypt(&dn, &ciphertext, &key).unwrap(), plaintext);
    assert!(decrypt(&dn, &ciphertext, &[0u8; 32]).is_err());

    // Bundle decode: metadata + object bytes + public key survive the round trip.
    let (bytes, obj, addr, content_key) = sample_bundle();
    let b = DecodedBundle::decode(&bytes).unwrap();
    let changes: serde_json::Value = serde_json::from_str(&b.changes_json()).unwrap();
    assert_eq!(changes[0]["message"], "first change");
    assert_eq!(changes[0]["id"], hex(&[1u8; 32]));
    assert_eq!(changes[0]["tree"][0]["path"], "readme.md");
    assert_eq!(changes[0]["tree"][0]["oid"], hex(&addr.0));
    assert_eq!(changes[0]["tree"][0]["visibility"], "public");
    assert_eq!(b.object(&addr.0).unwrap(), Some(obj.ciphertext.clone()));
    assert_eq!(b.nonce(&addr.0).unwrap(), Some(obj.nonce.to_vec()));
    assert_eq!(b.compressed(&addr.0).unwrap(), Some(false));
    assert_eq!(b.public_key(&addr.0).unwrap(), Some(content_key.to_vec()));
    assert_eq!(b.object(&[0u8; 32]).unwrap(), None);
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test::wasm_bindgen_test]
fn parity_wasm() {
    use loot_wasm::{blake3_address, decrypt, WasmBundle};

    let nonce = [3u8; 12];
    let ct = [1u8, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(blake3_address(&nonce, &ct).unwrap(), ref_address(&nonce, &ct).to_vec());
    assert_eq!(hex(&blake3_address(&nonce, &ct).unwrap()), FROZEN_ADDRESS);

    let key = [7u8; 32];
    let dn = [9u8; 12];
    let plaintext = b"loot slice 1 tracer bullet".to_vec();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let ciphertext = cipher.encrypt(Nonce::from_slice(&dn), plaintext.as_ref()).unwrap();
    assert_eq!(decrypt(&dn, &ciphertext, &key).unwrap(), plaintext);
    assert!(decrypt(&dn, &ciphertext, &[0u8; 32]).is_err());

    let (bytes, obj, addr, content_key) = sample_bundle();
    let b = WasmBundle::from_bytes(&bytes).unwrap();
    let changes: serde_json::Value = serde_json::from_str(&b.changes_json()).unwrap();
    assert_eq!(changes[0]["message"], "first change");
    assert_eq!(changes[0]["tree"][0]["oid"], hex(&addr.0));
    assert_eq!(b.object(&addr.0).unwrap(), Some(obj.ciphertext.clone()));
    assert_eq!(b.public_key(&addr.0).unwrap(), Some(content_key.to_vec()));
    assert_eq!(b.object(&[0u8; 32]).unwrap(), None);
}

/// blake3(nonce=[3;12] ‖ ciphertext=[1..=8]), frozen from native `loot-codec`.
const FROZEN_ADDRESS: &str = "270fc28469c89467298dc6454975985ba36dd2231ce075eba2f585d33d9793e7";
