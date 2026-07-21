//! Golden parity for the WASM core (Seam 2, #423).
//!
//! The wasm build must produce **byte-identical** crypto/codec output to the
//! native `loot-codec` the `loot` binary uses. To prove that, the assertions
//! feed the system-under-test **frozen bytes produced by the native build**
//! (`FROZEN_*` constants below) and check the decoded result — a symmetric
//! wasm miscompilation cannot cancel out, because nothing the wasm build
//! encodes is fed back into it.
//!
//! The same assertions run two ways, and share one block (`check_*`) so the two
//! builds cannot drift:
//!   - `cargo test -p loot-wasm` — natively against the pure `core` module.
//!     This build *also* regenerates the frozen bytes and asserts they still
//!     match the constants, so a change to the wire format updates them loudly.
//!   - `wasm-pack test --node` — against the exported `#[wasm_bindgen]` shell.

use loot_codec::{Oid, Visibility};

// --- fixed inputs (shared by both builds) ---
const ADDR_NONCE: [u8; 12] = [3u8; 12];
const ADDR_CIPHERTEXT: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const DEC_KEY: [u8; 32] = [7u8; 32];
const DEC_NONCE: [u8; 12] = [9u8; 12];
const DEC_PLAINTEXT: &[u8] = b"loot slice 1 tracer bullet";

// The sample object baked into FROZEN_BUNDLE: nonce/ciphertext = 0x42, key = 5.
const OBJ_BYTE: u8 = 0x42;
const CONTENT_KEY: [u8; 32] = [5u8; 32];

// /fetch request framing: one `have` id (0x11) + one `wants` id (0x22).
const REQ_HAVE: [u8; 32] = [0x11; 32];
const REQ_WANTS: [u8; 32] = [0x22; 32];

// --- frozen native vectors (regenerated + re-asserted by the native run) ---
/// blake3(ADDR_NONCE ‖ ADDR_CIPHERTEXT).
const FROZEN_ADDRESS: &str = "270fc28469c89467298dc6454975985ba36dd2231ce075eba2f585d33d9793e7";
/// blake3(0x42×12 ‖ 0x42×16) — the sample object's content address.
const FROZEN_OBJ_ADDR: &str = "62db251da2e062dcf972f9009539614e88b47fcbbc745aede97685c0242c35ea";
/// AES-256-GCM(DEC_KEY, DEC_NONCE) of DEC_PLAINTEXT.
const FROZEN_CIPHERTEXT: &str =
    "4beaebe09e83ad08c307eb09c69ed1beb7d511d3569b9bac0ada8ac5a72b120867419fca27c37c9b3c20";
/// The `/fetch` request framing for REQ_HAVE + REQ_WANTS (marker + counts + ids).
const FROZEN_FETCH_REQ: &str = "0800010000001111111111111111111111111111111111111111111111111111111111111111010000002222222222222222222222222222222222222222222222222222222222222222";
/// A one-change, one-object Sync frame, encoded by native `loot-codec`.
const FROZEN_BUNDLE: &str = "080000000000000100000062db251da2e062dcf972f9009539614e88b47fcbbc745aede97685c0242c35ea4242424242424242424242420010000000424242424242424242424242424242420001000000010000002a0100000062db251da2e062dcf972f9009539614e88b47fcbbc745aede97685c0242c35ea0505050505050505050505050505050505050505050505050505050505050505010000000101010101010101010101010101010101010101010101010101010101010101000000000c0000006669727374206368616e67650100000009000000726561646d652e6d6462db251da2e062dcf972f9009539614e88b47fcbbc745aede97685c0242c35ea000000000000000000000000";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn ref_address(nonce: &[u8; 12], ciphertext: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(nonce);
    h.update(ciphertext);
    *h.finalize().as_bytes()
}

// --- shared assertions: take values already resolved through each build's own
// --- surface, so both entry points check exactly the same things. ---

fn check_address(got: Vec<u8>) {
    assert_eq!(got, ref_address(&ADDR_NONCE, &ADDR_CIPHERTEXT).to_vec(), "address != independent blake3");
    assert_eq!(hex(&got), FROZEN_ADDRESS, "address != frozen native vector");
}

fn check_decrypt(got: Vec<u8>, wrong_key_errored: bool) {
    assert_eq!(got, DEC_PLAINTEXT, "decrypt of frozen ciphertext != plaintext");
    assert!(wrong_key_errored, "decrypt under the wrong key must error");
}

/// Everything the read path resolves from a decoded bundle, as plain values.
fn check_bundle(
    changes_json: String,
    object: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    compressed: Option<bool>,
    public_key: Option<Vec<u8>>,
    missing_object: Option<Vec<u8>>,
) {
    let changes: serde_json::Value = serde_json::from_str(&changes_json).unwrap();
    assert_eq!(changes[0]["message"], "first change");
    assert_eq!(changes[0]["id"], hex(&[1u8; 32]));
    assert_eq!(changes[0]["tree"][0]["path"], "readme.md");
    assert_eq!(changes[0]["tree"][0]["oid"], FROZEN_OBJ_ADDR);
    assert_eq!(changes[0]["tree"][0]["visibility"], "public");
    assert_eq!(object, Some(vec![OBJ_BYTE; 16]));
    assert_eq!(nonce, Some(vec![OBJ_BYTE; 12]));
    assert_eq!(compressed, Some(false));
    assert_eq!(public_key, Some(CONTENT_KEY.to_vec()));
    assert_eq!(missing_object, None, "an unknown address resolves to None, not an error");
}

fn check_fetch_request(got: Vec<u8>) {
    assert_eq!(hex(&got), FROZEN_FETCH_REQ, "/fetch request framing != frozen native vector");
}

fn frozen_obj_addr_bytes() -> Vec<u8> {
    unhex(FROZEN_OBJ_ADDR)
}

// ---------------------------------------------------------------------------
// Native entry point — pure `core`, plus regeneration of the frozen vectors.
// ---------------------------------------------------------------------------
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn parity_native() {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use loot_codec::bundle_codec::{BundleBody, Frame};
    use loot_codec::sealed::SealedObject;
    use loot_codec::ChangeNode;
    use loot_wasm::core::{address, decrypt, encode_fetch_request, DecodedBundle};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    // Rebuild the sample bundle + ciphertext natively and assert the frozen
    // constants still match — so a wire-format change trips here first.
    let obj = SealedObject {
        nonce: [OBJ_BYTE; 12],
        ciphertext: vec![OBJ_BYTE; 16],
        vis: Visibility::Public,
        grant_ids: vec!["*".into()],
        compressed: false,
    };
    let addr = obj.address();
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
    objs.insert(addr.clone(), obj);
    let mut keys = BTreeMap::new();
    keys.insert(addr.clone(), CONTENT_KEY);
    let body = BundleBody { changes: vec![change], objs, keys, attestations: vec![] };
    let bundle_bytes = Frame::Sync { purges: vec![], body }.encode();

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&DEC_KEY));
    let ciphertext = cipher.encrypt(Nonce::from_slice(&DEC_NONCE), DEC_PLAINTEXT).unwrap();

    // Print-on-mismatch so regenerating the vectors is a copy-paste (see the
    // PLACEHOLDER seeds); then hard-assert the frozen constants.
    let fetch_req = encode_fetch_request(&REQ_HAVE, &REQ_WANTS).unwrap();
    if hex(&addr.0) != FROZEN_OBJ_ADDR
        || hex(&ciphertext) != FROZEN_CIPHERTEXT
        || hex(&bundle_bytes) != FROZEN_BUNDLE
        || hex(&fetch_req) != FROZEN_FETCH_REQ
    {
        panic!(
            "frozen vectors stale — update consts:\nFROZEN_OBJ_ADDR = {:?}\nFROZEN_CIPHERTEXT = {:?}\nFROZEN_FETCH_REQ = {:?}\nFROZEN_BUNDLE = {:?}",
            hex(&addr.0),
            hex(&ciphertext),
            hex(&fetch_req),
            hex(&bundle_bytes)
        );
    }

    // Now the actual parity checks, all against the FROZEN bytes.
    check_address(address(&ADDR_NONCE, &ADDR_CIPHERTEXT).to_vec());
    check_fetch_request(encode_fetch_request(&REQ_HAVE, &REQ_WANTS).unwrap());

    let frozen_ct = unhex(FROZEN_CIPHERTEXT);
    let got = decrypt(&DEC_NONCE, &frozen_ct, &DEC_KEY).unwrap();
    let wrong = decrypt(&DEC_NONCE, &frozen_ct, &[0u8; 32]).is_err();
    check_decrypt(got, wrong);

    let a = frozen_obj_addr_bytes();
    let b = DecodedBundle::decode(&unhex(FROZEN_BUNDLE)).unwrap();
    check_bundle(
        b.changes_json(),
        b.object(&a).unwrap(),
        b.nonce(&a).unwrap(),
        b.compressed(&a).unwrap(),
        b.public_key(&a).unwrap(),
        b.object(&[0u8; 32]).unwrap(),
    );
}

// ---------------------------------------------------------------------------
// WASM entry point — the exported shell, against the SAME frozen bytes.
// ---------------------------------------------------------------------------
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test::wasm_bindgen_test]
fn parity_wasm() {
    use loot_wasm::{blake3_address, decrypt, encode_fetch_request, WasmBundle};

    check_address(blake3_address(&ADDR_NONCE, &ADDR_CIPHERTEXT).unwrap());
    check_fetch_request(encode_fetch_request(&REQ_HAVE, &REQ_WANTS).unwrap());

    let frozen_ct = unhex(FROZEN_CIPHERTEXT);
    let got = decrypt(&DEC_NONCE, &frozen_ct, &DEC_KEY).unwrap();
    let wrong = decrypt(&DEC_NONCE, &frozen_ct, &[0u8; 32]).is_err();
    check_decrypt(got, wrong);

    let a = frozen_obj_addr_bytes();
    let b = WasmBundle::from_bytes(&unhex(FROZEN_BUNDLE)).unwrap();
    check_bundle(
        b.changes_json(),
        b.object(&a).unwrap(),
        b.nonce(&a).unwrap(),
        b.compressed(&a).unwrap(),
        b.public_key(&a).unwrap(),
        b.object(&[0u8; 32]).unwrap(),
    );
}
