//! End-to-end relay sync (ADR 0011, 0014): serve a relay, push alice's signed
//! bundle, pull it into bob over real HTTP, and confirm the relay never holds
//! a key. Also exercises the allowlist: an unknown key is rejected.

use loot_core::{Change, DagRepo, Oid, Repo, RepoError, SyncBundle, Visibility};
use loot_identity::key_seal;
use loot_identity::Identity;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

fn tmp(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("loot-net-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn wait_for_relay(base: &str) {
    for _ in 0..50 {
        if loot_net::pull(base, &[]).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("relay did not come up");
}

fn alice_identity() -> Identity {
    Identity::generate()
}

fn build_restricted_repo(dir: &PathBuf, owner: &str) -> (DagRepo, Oid) {
    let mut repo = DagRepo::init(dir.join("work"), owner).unwrap();
    let oid = repo.put(b"secret bytes\n", Visibility::Restricted(vec![owner.into()])).unwrap();
    let mut tree = BTreeMap::new();
    tree.insert(PathBuf::from("secret.txt"), (oid.clone(), Visibility::Restricted(vec![owner.into()])));
    repo.record(Change { id: Oid([0; 32]), parents: vec![], message: "init".into(), tree }).unwrap();
    (repo, oid)
}

#[test]
fn push_then_pull_syncs_public_content_through_a_keyless_relay() {
    let relay_dir = tmp("relay");
    let addr = "127.0.0.1:47193";
    let base = format!("http://{addr}");

    let serve_dir = relay_dir.clone();
    std::thread::spawn(move || {
        let _ = loot_net::serve(serve_dir, addr, vec![]);
    });
    wait_for_relay(&base);

    let alice_id = alice_identity();
    let alice_dir = tmp("alice");
    let mut alice = DagRepo::init(alice_dir.join("work"), "alice").unwrap();
    let oid = alice.put(b"shared\n", Visibility::Public).unwrap();
    let mut tree = BTreeMap::new();
    tree.insert(PathBuf::from("f.txt"), (oid.clone(), Visibility::Public));
    let change_id = alice
        .record(Change { id: Oid([0; 32]), parents: vec![], message: "init".into(), tree })
        .unwrap();
    let alice_bundle = alice.bundle(&[]).unwrap();
    loot_net::push(&base, alice_bundle.0, &alice_id).unwrap();

    // Bob pulls (he has nothing yet) and applies.
    let bob_dir = tmp("bob");
    let mut bob = DagRepo::init(bob_dir.join("work"), "bob").unwrap();
    let pulled = loot_net::pull(&base, &bob.heads()).unwrap();
    assert!(!pulled.is_empty(), "relay should return alice's change");
    bob.apply(&SyncBundle(pulled), 0).unwrap();

    // Bob now holds the change and can read the public content.
    assert!(bob.heads().contains(&change_id), "bob must have alice's change");
    assert_eq!(bob.get(&oid, "bob", 0).unwrap(), b"shared\n");

    assert!(loot_net::is_relay(&relay_dir), "relay dir must be marked as a relay");
}

#[test]
fn relay_cannot_read_restricted_content_it_relays() {
    let relay_dir = tmp("relay-restricted");
    let addr = "127.0.0.1:47195";
    let base = format!("http://{addr}");
    let serve_dir = relay_dir.clone();
    std::thread::spawn(move || {
        let _ = loot_net::serve(serve_dir, addr, vec![]);
    });
    wait_for_relay(&base);

    let alice_id = alice_identity();
    let alice_dir = tmp("alice-restricted");
    let mut alice = DagRepo::init(alice_dir.join("work"), "alice").unwrap();
    let restricted = Visibility::Restricted(vec!["alice".into()]);
    let oid = alice.put(b"TOKEN=secret\n", restricted.clone()).unwrap();
    let mut tree = BTreeMap::new();
    tree.insert(PathBuf::from(".env"), (oid.clone(), restricted));
    alice
        .record(Change { id: Oid([0; 32]), parents: vec![], message: "init".into(), tree })
        .unwrap();
    loot_net::push(&base, alice.bundle(&[]).unwrap().0, &alice_id).unwrap();

    // The relay stored the change (the path resolves in its tree) but holds no
    // key for the restricted content and cannot read it.
    let relay_repo = DagRepo::load(&relay_dir, relay_dir.clone()).unwrap();
    let stored_oid = relay_repo
        .current_tree_oid(std::path::Path::new(".env"))
        .expect("relay must store the change referencing the restricted object");
    assert_eq!(stored_oid, oid, "relay must reference the same restricted ciphertext");
    assert!(
        relay_repo.get(&oid, "@relay", 0).is_err(),
        "relay must NOT be able to read restricted content it relays"
    );
}

#[test]
fn pull_with_up_to_date_have_returns_empty() {
    let relay_dir = tmp("relay2");
    let addr = "127.0.0.1:47194";
    let base = format!("http://{addr}");
    let serve_dir = relay_dir.clone();
    std::thread::spawn(move || {
        let _ = loot_net::serve(serve_dir, addr, vec![]);
    });
    wait_for_relay(&base);

    let alice_id = alice_identity();
    let alice_dir = tmp("alice2");
    let mut alice = DagRepo::init(alice_dir.join("work"), "alice").unwrap();
    let oid = alice.put(b"x\n", Visibility::Public).unwrap();
    let mut tree = BTreeMap::new();
    tree.insert(PathBuf::from("f.txt"), (oid, Visibility::Public));
    let change_id = alice
        .record(Change { id: Oid([0; 32]), parents: vec![], message: "init".into(), tree })
        .unwrap();
    loot_net::push(&base, alice.bundle(&[]).unwrap().0, &alice_id).unwrap();

    // Pulling with the change already in `have` yields a bundle with no changes.
    let pulled = loot_net::pull(&base, &[change_id]).unwrap();
    let parsed_empty = {
        // tag(1) + purge_count(4) + objs(4)+keys(4)+escrow(4)+changes(4) for an
        // all-empty bundle; rather than re-parse, assert apply finds nothing new.
        let mut bob = DagRepo::init(tmp("bob2").join("work"), "bob").unwrap();
        let outcomes = bob.apply(&SyncBundle(pulled), 0).unwrap();
        outcomes.is_empty()
    };
    assert!(parsed_empty, "pull with up-to-date have must yield no new changes");
}

#[test]
fn allowlist_rejects_unknown_pusher() {
    let relay_dir = tmp("relay-allowlist");
    let addr = "127.0.0.1:47196";
    let base = format!("http://{addr}");

    // Relay configured to only accept alice's key.
    let alice_id = Identity::generate();
    let allowed = vec![alice_id.public_key_bytes()];
    let serve_dir = relay_dir.clone();
    std::thread::spawn(move || {
        let _ = loot_net::serve(serve_dir, addr, allowed);
    });
    wait_for_relay(&base);

    // Eve (unknown key) tries to push — should be rejected.
    let eve_id = Identity::generate();
    let bundle = b"garbage bundle bytes";
    let err = loot_net::push(&base, bundle.to_vec(), &eve_id).unwrap_err();
    assert!(err.to_string().contains("401") || err.to_string().contains("rejected"),
        "expected relay to reject unknown pusher, got: {err}");

    // Alice (known key) can push (even if the bundle fails to stow as garbage,
    // the rejection is from stow not auth — a different error).
    let result = loot_net::push(&base, bundle.to_vec(), &alice_id);
    // May fail at stow level (bad bundle), but must NOT fail at auth level.
    if let Err(e) = result {
        assert!(!e.to_string().contains("401"),
            "alice should pass auth but got 401: {e}");
    }
}

/// Sealed grant relay round-trip: alice seals a content key for bob (x25519/ECIES),
/// signs it in a push envelope, deposits it at the relay mailbox addressed by
/// bob's pubkey hex, bob fetches+unwraps the envelope, checks the grantor is
/// registered, and applies the sealed grant — then he can read content he
/// previously couldn't decrypt. (ADR 0015)
#[test]
fn sealed_grant_relay_round_trip() {
    let relay_dir = tmp("relay-grant");
    let addr = "127.0.0.1:47197";
    let base = format!("http://{addr}");
    let serve_dir = relay_dir.clone();
    std::thread::spawn(move || {
        let _ = loot_net::serve(serve_dir, addr, vec![]);
    });
    wait_for_relay(&base);

    // Alice has an identity keypair (she signs the grant envelope).
    let alice_id = alice_identity();
    let alice_pubkey = alice_id.public_key_bytes();

    // Alice creates restricted content and holds the key.
    let alice_dir = tmp("alice-grant");
    let (mut alice_repo, oid) = build_restricted_repo(&alice_dir, "alice");

    // Bob has an identity keypair; alice will address the mailbox by bob's pubkey.
    let bob_id = Identity::generate();
    let bob_ed_pubkey = bob_id.public_key_bytes();
    let bob_x25519 = bob_id.x25519_pubkey_bytes();

    // Bob's pubkey hex = mailbox address (relay learns no names, ADR 0015).
    let bob_pubkey_hex: String = bob_ed_pubkey.iter().map(|b| format!("{b:02x}")).collect();

    let now = 0u64;

    // Alice produces a sealed grant bundle (tag 3): grantee_pubkey + wrapped_key + oid + payload.
    let sealed_bundle = alice_repo.grant_sealed(
        &oid, "bob", bob_ed_pubkey, alice_pubkey, now,
        |content_key| {
            key_seal::seal_key(content_key, &bob_x25519)
                .map_err(|e| RepoError::Backend(e.to_string()))
        }
    ).unwrap();

    // Alice wraps the bundle in a push envelope (she signs it — ADR 0015).
    let envelope = alice_id.wrap_envelope(&sealed_bundle.0);

    // Alice delivers the envelope to bob's pubkey-addressed mailbox.
    loot_net::deliver_grant(&base, &bob_pubkey_hex, &envelope).unwrap();

    // Bob peeks: should show 1 pending grant.
    let count = loot_net::peek_grants(&base, &bob_pubkey_hex).unwrap();
    assert_eq!(count, 1, "peek should show 1 pending grant before drain");

    // Bob fetches his grants (envelopes). The relay held opaque ciphertext.
    let envelopes = loot_net::fetch_grants(&base, &bob_pubkey_hex).unwrap();
    assert_eq!(envelopes.len(), 1, "bob should have exactly one pending grant");

    // Mailbox is now drained.
    let after_drain = loot_net::fetch_grants(&base, &bob_pubkey_hex).unwrap();
    assert!(after_drain.is_empty(), "grants must be deleted on delivery");

    // Unwrap the push envelope: get grantor pubkey + bundle bytes.
    let (grantor_pubkey, bundle_bytes) =
        loot_identity::unwrap_envelope(&envelopes[0], &[]).unwrap();
    assert_eq!(grantor_pubkey, alice_pubkey, "grantor pubkey must match alice's signing key");

    // Bob applies the sealed grant — his identity unseals the wrapped key.
    let mut bob_repo = DagRepo::init(tmp("bob-grant").join("work"), "bob").unwrap();
    let grant_bundle = SyncBundle(bundle_bytes.to_vec());
    bob_repo.apply_sealed_grant(&grant_bundle, grantor_pubkey, now, |wrapped| {
        bob_id.unseal_key(wrapped)
            .map_err(|e| RepoError::Backend(e.to_string()))
    }).unwrap();

    // Bob now holds alice's object (from the grant payload) and can read it.
    assert_eq!(
        bob_repo.get(&oid, "bob", 0).unwrap(),
        b"secret bytes\n",
        "bob must be able to read the content after receiving the sealed grant"
    );
}
