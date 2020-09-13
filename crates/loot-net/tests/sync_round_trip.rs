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
    let oid = alice.put(b"shared\n", Visibility::Internal).unwrap();
    let mut tree = BTreeMap::new();
    tree.insert(PathBuf::from("f.txt"), (oid.clone(), Visibility::Internal));
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

/// `GET /info` (#10): a live relay serves its discovery JSON over real HTTP —
/// the allowlist (as hex), the format version, and a null relay pubkey. Proves
/// the client `info()` fn decodes exactly what the handler serialized.
#[test]
fn info_endpoint_reports_allowlist_and_format_version() {
    let relay_dir = tmp("relay-info");
    let addr = "127.0.0.1:47202";
    let base = format!("http://{addr}");

    // Relay configured with a single allowlisted key.
    let alice_id = Identity::generate();
    let alice_pubkey = alice_id.public_key_bytes();
    let allowed = vec![alice_pubkey];
    let serve_dir = relay_dir.clone();
    std::thread::spawn(move || {
        let _ = loot_net::serve(serve_dir, addr, allowed);
    });
    wait_for_relay(&base);

    let info = loot_net::info(&base).expect("GET /info must succeed against a live relay");
    assert_eq!(info.format_major, loot_core::format::FORMAT_MAJOR);
    assert_eq!(info.format_minor, loot_core::format::FORMAT_MINOR);
    assert_eq!(
        info.allowed_pubkeys,
        vec![loot_core::hex::encode(&alice_pubkey)],
        "the allowlist is reported as hex pubkeys"
    );
    assert_eq!(info.relay_pubkey, None, "a zero-knowledge relay has no pubkey");
    assert!(info.version.contains("format v"));
}

/// An open relay (no allowlist) reports an empty pubkey list over `/info`.
#[test]
fn info_endpoint_reports_empty_allowlist_for_open_relay() {
    let relay_dir = tmp("relay-info-open");
    let addr = "127.0.0.1:47203";
    let base = format!("http://{addr}");
    let serve_dir = relay_dir.clone();
    std::thread::spawn(move || {
        let _ = loot_net::serve(serve_dir, addr, vec![]);
    });
    wait_for_relay(&base);

    let info = loot_net::info(&base).unwrap();
    assert!(info.allowed_pubkeys.is_empty(), "open relay reports no allowlisted keys");
}

/// Regression for #309: axum's implicit 2 MiB `DefaultBodyLimit` applied to
/// `/stow`, so any push whose bundle exceeded it bounced with 413 forever (the
/// closure only grows). The relay must accept bodies up to its own explicit
/// limit — well above one client batch.
#[test]
fn relay_accepts_a_push_larger_than_two_mib() {
    let relay_dir = tmp("relay-large");
    let addr = "127.0.0.1:47200";
    let base = format!("http://{addr}");
    let serve_dir = relay_dir.clone();
    std::thread::spawn(move || {
        let _ = loot_net::serve(serve_dir, addr, vec![]);
    });
    wait_for_relay(&base);

    let alice_id = alice_identity();
    let alice_dir = tmp("alice-large");
    let mut alice = DagRepo::init(alice_dir.join("work"), "alice").unwrap();
    // Restricted content is never compressed (ADR 0020), so the bundle really
    // carries all 3 MiB over the wire.
    let restricted = Visibility::Restricted(vec!["alice".into()]);
    let oid = alice.put(&vec![0xA5u8; 3 * 1024 * 1024], restricted.clone()).unwrap();
    let mut tree = BTreeMap::new();
    tree.insert(PathBuf::from("big.bin"), (oid.clone(), restricted));
    alice
        .record(Change { id: Oid([0; 32]), parents: vec![], message: "big".into(), tree })
        .unwrap();

    loot_net::push(&base, alice.bundle(&[]).unwrap().0, &alice_id)
        .expect("a >2 MiB push must be accepted, not 413'd");

    let relay_repo = DagRepo::load(&relay_dir, relay_dir.clone()).unwrap();
    assert!(
        relay_repo.missing_objects(&[oid.clone()]).is_empty(),
        "the relay must have stowed the large object"
    );
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
fn offer_then_fetch_negotiated_pull_round_trips() {
    // The production negotiated-pull path (#217): `/offer` then `/fetch` —
    // the endpoints `Workspace::pull_via`'s HTTP adapter drives. First
    // end-to-end coverage of these handlers (the older tests use `/negotiate`).
    let relay_dir = tmp("relay-offer");
    let addr = "127.0.0.1:47199";
    let base = format!("http://{addr}");
    let serve_dir = relay_dir.clone();
    std::thread::spawn(move || {
        let _ = loot_net::serve(serve_dir, addr, vec![]);
    });
    wait_for_relay(&base);

    let alice_id = alice_identity();
    let alice_dir = tmp("alice-offer");
    let mut alice = DagRepo::init(alice_dir.join("work"), "alice").unwrap();
    let oid = alice.put(b"negotiated
", Visibility::Internal).unwrap();
    let mut tree = BTreeMap::new();
    tree.insert(PathBuf::from("f.txt"), (oid.clone(), Visibility::Internal));
    let change_id = alice
        .record(Change { id: Oid([0; 32]), parents: vec![], message: "init".into(), tree })
        .unwrap();
    loot_net::push(&base, alice.bundle(&[]).unwrap().0, &alice_id).unwrap();

    // Round 1: offer against empty have — the relay offers the object closure.
    let bob_dir = tmp("bob-offer");
    let mut bob = DagRepo::init(bob_dir.join("work"), "bob").unwrap();
    let offered = loot_net::offer(&base, &bob.heads()).unwrap();
    assert!(offered.contains(&oid), "the relay offers the closure's addresses");

    // Round 2: fetch only what we lack; apply lands the change + bytes.
    let wants = bob.missing_objects(&offered);
    assert_eq!(wants, vec![oid.clone()]);
    let bytes = loot_net::fetch(&base, &bob.heads(), &wants).unwrap();
    bob.apply(&SyncBundle(bytes), 0).unwrap();
    assert!(bob.heads().contains(&change_id));
    assert_eq!(bob.get(&oid, "bob", 0).unwrap(), b"negotiated
");

    // Up to date: the offer subtracts what we now hold — nothing to want.
    let offered = loot_net::offer(&base, &bob.heads()).unwrap();
    assert!(bob.missing_objects(&offered).is_empty(), "re-negotiation finds nothing");
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
    let oid = alice.put(b"x\n", Visibility::Internal).unwrap();
    let mut tree = BTreeMap::new();
    tree.insert(PathBuf::from("f.txt"), (oid, Visibility::Internal));
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

/// A relay too old to read the format version this build wrote (the #361
/// outage: a `FORMAT_MAJOR` bump outran the deployed relay) rejects the push at
/// `stow` with the reader-centric "upgrade loot" message. End-to-end, the client
/// must translate that into the actionable truth — the *relay* is behind and
/// needs a redeploy — rather than passing the misleading "upgrade loot" through
/// (#431). Simulated by pushing a bundle marked one major ahead of the relay.
#[test]
fn push_of_future_major_bundle_hints_relay_redeploy() {
    let relay_dir = tmp("relay-format-skew");
    let addr = "127.0.0.1:47201";
    let base = format!("http://{addr}");

    let serve_dir = relay_dir.clone();
    std::thread::spawn(move || {
        let _ = loot_net::serve(serve_dir, addr, vec![]);
    });
    wait_for_relay(&base);

    // A bundle whose two-byte version marker claims a major the relay cannot
    // read. Auth passes (open relay, valid signature); stow's Frame::decode hits
    // read_version and returns UnsupportedFormat — exactly what a stale relay
    // does to a newer client's bundle.
    let id = Identity::generate();
    let future_major_bundle = vec![loot_core::format::FORMAT_MAJOR + 1, 0];
    let err = loot_net::push(&base, future_major_bundle, &id).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("unsupported format version"),
        "relay should reject the future major at stow, got: {msg}"
    );
    assert!(
        msg.contains("redeploy the relay") && msg.contains("setup:loot"),
        "client must surface the relay-redeploy hint, not just 'upgrade loot', got: {msg}"
    );
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

    // Bob's pubkey is the mailbox address; loot-net hexes it (relay learns no
    // names, ADR 0015). Callers pass raw key bytes, not a pre-hexed string.
    let now = 0u64;

    // Alice produces a sealed grant bundle (tag 3): grantee_pubkey + wrapped_key
    // + oid + reveal_at(0 = untimed) + payload.
    let sealed_bundle = alice_repo.grant_sealed(
        &oid, "bob", bob_ed_pubkey, alice_pubkey, 0, None, now,
        |content_key| {
            key_seal::seal_key(content_key, &bob_x25519)
                .map_err(|e| RepoError::Backend(e.to_string()))
        }
    ).unwrap();

    // Alice wraps the bundle in a push envelope (she signs it — ADR 0015).
    let envelope = alice_id.wrap_envelope(&sealed_bundle.0);

    // Alice delivers the envelope to bob's pubkey-addressed mailbox.
    loot_net::deliver_grant(&base, &bob_ed_pubkey, &envelope).unwrap();

    // Bob peeks: should show 1 pending grant.
    let count = loot_net::peek_grants(&base, &bob_ed_pubkey).unwrap();
    assert_eq!(count, 1, "peek should show 1 pending grant before drain");

    // Bob fetches his grants (envelopes). The relay held opaque ciphertext.
    let envelopes = loot_net::fetch_grants(&base, &bob_ed_pubkey).unwrap();
    assert_eq!(envelopes.len(), 1, "bob should have exactly one pending grant");

    // Mailbox is now drained.
    let after_drain = loot_net::fetch_grants(&base, &bob_ed_pubkey).unwrap();
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

/// Hard embargo end-to-end (ADR 0027, #14): a timed SealedGrant deposited at
/// the relay is invisible and unfetchable until the RELAY's clock passes its
/// `reveal_at` — the recipient's machine simply never holds the key bytes.
/// A due (past-reveal) timed grant delivers like any other.
#[test]
fn relay_withholds_timed_grant_until_reveal() {
    let relay_dir = tmp("relay-timed");
    let addr = "127.0.0.1:47198";
    let base = format!("http://{addr}");
    let serve_dir = relay_dir.clone();
    std::thread::spawn(move || {
        let _ = loot_net::serve(serve_dir, addr, vec![]);
    });
    wait_for_relay(&base);

    let alice_id = alice_identity();
    let alice_pubkey = alice_id.public_key_bytes();
    let alice_dir = tmp("alice-timed");
    let (mut alice_repo, oid) = build_restricted_repo(&alice_dir, "alice");

    let bob_id = Identity::generate();
    let bob_ed_pubkey = bob_id.public_key_bytes();
    let bob_x25519 = bob_id.x25519_pubkey_bytes();

    let wall_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // A grant embargoed until far in the future, and one already due.
    let far_future = wall_now + 3600;
    let withheld = alice_repo
        .grant_sealed(&oid, "bob", bob_ed_pubkey, alice_pubkey, far_future, None, 0, |k| {
            key_seal::seal_key(k, &bob_x25519).map_err(|e| RepoError::Backend(e.to_string()))
        })
        .unwrap();
    let due = alice_repo
        .grant_sealed(&oid, "bob", bob_ed_pubkey, alice_pubkey, wall_now.saturating_sub(60), None, 0, |k| {
            key_seal::seal_key(k, &bob_x25519).map_err(|e| RepoError::Backend(e.to_string()))
        })
        .unwrap();

    loot_net::deliver_grant(&base, &bob_ed_pubkey, &alice_id.wrap_envelope(&withheld.0)).unwrap();
    loot_net::deliver_grant(&base, &bob_ed_pubkey, &alice_id.wrap_envelope(&due.0)).unwrap();

    // The withheld grant is invisible: peek shows only the due one, and a
    // fetch delivers only the due one — the embargoed key bytes never leave
    // the relay, no matter what the CALLER's clock claims (there is no clock
    // parameter to lie with; the relay uses its own).
    assert_eq!(loot_net::peek_grants(&base, &bob_ed_pubkey).unwrap(), 1);
    let delivered = loot_net::fetch_grants(&base, &bob_ed_pubkey).unwrap();
    assert_eq!(delivered.len(), 1, "only the due grant is released");

    // The withheld one is still there for a post-reveal fetch (not dropped).
    assert_eq!(
        loot_net::peek_grants(&base, &bob_ed_pubkey).unwrap(),
        0,
        "the withheld grant stays invisible on subsequent peeks"
    );

    // The delivered (due) grant round-trips into readable content.
    let (grantor, bundle_bytes) = loot_identity::unwrap_envelope(&delivered[0], &[]).unwrap();
    assert_eq!(grantor, alice_pubkey);
    let mut bob_repo = DagRepo::init(tmp("bob-timed").join("work"), "bob").unwrap();
    bob_repo
        .apply_sealed_grant(&SyncBundle(bundle_bytes.to_vec()), grantor, wall_now, |w| {
            bob_id.unseal_key(w).map_err(|e| RepoError::Backend(e.to_string()))
        })
        .unwrap();
    assert_eq!(bob_repo.get(&oid, "bob", wall_now).unwrap(), b"secret bytes\n");
}

/// AC (#14): `reveal_at` rides inside the grantor-signed envelope — flipping
/// any byte of the frame (e.g. shortening the embargo) breaks the signature,
/// so a tampered copy cannot masquerade as a valid earlier-revealing grant.
#[test]
fn tampered_reveal_at_breaks_the_envelope_signature() {
    let alice_id = alice_identity();
    let alice_pubkey = alice_id.public_key_bytes();
    let alice_dir = tmp("alice-tamper");
    let (mut alice_repo, oid) = build_restricted_repo(&alice_dir, "alice");
    let bob_id = Identity::generate();
    let bob_x25519 = bob_id.x25519_pubkey_bytes();

    let timed = alice_repo
        .grant_sealed(&oid, "bob", bob_id.public_key_bytes(), alice_pubkey, 999_999, None, 0, |k| {
            key_seal::seal_key(k, &bob_x25519).map_err(|e| RepoError::Backend(e.to_string()))
        })
        .unwrap();
    let envelope = alice_id.wrap_envelope(&timed.0);

    // Intact: verifies, and the frame carries the declared reveal_at.
    let (_, bundle) = loot_identity::unwrap_envelope(&envelope, &[]).unwrap();
    match loot_core::bundle_codec::Frame::decode(bundle).unwrap() {
        loot_core::bundle_codec::Frame::SealedGrant { reveal_at, .. } => {
            assert_eq!(reveal_at, 999_999)
        }
        _ => panic!("expected SealedGrant"),
    }

    // Tamper with the reveal_at bytes inside the enveloped frame: the
    // signature check must fail — there is no way to alter the embargo
    // without becoming an invalid envelope.
    let mut tampered = envelope.clone();
    let n = tampered.len();
    // reveal_at sits in the frame header; flip a byte well past the envelope
    // header (1 + 32 + 64) and the frame's own marker/tag/pubkey/wrapped-key.
    let target = 1 + 32 + 64 + 2 + 1 + 32 + 80 + 32; // first reveal_at byte
    assert!(target < n);
    tampered[target] ^= 0xFF;
    assert!(
        loot_identity::unwrap_envelope(&tampered, &[]).is_err(),
        "a tampered reveal_at must break the grantor's envelope signature"
    );
}
