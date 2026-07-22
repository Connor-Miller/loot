//! Characterization tests for #321 (ADR 0023 amendment): lock every affected
//! verb's human/porcelain/json output **before** the rendering-seam refactor
//! (`src/emit.rs`) touches `main.rs`'s dispatch. A post-refactor run of this
//! same, unmodified file is the byte-identical proof the ticket requires.
//!
//! Black-box on purpose: every call here spawns the compiled `loot` binary
//! (`CARGO_BIN_EXE_loot`) exactly as an operator or agent would. `cmd_*` and
//! `OutFmt` are private to `main.rs`, so there is no in-process seam to call
//! instead — which is itself the fragmentation #321 fixes.
//!
//! **Why so few literal strings.** Every change/version id in this engine is
//! minted from OS randomness (`mint_change_id`,
//! `loot-core/src/engine/change_graph.rs`) and every stored object's address
//! carries a random per-put nonce (ADR 0003) — so no id or content address
//! reproduces across two test runs, and a hardcoded expectation for one would
//! be flaky by construction, not stable. Where a verb's output embeds one,
//! this file *peeks* the same value through the read-only `Workspace`/
//! `loot_core::verdict`/`loot_cli::render` calls the verb itself is built
//! from (never through the private `cmd_*` wiring under test) and builds the
//! expected string from that peek. Verbs whose output carries no id — most
//! of them; CA3 scopes address columns to `Conflict` rows only — get a plain
//! literal.

use loot_cli::{render, workspace::Workspace};
use loot_core::verdict::{self, LaneRow};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

const FORMAT_MAJOR: u8 = loot_core::format::FORMAT_MAJOR;

/// A fixed unix timestamp so lane heartbeats read as `0s ago` no matter how
/// long the test takes — `LOOT_CLOCK` is the engine's documented clock
/// override (`workspace.rs::real_now`), read fresh by every subprocess.
const FIXED_CLOCK: &str = "1700000000";

/// Two ed25519 keypairs, hardcoded as OpenSSH PEM so identity-derived bytes
/// (an attester's pubkey) are reproducible — unlike a change id, a pubkey
/// carries no engine-minted randomness once the keypair itself is fixed.
/// Generated once via `Identity::generate()` + `.save()`; not a secret, only
/// a test fixture.
const CONNOR_PRIV_PEM: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDNnyWwYBsSN9RI+g3soMTDvmiBo4tEcCsP+4kkiJNcwwAAAJDVnCWx1Zwl
sQAAAAtzc2gtZWQyNTUxOQAAACDNnyWwYBsSN9RI+g3soMTDvmiBo4tEcCsP+4kkiJNcww
AAAEBQRNVzqzaV9kRPNvRMO88QnHUN/glgOr3+r7t9TSAQ7s2fJbBgGxI31Ej6DeygxMO+
aIGji0RwKw/7iSSIk1zDAAAAC2Nvbm5vckBsb290AQI=
-----END OPENSSH PRIVATE KEY-----
";
const CONNOR_PUB_LINE: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM2fJbBgGxI31Ej6DeygxMO+aIGji0RwKw/7iSSIk1zD connor@loot\n";

fn area(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("loot-t321-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

/// Run the compiled `loot` binary and return its stdout, decoded lossily.
fn run(dir: &Path, args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_loot"))
        .args(args)
        .env("LOOT_CLOCK", FIXED_CLOCK)
        .current_dir(dir)
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap()
}

/// As [`run`], plus the process exit code (`buoy`'s ambiguous/none outcomes
/// exit non-zero by design, ADR 0025).
fn run_with_code(dir: &Path, args: &[&str]) -> (String, i32) {
    let out = Command::new(env!("CARGO_BIN_EXE_loot"))
        .args(args)
        .env("LOOT_CLOCK", FIXED_CLOCK)
        .current_dir(dir)
        .output()
        .unwrap();
    (
        String::from_utf8(out.stdout).unwrap(),
        out.status.code().unwrap_or(-1),
    )
}

/// A keyed repo with a random (test-fresh) identity — the common case: no
/// output under test embeds an identity-derived byte.
fn keyed_repo(dir: &Path, identity: &str) -> Workspace {
    Workspace::init_at(dir, identity).unwrap();
    loot_identity::generate_and_save(&dir.join(".loot"), &format!("{identity}@loot")).unwrap();
    let mut ws = Workspace::open_at(dir).unwrap();
    ws.start_fresh_change().unwrap();
    ws
}

/// A keyed repo over the fixed test keypair — used only by `buoy`, whose
/// output embeds the attester's pubkey.
fn fixed_keyed_repo(dir: &Path) -> Workspace {
    Workspace::init_at(dir, "connor").unwrap();
    let dot = dir.join(".loot");
    std::fs::write(dot.join("id"), CONNOR_PRIV_PEM).unwrap();
    std::fs::write(dot.join("id.pub"), CONNOR_PUB_LINE).unwrap();
    let mut ws = Workspace::open_at(dir).unwrap();
    ws.start_fresh_change().unwrap();
    ws
}

// --- status (2 of the 11 dying `match fmt` blocks) --------------------------

#[test]
fn status_reports_no_working_change_for_a_keyless_repo() {
    let dir = area("status-keyless");
    // No `generate_and_save` — a keyless repo mints no eager change handle
    // (`start_fresh_change` no-ops), which is the `live_working_row -> None`
    // path `cmd_status`'s first branch renders.
    Workspace::init_at(&dir, "tester").unwrap();

    assert_eq!(
        run(&dir, &["status"]),
        "no working change (run `loot describe -m \"<subject>\"` to start one)\n"
    );
    assert_eq!(
        run(&dir, &["status", "--porcelain"]),
        verdict::status_porcelain(None, None, &[])
    );
    assert_eq!(
        run(&dir, &["status", "--json"]),
        format!("{}\n", verdict::status_json(None, None, &[]))
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn status_reports_the_live_delta_for_a_dirty_working_change() {
    let dir = area("status-dirty");
    let mut ws = keyed_repo(&dir, "connor");
    std::fs::write(dir.join("a.txt"), b"hello\n").unwrap();

    // Peek what the verb itself computes — `status` is read-only (ADR 0030),
    // so this never disturbs the state the subprocess calls below observe.
    let row = ws.live_working_row().unwrap().expect("a pending delta");
    let divergent = ws.divergent_change_ids();
    let deltas = ws.working_delta().unwrap();
    let mut expected_human = format!(
        "working change {}  {}  \"{}\"\n",
        render::change_col(row.change_id, &divergent),
        render::short(&row.version),
        row.message,
    );
    for d in &deltas {
        expected_human.push_str(&render::delta_line(d));
        expected_human.push('\n');
    }
    let expected_porcelain =
        verdict::status_porcelain(row.change_id, Some(&row.version), &row.entries);
    let expected_json = format!(
        "{}\n",
        verdict::status_json(row.change_id, Some(&row.version), &row.entries)
    );
    drop(ws);

    assert_eq!(run(&dir, &["status"]), expected_human);
    assert_eq!(run(&dir, &["status", "--porcelain"]), expected_porcelain);
    assert_eq!(run(&dir, &["status", "--json"]), expected_json);

    let _ = std::fs::remove_dir_all(&dir);
}

// --- apply (Reconciliation shape, no conflict -> no oid at all) -------------

#[test]
fn apply_reports_a_converged_bundle_in_every_format() {
    let base = area("apply");
    let alice_dir = base.join("alice");
    let mut alice = keyed_repo(&alice_dir, "alice");
    std::fs::write(alice_dir.join("doc.txt"), b"v1\n").unwrap();
    alice.snapshot("doc").unwrap();
    alice.finalize_working().unwrap();
    let bundle = alice.bundle_full().unwrap();
    let bundle_path = base.join("b.bundle");
    std::fs::write(&bundle_path, &bundle.0).unwrap();
    let bundle_path_str = bundle_path.to_string_lossy().to_string();

    let bob_human = base.join("bob-human");
    keyed_repo(&bob_human, "bob");
    assert_eq!(
        run(&bob_human, &["apply", &bundle_path_str]),
        format!(
            "applied {bundle_path_str} as bob:\n  doc.txt                  converged\nrun `loot surface` to materialize what you may see\n"
        )
    );

    let bob_porcelain = base.join("bob-porcelain");
    keyed_repo(&bob_porcelain, "bob");
    assert_eq!(
        run(&bob_porcelain, &["apply", &bundle_path_str, "--porcelain"]),
        "=\tdoc.txt\t-\t-\n"
    );

    let bob_json = base.join("bob-json");
    keyed_repo(&bob_json, "bob");
    assert_eq!(
        run(&bob_json, &["apply", &bundle_path_str, "--json"]),
        format!(
            "{{\"contract\":{FORMAT_MAJOR},\"verdicts\":[{{\"status\":\"=\",\"path\":\"doc.txt\",\"base\":null,\"incoming\":null}}]}}\n"
        )
    );

    let _ = std::fs::remove_dir_all(&base);
}

// --- ferry (Reconciliation shape; trivial up-to-date pass, no oid) ---------

#[test]
fn ferry_reports_the_trivial_bare_mirror_pass_in_every_format() {
    for tag in ["human", "porcelain", "json"] {
        let base = area(&format!("ferry-{tag}"));
        let dir = base.join("primary");
        let mut ws = keyed_repo(&dir, "connor");
        std::fs::write(dir.join("a.txt"), b"one\n").unwrap();
        ws.snapshot("first").unwrap();
        ws.finalize_working().unwrap();
        drop(ws);

        let gitdir = base.join("mirror.git").to_string_lossy().to_string();
        let (expected1, expected2, flag): (String, String, Option<&str>) = match tag {
            "human" => (
                format!(
                    "note: initialized bare mirror at {gitdir}\nferry: ingested 0 git commit(s), projected 1 loot change(s)\n"
                ),
                "ferry: up to date (nothing to ingest or project)\n".to_string(),
                None,
            ),
            "porcelain" => (String::new(), String::new(), Some("--porcelain")),
            "json" => (
                format!("{{\"contract\":{FORMAT_MAJOR},\"verdicts\":[]}}\n"),
                format!("{{\"contract\":{FORMAT_MAJOR},\"verdicts\":[]}}\n"),
                Some("--json"),
            ),
            _ => unreachable!(),
        };

        let mut args1 = vec!["ferry", "--git-dir", gitdir.as_str()];
        if let Some(f) = flag {
            args1.push(f);
        }
        assert_eq!(run(&dir, &args1), expected1, "first ferry pass ({tag})");

        let mut args2 = vec!["ferry", "--git-dir", gitdir.as_str()];
        if let Some(f) = flag {
            args2.push(f);
        }
        assert_eq!(
            run(&dir, &args2),
            expected2,
            "second (up to date) ferry pass ({tag})"
        );

        let _ = std::fs::remove_dir_all(&base);
    }
}

// --- lane merge + conflicts (Reconciliation shape; a real conflict) --------

#[test]
fn lane_merge_and_conflicts_report_a_real_conflict_in_every_format() {
    for tag in ["human", "porcelain", "json"] {
        let base = area(&format!("conflict-{tag}"));
        let dir = base.join("primary");
        let mut ws = keyed_repo(&dir, "connor");
        std::fs::write(dir.join("base.txt"), b"base\n").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();

        let lane_dir = ws
            .spawn_lane(Some("feature"), Some(&base.join("feature")))
            .unwrap()
            .dir;
        {
            let mut lws = Workspace::open_at(&lane_dir).unwrap();
            std::fs::write(lane_dir.join("a.txt"), b"feature side\n").unwrap();
            lws.snapshot("feat").unwrap();
            lws.finalize_working().unwrap();
        }
        let mut ws = Workspace::open_at(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"home side\n").unwrap();
        ws.snapshot("home").unwrap();
        ws.finalize_working().unwrap();

        // Peek both sides' already-stored content addresses — set before the
        // merge runs, so this never touches the conflict machinery itself.
        let ours = ws.current_tree_oid(Path::new("a.txt")).unwrap();
        let lws = Workspace::open_at(&lane_dir).unwrap();
        let theirs = lws.current_tree_oid(Path::new("a.txt")).unwrap();
        drop(lws);
        drop(ws);

        let merge_verdicts = vec![
            loot_core::PathVerdict::new(
                "a.txt",
                loot_core::MergeOutcome::Conflict {
                    ours: ours.clone(),
                    theirs: theirs.clone(),
                },
            ),
            loot_core::PathVerdict::new("base.txt", loot_core::MergeOutcome::Converged),
        ];
        let conflict_verdicts = vec![loot_core::PathVerdict::new(
            "a.txt",
            loot_core::MergeOutcome::Conflict {
                ours: ours.clone(),
                theirs: theirs.clone(),
            },
        )];

        match tag {
            "human" => {
                let outcomes = BTreeMap::from([
                    (
                        PathBuf::from("a.txt"),
                        loot_core::MergeOutcome::Conflict {
                            ours: ours.clone(),
                            theirs: theirs.clone(),
                        },
                    ),
                    (
                        PathBuf::from("base.txt"),
                        loot_core::MergeOutcome::Converged,
                    ),
                ]);
                let expected_merge = format!(
                    "merged lane 'feature' into 'main':\n{}resolve 1 conflict(s) with `loot resolve <path> <file>` — each advances the primary's tip\n",
                    render::outcome_rows(&outcomes)
                );
                let expected_conflicts = format!(
                    "conflict at a.txt\n  ours:   {}\n  theirs: {}\n",
                    render::short(&ours),
                    render::short(&theirs)
                );
                assert_eq!(run(&dir, &["lane", "merge", "feature"]), expected_merge);
                assert_eq!(run(&dir, &["conflicts"]), expected_conflicts);
            }
            "porcelain" => {
                assert_eq!(
                    run(&dir, &["lane", "merge", "feature", "--porcelain"]),
                    verdict::porcelain(&merge_verdicts)
                );
                assert_eq!(
                    run(&dir, &["conflicts", "--porcelain"]),
                    verdict::porcelain(&conflict_verdicts)
                );
            }
            "json" => {
                assert_eq!(
                    run(&dir, &["lane", "merge", "feature", "--json"]),
                    format!("{}\n", verdict::json(&merge_verdicts))
                );
                assert_eq!(
                    run(&dir, &["conflicts", "--json"]),
                    format!("{}\n", verdict::json(&conflict_verdicts))
                );
            }
            _ => unreachable!(),
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}

// --- lane new + lanes (Lanes shape) -----------------------------------------

#[test]
fn lane_new_and_list_report_the_freshly_spawned_lane_in_every_format() {
    for tag in ["human", "porcelain", "json"] {
        let base = area(&format!("lane-{tag}"));
        let dir = base.join("primary");
        let mut ws = keyed_repo(&dir, "connor");
        std::fs::write(dir.join("a.txt"), b"one\n").unwrap();
        ws.snapshot("first").unwrap();
        ws.finalize_working().unwrap();
        let tip = ws.heads()[0].clone();
        let change_id = ws.repo().change_change_id(&tip);
        drop(ws);

        // `spawn_lane_as` canonicalizes the target dir (Windows extended-path
        // prefix included) and, with no `--ticket` handle, keys the lane's id
        // off the dir's own basename (`free_lane_id`, workspace.rs) — so both
        // must be derived the same way here, not guessed.
        let lane_path = base.join("lane-dir");
        std::fs::create_dir_all(&lane_path).unwrap();
        let lane_path = std::fs::canonicalize(&lane_path).unwrap();
        let lane_path_str = lane_path.to_string_lossy().to_string();

        let row = LaneRow {
            id: "lane-dir".to_string(),
            name: Some(tag.to_string()),
            path: lane_path.clone(),
            tip: Some(tip.clone()),
            change: change_id.map(|c| loot_core::hex::encode(&c)),
            pr: None,
            dirty: Some(false),
            heartbeat_age: 0,
            landed: false,
            stale: false,
        };
        let expected_new_human = format!(
            "lane 'lane-dir' at {} — sealed over this repo's store, born at the finalized tip\n  named '{tag}' — persists until `loot lane rm {tag}`\n",
            lane_path.display(),
        );
        let expected_list_human = format!(
            "{:<16} {:<16} {}  tip {}  (heartbeat 0s ago)\n",
            "lane-dir",
            tag,
            lane_path.display(),
            render::short(&tip),
        );

        match tag {
            "human" => {
                assert_eq!(
                    run(
                        &dir,
                        &["lane", "new", "--name", tag, "--at", &lane_path_str]
                    ),
                    expected_new_human
                );
                assert_eq!(run(&dir, &["lanes"]), expected_list_human);
            }
            "porcelain" => {
                assert_eq!(
                    run(
                        &dir,
                        &[
                            "lane",
                            "new",
                            "--name",
                            tag,
                            "--at",
                            &lane_path_str,
                            "--porcelain"
                        ]
                    ),
                    verdict::lanes_porcelain(&[row.clone()])
                );
                assert_eq!(
                    run(&dir, &["lanes", "--porcelain"]),
                    verdict::lanes_porcelain(&[row.clone()])
                );
            }
            "json" => {
                assert_eq!(
                    run(
                        &dir,
                        &[
                            "lane",
                            "new",
                            "--name",
                            tag,
                            "--at",
                            &lane_path_str,
                            "--json"
                        ]
                    ),
                    format!("{}\n", verdict::lanes_json(&[row.clone()]))
                );
                assert_eq!(
                    run(&dir, &["lanes", "--json"]),
                    format!("{}\n", verdict::lanes_json(&[row.clone()]))
                );
            }
            _ => unreachable!(),
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}

// --- buoy (its own frozen shape, ADR 0025) ----------------------------------

#[test]
fn buoy_reports_a_resolved_role_and_the_none_outcome_in_every_format() {
    let dir = area("buoy");
    let mut ws = fixed_keyed_repo(&dir);
    std::fs::write(dir.join("a.txt"), b"one\n").unwrap();
    ws.snapshot("first").unwrap();
    ws.finalize_working().unwrap();
    let change = ws.heads()[0].clone();
    drop(ws);

    let change_hex = loot_core::hex::encode(&change.0);
    run(&dir, &["attest", &change_hex, "reviewed"]);

    let attester = loot_identity::Identity::load(&dir.join(".loot").join("id"))
        .unwrap()
        .public_key_bytes();
    let name_of = |pk: &[u8; 32]| format!("{}…", loot_core::hex::short(pk, 4));
    let result = loot_core::buoy::BuoyResult::Resolved {
        change: change.clone(),
        attesters: vec![attester],
    };
    let expected_human = render::render_buoy_human(&result, "reviewed", &name_of);
    let bv = verdict::BuoyVerdict::Resolved {
        role: "reviewed".to_string(),
        change: change.clone(),
        attesters: vec![attester],
    };

    // `buoy` is read-only, so the same fixture serves all three formats.
    assert_eq!(run(&dir, &["buoy", "reviewed"]), expected_human);
    assert_eq!(
        run(&dir, &["buoy", "reviewed", "--porcelain"]),
        bv.porcelain()
    );
    assert_eq!(
        run(&dir, &["buoy", "reviewed", "--json"]),
        format!("{}\n", bv.json())
    );

    // `None` (no attestation for the role): the exit code carries the
    // outcome, and porcelain emits no rows at all (ADR 0025).
    let (human_none, code_none) = run_with_code(&dir, &["buoy", "no-such-role"]);
    assert_eq!(human_none, "no buoy for role 'no-such-role'\n");
    assert_eq!(code_none, 2);
    let (porcelain_none, _) = run_with_code(&dir, &["buoy", "no-such-role", "--porcelain"]);
    assert_eq!(porcelain_none, "");
    let (json_none, _) = run_with_code(&dir, &["buoy", "no-such-role", "--json"]);
    assert_eq!(
        json_none,
        format!("{{\"contract\":{FORMAT_MAJOR},\"role\":\"no-such-role\",\"status\":\"none\"}}\n")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// --- pull (Reconciliation shape + a human-only auto-surface tail) ---------

#[test]
fn pull_reports_a_converged_change_in_every_format() {
    let base = area("pull");
    let relay_dir = base.join("relay");
    let addr = "127.0.0.1:47511";
    let relay_url = format!("http://{addr}");
    std::thread::spawn({
        let relay_dir = relay_dir.clone();
        move || {
            let _ = loot_net::serve(relay_dir, addr, vec![]);
        }
    });
    for _ in 0..100 {
        if loot_net::pull(&relay_url, &[]).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let alice_dir = base.join("alice");
    let mut alice = keyed_repo(&alice_dir, "alice");
    std::fs::write(alice_dir.join("doc.txt"), b"v1\n").unwrap();
    alice.snapshot("doc").unwrap();
    alice.finalize_working().unwrap();
    run(&alice_dir, &["push", &relay_url]);

    let bob_human = base.join("bob-human");
    keyed_repo(&bob_human, "bob");
    let out_human = run(&bob_human, &["pull", &relay_url]);
    let bob_ws = Workspace::open_at(&bob_human).unwrap();
    let head = bob_ws.heads()[0].clone();
    drop(bob_ws);
    assert_eq!(
        out_human,
        format!(
            "pulled from {relay_url} as bob:\n  doc.txt                  converged\nconverged onto one line:\n  doc.txt                          public\nsurfaced {} as bob\n",
            render::short(&head)
        )
    );

    let bob_porcelain = base.join("bob-porcelain");
    keyed_repo(&bob_porcelain, "bob");
    assert_eq!(
        run(&bob_porcelain, &["pull", &relay_url, "--porcelain"]),
        "=\tdoc.txt\t-\t-\n"
    );

    let bob_json = base.join("bob-json");
    keyed_repo(&bob_json, "bob");
    assert_eq!(
        run(&bob_json, &["pull", &relay_url, "--json"]),
        format!(
            "{{\"contract\":{FORMAT_MAJOR},\"verdicts\":[{{\"status\":\"=\",\"path\":\"doc.txt\",\"base\":null,\"incoming\":null}}]}}\n"
        )
    );

    let _ = std::fs::remove_dir_all(&base);
}

// --- machine error channel (#430) -------------------------------------------

/// Run the binary and return `(stderr, exit_code)`. The error channel writes to
/// stderr, so these tests read it directly rather than stdout.
fn run_stderr_with_code(dir: &Path, args: &[&str]) -> (String, i32) {
    let out = Command::new(env!("CARGO_BIN_EXE_loot"))
        .args(args)
        .env("LOOT_CLOCK", FIXED_CLOCK)
        .current_dir(dir)
        .output()
        .unwrap();
    (String::from_utf8(out.stderr).unwrap(), out.status.code().unwrap_or(-1))
}

/// The whole contract, both directions: a `Workspace::open` failure in a
/// non-repo directory carries the CLI-level `no_repo` slug. Under `--json` the
/// taxonomy travels as a `{"contract":N,"error":{"code","message"}}` object on
/// stderr with a non-zero exit; **without** `--json` the output is byte-for-byte
/// the pre-#430 `loot: <message>` line (no human/script breakage).
#[test]
fn json_failure_emits_coded_error_object_non_json_is_unchanged() {
    let dir = area("err-no-repo");
    std::fs::create_dir_all(&dir).unwrap();

    // The message is `Workspace::open`'s own prose, with `.` as the display path
    // (`open` discovers from the current directory).
    let message = "not a loot repo at . (no .loot/). Run `loot init` first.";

    // Non-`--json`: byte-for-byte the old `loot: <message>` line, exit non-zero.
    let (stderr, code) = run_stderr_with_code(&dir, &["status"]);
    assert_eq!(stderr, format!("loot: {message}\n"));
    assert_ne!(code, 0, "a failure exits non-zero");

    // `--json`: the coded object, contract-versioned, exit non-zero.
    let (stderr, code) = run_stderr_with_code(&dir, &["status", "--json"]);
    assert_eq!(
        stderr,
        format!(
            "{{\"contract\":{FORMAT_MAJOR},\"error\":{{\"code\":\"no_repo\",\"message\":\"{message}\"}}}}\n"
        )
    );
    assert_ne!(code, 0, "a failure exits non-zero");

    let _ = std::fs::remove_dir_all(&dir);
}

/// The flag gate carries its own CLI-level slug (`unknown_flag`), and the
/// `--json` selector is honored even when the failing flag list *contains* the
/// bad flag: the coded object still reaches stderr.
#[test]
fn unknown_flag_carries_its_slug_under_json() {
    let dir = area("err-unknown-flag");
    keyed_repo(&dir, "connor");

    let (stderr, code) = run_stderr_with_code(&dir, &["status", "--json", "--bogus"]);
    assert!(
        stderr.starts_with(&format!("{{\"contract\":{FORMAT_MAJOR},\"error\":{{\"code\":\"unknown_flag\",")),
        "coded unknown_flag object on stderr: {stderr}"
    );
    assert!(stderr.contains("--bogus"), "the message still names the offending flag: {stderr}");
    assert_ne!(code, 0);

    // Without `--json`, the same failure prints the unchanged `loot: <prose>`.
    let (stderr, _) = run_stderr_with_code(&dir, &["status", "--bogus"]);
    assert!(stderr.starts_with("loot: unknown flag '--bogus'"), "unchanged prose: {stderr}");
    assert!(!stderr.contains("\"code\""), "no JSON leaks into the human path: {stderr}");

    let _ = std::fs::remove_dir_all(&dir);
}
