//! End-to-end CLI-shape checks that genuinely need a real process (#322).
//!
//! These spawn the built binary with a **controlled cwd** — an empty temp
//! directory, never the test runner's own. The unit tests that used to cover
//! this by calling `cmd_*` handlers directly opened a workspace from the
//! ambient cwd, which walks up into the developer's *real* `.loot` store when
//! the suite runs from the repo (the near-miss that filed the ticket: a lane
//! gc almost reaped a live lane). Handler-level logic stays in unit tests
//! against the pure gates; only the process-shaped contract lives here.

use std::path::PathBuf;
use std::process::Command;

/// A fresh, empty cwd for one spawned invocation.
fn empty_cwd(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "loot-cli-smoke-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Bare `loot lane` defaults to `list` and, outside any repo, must return the
/// not-a-repo refusal — never panic (the #278 empty-argv slice) and never go
/// looking for someone else's `.loot`.
#[test]
fn bare_lane_outside_a_repo_refuses_without_panicking() {
    let cwd = empty_cwd("bare-lane");
    let out = Command::new(env!("CARGO_BIN_EXE_loot"))
        .arg("lane")
        .current_dir(&cwd)
        .output()
        .expect("spawn loot");
    assert!(!out.status.success(), "no repo here — the verb must refuse");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("not a loot repo"),
        "the refusal names the cause: {err}"
    );
    let _ = std::fs::remove_dir_all(&cwd);
}

/// `loot embargo-status <path>` (#15), end-to-end through the real binary:
/// an embargoed path reports "embargoed until" before its reveal instant and
/// "revealed" after — driven by `LOOT_CLOCK`, the cross-process clock
/// override (`real_now`, workspace.rs) so the test never races real wall
/// time. Also covers the "not in the working tree" AC: after the path is
/// deleted and the deletion recorded, embargo-status still finds it via
/// history instead of erroring.
#[test]
fn embargo_status_reports_embargoed_then_revealed_then_survives_deletion() {
    let cwd = empty_cwd("embargo-status");
    let run = |args: &[&str], clock: u64| {
        Command::new(env!("CARGO_BIN_EXE_loot"))
            .args(args)
            .current_dir(&cwd)
            .env("LOOT_CLOCK", clock.to_string())
            .output()
            .expect("spawn loot")
    };

    let reveal_at: u64 = 2_000;
    assert!(run(&["init", "--identity", "connor"], 0).status.success());

    std::fs::write(cwd.join(".lootattributes"), format!("plans.md embargoed={reveal_at}\n")).unwrap();
    std::fs::write(cwd.join("plans.md"), b"cve fix\n").unwrap();
    let described = run(&["describe", "-m", "embargo plans"], 0);
    assert!(described.status.success(), "{}", String::from_utf8_lossy(&described.stderr));

    // Before reveal_at: withheld.
    let before = run(&["embargo-status", "plans.md"], reveal_at - 1);
    assert!(before.status.success(), "{}", String::from_utf8_lossy(&before.stderr));
    let before_out = String::from_utf8_lossy(&before.stdout);
    assert!(
        before_out.contains("embargoed until 2000"),
        "expected the unix timestamp in the output: {before_out}"
    );
    assert!(
        before_out.chars().any(|c| c.is_ascii_digit()) && before_out.contains('-') && before_out.contains(':'),
        "expected a human-readable date/time alongside the unix timestamp: {before_out}"
    );

    // At/after reveal_at: revealed.
    let after = run(&["embargo-status", "plans.md"], reveal_at);
    assert!(after.status.success(), "{}", String::from_utf8_lossy(&after.stderr));
    assert_eq!(String::from_utf8_lossy(&after.stdout), "plans.md: revealed\n");

    // Finalize so the next describe starts a fresh working change, then
    // delete the path off the live tree — history must still explain it.
    assert!(run(&["new"], reveal_at).status.success());
    std::fs::remove_file(cwd.join("plans.md")).unwrap();
    std::fs::remove_file(cwd.join(".lootattributes")).unwrap();
    let deleted = run(&["describe", "-m", "delete plans"], reveal_at);
    assert!(deleted.status.success(), "{}", String::from_utf8_lossy(&deleted.stderr));

    let after_delete = run(&["embargo-status", "plans.md"], reveal_at);
    assert!(after_delete.status.success(), "{}", String::from_utf8_lossy(&after_delete.stderr));
    assert_eq!(
        String::from_utf8_lossy(&after_delete.stdout),
        "plans.md: revealed\n",
        "gone from the working tree, but still explainable via history"
    );

    // A path that never existed at all is a loud error, not a silent state.
    let missing = run(&["embargo-status", "never.md"], reveal_at);
    assert!(!missing.status.success(), "an unknown path must refuse");
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("not found"),
        "{}",
        String::from_utf8_lossy(&missing.stderr)
    );

    let _ = std::fs::remove_dir_all(&cwd);
}
