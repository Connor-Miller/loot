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
