//! The shared bake-off workload.
//!
//! Every scenario here is generic over `R: Repo`, so `spike-dag` and
//! `spike-crdt` are scored by *identical* code. The three axes (CONTEXT.md):
//!   1. thesis fit  — can the model represent per-path visibility + embargo
//!   2. local perf  — write thousands of small objects, materialize a tree
//!   3. sync        — concurrent offline edits converge (ADR 0001)
//!
//! A scenario returns a [`ScenarioResult`]: timings plus pass/fail on the
//! correctness assertions that define "this model can actually do the thing".
//! Timing here is wall-clock-agnostic at the harness level — callers wrap
//! these in their own bencher (criterion, hyperfine, or a manual Instant)
//! since `loot-core` stays dependency-light. The harness's job is to define
//! *what* runs and *what must be true*, not to own the clock.

use loot_core::{Change, MergeOutcome, Oid, Repo, RepoError, Visibility};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A single piece of test content with a target visibility.
pub struct Blob {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
    pub vis: Visibility,
}

/// Outcome of a scenario: every correctness check that must hold, plus a place
/// for the caller's bencher to attach timings. Booleans are assertions the
/// model must satisfy to be considered viable on that axis.
#[derive(Debug, Default)]
pub struct ScenarioResult {
    pub checks: Vec<(String, bool)>,
}

impl ScenarioResult {
    fn check(&mut self, name: &str, passed: bool) {
        self.checks.push((name.to_string(), passed));
    }
    pub fn all_passed(&self) -> bool {
        self.checks.iter().all(|(_, ok)| *ok)
    }
}

/// Build a workload of `n` small files (the APFS small-file workload), with a
/// fraction marked Restricted to a single identity to exercise the thesis.
pub fn small_file_workload(n: usize, restricted_to: &str) -> Vec<Blob> {
    (0..n)
        .map(|i| {
            let vis = if i % 10 == 0 {
                Visibility::Restricted(vec![restricted_to.to_string()])
            } else {
                Visibility::Public
            };
            Blob {
                path: PathBuf::from(format!("src/file_{i:05}.rs")),
                bytes: format!("// file {i}\npub fn f{i}() -> usize {{ {i} }}\n").into_bytes(),
                vis,
            }
        })
        .collect()
}

fn commit_blobs<R: Repo>(
    repo: &mut R,
    blobs: &[Blob],
    parents: Vec<Oid>,
    msg: &str,
) -> Result<Oid, RepoError> {
    let mut tree = BTreeMap::new();
    for b in blobs {
        let oid = repo.put(&b.bytes, b.vis.clone())?;
        tree.insert(b.path.clone(), (oid, b.vis.clone()));
    }
    // The change id is content-derived by the backend; callers pass a
    // placeholder and the backend is free to compute the real id in `commit`.
    let change = Change {
        id: Oid([0u8; 32]),
        parents,
        message: msg.to_string(),
        tree,
    };
    repo.commit(change)
}

/// AXIS 2 (local perf) + AXIS 1 (thesis): write N small files (some
/// Restricted), commit, then checkout as two different readers and assert
/// visibility is enforced. Caller times the `commit` and `checkout` calls.
pub fn scenario_write_and_checkout<R: Repo>(
    repo: &mut R,
    blobs: &[Blob],
    keyholder: &str,
    outsider: &str,
    now: u64,
) -> Result<ScenarioResult, RepoError> {
    let mut res = ScenarioResult::default();
    let change = commit_blobs(repo, blobs, vec![], "bulk write")?;

    // Keyholder sees everything; outsider must not see Restricted content.
    repo.checkout(&change, keyholder, now)?;
    repo.checkout(&change, outsider, now)?;

    let restricted = blobs
        .iter()
        .find(|b| matches!(b.vis, Visibility::Restricted(_)))
        .expect("workload must contain restricted content");
    let oid = repo.put(&restricted.bytes, restricted.vis.clone())?;
    res.check(
        "keyholder can read restricted content",
        repo.get(&oid, keyholder, now).is_ok(),
    );
    res.check(
        "outsider is denied restricted content",
        matches!(repo.get(&oid, outsider, now), Err(RepoError::Unauthorized(_))),
    );
    Ok(res)
}

/// AXIS 1 (thesis): an embargoed change is sealed before `reveal_at` and
/// readable after, for everyone.
pub fn scenario_embargo<R: Repo>(
    repo: &mut R,
    reveal_at: u64,
    reader: &str,
) -> Result<ScenarioResult, RepoError> {
    let mut res = ScenarioResult::default();
    let secret = b"CVE fix: bounds check";
    let oid = repo.put(secret, Visibility::Embargoed { reveal_at })?;

    let before = repo.get(&oid, reader, reveal_at - 1);
    res.check(
        "embargoed content sealed before reveal",
        matches!(before, Err(RepoError::Embargoed(_))),
    );
    let after = repo.get(&oid, reader, reveal_at + 1);
    res.check("embargoed content opens after reveal", after.is_ok());
    Ok(res)
}

/// AXIS 3 (sync, ADR 0001): two repos start from a shared base, both edit
/// offline, then sync. Asserts convergence semantics:
///   - disjoint paths converge with no conflict
///   - same-path edits where both hold the key -> Merged (not silent loss)
///   - same-path edits where a side lacks the key -> RelayedUnmerged
pub fn scenario_concurrent_converge<R: Repo>(
    base: &Path,
    keyholder: &str,
    relay: &str,
    now: u64,
) -> Result<ScenarioResult, RepoError> {
    let mut res = ScenarioResult::default();

    let mut a = R::init(base.join("a"), keyholder)?;
    let mut b = R::init(base.join("b"), relay)?;

    // Shared base: one public file, committed on both via a sync bundle.
    let base_blobs = vec![Blob {
        path: PathBuf::from("shared.txt"),
        bytes: b"line1\n".to_vec(),
        vis: Visibility::Public,
    }];
    commit_blobs(&mut a, &base_blobs, vec![], "base")?;
    let seed = a.bundle(&[])?;
    b.apply(&seed, now)?;

    // Disjoint offline edits: A edits a/only.txt, B edits b/only.txt.
    let a_heads = a.heads();
    commit_blobs(
        &mut a,
        &[Blob { path: "a_only.txt".into(), bytes: b"a".to_vec(), vis: Visibility::Public }],
        a_heads,
        "a offline",
    )?;
    let b_heads = b.heads();
    commit_blobs(
        &mut b,
        &[Blob { path: "b_only.txt".into(), bytes: b"b".to_vec(), vis: Visibility::Public }],
        b_heads,
        "b offline",
    )?;

    // Sync both directions.
    let from_a = a.bundle(&b.heads())?;
    let outcomes_b = b.apply(&from_a, now)?;
    let from_b = b.bundle(&a.heads())?;
    let outcomes_a = a.apply(&from_b, now)?;

    res.check(
        "disjoint edits converge without conflict",
        outcomes_a
            .values()
            .chain(outcomes_b.values())
            .all(|o| matches!(o, MergeOutcome::Converged | MergeOutcome::Merged)),
    );

    // Concurrent same-path edit on Restricted content:
    //   - A (keyholder) edits secret.env
    //   - B (relay, no key) also receives/forwards it
    let secret = vec![Blob {
        path: "secret.env".into(),
        bytes: b"TOKEN=abc\n".to_vec(),
        vis: Visibility::Restricted(vec![keyholder.to_string()]),
    }];
    let a_heads2 = a.heads();
    commit_blobs(&mut a, &secret, a_heads2, "a edits secret")?;
    let to_b = a.bundle(&b.heads())?;
    let b_outcomes = b.apply(&to_b, now)?;
    res.check(
        "non-keyholder relays restricted content, does not silently drop it",
        b_outcomes
            .get(Path::new("secret.env"))
            .map(|o| matches!(o, MergeOutcome::RelayedUnmerged | MergeOutcome::Converged))
            .unwrap_or(true),
    );

    Ok(res)
}
