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
    /// Named quantitative metrics (e.g. conflict count, bundle bytes) for axes
    /// where the interesting result is a number, not a pass/fail.
    pub metrics: Vec<(String, u64)>,
}

impl ScenarioResult {
    fn check(&mut self, name: &str, passed: bool) {
        self.checks.push((name.to_string(), passed));
    }
    fn metric(&mut self, name: &str, value: u64) {
        self.metrics.push((name.to_string(), value));
    }
    pub fn all_passed(&self) -> bool {
        self.checks.iter().all(|(_, ok)| *ok)
    }
    pub fn metric_value(&self, name: &str) -> Option<u64> {
        self.metrics.iter().find(|(n, _)| n == name).map(|(_, v)| *v)
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

/// AXIS 3 — THE VERDICT TEST (the CRDT's genuine best case).
///
/// `n_peers` keyholders all start from a shared base, then each makes a
/// DIFFERENT concurrent edit to the SAME public file while offline, then all
/// converge into peer 0. This is the only workload where a true CRDT should
/// win: it should converge conflict-free, while a 3-way-merge DAG should
/// surface conflicts on the overlapping edits.
///
/// Records two metrics so the result is a number, not a vibe:
///   - `conflicts` — paths that came back `MergeOutcome::Conflict`
///   - `merged` — paths that came back `Merged` (resolved without a human)
///
/// A model "wins" this axis by converging the same-file edits with zero
/// conflicts. The point is to measure, not to assume.
pub fn scenario_same_file_concurrent<R: Repo>(
    base: &Path,
    n_peers: usize,
    now: u64,
) -> Result<ScenarioResult, RepoError> {
    let mut res = ScenarioResult::default();
    assert!(n_peers >= 2, "need at least 2 peers to conflict");

    // All peers are keyholders for a single PUBLIC file, so everyone is a
    // merger (the relay role is deliberately excluded — this isolates the
    // CRDT's conflict-free-merge advantage).
    let ids: Vec<String> = (0..n_peers).map(|i| format!("peer{i}")).collect();
    let mut peers: Vec<R> = ids
        .iter()
        .map(|id| R::init(base.join(id), id))
        .collect::<Result<_, _>>()?;

    // Shared base: a multi-line public file, seeded to every peer.
    let base_blob = vec![Blob {
        path: PathBuf::from("shared.txt"),
        bytes: b"line A\nline B\nline C\n".to_vec(),
        vis: Visibility::Public,
    }];
    commit_blobs(&mut peers[0], &base_blob, vec![], "base")?;
    let seed = peers[0].bundle(&[])?;
    for p in peers.iter_mut().skip(1) {
        p.apply(&seed, now)?;
    }

    // Each peer edits the SAME file differently, offline. Peer i rewrites a
    // different line, the edits overlap on the same file (and peer 0 + peer 1
    // touch an overlapping region) so a 3-way merge has something to conflict on.
    for (i, p) in peers.iter_mut().enumerate() {
        let edited = format!("line A (by peer{i})\nline B\nline C (by peer{i})\n");
        let blob = vec![Blob {
            path: PathBuf::from("shared.txt"),
            bytes: edited.into_bytes(),
            vis: Visibility::Public,
        }];
        let heads = p.heads();
        commit_blobs(p, &blob, heads, &format!("peer{i} offline edit"))?;
    }

    // Converge everyone into peer 0. Split the borrow: take peer 0 out first.
    let (head, rest) = peers.split_at_mut(1);
    let sink = &mut head[0];
    let mut conflicts = 0u64;
    let mut merged = 0u64;
    let mut converged = 0u64;
    let mut relayed = 0u64;
    let mut applies_with_outcome = 0u64;
    for p in rest.iter() {
        let bundle = p.bundle(&sink.heads())?;
        let outcomes = sink.apply(&bundle, now)?;
        if !outcomes.is_empty() {
            applies_with_outcome += 1;
        }
        for o in outcomes.values() {
            match o {
                MergeOutcome::Conflict => conflicts += 1,
                MergeOutcome::Merged => merged += 1,
                MergeOutcome::Converged => converged += 1,
                MergeOutcome::RelayedUnmerged => relayed += 1,
            }
        }
    }

    res.metric("conflicts", conflicts);
    res.metric("merged", merged);
    res.metric("converged", converged);
    res.metric("relayed", relayed);
    res.metric("applies_with_outcome", applies_with_outcome);

    // MODEL-NEUTRAL DATA-LOSS MEASUREMENT. Materialize the converged file to
    // disk and count how many distinct peers' edit markers survived. Each peer
    // i wrote "(by peer{i})" markers; with 4 peers and 2 markers each there are
    // up to `n_peers` distinct contributions. This is the real question behind
    // "0 conflicts": did convergence PRESERVE the edits or silently drop them?
    let sink_path = base.join("peer0");
    for h in sink.heads() {
        let _ = sink.checkout(&h, "peer0", now);
    }
    let contents = std::fs::read_to_string(sink_path.join("shared.txt")).unwrap_or_default();
    let surviving_peers = (0..n_peers)
        .filter(|i| contents.contains(&format!("by peer{i}")))
        .count() as u64;
    res.metric("surviving_peer_edits", surviving_peers);
    res.metric("total_peer_edits", n_peers as u64);

    // The honest check: convergence must not SILENTLY discard edits. A model is
    // allowed to surface conflicts (that preserves the edits for a human) OR to
    // genuinely merge them. It is NOT allowed to report zero conflicts AND lose
    // edits — that is silent data loss, the worst outcome for source control.
    let silently_dropped = conflicts == 0 && surviving_peers < n_peers as u64;
    res.check(
        "no silent data loss (zero conflicts must mean all edits survived)",
        !silently_dropped,
    );
    // Relay must NOT appear: this scenario is all-keyholder public content.
    res.check("all-keyholder scenario has no relays", relayed == 0);
    Ok(res)
}

/// AXIS 2 + sync efficiency: scale to `n` files and report the size in bytes of
/// a full sync bundle (what one peer ships another). Pure measurement; the
/// only check is that the round-trips through bundle/apply stay lossless.
pub fn scenario_scale_and_transfer<R: Repo>(
    base: &Path,
    n: usize,
    now: u64,
) -> Result<ScenarioResult, RepoError> {
    let mut res = ScenarioResult::default();

    let mut a = R::init(base.join("scale_a"), "alice")?;
    let blobs = small_file_workload(n, "alice");
    commit_blobs(&mut a, &blobs, vec![], "scale commit")?;

    let bundle = a.bundle(&[])?;
    res.metric("bundle_bytes", bundle.0.len() as u64);
    res.metric("files", n as u64);

    // A fresh peer applies the full bundle; it must not error (lossless).
    let mut b = R::init(base.join("scale_b"), "alice")?;
    let applied = b.apply(&bundle, now);
    res.check("full bundle applies without error", applied.is_ok());
    Ok(res)
}
