//! The `review` / `land` / `status` flows — the ps1's body, now composing the
//! typed pieces: [`loot_cli::ledger`] owns the pr-map ledger, [`crate::forge`]
//! is the only door to GitHub, [`crate::policy`] holds the decisions, and loot
//! state is read/mutated **in-process** through `loot_cli`'s [`Workspace`] and
//! [`ferry`]. Two seams that face GitHub — [`land_gate`] (the pre-finalize
//! decision) and [`execute_landing`] (the post-finalize signal dance) — are
//! split out as forge-only functions so they can be tested against the
//! [`crate::forge::FakeForge`] without a real Workspace or network.

use crate::forge::{Forge, PrState};
use crate::harbor::HarborLock;
use loot_cli::ledger::{PrLane, PrMap};
use crate::policy::{
    approval, dock_targeting, interpret_landing, mirror_drift_warning, parse_review_line, pre_land,
    review_currency, Ancestry, Approval, Currency, DockTarget, LandingStatus, PreLand,
    ReviewOutcome,
};
use loot_cli::ferry::{self, WipState};
use loot_cli::workspace::Workspace;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long a land waits for a concurrent land to release the harbor lock
/// before giving up (ADR 0036). A land's git-main section is a few seconds, so
/// a generous wait lets a queue of agents drain rather than erroring on the
/// first contention.
const HARBOR_WAIT: Duration = Duration::from_secs(120);
/// A harbor lock older than this is presumed a crashed land and broken so the
/// harbor can never wedge permanently.
const HARBOR_STALE: Duration = Duration::from_secs(600);

/// The local-only ledger/mirror paths under `.loot/git-mirror/`.
struct Paths {
    root: PathBuf,
    mirror: PathBuf,
    pr_map: PathBuf,
    wip: PathBuf,
}

fn paths(ws: &Workspace) -> Paths {
    let mirror_dir = ws.store().git_mirror_dir();
    let root = ws.dot().parent().unwrap_or_else(|| Path::new(".")).to_path_buf();
    Paths {
        pr_map: ws.store().git_pr_map(),
        wip: ws.store().git_wip(),
        mirror: mirror_dir.join("mirror.git"),
        root,
    }
}

fn read_pr_map(path: &Path) -> PrMap {
    PrMap::parse(&std::fs::read_to_string(path).unwrap_or_default())
}

fn write_pr_map(path: &Path, map: &PrMap) -> Result<(), String> {
    std::fs::write(path, map.encode()).map_err(|e| format!("write pr-map: {e}"))
}

fn hex8(s: Option<&str>) -> String {
    match s {
        Some(v) if v.len() >= 8 => v[..8].to_string(),
        Some(v) => v.to_string(),
        None => "-".to_string(),
    }
}

/// The dock git-main tracks, from the mirror config (`dock = <name>`, default
/// `main`). The land gate refuses a lane on any other dock (see [`LandFacts`]).
fn tracked_dock(config_path: &Path) -> String {
    let text = std::fs::read_to_string(config_path).unwrap_or_default();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == "dock" {
                return v.trim().to_string();
            }
        }
    }
    "main".to_string()
}

// ---------------------------------------------------------------------------
// review
// ---------------------------------------------------------------------------

/// Project the ambient dock's WIP for review: `ferry --with-wip` → single-ref
/// push → open or refresh the PR, recording it in the pr-map ledger.
pub fn review(
    ws: &mut Workspace,
    forge: &dyn Forge,
    title: Option<&str>,
    dry_run: bool,
) -> Result<(), String> {
    let p = paths(ws);
    // Surface mirror drift before projecting anything: a review opened while the
    // mirror has diverged from origin/main is exactly how PR #241 projected a
    // revert of landed work (#243).
    warn_if_drifted(ws);

    let report = ferry::run(ws, None, None, /* with_wip */ true)?;
    for note in &report.notes {
        println!("  {note}");
    }
    let line = report
        .review
        .as_deref()
        .ok_or("ferry emitted no review line")?;
    let projected = match parse_review_line(line)? {
        ReviewOutcome::Nothing => {
            println!("nothing to review.");
            return Ok(());
        }
        ReviewOutcome::Projected(r) => r,
    };

    println!(">>> push (single-ref, inline URL) {}", projected.branch);
    if !dry_run {
        forge.push_ref(
            &format!("refs/heads/{b}:refs/heads/{b}", b = projected.branch),
            /* force */ true,
        )?;
    }

    let mut map = read_pr_map(&p.pr_map);
    if let Some(lane) = map.lane_for(&projected.change, &projected.dock) {
        println!("review round updated on PR #{} (op={})", lane.pr, projected.op);
        return Ok(());
    }
    if dry_run {
        println!("(dry run) would open a PR for {}", projected.branch);
        return Ok(());
    }

    let title = resolve_title(ws, title, &projected.dock);
    // ASCII, matching the ps1's audit strings so a shadow-run compares byte for
    // byte (PowerShell 5.1 was ASCII-constrained; loot-first keeps the parity).
    let body = format!(
        "Review view of unfinalized loot WIP (change `{}`, dock `{}`) - see \
         docs/agents/workflow.md. Lands via loot on approval; GitHub will mark it \
         Merged by reachability.",
        projected.change, projected.dock
    );
    println!(">>> gh pr create --head {}", projected.branch);
    let pr = forge.create_pr(&projected.branch, "main", &title, &body)?;
    map.push(PrLane { change: projected.change.clone(), dock: projected.dock.clone(), pr });
    write_pr_map(&p.pr_map, &map)?;
    println!("opened PR #{pr} for {}", projected.branch);
    Ok(())
}

/// The PR title: explicit `--title`, else the working change's message (unless
/// it is the un-described placeholder), else a dock-derived fallback.
fn resolve_title(ws: &mut Workspace, title: Option<&str>, dock: &str) -> String {
    if let Some(t) = title.map(str::trim).filter(|t| !t.is_empty()) {
        return t.to_string();
    }
    if let Ok(Some(row)) = ws.live_working_row() {
        let m = row.message.trim();
        if !m.is_empty() && m != "(working change)" {
            return m.to_string();
        }
    }
    format!("loot-first: {dock}")
}

// ---------------------------------------------------------------------------
// land — the pre-finalize gate (forge-only, tested against the fake)
// ---------------------------------------------------------------------------

/// Facts the land gate decides on, read once by [`land`] before touching the
/// forge for the PR snapshot.
pub struct LandFacts<'a> {
    pub pr: u64,
    pub lane_dock: &'a str,
    /// The dock currently ambient in the workspace (main normalized to `main`).
    pub ambient_dock: &'a str,
    /// The dock git-main tracks (mirror config `dock`, default `main`). A lane on
    /// any other dock cannot be projected to main by a bare `ferry` — it must be
    /// merged into the tracked dock first (the gap that made the first #218 land
    /// a silent no-op that still reported success).
    pub tracked_dock: &'a str,
    /// The version the review lane last projected (from the `wip` ledger).
    pub reviewed_version: Option<&'a str>,
    /// The live working-change version now (`None` when the change is empty).
    pub current_version: Option<&'a str>,
}

/// The outcome of the pre-finalize gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    /// All guards passed; `self_fast_path` drives only the log line.
    Proceed { self_fast_path: bool },
    /// A guard refused, with an operator-facing reason.
    Refuse(String),
}

/// Run every pre-finalize guard against the forge and the read facts: PR is
/// OPEN, approval (#152), dock-targeting (#153), review-currency (ADR 0033).
pub fn land_gate(forge: &dyn Forge, f: &LandFacts) -> Result<Gate, String> {
    let view = forge.pr_view(f.pr)?;
    if view.state != PrState::Open {
        return Ok(Gate::Refuse(format!("PR #{} is {:?}, not OPEN", f.pr, view.state)));
    }
    let viewer = forge.viewer_login()?;
    let appr = approval(view.review_decision, &view.author_login, &viewer);
    if appr == Approval::Refused {
        return Ok(Gate::Refuse(format!(
            "PR #{} not approved (reviewDecision {:?}, author {})",
            f.pr, view.review_decision, view.author_login
        )));
    }
    if dock_targeting(f.ambient_dock, f.lane_dock) == DockTarget::Mismatch {
        return Ok(Gate::Refuse(format!(
            "ambient dock is '{}', not '{}' — run 'loot dock {}' first \
             (land refuses to finalize another lane)",
            f.ambient_dock, f.lane_dock, f.lane_dock
        )));
    }
    // The lane must be on the dock git-main tracks; a side-lane change cannot be
    // projected to main by a bare `ferry`, so landing it would finalize + reap
    // the lane while git-main never moves (the false-success gap the first #218
    // land hit). Refuse and point at the merge-first path.
    if f.lane_dock != f.tracked_dock {
        return Ok(Gate::Refuse(format!(
            "PR #{}'s review lane is on dock '{}', but git-main tracks '{}' — a \
             side-lane change can't project to main directly. Merge it in first: \
             `loot dock {}` then `loot dock merge {}`, and land from '{}'.",
            f.pr, f.lane_dock, f.tracked_dock, f.tracked_dock, f.lane_dock, f.tracked_dock
        )));
    }
    if review_currency(f.reviewed_version, f.current_version) == Currency::Stale {
        return Ok(Gate::Refuse(format!(
            "working change amended since the last review round \
             (version {} != reviewed {}) — run 'loot-first review' and \
             re-approve before landing",
            hex8(f.current_version),
            hex8(f.reviewed_version)
        )));
    }
    Ok(Gate::Proceed { self_fast_path: appr == Approval::SelfAuthoredFastPath })
}

// ---------------------------------------------------------------------------
// land — the landing executor (forge-only, tested against the fake)
// ---------------------------------------------------------------------------

/// After finalize + ferry, publish the land and interpret GitHub's async
/// reaction (#150/#166). `poll_attempts`/`sleep` drive the terminal-state poll;
/// production passes 10 attempts and a 2s sleep, tests pass a no-op sleep.
pub fn execute_landing(
    forge: &dyn Forge,
    pr: u64,
    change_hex: &str,
    dock: &str,
    main_sha: &str,
    poll_attempts: usize,
    sleep: &mut dyn FnMut(),
) -> Result<LandingStatus, String> {
    let branch = format!("review/{dock}");
    // ASCII pointer strings, matching the ps1's audit trail (shadow-run parity).
    let pointer = format!("Landed via loot as change `{change_hex}` -> main `{main_sha}`.");

    // Fast-forward main. A non-fast-forward means GitHub main diverged (#151):
    // close with a reconcile pointer and stop — do not collapse a stale head.
    if forge.push_ref("refs/heads/main:refs/heads/main", false).is_err() {
        let diverged = format!(
            "Landed via loot as change `{change_hex}` -> mirror main `{main_sha}`. \
             GitHub main had diverged; reconcile with 'loot ferry' then push."
        );
        forge.close_pr(pr, &diverged)?;
        return Ok(LandingStatus::ClosedWithPointer);
    }

    // Collapse the PR head onto the landed sha (zero-diff), then poll for the
    // terminal state GitHub settles into.
    forge.push_ref(&format!("{main_sha}:refs/heads/{branch}"), true)?;
    let mut state = PrState::Open;
    for _ in 0..poll_attempts {
        sleep();
        state = forge.pr_state(pr)?;
        if state != PrState::Open {
            break;
        }
    }

    let status = interpret_landing(true, state);
    match status {
        LandingStatus::Merged => forge.comment_pr(pr, &pointer)?,
        LandingStatus::ClosedByCollapse => forge.comment_pr(
            pr,
            &format!(
                "{pointer} GitHub auto-closed on the zero-diff collapse - this \
                 close is the landing signal (map #148); the signed commit on \
                 main is the authoritative record."
            ),
        )?,
        LandingStatus::ClosedWithPointer => forge.close_pr(pr, &pointer)?,
    }
    // Best-effort: drop the provisional remote branch (ignored on failure,
    // matching the ps1).
    let _ = forge.push_ref(&format!(":refs/heads/{branch}"), false);
    Ok(status)
}

// ---------------------------------------------------------------------------
// land — the full flow (Workspace + ferry + forge)
// ---------------------------------------------------------------------------

/// Land an approved PR the loot way: gate → (pre-land `cargo test`) → finalize
/// (`loot new`) → ferry (project + reap) → publish + interpret the signal →
/// relay push → clear the lane.
pub fn land(
    ws: &mut Workspace,
    forge: &dyn Forge,
    pr: u64,
    skip_tests: bool,
    dry_run: bool,
) -> Result<(), String> {
    let p = paths(ws);
    // A land onto a drifted mirror would project this change over a `main` that
    // is not origin's — the #243 hazard. Warn loudly up front (break-glass stays
    // open per loot's philosophy; the operator decides).
    warn_if_drifted(ws);
    let mut map = read_pr_map(&p.pr_map);
    let lane = map
        .lane_for_pr(pr)
        .cloned()
        .ok_or_else(|| format!("PR #{pr} is not in the pr-map ledger (was it opened by 'review'?)"))?;

    let ambient = ws.current_dock().unwrap_or("main").to_string();
    let tracked = tracked_dock(&ws.store().git_config());
    let reviewed = WipState::parse(&std::fs::read_to_string(&p.wip).unwrap_or_default())
        .reviewed_version(&lane.change, &lane.dock)
        .map(str::to_string);
    let current = ws
        .live_working_row()?
        .and_then(|r| (!r.empty).then(|| r.version_hex()));

    let facts = LandFacts {
        pr,
        lane_dock: &lane.dock,
        ambient_dock: &ambient,
        tracked_dock: &tracked,
        reviewed_version: reviewed.as_deref(),
        current_version: current.as_deref(),
    };
    match land_gate(forge, &facts)? {
        Gate::Refuse(why) => return Err(why),
        Gate::Proceed { self_fast_path } => {
            println!(
                "land: pr #{pr} approved{}",
                if self_fast_path { " (self-authored fast path)" } else { "" }
            );
        }
    }

    if dry_run {
        println!("(dry run) stopping before finalize");
        return Ok(());
    }

    // Pre-land gate (#155): the review approved projected WIP; nothing has yet
    // proven the landed commit builds. Finalize is the point of no return.
    match pre_land(skip_tests) {
        PreLand::Skip => println!("pre-land cargo test SKIPPED (--skip-tests break-glass)"),
        PreLand::RunTests => {
            println!(">>> cargo test  (pre-land gate: the landed commit must build)");
            run_pre_land_tests(&p.root)?;
        }
    }

    println!(">>> loot new  (finalize + sign)");
    ws.finalize_capturing(&[], false)?;
    ws.record_op("new", "finalize (loot-first land)", false);

    // The harbor (ADR 0036): one land projects to git-main at a time. Take the
    // shared-store lock *after* the slow pre-land tests and the git-quiet
    // finalize, and hold it only across the git-main-critical section below —
    // ferry's projection, the fast-forward push, the PR-head collapse. A
    // concurrent land from another lane waits here, then ferries against the
    // main this one moved (ferry's ingest→reconcile converges the two lines; the
    // lock removes only the *race*). RAII: every `?` below releases the harbor.
    println!(">>> harbor: acquiring the land lock");
    let harbor = HarborLock::acquire(ws.store().harbor_lock(), HARBOR_WAIT, HARBOR_STALE)?;
    // The pre-ferry mirror tip — proof the land actually moved main (#195).
    let main_before = mirror_main_sha(&p.mirror).ok();

    println!(">>> loot ferry  (project signed change → main, reap the lane)");
    let fr = ferry::run(ws, None, None, /* with_wip */ false)?;
    for note in &fr.notes {
        println!("  {note}");
    }

    // Conflict-bounce (ADR 0036): if this change collided with work that landed
    // on main while the lane worked, ferry holds the conflicted paths at their
    // last clean state and never cleanly integrates the change. Do not push a
    // partial land — bounce it back to this agent. The signed change is
    // untouched in the store and nothing reached GitHub (the harbor drops here).
    if !ws.conflicts().is_empty() {
        let paths: Vec<String> = ws.conflicts().keys().map(|p| p.display().to_string()).collect();
        return Err(format!(
            "harbor bounce: this change conflicts with what landed on main while you worked \
             ({}) — nothing was pushed and your signed change is safe. Reconcile each with \
             `loot resolve <path> <file>`, then re-run `loot-first land --pr {pr}`.",
            paths.join(", ")
        ));
    }

    let main_sha = mirror_main_sha(&p.mirror)?;
    // #195 guard: a ferry that could not project this change to main (a lane
    // never merged into the harbor) leaves main exactly where it was — yet the
    // collapse-and-auto-close below would still emit a green `landed:`. Refuse
    // loudly rather than land a lie. The first land ever (empty mirror before,
    // so `main_before == None`) is unaffected — see [`harbor_moved_main`].
    if !harbor_moved_main(main_before.as_deref(), &main_sha) {
        return Err(format!(
            "harbor: git-main did not move (still {}) — this lane's change was not integrated \
             into the harbor, so there is nothing to collapse the PR onto (issue #195). \
             Nothing was pushed; check the `loot ferry` output above.",
            &main_sha[..main_sha.len().min(12)]
        ));
    }

    println!(">>> publish main + collapse PR head → {}", &main_sha[..main_sha.len().min(8)]);
    let mut sleep = || std::thread::sleep(std::time::Duration::from_secs(2));
    let status = execute_landing(forge, pr, &lane.change, &lane.dock, &main_sha, 10, &mut sleep)?;

    // git-main is published; free the harbor before the relay push (independent
    // of git-main) and the lane-landed bookkeeping so the next agent proceeds.
    harbor.release();

    println!(">>> loot push  (relay)");
    if let Err(e) = relay_push(&p.root) {
        eprintln!("warning: relay push failed ({e}); the land stands — retry `loot push`.");
    }

    map.remove_pr(pr);
    write_pr_map(&p.pr_map, &map)?;
    println!(
        "landed: change_id={} main={main_sha} pr=#{pr} status={}",
        lane.change,
        landing_word(status)
    );

    // Lane lifecycle (ADR 0034, #231): a landed *isolation* lane is done — mark
    // it so `loot lane gc` reaps it (unnamed lanes only; the reaper cannot run
    // here because this process's cwd is the lane directory). Best-effort: a
    // failed marker never un-lands anything.
    if let Some(id) = ws.lane_id() {
        match ws.store().mark_lane_landed(id) {
            Ok(()) => println!(
                "lane '{id}' marked landed — `loot lane gc` (from the primary) reaps it \
                 unless it was named"
            ),
            Err(e) => eprintln!("warning: could not mark lane '{id}' landed ({e})"),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// tag — the tag-push ferry verb (#256, loot-site epic step 5)
// ---------------------------------------------------------------------------

/// Cut a release tag the loot way: project `main`, mint an annotated tag on it,
/// and push the tag to GitHub so cargo-dist's `release.yml` fires. It rides the
/// same rails as [`land`] — warn-if-drifted, then hold the harbor lock (ADR
/// 0036) across the whole git-main-critical section (project → main FF push →
/// tag push) so a concurrent land and this tag can never race the projection.
/// The tag only ever points at the sealed-free projected `main`, and the push
/// carries a single tag ref, so the public boundary is never widened. No raw
/// git: every GitHub push goes through the [`Forge`] seam.
pub fn tag(ws: &mut Workspace, forge: &dyn Forge, name: &str, message: &str) -> Result<(), String> {
    // A tag onto a drifted mirror would point at a `main` that is not origin's
    // (the #243 hazard); warn loudly up front, but let the operator decide.
    warn_if_drifted(ws);

    println!(">>> harbor: acquiring the land lock (tag)");
    let harbor = HarborLock::acquire(ws.store().harbor_lock(), HARBOR_WAIT, HARBOR_STALE)?;

    // Project the tracked dock's tip → mirror main (the reconcile path), so the
    // tag lands on the current projection rather than a stale one. Idempotent
    // when main is already current — this cuts a tag, it lands no new change.
    println!(">>> loot ferry  (project → main)");
    let fr = ferry::run(ws, None, None, /* with_wip */ false)?;
    for note in &fr.notes {
        println!("  {note}");
    }

    let target = ferry::tag_projected_main(ws, name, message)?;
    println!(">>> tag {name} -> main {}", &target[..target.len().min(8)]);

    execute_tag_push(forge, name)?;
    // The tag is published; free the harbor for the next land.
    harbor.release();

    println!("tagged: {name} main={target} pushed=origin (release.yml fires on the tag)");
    Ok(())
}

/// Publish a freshly-minted release tag: fast-forward GitHub `main` so it holds
/// the tagged commit, *then* push the tag ref itself. Split out (like
/// [`execute_landing`]) so the intent stream is testable against a fake forge.
/// Both pushes are non-force: a diverged `main` or a tag that already exists on
/// origin makes this refuse rather than clobber — and because main goes first,
/// a diverged main aborts before the tag is ever pushed.
pub fn execute_tag_push(forge: &dyn Forge, name: &str) -> Result<(), String> {
    // Ensure origin main holds the tagged commit before the tag references it.
    forge
        .push_ref("refs/heads/main:refs/heads/main", false)
        .map_err(|e| {
            format!(
                "publish main before tagging failed ({e}) — GitHub main may have diverged; \
                 reconcile with `loot ferry` (or land the pending work) and retry the tag"
            )
        })?;
    let tag_ref = format!("refs/tags/{name}");
    forge
        .push_ref(&format!("{tag_ref}:{tag_ref}"), false)
        .map_err(|e| format!("push tag '{name}' failed ({e}) — does it already exist on origin?"))?;
    Ok(())
}

/// The #195 guard, as a pure decision: did this land actually move git-main?
/// `before` is the mirror tip captured before ferry; `after` the tip after. A
/// land that leaves them equal never integrated its change into the harbor and
/// must refuse, not false-report `landed:`. `before == None` (the empty mirror
/// before the very first land) never equals a real post-ferry sha, so the first
/// land always reads as moved.
fn harbor_moved_main(before: Option<&str>, after: &str) -> bool {
    before != Some(after)
}

fn landing_word(s: LandingStatus) -> &'static str {
    match s {
        LandingStatus::Merged => "merged",
        LandingStatus::ClosedByCollapse => "closed-by-collapse",
        LandingStatus::ClosedWithPointer => "closed-with-pointer",
    }
}

// ---------------------------------------------------------------------------
// mirror drift guard (#243, Deliverable 2)
// ---------------------------------------------------------------------------

/// Compare the mirror's projected `main` against the checkout's real
/// `origin/main` and return the loud operator warning if they have drifted
/// (#243). Best-effort and side-effect-free: an unbound mirror, a missing
/// `origin/main`, or any git error yields `None` (nothing to warn about) rather
/// than failing the surrounding command. Reads the local remote-tracking ref
/// only — no network — so `status` / `review` stay cheap; a stale `origin/main`
/// just means a `git fetch` would sharpen the check.
pub fn mirror_drift(ws: &Workspace) -> Option<String> {
    let p = paths(ws);
    let mirror = git_rev_parse(&p.mirror, "refs/heads/main")?;
    let origin = git_rev_parse(&p.root, "refs/remotes/origin/main")?;
    let ancestry = mirror_ancestry(&p.root, &mirror, &origin);
    mirror_drift_warning(&mirror, &origin, ancestry)
}

/// Print the drift warning to stderr if the mirror has drifted — the loud
/// surface `status` / `review` / `land` share. Never fails the caller (a guard
/// must not itself become a reason a command can't run).
fn warn_if_drifted(ws: &Workspace) {
    if let Some(w) = mirror_drift(ws) {
        eprintln!("!! {w}");
    }
}

/// Resolve `refname` in `repo` to a full sha, or `None` if the ref is absent or
/// git errors. `--verify -q` keeps a missing ref quiet.
fn git_rev_parse(repo: &Path, refname: &str) -> Option<String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--verify", "-q", refname])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!sha.is_empty()).then_some(sha)
}

/// Classify how `mirror` stands against `origin`, using `repo` (the checkout,
/// which holds `origin/main` and — in the common drift — the mirror commit too)
/// as the ancestry oracle. Equal shas are [`Ancestry::Same`]; a mirror that is a
/// strict ancestor of origin is [`Ancestry::MirrorBehind`]; anything else is
/// [`Ancestry::Diverged`] — including a mirror commit `repo` does not have (a
/// never-pushed projection, or a genuine unpushed-ahead mirror), which makes the
/// ancestry probe fail and reads as the safe, loud divergence answer.
fn mirror_ancestry(repo: &Path, mirror: &str, origin: &str) -> Ancestry {
    if mirror == origin {
        Ancestry::Same
    } else if is_ancestor(repo, mirror, origin) {
        Ancestry::MirrorBehind
    } else {
        Ancestry::Diverged
    }
}

/// `git merge-base --is-ancestor a b`: true iff `a` is an ancestor of `b`. Any
/// error (including an object `repo` does not have) reads as false.
fn is_ancestor(repo: &Path, a: &str, b: &str) -> bool {
    std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["merge-base", "--is-ancestor", a, b])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The mirror's main tip after ferry — a local read on the bare mirror.
fn mirror_main_sha(mirror: &Path) -> Result<String, String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(mirror)
        .args(["rev-parse", "refs/heads/main"])
        .output()
        .map_err(|e| format!("git rev-parse: spawn failed: {e}"))?;
    if !out.status.success() {
        return Err("mirror main has no tip after ferry".into());
    }
    let sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if sha.is_empty() {
        return Err("mirror main has no tip after ferry".into());
    }
    Ok(sha)
}

/// The pre-land gate: `cargo test` over the whole workspace, from the checkout.
fn run_pre_land_tests(root: &Path) -> Result<(), String> {
    let status = std::process::Command::new("cargo")
        .arg("test")
        .current_dir(root)
        .status()
        .map_err(|e| format!("cargo test: spawn failed: {e}"))?;
    if !status.success() {
        return Err("pre-land cargo test failed — not landing".into());
    }
    Ok(())
}

/// The relay sync (`loot push`) — not a policy decision, so it shells out to the
/// release binary rather than re-implementing the loot-net client here.
fn relay_push(root: &Path) -> Result<(), String> {
    let bin = if cfg!(windows) { "loot.exe" } else { "loot" };
    let loot = root.join("target").join("release").join(bin);
    let status = std::process::Command::new(loot)
        .arg("push")
        .current_dir(root)
        .status()
        .map_err(|e| format!("loot push: spawn failed: {e}"))?;
    if !status.success() {
        return Err("loot push returned non-zero".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

/// Show the in-flight review lanes and their PRs.
pub fn status(ws: &Workspace) -> Result<(), String> {
    let p = paths(ws);
    warn_if_drifted(ws);
    let map = read_pr_map(&p.pr_map);
    if map.lanes.is_empty() {
        println!("no in-flight review lanes");
        return Ok(());
    }
    for l in &map.lanes {
        println!("lane change={} dock={} pr=#{}", hex8(Some(&l.change)), l.dock, l.pr);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// init-hook
// ---------------------------------------------------------------------------

/// Install the warn-only pre-commit hook (#151): committing directly to git
/// main is break-glass — warned, never blocked (git main is a projection of
/// loot). Successor to the ps1's `init-hook`, so the guard survives the ps1's
/// deletion. ASCII body, `\n`-only, matching the ps1's install.
pub fn init_hook(ws: &Workspace) -> Result<(), String> {
    let hook_dir = paths(ws).root.join(".git").join("hooks");
    if !hook_dir.exists() {
        return Err(format!("no .git/hooks at {}", hook_dir.display()));
    }
    let hook = hook_dir.join("pre-commit");
    let body = "#!/bin/sh\n\
        # loot-first guard (map #148, warn-only by design - break-glass stays open).\n\
        branch=$(git symbolic-ref --short HEAD 2>/dev/null)\n\
        if [ \"$branch\" = \"main\" ]; then\n\
        \x20 echo \"loot: warning - committing directly to git main is off the loot-first path.\" >&2\n\
        \x20 echo \"      git main is a projection of loot; the next 'loot ferry' ingests this.\" >&2\n\
        \x20 echo \"      prefer: loot dock <task> -> loot ferry --with-wip -> PR  (docs/agents/workflow.md)\" >&2\n\
        fi\n\
        exit 0\n";
    std::fs::write(&hook, body).map_err(|e| format!("write pre-commit hook: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755));
    }
    println!("installed warn-only pre-commit hook at {}", hook.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forge::{FakeForge, PrView, ReviewDecision};

    fn view(decision: ReviewDecision, author: &str, state: PrState) -> PrView {
        PrView { state, review_decision: decision, author_login: author.into() }
    }

    fn facts<'a>(
        ambient: &'a str,
        lane_dock: &'a str,
        reviewed: Option<&'a str>,
        current: Option<&'a str>,
    ) -> LandFacts<'a> {
        // Default the tracked dock to the lane's own dock, so these tests
        // exercise the other guards; the tracked-dock guard has its own test.
        LandFacts {
            pr: 218,
            lane_dock,
            ambient_dock: ambient,
            tracked_dock: lane_dock,
            reviewed_version: reviewed,
            current_version: current,
        }
    }

    #[test]
    fn gate_proceeds_on_approved() {
        let f = FakeForge::new().with_view(view(ReviewDecision::Approved, "someone", PrState::Open));
        let g = land_gate(&f, &facts("ferry", "ferry", None, None)).unwrap();
        assert_eq!(g, Gate::Proceed { self_fast_path: false });
    }

    #[test]
    fn gate_self_authored_fast_path() {
        let f = FakeForge::new()
            .with_viewer("connor")
            .with_view(view(ReviewDecision::Other, "connor", PrState::Open));
        let g = land_gate(&f, &facts("ferry", "ferry", None, None)).unwrap();
        assert_eq!(g, Gate::Proceed { self_fast_path: true });
    }

    #[test]
    fn gate_refuses_non_open_pr() {
        let f = FakeForge::new().with_view(view(ReviewDecision::Approved, "someone", PrState::Merged));
        let Gate::Refuse(why) = land_gate(&f, &facts("ferry", "ferry", None, None)).unwrap() else {
            panic!("expected refuse");
        };
        assert!(why.contains("not OPEN"), "{why}");
    }

    #[test]
    fn gate_refuses_unapproved_from_other_author() {
        let f = FakeForge::new()
            .with_viewer("connor")
            .with_view(view(ReviewDecision::ChangesRequested, "someone", PrState::Open));
        let Gate::Refuse(why) = land_gate(&f, &facts("ferry", "ferry", None, None)).unwrap() else {
            panic!("expected refuse");
        };
        assert!(why.contains("not approved"), "{why}");
    }

    #[test]
    fn gate_refuses_dock_mismatch() {
        let f = FakeForge::new().with_view(view(ReviewDecision::Approved, "someone", PrState::Open));
        // Ambient dock is main, but the lane belongs to 'ferry'.
        let Gate::Refuse(why) = land_gate(&f, &facts("main", "ferry", None, None)).unwrap() else {
            panic!("expected refuse");
        };
        assert!(why.contains("ambient dock"), "{why}");
    }

    #[test]
    fn gate_refuses_side_lane_not_on_tracked_dock() {
        // The exact first-#218-land bug: lane and ambient agree, but git-main
        // tracks a different dock — a bare ferry would no-op yet report success.
        let f = FakeForge::new().with_view(view(ReviewDecision::Approved, "someone", PrState::Open));
        let facts = LandFacts {
            pr: 218,
            lane_dock: "loot-first",
            ambient_dock: "loot-first",
            tracked_dock: "main",
            reviewed_version: None,
            current_version: None,
        };
        let Gate::Refuse(why) = land_gate(&f, &facts).unwrap() else {
            panic!("expected refuse");
        };
        assert!(why.contains("side-lane") && why.contains("git-main tracks 'main'"), "{why}");
    }

    #[test]
    fn gate_refuses_stale_review() {
        let f = FakeForge::new().with_view(view(ReviewDecision::Approved, "someone", PrState::Open));
        let Gate::Refuse(why) =
            land_gate(&f, &facts("ferry", "ferry", Some("aaaaaaaa1111"), Some("bbbbbbbb2222"))).unwrap()
        else {
            panic!("expected refuse");
        };
        assert!(why.contains("amended since"), "{why}");
    }

    fn no_sleep() -> impl FnMut() {
        || {}
    }

    #[test]
    fn harbor_guard_refuses_a_no_op_land() {
        // #195: a ferry that leaves main where it was must read as "not moved".
        assert!(!harbor_moved_main(Some("abc123"), "abc123"), "unchanged main = not integrated");
    }

    #[test]
    fn harbor_guard_passes_when_main_advances() {
        assert!(harbor_moved_main(Some("abc123"), "def456"), "advanced main = integrated");
        // First land ever: empty mirror before can never match a real sha.
        assert!(harbor_moved_main(None, "def456"), "first land is always a move");
    }

    #[test]
    fn landing_merged_by_reachability() {
        let f = FakeForge::new().with_poll(vec![PrState::Merged]);
        let mut s = no_sleep();
        let st = execute_landing(&f, 218, "deadbeef", "ferry", "abc1234567", 10, &mut s).unwrap();
        assert_eq!(st, LandingStatus::Merged);
        let calls = f.calls();
        assert!(calls.iter().any(|c| c.contains("push refs/heads/main:refs/heads/main")));
        assert!(calls.iter().any(|c| c.contains("push abc1234567:refs/heads/review/ferry force=true")));
        assert!(calls.iter().any(|c| c.starts_with("comment_pr #218")));
        // Provisional branch cleaned up.
        assert!(calls.iter().any(|c| c.contains("push :refs/heads/review/ferry")));
    }

    #[test]
    fn landing_auto_close_is_the_signal() {
        let f = FakeForge::new().with_poll(vec![PrState::Open, PrState::Closed]);
        let mut s = no_sleep();
        let st = execute_landing(&f, 218, "deadbeef", "ferry", "abc1234567", 10, &mut s).unwrap();
        assert_eq!(st, LandingStatus::ClosedByCollapse);
        assert!(f.calls().iter().any(|c| c.contains("auto-closed on the zero-diff collapse")));
    }

    #[test]
    fn landing_diverged_main_closes_with_pointer() {
        let f = FakeForge::new().failing_push("refs/heads/main:refs/heads/main");
        let mut s = no_sleep();
        let st = execute_landing(&f, 218, "deadbeef", "ferry", "abc1234567", 10, &mut s).unwrap();
        assert_eq!(st, LandingStatus::ClosedWithPointer);
        let calls = f.calls();
        // Diverged path: close with the reconcile pointer, and NEVER collapse the head.
        assert!(calls.iter().any(|c| c.contains("close_pr #218") && c.contains("diverged")));
        assert!(!calls.iter().any(|c| c.contains("push abc1234567:")), "must not collapse a stale head");
    }

    #[test]
    fn landing_open_after_poll_closes_with_pointer() {
        let f = FakeForge::new().with_poll(vec![PrState::Open]);
        let mut s = no_sleep();
        let st = execute_landing(&f, 218, "deadbeef", "ferry", "abc1234567", 3, &mut s).unwrap();
        assert_eq!(st, LandingStatus::ClosedWithPointer);
        assert!(f.calls().iter().any(|c| c.starts_with("close_pr #218")));
    }

    #[test]
    fn tag_push_publishes_main_then_the_tag_ref() {
        let f = FakeForge::new();
        execute_tag_push(&f, "v0.1.0").unwrap();
        // main is fast-forwarded first, then the tag ref rides on top — both
        // non-force single-ref pushes.
        assert_eq!(
            f.calls(),
            vec![
                "push refs/heads/main:refs/heads/main force=false".to_string(),
                "push refs/tags/v0.1.0:refs/tags/v0.1.0 force=false".to_string(),
            ]
        );
    }

    #[test]
    fn tag_push_refuses_on_diverged_main_without_pushing_the_tag() {
        let f = FakeForge::new().failing_push("refs/heads/main:refs/heads/main");
        let err = execute_tag_push(&f, "v0.1.0").unwrap_err();
        assert!(err.contains("diverged"), "{err}");
        // main went first and failed, so the tag ref was never pushed.
        assert!(
            !f.calls().iter().any(|c| c.contains("refs/tags/")),
            "a diverged main must abort before the tag is pushed: {:?}",
            f.calls()
        );
    }
}
