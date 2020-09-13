//! The `review` / `land` / `status` flows — the ps1's body, now composing the
//! typed pieces: [`crate::ledger`] owns the on-disk ledgers, [`crate::forge`]
//! is the only door to GitHub, [`crate::policy`] holds the decisions, and loot
//! state is read/mutated **in-process** through `loot_cli`'s [`Workspace`] and
//! [`ferry`]. Two seams that face GitHub — [`land_gate`] (the pre-finalize
//! decision) and [`execute_landing`] (the post-finalize signal dance) — are
//! split out as forge-only functions so they can be tested against the
//! [`crate::forge::FakeForge`] without a real Workspace or network.

use crate::forge::{Forge, PrState};
use crate::ledger::{PrLane, PrMap};
use crate::policy::{
    approval, dock_targeting, interpret_landing, parse_review_line, pre_land, review_currency,
    Approval, Currency, DockTarget, LandingStatus, PreLand, ReviewOutcome,
};
use loot_cli::ferry::{self, WipState};
use loot_cli::workspace::Workspace;
use std::path::{Path, PathBuf};

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
        pr_map: mirror_dir.join("pr-map"),
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
    let mut map = read_pr_map(&p.pr_map);
    let lane = map
        .lane_for_pr(pr)
        .cloned()
        .ok_or_else(|| format!("PR #{pr} is not in the pr-map ledger (was it opened by 'review'?)"))?;

    let ambient = ws.current_dock().unwrap_or("main").to_string();
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

    println!(">>> loot ferry  (project signed change → main, reap the lane)");
    let fr = ferry::run(ws, None, None, /* with_wip */ false)?;
    for note in &fr.notes {
        println!("  {note}");
    }

    let main_sha = mirror_main_sha(&p.mirror)?;
    println!(">>> publish main + collapse PR head → {}", &main_sha[..main_sha.len().min(8)]);
    let mut sleep = || std::thread::sleep(std::time::Duration::from_secs(2));
    let status = execute_landing(forge, pr, &lane.change, &lane.dock, &main_sha, 10, &mut sleep)?;

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
    Ok(())
}

fn landing_word(s: LandingStatus) -> &'static str {
    match s {
        LandingStatus::Merged => "merged",
        LandingStatus::ClosedByCollapse => "closed-by-collapse",
        LandingStatus::ClosedWithPointer => "closed-with-pointer",
    }
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
        LandFacts { pr: 218, lane_dock, ambient_dock: ambient, reviewed_version: reviewed, current_version: current }
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
}
