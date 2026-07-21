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
use loot_cli::workspace::{is_undescribed, Workspace};
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

/// The local-only ledger/mirror paths under `.loot/git-mirror/`, plus the two
/// working directories a land straddles — which are the SAME directory on the
/// primary and different ones from a lane (#287, the same shared-vs-position
/// confusion as the #229 mirror-gitdir and gh-cwd dogfood fixes).
struct Paths {
    /// The landing *position's* own tree (`Workspace::root()`): the lane dir
    /// from a lane, the checkout from the primary. Where anything that must see
    /// the tree about to land runs — the pre-land `cargo test` gate, and the
    /// relay `loot push` cwd (a lane's `.loot` points at the shared store, so
    /// push resolves the same store from here while recording its op in this
    /// position's oplog, per ADR 0034 single-writer).
    position: PathBuf,
    /// The primary git checkout (the shared store's `.loot` parent): the only
    /// position with a `.git`, so it is where the drift guard's origin reads
    /// and the pre-commit hook live. Deliberately NOT `position` — a lane has
    /// no `.git`, and deriving everything from here is what #287 fixed.
    checkout: PathBuf,
    mirror: PathBuf,
    pr_map: PathBuf,
    pr_map_lock: PathBuf,
    wip: PathBuf,
}

fn paths(ws: &Workspace) -> Paths {
    let mirror_dir = ws.store().git_mirror_dir();
    let checkout = ws.dot().parent().unwrap_or_else(|| Path::new(".")).to_path_buf();
    Paths {
        pr_map: ws.store().git_pr_map(),
        pr_map_lock: ws.store().git_pr_map_lock(),
        wip: ws.store().git_wip(),
        mirror: mirror_dir.join("mirror.git"),
        position: ws.root().to_path_buf(),
        checkout,
    }
}

/// Reads via [`loot_core::store::read_replaced`]: the ledger is replaced by
/// [`atomic_write`](loot_core::store::atomic_write) in [`update_pr_map`], and
/// on Windows a reader racing that rename-replace transiently hits
/// `PermissionDenied` (#293 tail) — a bare read would swallow it into an
/// empty map, the exact "not in the pr-map ledger" symptom #336 recovers from.
fn read_pr_map(path: &Path) -> PrMap {
    let text = loot_core::store::read_replaced(path)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    PrMap::parse(&text)
}

/// How long a ledger write waits on the pr-map lock, and when a leftover lock
/// is presumed crashed and broken (#336). A locked read-apply-write is
/// microseconds, so any honest contention clears within a poll or two; the
/// budgets exist only so a crashed writer can never wedge review/land.
const LEDGER_WAIT: Duration = Duration::from_secs(10);
const LEDGER_STALE: Duration = Duration::from_secs(60);
const LEDGER_POLL: Duration = Duration::from_millis(100);

/// The pr-map ledger's one write door (#336): take the ledger lock, re-read
/// the file fresh, apply only this operation's own row change, write
/// atomically. `review`'s row add and `land`'s row remove both funnel here,
/// so a copy read earlier in a flow is only ever a lookup — never what gets
/// written back. (The lost-update this kills, live 2026-07-18: a land's read
/// → whole-file rewrite spanned its tests/ferry/push, erasing all three rows
/// sibling reviews had recorded in between.) The write is
/// [`atomic_write`](loot_core::store::atomic_write), like every replaced file
/// under `git-mirror/` (#307): unlocked readers (`status`, `loot lanes`,
/// land's lookup) must never observe a truncated ledger, and a crash
/// mid-write must not lose rows — the same failure class the lock exists for.
fn update_pr_map(
    pr_map: &Path,
    lock: &Path,
    apply: impl FnOnce(&mut PrMap),
) -> Result<(), String> {
    let _lock = HarborLock::acquire_contending(
        lock.to_path_buf(),
        LEDGER_WAIT,
        LEDGER_STALE,
        LEDGER_POLL,
        &|p| {
            format!(
                "another review/land is writing the pr-map ledger ({}) — ledger writes \
                 serialize under this lock (#336); retry, or remove the file if you are \
                 sure no loot-first is running",
                p.display()
            )
        },
    )?;
    let mut map = read_pr_map(pr_map);
    apply(&mut map);
    loot_core::store::atomic_write(pr_map, map.encode().as_bytes())
        .map_err(|e| format!("write pr-map: {e}"))
}

fn hex8(s: Option<&str>) -> String {
    match s {
        Some(v) if v.len() >= 8 => v[..8].to_string(),
        Some(v) => v.to_string(),
        None => "-".to_string(),
    }
}

/// A position for an operator-facing message: the primary's owner key is the
/// empty string (#281), which would read as nothing at all.
fn position_name(owner: &str) -> String {
    if owner.is_empty() { "the primary".to_string() } else { format!("lane '{owner}'") }
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
    // revert of landed work (#243). Local read only — review stays cheap.
    warn_if_drifted(ws, OriginRef::Tracking);

    let report = ferry::run(ws, None, None, /* with_wip */ true, /* seal_wip */ false)?;
    for note in &report.notes {
        println!("  {note}");
    }
    // No op record: a review pass is a pure projection (ADR 0039) — it never
    // ingests, reconciles, or otherwise changes the view, so there is nothing
    // for `loot undo` to walk. (#292's defect 2 — a view-changing catch-up
    // with no op-log entry — died with the catch-up itself.)
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

    // A lookup only — the row add below re-reads under the ledger lock (#336).
    // The idempotency check is race-free unlocked: (change, dock, owner) rows
    // are written only from their own position (ADR 0034 single-writer).
    let map = read_pr_map(&p.pr_map);
    if let Some(lane) = map.lane_for(&projected.change, &projected.dock, &projected.owner) {
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
    update_pr_map(&p.pr_map, &p.pr_map_lock, |m| {
        m.push(PrLane {
            change: projected.change.clone(),
            dock: projected.dock.clone(),
            pr,
            owner: projected.owner.clone(),
        })
    })?;
    println!("opened PR #{pr} for {}", projected.branch);
    Ok(())
}

/// The PR title: explicit `--title`, else the working change's **subject** — its
/// first line, git-style (unless it is the un-described placeholder) — else a
/// dock-derived fallback.
///
/// Subject-only because a loot message is subject + body like a commit message's,
/// and GitHub hard-caps a PR title at 256 chars: passing the whole thing failed
/// the `createPullRequest` mutation outright. Latent until #174 made
/// `describe -m` mandatory before a land, which is what made bodies routine.
fn resolve_title(ws: &mut Workspace, title: Option<&str>, dock: &str) -> String {
    if let Some(t) = title.map(str::trim).filter(|t| !t.is_empty()) {
        return t.to_string();
    }
    if let Ok(Some(row)) = ws.live_working_row() {
        let m = row.message.trim();
        if !is_undescribed(m) {
            return subject_of(m).to_string();
        }
    }
    format!("loot-first: {dock}")
}

/// A message's subject: its first line, trimmed. GitHub rejects a PR title over
/// 256 chars, so a subject that long is truncated on a char boundary (never a
/// byte one — loot messages are UTF-8 and a split mid-codepoint would panic).
fn subject_of(message: &str) -> &str {
    let first = message.lines().next().unwrap_or("").trim_end();
    match first.char_indices().nth(MAX_PR_TITLE) {
        None => first,
        Some((cut, _)) => &first[..cut],
    }
}

/// GitHub's hard cap on a PR title (`createPullRequest` rejects longer).
const MAX_PR_TITLE: usize = 256;

// ---------------------------------------------------------------------------
// land — the pre-finalize gate (forge-only, tested against the fake)
// ---------------------------------------------------------------------------

/// Facts the land gate decides on, read once by [`land`] before touching the
/// forge for the PR snapshot.
pub struct LandFacts<'a> {
    pub pr: u64,
    pub lane_dock: &'a str,
    /// The position that opened the PR (the pr-map lane's owner, #281): an
    /// isolation-lane id, empty for the primary (and for pre-#281 rows).
    pub lane_owner: &'a str,
    /// The position running this land: `Workspace::lane_id()`, empty on the
    /// primary. A land finalizes *this* position's working change, so it must
    /// be the one that opened the PR.
    pub position: &'a str,
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
    /// The live working-change message now (`None` when the change is empty).
    /// [`land_gate`] checks this for the `loot resolve` placeholder subject
    /// (#316) — the version alone can't distinguish a change that's been
    /// re-described after a bounce from one still carrying the placeholder.
    pub current_subject: Option<&'a str>,
}

/// The outcome of the pre-finalize gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    /// All guards passed; `self_fast_path` drives only the log line.
    Proceed { self_fast_path: bool },
    /// A guard refused, with an operator-facing reason.
    Refuse(String),
}

/// The *fallback* message `loot resolve` gives the change it creates when a
/// same-path conflict bounces a land and no ours-line subject was derivable
/// (`crates/loot-core/src/engine.rs`, `RESOLVE_FALLBACK_PREFIX`). Since #337
/// a resolution normally inherits the landed change's subject with a
/// `(conflict resolution: <path>)` suffix, so this prefix only ever surfaces
/// on the pre-dock flow or a subject-less line. [`land_gate`] still refuses
/// to finalize a working change carrying it (#316) — landing it verbatim
/// would publish the placeholder as git main's permanent commit subject
/// instead of the change's real described subject. Kept local rather than
/// shared from loot-core to avoid a cross-crate string coupling; if
/// engine.rs's format ever changes, this prefix needs to follow it.
const RESOLVE_PLACEHOLDER_PREFIX: &str = "resolve conflict at ";

/// Run every pre-finalize guard against the forge and the read facts: PR is
/// OPEN, approval (#152), dock-targeting (#153), review-currency (ADR 0033),
/// resolve-placeholder subject (#316).
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
    // Position guard (#281): a land finalizes and signs *this* position's
    // working change, then collapses the PR — run from any other position it
    // would sign the wrong work against the wrong branch. Every lane's home
    // dock is `main`, so the dock guard above cannot catch this.
    if f.lane_owner != f.position {
        return Ok(Gate::Refuse(format!(
            "PR #{} was opened from {} — this is {}; land finalizes the current \
             position's working change, so run it from the position that opened \
             the PR (#281)",
            f.pr,
            position_name(f.lane_owner),
            position_name(f.position)
        )));
    }
    // The lane must be on the dock git-main tracks; a side-lane change cannot be
    // projected to main by a bare `ferry`, so landing it would finalize + reap
    // the lane while git-main never moves (the false-success gap the first #218
    // land hit). Refuse and point at the merge-first path.
    if f.lane_dock != f.tracked_dock {
        return Ok(Gate::Refuse(format!(
            "PR #{}'s review lane is on dock '{}', but git-main tracks '{}' — a \
             side-lane change can't project to main directly. Merge it in first \
             from the primary: `loot lane merge {}`, then land from '{}'.",
            f.pr, f.lane_dock, f.tracked_dock, f.lane_dock, f.tracked_dock
        )));
    }
    // #316: a same-path conflict bounce is resolved via `loot resolve`, which
    // mints the change's message as the placeholder above — describing what
    // happened at resolve time, not the change's actual subject. Landing it
    // as-is would carry that placeholder onto git main's permanent log rather
    // than the subject the operator originally gave the change (the audit
    // trail survives via the PR pointer either way, but the human subject on
    // main would be lost). Refuse and name the fix.
    if let Some(subject) = f.current_subject {
        if subject.starts_with(RESOLVE_PLACEHOLDER_PREFIX) {
            return Ok(Gate::Refuse(format!(
                "working change carries the auto-minted resolve placeholder subject \
                 (\"{subject}\") — a land would publish that as git main's commit \
                 subject. Run 'loot describe -m \"<subject>\"' to restore the change's \
                 real subject, then land again."
            )));
        }
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
/// reaction (#150/#166). `branch` is the PR's review branch, derived from the
/// pr-map lane's owner (#281) — this function no longer assumes the dock names
/// it. `poll_attempts`/`sleep` drive the terminal-state poll; production
/// passes 10 attempts and a 2s sleep, tests pass a no-op sleep.
pub fn execute_landing(
    forge: &dyn Forge,
    pr: u64,
    change_hex: &str,
    branch: &str,
    main_sha: &str,
    poll_attempts: usize,
    sleep: &mut dyn FnMut(),
) -> Result<LandingStatus, String> {
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
    // open per loot's philosophy; the operator decides). This verb pushes, so it
    // asks the remote: at the moment of the loudest warning, be sure.
    warn_if_drifted(ws, OriginRef::Remote);
    // A lookup only, never written back: this copy goes stale the moment a
    // sibling review records a row, and a land spans minutes (#336).
    let lane = read_pr_map(&p.pr_map)
        .lane_for_pr(pr)
        .cloned()
        .ok_or_else(|| {
            let mut m = format!("PR #{pr} is not in the pr-map ledger (was it opened by 'review'?)");
            // #418 belt-and-suspenders: if the ambient anchor is a sealed line
            // ahead of main with no PR (a `--seal-wip` override, or any bare-verb
            // seal), the missing PR is the *symptom* — point at the recovery round.
            if ws.sealed_unlanded_anchor().is_some() {
                m.push_str(&format!("\n  {}", loot_cli::workspace::SEAL_WIP_RECOVERY));
            }
            m
        })?;

    let ambient = ws.current_dock().unwrap_or("main").to_string();
    let tracked = tracked_dock(&ws.store().git_config());
    let position = ws.lane_id().unwrap_or("").to_string();
    let reviewed = WipState::parse(&std::fs::read_to_string(&p.wip).unwrap_or_default())
        .reviewed_version(&lane.change, &lane.dock, &lane.owner)
        .map(str::to_string);
    // Bound once so `current_version` and `current_subject` (#316) read the
    // same row instead of two separate `live_working_row()` calls disagreeing
    // under a race.
    let row = ws.live_working_row()?;
    let current = row.as_ref().and_then(|r| (!r.empty).then(|| r.version_hex()));
    let current_subject = row.as_ref().and_then(|r| (!r.empty).then(|| r.message.as_str()));

    let facts = LandFacts {
        pr,
        lane_dock: &lane.dock,
        lane_owner: &lane.owner,
        position: &position,
        ambient_dock: &ambient,
        tracked_dock: &tracked,
        reviewed_version: reviewed.as_deref(),
        current_version: current.as_deref(),
        current_subject,
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
            // In the landing position's tree (#287): from a lane, the shared
            // root is the primary's — possibly stale — checkout, and a gate run
            // there proves nothing about the commit this land is about to sign.
            run_pre_land_tests(&p.position)?;
        }
    }

    println!(">>> loot new  (finalize + sign)");
    // The mis-seal gate rides the finalize seam itself (#353, ADR 0038 §1), so
    // this signing runs gated with no override: a first-seal secret refuses the
    // land; the remedy is a `.lootattributes` rule or an explicit
    // `loot new --allow-reveal <path>` in the lane, then re-land.
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
    // The finalize above already sealed and signed the reviewed change, so this
    // ferry pass captures no wip — but pass the override anyway: `land` is the
    // authorized finalizer, and the #418 guard is only for the bare verbs.
    let fr = ferry::run(ws, None, None, /* with_wip */ false, /* seal_wip */ true)?;
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
        // "Did not move within THIS invocation" is not yet "nothing to land"
        // (#349): an earlier bare `loot ferry` may already have projected this
        // lane's signed line onto mirror main, leaving only the push + PR
        // collapse owed — and a refusal here wedges (re-running land can never
        // move main again; the live workaround was describing a dummy edit).
        // Prove the already-projected state from git facts before refusing.
        let tip_hex = ws.finalized_anchor().map(|t| loot_core::hex::encode(&t.0));
        if already_projected_unpushed(&p.checkout, &p.mirror, &main_sha, tip_hex.as_deref()) {
            println!(
                "harbor: main did not move in this land, but it already carries this land's \
                 signed tip ahead of origin/main — an earlier ferry projected it (#349); \
                 proceeding to the owed push + PR collapse"
            );
        } else {
            return Err(format!(
                "harbor: git-main did not move (still {}) — this lane's change was not integrated \
                 into the harbor, so there is nothing to collapse the PR onto (issue #195). \
                 Nothing was pushed; check the `loot ferry` output above.",
                &main_sha[..main_sha.len().min(12)]
            ));
        }
    }

    println!(">>> publish main + collapse PR head → {}", &main_sha[..main_sha.len().min(8)]);
    // The PR's review branch carries the opening position (#281): the owning
    // lane's id, or the dock name for a primary-opened (or pre-#281) lane.
    let branch = lane.review_branch();
    let mut sleep = || std::thread::sleep(std::time::Duration::from_secs(2));
    let status = execute_landing(forge, pr, &lane.change, &branch, &main_sha, 10, &mut sleep)?;

    // git-main is published; free the harbor before the relay push (independent
    // of git-main) and the lane-landed bookkeeping so the next agent proceeds.
    harbor.release();

    println!(">>> loot push  (relay)");
    if let Err(e) = relay_push(&p.position) {
        eprintln!("warning: relay push failed ({e}); the land stands — retry `loot push`.");
    }

    update_pr_map(&p.pr_map, &p.pr_map_lock, |m| m.remove_pr(pr))?;
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
        // A lane land leaves the primary's main dock behind the harbor it just
        // advanced — by construction, not by accident (#265). Positional state
        // is single-writer (ADR 0034), so this land must not advance another
        // position's pointers; say it instead. The catch-up is a clean FF.
        println!(
            "note: the primary's main dock is now behind landed main — `loot adopt` from \
             the primary fast-forwards it (any bare `loot ferry` there does too)."
        );
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
    // (the #243 hazard); warn loudly up front, but let the operator decide. Like
    // `land`, this verb pushes, so the remote answers rather than a stale ref.
    warn_if_drifted(ws, OriginRef::Remote);

    println!(">>> harbor: acquiring the land lock (tag)");
    let harbor = HarborLock::acquire(ws.store().harbor_lock(), HARBOR_WAIT, HARBOR_STALE)?;

    // Project the tracked dock's tip → mirror main (the reconcile path), so the
    // tag lands on the current projection rather than a stale one. Idempotent
    // when main is already current — this cuts a tag, it lands no new change.
    println!(">>> loot ferry  (project → main)");
    // Cutting a release tag is not a finalizer: it projects landed main, never
    // reviews a change. If the operator has live described WIP, this bare ferry
    // must refuse rather than silently seal it (#418) — pass the guard through.
    let fr = ferry::run(ws, None, None, /* with_wip */ false, /* seal_wip */ false)?;
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

/// The #349 escape hatch, consulted only when [`harbor_moved_main`] reads "not
/// moved": is the mirror's `main` *already* carrying this land's signed line,
/// with only the push + PR collapse owed? An earlier bare `loot ferry` projects
/// any unprojected signed history the moment it runs, so a land's own ferry can
/// find nothing to do while the publication is still owed — indistinguishable,
/// within one invocation, from the "never integrated" case #195 refuses.
/// The distinction is provable from git facts, all three of which must hold:
///
/// 1. `origin/main` is known to the checkout — fresh, because the land's
///    up-front drift guard fetched it ([`OriginRef::Remote`]); a tracking read
///    here costs no second round-trip and stays offline-safe;
/// 2. the mirror's `main` is **strictly ahead** of it (origin's tip is a proper
///    ancestor — asked of the mirror, which always holds its own lineage, the
///    same oracle choice as [`mirror_ancestry`]); and
/// 3. a commit in `origin/main..main` — the **unpushed** span only, never all
///    of history (#367) — carries this land's finalized tip as its
///    `Loot-Change-Id` trailer — the trailer every ferry projection mints, so
///    "an earlier ferry already projected exactly the line this land was about
///    to" is a fact, not an inference. Without this walk, a *sibling's*
///    unpushed projection would unlock a land whose own change never
///    integrated — and without the range bound, a tip *already pushed* (its
///    trailer reachable from origin) would pass all three conditions and land
///    the sibling's projected-but-unlanded line: both are the exact green lie
///    #195 forbids.
///
/// Anything unprovable — no origin ref, mirror behind or diverged, no finalized
/// tip, trailer absent — reads `false`, leaving the #195 refusal as the
/// conservative default.
fn already_projected_unpushed(
    checkout: &Path,
    mirror: &Path,
    main_sha: &str,
    tip_hex: Option<&str>,
) -> bool {
    let Some(tip) = tip_hex else { return false };
    let Some(origin) = origin_main(checkout, OriginRef::Tracking) else { return false };
    if origin == main_sha {
        return false; // mirror == origin: genuinely nothing unpushed — #195 stands
    }
    if !is_ancestor(mirror, /* ancestor */ &origin, /* descendant */ main_sha) {
        return false; // behind or diverged: no clean fast-forward is owed from here
    }
    projected_on(mirror, &origin, main_sha, tip)
}

/// Whether a commit in `origin..main_sha` in `repo` carries
/// `Loot-Change-Id: <change_hex>` — the trailer [`ferry`]'s projection mints on
/// every mirrored change. The walk is bounded to the unpushed span (#367): a
/// trailer already reachable from `origin` means the tip is published, so this
/// land owes no push — proceeding would publish whatever *else* sits unpushed
/// on the mirror. The caller's ancestry check guarantees `origin` exists in
/// `repo`. `--fixed-strings` so the needle is never a regex; any git failure
/// reads as "not projected" (the conservative answer).
fn projected_on(repo: &Path, origin: &str, main_sha: &str, change_hex: &str) -> bool {
    let needle = format!("{}: {change_hex}", loot_core::bridge::TRAILER_CHANGE_ID);
    let range = format!("{origin}..{main_sha}");
    std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["log", "--fixed-strings", "-1", "--format=%H", &format!("--grep={needle}"), &range])
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
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

/// Where the guard reads `origin/main` from — the one axis on which the four
/// verbs differ (#273).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginRef {
    /// The checkout's local `refs/remotes/origin/main`. No network, so `status`
    /// and `review` stay cheap; a stale ref only ever reads as
    /// [`Ancestry::MirrorAhead`], which is quiet.
    Tracking,
    /// Fetch `main` from the remote first. Reserved for `land` and `tag`, which
    /// already talk to the network to push — one more round-trip is free there,
    /// and it turns their verdict from a guess into a fact. This is what pays
    /// for [`Ancestry::MirrorAhead`] being quiet: once a stale tracking ref reads
    /// as the healthy *ahead*, a `main` that moved under us would go unnoticed at
    /// exactly the two verbs that must not miss it. Falls back to the tracking
    /// ref (with a note) when the remote is unreachable, so an offline land still
    /// runs.
    Remote,
}

/// Compare the mirror's projected `main` against the real `origin/main` and
/// return the loud operator warning if they have drifted (#243). Best-effort and
/// side-effect-free: an unbound mirror, a missing `origin/main`, or any git error
/// yields `None` (nothing to warn about) rather than failing the surrounding
/// command.
pub fn mirror_drift(ws: &Workspace, origin_ref: OriginRef) -> Option<String> {
    let p = paths(ws);
    let mirror = git_rev_parse(&p.mirror, "refs/heads/main")?;
    // The guard's git reads run in the *checkout*, never the position (#287):
    // only the primary has a `.git` with the origin/main tracking ref — a lane
    // dir would make every probe fail and silently mute the guard.
    let origin = origin_main(&p.checkout, origin_ref)?;
    let ancestry = mirror_ancestry(&p.checkout, &p.mirror, &mirror, &origin);
    mirror_drift_warning(&mirror, &origin, ancestry)
}

/// Resolve origin's `main` for the guard, per [`OriginRef`]. Always returns a
/// commit the *checkout* holds, which `mirror_ancestry`'s "behind" probe relies
/// on: `Tracking` reads a ref (so its objects are present by definition), and
/// `Remote` fetches before answering.
fn origin_main(root: &Path, origin_ref: OriginRef) -> Option<String> {
    let tracking = || git_rev_parse(root, "refs/remotes/origin/main");
    match origin_ref {
        OriginRef::Tracking => tracking(),
        OriginRef::Remote => match git_fetch_main(root) {
            Some(sha) => Some(sha),
            None => {
                // Say so rather than degrade in silence: this verb advertises a
                // fact, and the operator is about to act on the answer.
                eprintln!(
                    "!! drift guard: could not reach origin — judging against the local \
                     origin/main, which may be stale"
                );
                tracking()
            }
        },
    }
}

/// Fetch origin's `main` and return its tip. Fetches rather than `ls-remote`ing
/// on purpose: ancestry needs operands git can *walk*, and a bare sha is not one
/// — the checkout may never have seen that commit, and the probe would fail into
/// a false [`Ancestry::Diverged`] on exactly the fresh break-glass push this is
/// here to catch. Touches only objects and refs (never the working tree); `None`
/// on any failure, leaving the caller to fall back to the tracking ref.
fn git_fetch_main(repo: &Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["fetch", "-q", "origin", "main"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    git_rev_parse(repo, "FETCH_HEAD")
}

/// Print the drift warning to stderr if the mirror has drifted — the loud
/// surface `status` / `review` / `land` / `tag` share. Never fails the caller (a
/// guard must not itself become a reason a command can't run).
fn warn_if_drifted(ws: &Workspace, origin_ref: OriginRef) {
    if let Some(w) = mirror_drift(ws, origin_ref) {
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

/// Classify how `mirror` stands against `origin`, probing **both** directions —
/// each in the repo that is guaranteed to hold both commits when that answer is
/// the true one (#273):
///
/// - *Ahead* (`origin` is an ancestor of `mirror`) is asked of `mirror_repo`. A
///   mirror always holds its own lineage, so if origin really is behind the
///   mirror's tip, the mirror holds origin's commit too and can answer. The
///   checkout often cannot — it may never have fetched the mirror's tip — which
///   is exactly why asking it there collapsed *ahead* into [`Ancestry::Diverged`]
///   and made the guard cry wolf on every post-land command.
/// - *Behind* (`mirror` is an ancestor of `origin`) is asked of `checkout`. If
///   the mirror is truly behind, its tip is in `origin/main`'s lineage, which the
///   checkout holds by definition of having that ref.
///
/// Equal shas short-circuit to [`Ancestry::Same`]. When neither probe answers —
/// a genuine fork, or a commit no repo here holds — the result is the safe, loud
/// [`Ancestry::Diverged`]. Ahead is probed first: it is the common healthy path,
/// so the usual case costs one `git` call rather than two.
///
/// `origin` must be a commit `checkout` holds — see [`origin_main`], which is
/// what guarantees it for both [`OriginRef`] modes.
fn mirror_ancestry(checkout: &Path, mirror_repo: &Path, mirror: &str, origin: &str) -> Ancestry {
    if mirror == origin {
        Ancestry::Same
    } else if is_ancestor(mirror_repo, /* ancestor */ origin, /* descendant */ mirror) {
        Ancestry::MirrorAhead
    } else if is_ancestor(checkout, /* ancestor */ mirror, /* descendant */ origin) {
        Ancestry::MirrorBehind
    } else {
        Ancestry::Diverged
    }
}

/// `git merge-base --is-ancestor`: true iff `ancestor` is an ancestor of
/// `descendant`, as judged by `repo`. The parameters are named rather than
/// positional-by-convention because the two call sites above deliberately
/// transpose them — swapping a pair silently inverts the guard's verdict.
///
/// Any error (including an object `repo` does not have) reads as false. Captures
/// output rather than inheriting the terminal: a missing object makes git print
/// `fatal: Not a valid commit name …`, and a best-effort guard must not leak
/// that — it reads like a real failure of the command the operator ran (#273).
fn is_ancestor(repo: &Path, ancestor: &str, descendant: &str) -> bool {
    std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["merge-base", "--is-ancestor", ancestor, descendant])
        .output()
        .map(|o| o.status.success())
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

/// The pre-land gate: `cargo test` over the whole workspace, run in the landing
/// *position's* tree (#287) — the lane dir from a lane, the checkout from the
/// primary. It must test the tree about to be signed, not the shared root.
fn run_pre_land_tests(position: &Path) -> Result<(), String> {
    let status = std::process::Command::new("cargo")
        .arg("test")
        .current_dir(position)
        .status()
        .map_err(|e| format!("cargo test: spawn failed: {e}"))?;
    if !status.success() {
        return Err("pre-land cargo test failed — not landing".into());
    }
    Ok(())
}

/// The relay sync (`loot push`) — not a policy decision, so it shells out to the
/// `loot` binary rather than re-implementing the loot-net client here.
///
/// Runs in the landing position's tree (#287): `loot push` discovers `.loot`
/// from its cwd, and a lane's `.loot` points at the shared store, so the push
/// ships the same store either way — but from here the position guard
/// (`has_unsigned_tip`) reads the tip this land just signed, and the push op
/// lands in *this* position's oplog rather than the primary's (ADR 0034: no
/// mutable file has two writers).
fn relay_push(position: &Path) -> Result<(), String> {
    let bin = if cfg!(windows) { "loot.exe" } else { "loot" };
    // The `loot` built beside this running `loot-first` — the pair come from
    // one `cargo build`, and a lane tree holds no `target/release` of its own
    // (#287: the old position-blind path only worked because it always pointed
    // at the primary's). Fall back to the position's release build for a
    // loot-first invoked outside its build tree.
    let loot = std::env::current_exe()
        .ok()
        .and_then(|exe| Some(exe.parent()?.join(bin)))
        .filter(|p| p.is_file())
        .unwrap_or_else(|| position.join("target").join("release").join(bin));
    let status = std::process::Command::new(loot)
        .arg("push")
        .current_dir(position)
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
    // Local read only: `status` is the verb operators run constantly, and it has
    // no other reason to touch the network.
    warn_if_drifted(ws, OriginRef::Tracking);
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
    let hook_dir = paths(ws).checkout.join(".git").join("hooks");
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

    // -----------------------------------------------------------------------
    // subject_of — the PR title is a subject, not a whole message (#174 lane)
    // -----------------------------------------------------------------------

    #[test]
    fn a_pr_title_is_the_messages_first_line_not_its_body() {
        // Live finding on the #174 land: the whole subject+body message went to
        // `gh pr create`, and GitHub rejected the mutation ("Title is too long").
        let msg = "fix: the subject\n\nA body paragraph explaining why, which is\nnot the title.";
        assert_eq!(subject_of(msg), "fix: the subject");
    }

    #[test]
    fn a_one_line_message_is_its_own_subject() {
        assert_eq!(subject_of("fix: a one-liner"), "fix: a one-liner");
        assert_eq!(subject_of(""), "");
    }

    #[test]
    fn an_overlong_subject_is_cut_to_githubs_cap_on_a_char_boundary() {
        // Cutting on a *byte* boundary would panic mid-codepoint. The em-dashes
        // loot's own messages are full of are 3 bytes each, so the cut lands
        // inside one unless char_indices drives it.
        let long = "—".repeat(400);
        let cut = subject_of(&long);
        assert_eq!(cut.chars().count(), MAX_PR_TITLE, "cut to the cap, in chars");
        assert!(long.starts_with(cut), "and it is a prefix of the subject");
    }

    // -----------------------------------------------------------------------
    // update_pr_map — the pr-map ledger's one write door (#336)
    // -----------------------------------------------------------------------

    #[test]
    fn a_land_finishing_after_sibling_reviews_keeps_their_rows() {
        // The #336 lost-update, replayed: a land read the ledger, sibling
        // reviews then recorded their rows, and the land's whole-file rewrite
        // of its stale copy erased them all. The write door re-reads under the
        // ledger lock and applies only its own row change, so the land's early
        // read is just a lookup — never what gets written back.
        let dir = scratch("336-lost-update");
        let pr_map = dir.join("pr-map");
        let lock = dir.join("pr-map.lock");
        std::fs::write(&pr_map, "aaaa main 19 t19\n").unwrap();

        // The land reads its lane up front (the copy that used to be written
        // back verbatim at the end)...
        let early = read_pr_map(&pr_map);
        assert!(early.lane_for_pr(19).is_some());

        // ...a sibling review records its row while the land runs...
        update_pr_map(&pr_map, &lock, |m| {
            m.push(PrLane { change: "bbbb".into(), dock: "grant".into(), pr: 333, owner: "t5".into() })
        })
        .unwrap();

        // ...and the land's close-out clears only its own row.
        update_pr_map(&pr_map, &lock, |m| m.remove_pr(19)).unwrap();

        let after = read_pr_map(&pr_map);
        assert!(after.lane_for_pr(19).is_none(), "the landed lane is cleared");
        assert_eq!(
            after.lane_for_pr(333).map(|l| l.owner.as_str()),
            Some("t5"),
            "a sibling review's row recorded mid-land survives the land's write (#336)"
        );
    }

    #[test]
    fn the_ledger_lock_is_held_only_across_the_write() {
        let dir = scratch("336-lock-release");
        let pr_map = dir.join("pr-map");
        let lock = dir.join("pr-map.lock");
        update_pr_map(&pr_map, &lock, |m| {
            m.push(PrLane { change: "cccc".into(), dock: "main".into(), pr: 1, owner: String::new() })
        })
        .unwrap();
        assert!(!lock.exists(), "the ledger lock releases with the write");
        assert_eq!(read_pr_map(&pr_map).lanes.len(), 1);
    }

    // -----------------------------------------------------------------------
    // mirror_ancestry — the oracle behind the drift guard (#273)
    // -----------------------------------------------------------------------

    /// A throwaway dir, isolated per test name and process.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("loot-273-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn git(repo: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("git {args:?}: {e}"));
        assert!(out.status.success(), "git {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// A git repo with one commit on `main`, identity configured so commits work
    /// on a bare CI box.
    fn git_repo(base: &Path, name: &str) -> PathBuf {
        let dir = base.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        git(&dir, &["init", "-q", "-b", "main"]);
        git(&dir, &["config", "user.email", "t@loot.test"]);
        git(&dir, &["config", "user.name", "loot test"]);
        commit(&dir, "base");
        dir
    }

    /// An empty commit on the current branch, tagged with a ref named `msg` so
    /// other repos can fetch it by name (fetching a bare sha needs
    /// `uploadpack.allowAnySHA1InWant`); returns its sha.
    fn commit(repo: &Path, msg: &str) -> String {
        git(repo, &["commit", "-q", "--allow-empty", "-m", msg]);
        let sha = git(repo, &["rev-parse", "HEAD"]);
        git(repo, &["update-ref", &format!("refs/heads/{msg}"), &sha]);
        sha
    }

    /// Copy the lineage of the ref named `refname` from `from` into `to` — the
    /// fetch that decides whether a repo can answer an ancestry question about
    /// that commit at all.
    fn fetch(to: &Path, from: &Path, refname: &str) {
        git(
            to,
            &[
                "fetch",
                "-q",
                from.to_str().unwrap(),
                &format!("refs/heads/{refname}:refs/heads/from-{refname}"),
            ],
        );
    }

    /// Whether `repo` holds `sha` as a commit — asked without panicking, so a
    /// test can state "this repo cannot answer".
    fn has_commit(repo: &Path, sha: &str) -> bool {
        std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["cat-file", "-e", &format!("{sha}^{{commit}}")])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[test]
    fn ancestry_same_when_shas_match() {
        let base = scratch("same");
        let checkout = git_repo(&base, "checkout");
        let mirror = git_repo(&base, "mirror");
        let sha = git(&checkout, &["rev-parse", "HEAD"]);
        assert_eq!(mirror_ancestry(&checkout, &mirror, &sha, &sha), Ancestry::Same);
    }

    #[test]
    fn ancestry_behind_when_origin_advanced_past_the_mirror() {
        // A break-glass git land: origin/main has a commit the mirror never
        // ingested. The checkout holds both, and this must stay a warning.
        let base = scratch("behind");
        let checkout = git_repo(&base, "checkout");
        let mirror_sha = git(&checkout, &["rev-parse", "HEAD"]);
        let origin_sha = commit(&checkout, "landedelsewhere");
        let mirror = git_repo(&base, "mirror");
        fetch(&mirror, &checkout, "base");
        assert_eq!(
            mirror_ancestry(&checkout, &mirror, &mirror_sha, &origin_sha),
            Ancestry::MirrorBehind
        );
    }

    #[test]
    fn ancestry_ahead_when_the_mirror_leads_a_stale_tracking_ref() {
        // The #273 repro: the mirror pushed, the checkout has not fetched, so
        // its origin/main is one behind. The checkout holds both commits — and
        // this still read as Diverged before the fix.
        let base = scratch("ahead");
        let checkout = git_repo(&base, "checkout");
        let origin_sha = git(&checkout, &["rev-parse", "HEAD"]);
        let mirror_sha = commit(&checkout, "landed");
        let mirror = git_repo(&base, "mirror");
        fetch(&mirror, &checkout, "landed");
        assert_eq!(
            mirror_ancestry(&checkout, &mirror, &mirror_sha, &origin_sha),
            Ancestry::MirrorAhead
        );
    }

    #[test]
    fn ancestry_ahead_even_when_the_checkout_lacks_the_mirror_commit() {
        // The case the old doc claimed was undecidable. The checkout cannot
        // answer — it has never seen the mirror's tip — but the mirror always
        // holds its own lineage, so the mirror is the oracle that can.
        let base = scratch("ahead-unfetched");
        let mirror = git_repo(&base, "mirror");
        let origin_sha = git(&mirror, &["rev-parse", "HEAD"]);
        let mirror_sha = commit(&mirror, "unpushed");
        let checkout = git_repo(&base, "checkout");
        fetch(&checkout, &mirror, "base");
        assert!(
            !has_commit(&checkout, &mirror_sha),
            "precondition: the checkout must not hold the mirror's tip"
        );
        assert_eq!(
            mirror_ancestry(&checkout, &mirror, &mirror_sha, &origin_sha),
            Ancestry::MirrorAhead
        );
    }

    #[test]
    fn ancestry_diverged_when_neither_reaches_the_other() {
        // The real #243/#241 shape: the mirror projected a main that never
        // reached origin. This must stay the loudest answer.
        let base = scratch("diverged");
        let checkout = git_repo(&base, "checkout");
        let fork = git(&checkout, &["rev-parse", "HEAD"]);
        let origin_sha = commit(&checkout, "originside");
        git(&checkout, &["checkout", "-q", &fork]);
        let mirror_sha = commit(&checkout, "mirrorside");
        let mirror = git_repo(&base, "mirror");
        fetch(&mirror, &checkout, "mirrorside");
        fetch(&mirror, &checkout, "originside");
        assert_eq!(
            mirror_ancestry(&checkout, &mirror, &mirror_sha, &origin_sha),
            Ancestry::Diverged
        );
    }

    /// An `origin` repo and a checkout cloned from it, as `land` / `tag` see the
    /// world.
    fn origin_and_clone(base: &Path) -> (PathBuf, PathBuf) {
        let origin = git_repo(base, "origin");
        let checkout = base.join("checkout");
        let out = std::process::Command::new("git")
            .args(["clone", "-q"])
            .arg(&origin)
            .arg(&checkout)
            .output()
            .unwrap();
        assert!(out.status.success(), "clone: {}", String::from_utf8_lossy(&out.stderr));
        (origin, checkout)
    }

    #[test]
    fn remote_refresh_reads_mains_tip_and_brings_its_objects() {
        // The land/tag refresh must fetch, not just ls-remote: a sha the checkout
        // does not hold is not an operand `merge-base` can walk, and the behind
        // probe would fail into a false Diverged.
        let base = scratch("refresh");
        let (origin, checkout) = origin_and_clone(&base);
        let tip = commit(&origin, "breakglasspush");
        assert!(!has_commit(&checkout, &tip), "precondition: not fetched yet");
        assert_eq!(origin_main(&checkout, OriginRef::Remote), Some(tip.clone()));
        assert!(has_commit(&checkout, &tip), "the refresh must bring the objects, not just the sha");
    }

    #[test]
    fn remote_refresh_sees_a_break_glass_push_the_tracking_ref_still_hides() {
        // Why `Remote` exists: with MirrorAhead quiet, a stale tracking ref would
        // read this as the healthy ahead and say nothing. The refresh is what
        // keeps the real #243 case loud at the two verbs that push.
        let base = scratch("refresh-behind");
        let (origin, checkout) = origin_and_clone(&base);
        let mirror_sha = git(&checkout, &["rev-parse", "HEAD"]);
        let mirror = git_repo(&base, "mirror");
        // Seed the mirror from `origin` — a clone carries only `main`.
        fetch(&mirror, &origin, "base");
        commit(&origin, "breakglasspush");

        let stale = origin_main(&checkout, OriginRef::Tracking).expect("tracking ref");
        assert_eq!(
            mirror_ancestry(&checkout, &mirror, &mirror_sha, &stale),
            Ancestry::Same,
            "the stale tracking ref cannot see the push"
        );

        let fresh = origin_main(&checkout, OriginRef::Remote).expect("refresh");
        assert_eq!(
            mirror_ancestry(&checkout, &mirror, &mirror_sha, &fresh),
            Ancestry::MirrorBehind,
            "a fetched origin must read as behind — not as a false Diverged"
        );
    }

    #[test]
    fn remote_refresh_falls_back_to_the_tracking_ref_when_origin_is_unreachable() {
        // Offline: fall back rather than failing the verb the guard is advising.
        let base = scratch("refresh-offline");
        let checkout = git_repo(&base, "checkout");
        let sha = git(&checkout, &["rev-parse", "HEAD"]);
        git(&checkout, &["update-ref", "refs/remotes/origin/main", &sha]);
        assert_eq!(origin_main(&checkout, OriginRef::Remote), Some(sha));
    }

    #[test]
    fn ancestry_diverged_when_no_repo_holds_the_mirror_commit() {
        // Nothing can answer: the probe fails in both oracles and folds into the
        // safe, loud answer rather than erroring.
        let base = scratch("missing");
        let checkout = git_repo(&base, "checkout");
        let mirror = git_repo(&base, "mirror");
        let origin_sha = git(&checkout, &["rev-parse", "HEAD"]);
        let ghost = "d15f24799f5a1a91f5f821f14190625143e829e5";
        assert_eq!(mirror_ancestry(&checkout, &mirror, ghost, &origin_sha), Ancestry::Diverged);
    }

    // -----------------------------------------------------------------------
    // paths — position root vs. shared-store checkout (#287)
    // -----------------------------------------------------------------------

    /// A keyed primary with one finalized change plus a spawned lane — the
    /// smallest real Workspace pair that reproduces #287. Built entirely inside
    /// `scratch`, via explicit `open_at` paths (never a cwd walk, so the test
    /// can never touch a real `.loot`).
    fn primary_and_lane(tag: &str) -> (PathBuf, Workspace, PathBuf, Workspace) {
        let base = scratch(tag);
        let primary = base.join("primary");
        Workspace::init_at(&primary, "connor").unwrap();
        loot_identity::generate_and_save(&primary.join(".loot"), "connor@loot").unwrap();
        let mut ws = Workspace::open_at(&primary).unwrap();
        ws.start_fresh_change().unwrap();
        std::fs::write(primary.join("base.txt"), b"base").unwrap();
        ws.snapshot("base").unwrap();
        ws.finalize_working().unwrap();
        let spawned = ws.spawn_lane(None, Some(&base.join("t287"))).unwrap();
        let lane_dir = spawned.dir.clone();
        let lane_ws = Workspace::open_at(&lane_dir).unwrap();
        (primary, ws, lane_dir, lane_ws)
    }

    fn canon(p: &Path) -> PathBuf {
        std::fs::canonicalize(p).unwrap_or_else(|e| panic!("canonicalize {}: {e}", p.display()))
    }

    #[test]
    fn the_pre_land_gate_runs_in_the_landing_positions_tree_not_the_shared_stores() {
        // #287: `ws.dot()` is the SHARED store's `.loot`, so deriving the gate
        // root from it made `run_pre_land_tests` compile-and-test the primary
        // checkout's (possibly stale) tree when landing from a lane — the #284
        // land was validated only because the operator had run the suite in the
        // lane by hand. The gate (and the relay push cwd) must be the landing
        // position's own tree.
        let (primary, _ws, lane_dir, lane_ws) = primary_and_lane("287-gate-root");
        let p = paths(&lane_ws);
        assert_eq!(
            canon(&p.position),
            canon(&lane_dir),
            "the pre-land gate must run in the lane tree, not the primary checkout"
        );
        // The checkout stays the primary on purpose: it is the only position
        // with a `.git`, and the drift guard's origin reads and the pre-commit
        // hook live there.
        assert_eq!(canon(&p.checkout), canon(&primary), "git/gh reads stay on the checkout");
    }

    #[test]
    fn on_the_primary_the_position_and_the_checkout_are_the_same_directory() {
        // The primary is the degenerate case: its tree IS the checkout, so the
        // #287 split must not move anything for a primary land.
        let (primary, ws, _lane_dir, _lane_ws) = primary_and_lane("287-primary");
        let p = paths(&ws);
        assert_eq!(canon(&p.position), canon(&primary));
        assert_eq!(canon(&p.checkout), canon(&primary));
    }

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
            lane_owner: "",
            position: "",
            ambient_dock: ambient,
            tracked_dock: lane_dock,
            reviewed_version: reviewed,
            current_version: current,
            current_subject: None,
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
            lane_owner: "",
            position: "",
            ambient_dock: "loot-first",
            tracked_dock: "main",
            reviewed_version: None,
            current_version: None,
            current_subject: None,
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

    #[test]
    fn gate_refuses_resolve_placeholder_subject() {
        // #316: a bounced land resolved via `loot resolve` mints "resolve
        // conflict at <path>" (engine.rs) as the change's message. Landing it
        // as-is would carry that placeholder onto git main's permanent log
        // instead of the change's real described subject — refuse and name
        // the fix, mirroring the #174 `(working change)` precedent.
        let f = FakeForge::new().with_view(view(ReviewDecision::Approved, "someone", PrState::Open));
        let facts = LandFacts {
            current_subject: Some("resolve conflict at crates/loot-cli/src/main.rs"),
            ..facts("ferry", "ferry", None, None)
        };
        let Gate::Refuse(why) = land_gate(&f, &facts).unwrap() else {
            panic!("expected refuse");
        };
        assert!(why.contains("loot describe"), "{why}");
        assert!(why.contains("resolve conflict at crates/loot-cli/src/main.rs"), "{why}");
    }

    #[test]
    fn gate_proceeds_on_a_real_described_subject() {
        // A normal subject — even one that happens to be about a "resolve" —
        // must not trip the #316 guard; only the exact auto-minted prefix does.
        let f = FakeForge::new().with_view(view(ReviewDecision::Approved, "someone", PrState::Open));
        let facts = LandFacts {
            current_subject: Some("loot status: show ambient dock and pending PR (#7)"),
            ..facts("ferry", "ferry", None, None)
        };
        assert_eq!(land_gate(&f, &facts).unwrap(), Gate::Proceed { self_fast_path: false });
    }

    fn no_sleep() -> impl FnMut() {
        || {}
    }

    #[test]
    fn gate_refuses_a_land_from_another_position() {
        // #281: the PR was opened from lane t67; landing it from anywhere else
        // (here: the primary) would finalize the *wrong* position's working
        // change and collapse t67's branch over work it never reviewed. The
        // dock guard can't catch this — every lane's home dock is `main`.
        let f = FakeForge::new().with_view(view(ReviewDecision::Approved, "someone", PrState::Open));
        let facts = LandFacts { lane_owner: "t67", ..facts("main", "main", None, None) };
        let Gate::Refuse(why) = land_gate(&f, &facts).unwrap() else {
            panic!("expected refuse");
        };
        assert!(why.contains("lane 't67'") && why.contains("the primary"), "{why}");
    }

    #[test]
    fn gate_allows_the_owning_lane_to_land() {
        // The same PR lands fine from the position that opened it.
        let f = FakeForge::new().with_view(view(ReviewDecision::Approved, "someone", PrState::Open));
        let facts =
            LandFacts { lane_owner: "t67", position: "t67", ..facts("main", "main", None, None) };
        assert_eq!(land_gate(&f, &facts).unwrap(), Gate::Proceed { self_fast_path: false });
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

    // -----------------------------------------------------------------------
    // already_projected_unpushed — the #195 guard's #349 blind spot
    // -----------------------------------------------------------------------

    /// A mirror seeded from the checkout's `main`, sharing lineage — the shape
    /// ferry leaves behind. Initialized on a throwaway unborn branch so the
    /// fetch may write `refs/heads/main`, then switched onto it.
    fn mirror_of(base: &Path, checkout: &Path) -> PathBuf {
        let dir = base.join("mirror");
        std::fs::create_dir_all(&dir).unwrap();
        git(&dir, &["init", "-q", "-b", "seed"]);
        git(&dir, &["config", "user.email", "t@loot.test"]);
        git(&dir, &["config", "user.name", "loot test"]);
        git(&dir, &["fetch", "-q", checkout.to_str().unwrap(), "refs/heads/main:refs/heads/main"]);
        git(&dir, &["checkout", "-q", "main"]);
        dir
    }

    /// An empty commit whose message carries the `Loot-Change-Id` trailer a
    /// ferry projection mints — the mirror-side shape of a projected change.
    fn projected_commit(repo: &Path, change_hex: &str) -> String {
        let msg = format!("a projected change\n\nLoot-Change-Id: {change_hex}");
        git(repo, &["commit", "-q", "--allow-empty", "-m", &msg]);
        git(repo, &["rev-parse", "HEAD"])
    }

    /// The #349 repro at the decision seam: describe → a pre-land bare ferry
    /// projected the signed line onto mirror main → land's own ferry no-ops
    /// (main does not move within the invocation) — but the mirror is strictly
    /// ahead of origin/main and carries this land's tip, so the land must
    /// proceed to the owed push + collapse instead of refusing and wedging.
    #[test]
    fn already_projected_line_ahead_of_origin_reads_as_landable() {
        let base = scratch("349-already-projected");
        let checkout = git_repo(&base, "checkout");
        let origin_sha = git(&checkout, &["rev-parse", "HEAD"]);
        git(&checkout, &["update-ref", "refs/remotes/origin/main", &origin_sha]);
        let mirror = mirror_of(&base, &checkout);
        let tip = "ab".repeat(32);
        let main_sha = projected_commit(&mirror, &tip);
        assert!(
            already_projected_unpushed(&checkout, &mirror, &main_sha, Some(&tip)),
            "mirror ahead of origin/main and carrying this land's tip = push owed, not a refusal"
        );
    }

    #[test]
    fn a_mirror_matching_origin_is_genuinely_nothing_to_land() {
        // The refusal the #195 guard exists for must stand: mirror main ==
        // origin/main == before — nothing new projected, nothing unpushed.
        let base = scratch("349-nothing-to-land");
        let checkout = git_repo(&base, "checkout");
        let origin_sha = git(&checkout, &["rev-parse", "HEAD"]);
        git(&checkout, &["update-ref", "refs/remotes/origin/main", &origin_sha]);
        let mirror = mirror_of(&base, &checkout);
        assert!(!already_projected_unpushed(&checkout, &mirror, &origin_sha, Some(&"ab".repeat(32))));
    }

    #[test]
    fn an_ahead_line_that_is_not_this_lands_does_not_unlock_the_land() {
        // A sibling's unpushed projection makes the mirror ahead — but this
        // land's tip is absent from main, so pushing would green-lie exactly
        // the way #195 forbids.
        let base = scratch("349-siblings-line");
        let checkout = git_repo(&base, "checkout");
        let origin_sha = git(&checkout, &["rev-parse", "HEAD"]);
        git(&checkout, &["update-ref", "refs/remotes/origin/main", &origin_sha]);
        let mirror = mirror_of(&base, &checkout);
        let main_sha = projected_commit(&mirror, &"cd".repeat(32));
        assert!(!already_projected_unpushed(&checkout, &mirror, &main_sha, Some(&"ab".repeat(32))));
    }

    #[test]
    fn an_already_pushed_tip_behind_a_siblings_projection_does_not_unlock_the_land() {
        // The #367 variant of the green lie: this land's tip is already
        // published (its trailer commit IS origin/main), and a sibling's
        // unpushed projection sits ahead of it on the mirror. All three
        // conditions of the unbounded walk would pass — and the land would
        // push the sibling's projected-but-unlanded line. Bounding the
        // trailer walk to `origin/main..main` must read this as "nothing
        // unpushed of OURS" and keep the refusal.
        let base = scratch("367-pushed-tip-sibling-ahead");
        let checkout = git_repo(&base, "checkout");
        let tip = "ab".repeat(32);
        let ours_pushed = projected_commit(&checkout, &tip);
        git(&checkout, &["update-ref", "refs/remotes/origin/main", &ours_pushed]);
        let mirror = mirror_of(&base, &checkout);
        let main_sha = projected_commit(&mirror, &"cd".repeat(32));
        assert!(
            !already_projected_unpushed(&checkout, &mirror, &main_sha, Some(&tip)),
            "a tip reachable from origin/main owes no push — the ahead line is the sibling's"
        );
    }

    #[test]
    fn no_origin_ref_keeps_the_conservative_refusal() {
        // Unprovable = refuse: with no origin/main to compare against, "ahead"
        // cannot be established and the old guard's verdict stands.
        let base = scratch("349-no-origin");
        let checkout = git_repo(&base, "checkout");
        let mirror = mirror_of(&base, &checkout);
        let tip = "ab".repeat(32);
        let main_sha = projected_commit(&mirror, &tip);
        assert!(!already_projected_unpushed(&checkout, &mirror, &main_sha, Some(&tip)));
    }

    #[test]
    fn a_diverged_mirror_keeps_the_conservative_refusal() {
        // origin/main advanced past the fork with a commit the mirror never
        // ingested: the mirror is not strictly ahead, so nothing here is a
        // clean fast-forward push — refuse as before.
        let base = scratch("349-diverged");
        let checkout = git_repo(&base, "checkout");
        let mirror = mirror_of(&base, &checkout);
        let origin_sha = commit(&checkout, "originside");
        git(&checkout, &["update-ref", "refs/remotes/origin/main", &origin_sha]);
        let tip = "ab".repeat(32);
        let main_sha = projected_commit(&mirror, &tip);
        assert!(!already_projected_unpushed(&checkout, &mirror, &main_sha, Some(&tip)));
    }

    #[test]
    fn a_land_with_no_finalized_tip_keeps_the_conservative_refusal() {
        let base = scratch("349-no-tip");
        let checkout = git_repo(&base, "checkout");
        let origin_sha = git(&checkout, &["rev-parse", "HEAD"]);
        git(&checkout, &["update-ref", "refs/remotes/origin/main", &origin_sha]);
        let mirror = mirror_of(&base, &checkout);
        let main_sha = projected_commit(&mirror, &"ab".repeat(32));
        assert!(!already_projected_unpushed(&checkout, &mirror, &main_sha, None));
    }

    #[test]
    fn landing_merged_by_reachability() {
        let f = FakeForge::new().with_poll(vec![PrState::Merged]);
        let mut s = no_sleep();
        let st =
            execute_landing(&f, 218, "deadbeef", "review/ferry", "abc1234567", 10, &mut s).unwrap();
        assert_eq!(st, LandingStatus::Merged);
        let calls = f.calls();
        assert!(calls.iter().any(|c| c.contains("push refs/heads/main:refs/heads/main")));
        assert!(calls.iter().any(|c| c.contains("push abc1234567:refs/heads/review/ferry force=true")));
        assert!(calls.iter().any(|c| c.starts_with("comment_pr #218")));
        // Provisional branch cleaned up.
        assert!(calls.iter().any(|c| c.contains("push :refs/heads/review/ferry")));
    }

    #[test]
    fn landing_collapses_the_lane_named_branch() {
        // A lane-opened PR's head is review/<lane-id> (#281): the collapse and
        // the cleanup must target the branch the pr-map lane names, not the
        // dock (every lane's dock is `main`).
        let f = FakeForge::new().with_poll(vec![PrState::Merged]);
        let mut s = no_sleep();
        let st =
            execute_landing(&f, 281, "deadbeef", "review/t281", "abc1234567", 10, &mut s).unwrap();
        assert_eq!(st, LandingStatus::Merged);
        let calls = f.calls();
        assert!(calls.iter().any(|c| c.contains("push abc1234567:refs/heads/review/t281 force=true")));
        assert!(calls.iter().any(|c| c.contains("push :refs/heads/review/t281")));
    }

    #[test]
    fn landing_auto_close_is_the_signal() {
        let f = FakeForge::new().with_poll(vec![PrState::Open, PrState::Closed]);
        let mut s = no_sleep();
        let st =
            execute_landing(&f, 218, "deadbeef", "review/ferry", "abc1234567", 10, &mut s).unwrap();
        assert_eq!(st, LandingStatus::ClosedByCollapse);
        assert!(f.calls().iter().any(|c| c.contains("auto-closed on the zero-diff collapse")));
    }

    #[test]
    fn landing_diverged_main_closes_with_pointer() {
        let f = FakeForge::new().failing_push("refs/heads/main:refs/heads/main");
        let mut s = no_sleep();
        let st =
            execute_landing(&f, 218, "deadbeef", "review/ferry", "abc1234567", 10, &mut s).unwrap();
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
        let st =
            execute_landing(&f, 218, "deadbeef", "review/ferry", "abc1234567", 3, &mut s).unwrap();
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
