//! `loot ferry` — the bidirectional loot ↔ git mirror driver (GB1, ADR 0028).
//!
//! One deliberate pass: **ingest** git-native commits from the mirrored branch
//! as loot changes (sealing at ingest via `.lootattributes`), **reconcile**
//! them into the ambient dock with loot's converge classifier (loot is the
//! merge authority — git never merges), then **project** every travel-worthy
//! loot change to a git commit carrying `Loot-*` trailers, with every head
//! reachable under `refs/loot/heads/*` and `refs/heads/main` tracking the
//! designated dock. Sealed / unreadable paths are omitted from git entirely.
//!
//! The spine is the mark map (sha ↔ change-id ↔ origin) plus last-synced
//! pointers, both local-only under `.loot/git-mirror/` and rebuildable from
//! trailers. The pure formats live in `loot_core::bridge`; this module owns
//! the git2 plumbing.

use crate::workspace::Workspace;
use loot_core::bridge::{
    self, FerryState, MarkMap, MarkOrigin, TRAILER_AUTHOR, TRAILER_CHANGE_ID, TRAILER_GIT_AUTHOR,
    TRAILER_PREDECESSORS, TRAILER_PROVISIONAL, TRAILER_SIGNATURE,
};
use loot_core::{hex, MergeOutcome, Oid, RepoError, Visibility};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The branch the bridge mirrors and ingests from (v1 watches exactly one).
const MAIN_REF: &str = "refs/heads/main";
/// SSHSIG namespace for git commit signing (what `git verify-commit` expects).
const GIT_SIG_NAMESPACE: &str = "git";

/// What one ferry pass did, for CLI reporting.
#[derive(Default)]
pub struct FerryReport {
    /// git-native commits ingested as loot changes.
    pub ingested: usize,
    /// loot changes projected as git commits.
    pub projected: usize,
    /// Per-path outcomes when the pass had to merge diverged sides.
    pub outcomes: BTreeMap<PathBuf, MergeOutcome>,
    /// Human-relevant events (baseline adoption, skipped main update, ...).
    pub notes: Vec<String>,
    /// The WIP review projection this pass made (map #148), preformatted as a
    /// stable machine-parsable line for the orchestrator.
    pub review: Option<String>,
}

/// Run one ferry pass. `git_dir_flag`/`dock_flag` override the mirror config
/// under `.loot/git-mirror/config`; the override persists only when a full
/// pass succeeds (#201 — a failed probe must not rebind).
///
/// Two modes (ADR 0039):
///
/// - **`with_wip == false`** — the full bidirectional reconcile: ingest new
///   git-native commits, reconcile them into the ambient dock (the carry —
///   one commit per change), project every travel-worthy change, and advance
///   the mirror's `main`.
/// - **`with_wip == true`** — the **review projection, and nothing else**:
///   project the ambient dock's *unfinalized* working change as a provisional
///   commit (map #148) on `refs/heads/review/<lane-id>` — `review/<dock>` on
///   the primary, so concurrent lanes never share a review ref (#281). No
///   ingest, no reconcile, no mirror-`main` advance, no projection of other
///   changes, and the bridge spine (marks/state/config) is not rewritten: a
///   review pass is read-only with respect to the dock tip and the mirror's
///   `main`, which is what lets a lane behind git `main` review normally
///   instead of stranding (#292's `REFUSE_REVIEW_STALE_ANCHOR`, now gone).
///
/// Provisional lifecycle reaping runs on every pass regardless of the flag —
/// it touches only `review/*` refs and the local wip ledger, never the spine.
pub fn run(
    ws: &mut Workspace,
    git_dir_flag: Option<&str>,
    dock_flag: Option<&str>,
    with_wip: bool,
) -> Result<FerryReport, String> {
    let mut report = FerryReport::default();
    let mirror_dir = ws.store().git_mirror_dir();
    std::fs::create_dir_all(&mirror_dir).map_err(|e| format!("create {}: {e}", mirror_dir.display()))?;

    // --- config: where the mirror lives, which dock main tracks ---
    let cfg_path = ws.store().git_config();
    let mut cfg = crate::kv::parse(&read_or_empty(&cfg_path));
    if let Some(dir) = git_dir_flag {
        cfg.insert("gitdir".into(), dir.into());
    }
    if let Some(dock) = dock_flag {
        // Designating a *non-main* dock for git-main is retired (#253/ADR 0034):
        // named docks are gone, so git-main tracks the primary. `--dock main` is
        // the harmless default; anything else can no longer name a live position.
        if dock != "main" {
            return Err(format!(
                "designating dock '{dock}' for git-main is retired (#253/ADR 0034) — \
                 git-main tracks the primary. Drop `--dock {dock}`."
            ));
        }
        cfg.insert("dock".into(), "main".into());
    }
    let git_dir = resolve_gitdir(
        cfg.get("gitdir")
            .ok_or("no mirror bound — run `loot ferry --git-dir <path>` once to bind one")?,
        ws.store().dot(),
    );
    // The config persists with the spine at the END of the pass, not here: a
    // flag on a run that then fails must not rebind future bare passes (#201
    // — a failed `--dock` probe silently retargeted main at a stale dock tip,
    // and every later ferry rewrote the mirror's main backward from it).

    // --- open (or create, bare) the git side ---
    let git = match git2::Repository::open(&git_dir) {
        Ok(r) => r,
        Err(_) if !Path::new(&git_dir).exists() => {
            report.notes.push(format!("initialized bare mirror at {git_dir}"));
            git2::Repository::init_bare(&git_dir).map_err(|e| format!("init mirror: {e}"))?
        }
        Err(e) => return Err(format!("open git mirror {git_dir}: {e}")),
    };

    // --- identity map + allowed-signers (seeded once, kept local) ---
    let mut id_map = crate::kv::parse(&read_or_empty(&ws.store().git_identity_map()));
    if let Some(pk) = ws.author_pubkey() {
        let pk_hex = hex::encode(&pk);
        if !id_map.contains_key(&pk_hex) {
            let (name, email) = self_name_email(ws, &git);
            id_map.insert(pk_hex, format!("{name} <{email}>"));
            write_spine(&ws.store().git_identity_map(), &crate::kv::encode(&id_map))?;
        }
        if let Some(pub_line) = ws.public_key_openssh() {
            let (_, email) = self_name_email(ws, &git);
            let signers = format!("{email} namespaces=\"{GIT_SIG_NAMESPACE}\" {pub_line}\n");
            std::fs::write(ws.store().git_allowed_signers(), signers)
                .map_err(|e| format!("write allowed-signers: {e}"))?;
        }
    }

    // --- marks + state (rebuild loot-origin marks from trailers if lost) ---
    let marks_path = ws.store().git_marks();
    let mut marks = if marks_path.exists() {
        MarkMap::parse(&read_or_empty(&marks_path))?
    } else {
        let rebuilt = rebuild_marks(ws, &git)?;
        if !rebuilt.is_empty() {
            report
                .notes
                .push(format!("rebuilt {} mark(s) from commit trailers", rebuilt.len()));
        }
        rebuilt
    };
    let state_path = ws.store().git_state();
    let had_state = state_path.exists();
    let mut state = FerryState::parse(&read_or_empty(&state_path))?;

    // Promote any due embargoed keys before reading content, as every
    // content-reading verb does (ADR 0007) — a due path projects readable.
    ws.flush_due_escrow()?;

    // Bootstrap: pre-bridge git history (no trailers, no state) is adopted as
    // the baseline, not ingested — the dogfood repo's dual-run past stays
    // git's. The baseline commit is marked as standing for the current dock
    // anchor, so later git-native commits on top of it parent-map exactly and
    // pre-bridge loot history is never re-projected as a parallel root.
    let main_tip = git
        .find_reference(MAIN_REF)
        .ok()
        .and_then(|r| r.target())
        .map(|o| o.to_string());
    // (Review mode never bootstraps: adopting a baseline writes the spine,
    // and a review pass leaves the spine alone — a fresh mirror simply has
    // no marks yet and the review below refuses with "run a plain ferry".)
    if !with_wip && !had_state && marks.is_empty() {
        if let (Some(sha), Some(anchor)) = (&main_tip, ws.finalized_anchor()) {
            state.git_main = Some(sha.clone());
            marks.insert(sha.clone(), anchor, MarkOrigin::Git);
            report.notes.push(format!(
                "adopted existing git history at {} as the pre-bridge baseline (not ingested)",
                &sha[..12.min(sha.len())]
            ));
        }
    }
    // The last-agreement tree, for holding conflicted paths at their last
    // clean state in git (captured before this pass moves the pointer).
    let last_clean_sha = state.git_main.clone();

    // --- ingest: new commits on the mirrored branch ---
    // Review mode skips the whole ingest → reconcile → project half: review
    // is a pure projection of the WIP (ADR 0039). The dock tip and mirror
    // `main` are read, never written, so a lane whose anchor fell behind git
    // `main` reviews from its own anchor marks instead of catching up.
    if let Some(tip) = main_tip.as_ref().filter(|_| !with_wip) {
        let new_shas = walk_new_commits(&git, tip, &marks, state.git_main.as_deref())?;
        // The loot side of the divergence check, pinned before ingest — an
        // ingested change becomes a graph head itself, so the post-ingest
        // anchor can't tell fast-forward from true divergence.
        let ours = ws.finalized_anchor();
        // Each ingest persists its change to the shared graph as it goes,
        // while the marks naming them persist only with the spine at the end
        // of the pass — so an abort anywhere between used to strand the
        // ingested changes as unmarked heads. The next pass re-walked and
        // re-ingested them (fresh ids), and worse: the next *snapshot* folded
        // the dangling head under the working change, making `anchor()` claim
        // the dock covers git main while the disk never materialized it
        // (#307). So an aborted pass rolls back what it minted — the changes
        // walk into the abandoned set, children first — and the spine stays
        // untouched (#201): the re-run simply redoes the ingest.
        let mut minted: Vec<Oid> = Vec::new();
        let mut ingest_err: Option<String> = None;
        for sha in &new_shas {
            if let Err(e) = ingest_commit(ws, &git, sha, &mut marks, &id_map, &mut minted, &mut report)
            {
                ingest_err = Some(e);
                break;
            }
        }
        if let Some(e) = ingest_err {
            return Err(rollback_note(ws.rollback_ingested(&minted), e));
        }
        let target = marks.change_for(tip).cloned().map(|(t, _)| t);

        // --- reconcile: advance the ambient dock to cover the git side ---
        // The whole decision — capture-first (unconditional: the reconcile may
        // materialize the target tree over the disk, so a live working change
        // is captured before it can be clobbered, #280; a capture that just
        // duplicates the incoming target — the co-located checkout after a
        // `git pull` — is recognized and dropped), adopt-vs-merge, which tip
        // advances — lives in Workspace::reconcile_onto (R2, #178); the bridge
        // only supplies the incoming line and its pinned anchor.
        // (Only the full pass reaches this — review mode never reconciles,
        // ADR 0039. The label survives solely as the merge subject of the
        // foreign-work fallback; a self-authored diverged line carries, so
        // nothing on landed history wears it.)
        report.outcomes = match ws.reconcile_onto(
            target.as_ref(),
            ours.as_ref(),
            "ferry: reconcile git main",
        ) {
            Ok(outcomes) => outcomes,
            // A reconcile refusal (#275) aborts the pass — roll the
            // freshly ingested changes back with it (#307, above).
            Err(e) => return Err(rollback_note(ws.rollback_ingested(&minted), e)),
        };
        // Past the reconcile the ingested changes are folded into the dock's
        // line — rollback is no longer safe, so their marks persist NOW,
        // not at end-of-pass: a later abort (projection, refs) must never
        // strand integrated changes unmarked (#307's "never one without the
        // other", the persist arm).
        if !minted.is_empty() {
            write_spine(&marks_path, &marks.encode())?;
        }
    }

    // --- project: every travel-worthy change gets a mirrored commit ---
    let last_clean_tree = last_clean_sha
        .as_deref()
        .and_then(|sha| git2::Oid::from_str(sha).ok())
        .and_then(|oid| git.find_commit(oid).ok())
        .and_then(|c| c.tree().ok());
    let generations = ws.graph().generations();
    // Everything a mark (or an ancestor of one) already stands for is
    // represented in git — marked changes map 1:1, and their ancestry is the
    // pre-bridge history the bootstrap baseline covers wholesale.
    // Review mode projects nothing here: advancing the mirror with signed
    // history is the full pass's job, and doing it from review was the
    // trigger half of the #349 pre-projection trap (ADR 0039).
    let represented = ws.graph().ancestor_closure(marks.change_ids());
    for id in ws.graph().ids_topo().into_iter().filter(|_| !with_wip) {
        if represented.contains(&id) {
            continue;
        }
        // The ephemeral working change never travels (ADR 0018).
        if ws.graph().author(&id).is_some() && ws.graph().signature(&id).is_none() {
            continue;
        }
        let (sha, skipped) = project_change(ws, &git, &id, &marks, &generations, last_clean_tree.as_ref(), &id_map)?;
        if !skipped.is_empty() {
            report.notes.push(format!(
                "publication of {} omitted {} sealed path(s): {}",
                hex::short(&id.0, 8),
                skipped.len(),
                skipped.join(", ")
            ));
        }
        marks.insert(sha, id, MarkOrigin::Loot);
        report.projected += 1;
    }

    // --- refs: heads, and git-main tracking the primary (full pass only) ---
    if !with_wip {
        update_loot_refs(ws, &git, &marks)?;
    }
    // git-main tracks the primary's finalized anchor (#253/ADR 0034): named docks
    // are retired, so there is no other position's tip to designate.
    let main_target = ws.finalized_anchor().filter(|_| !with_wip);
    if let Some(tip_change) = main_target {
        if let Some(sha) = marks.sha_for(&tip_change) {
            let oid = git2::Oid::from_str(sha).map_err(|e| e.to_string())?;
            let main_checked_out = !git.is_bare()
                && git.head().ok().and_then(|h| h.name().map(String::from)).as_deref()
                    == Some(MAIN_REF);
            if main_checked_out {
                report.notes.push(
                    "main is checked out in the mirror — left to git (refs/loot/* updated)".into(),
                );
            } else if let Some(cur) = git
                .find_reference(MAIN_REF)
                .ok()
                .and_then(|r| r.target())
                .filter(|cur| *cur != oid && !git.graph_descendant_of(oid, *cur).unwrap_or(false))
            {
                // Fast-forward only (#201): the published branch is append-only
                // to everything downstream (the GitHub push rejects a regression
                // anyway) — a target that does not descend from the current tip
                // means the primary was settled backward (e.g. `loot adopt
                // <older>`), so say so instead of silently moving main backward.
                report.notes.push(format!(
                    "main NOT moved to {} — it does not descend from the current tip {}; \
                     was the primary settled onto an older change? see .loot/git-mirror/config",
                    &sha[..12.min(sha.len())],
                    &cur.to_string()[..12]
                ));
            } else {
                git.reference(MAIN_REF, oid, true, "loot ferry")
                    .map_err(|e| format!("update main: {e}"))?;
                if git.is_bare() {
                    let _ = git.set_head(MAIN_REF);
                }
            }
        }
    }

    // --- review lane: provisional WIP projection + lifecycle reap (#148) ---
    //
    // The lane is keyed by the *durable* change id (map #132) so it survives
    // every re-snapshot; entries live in `.loot/git-mirror/wip`, deliberately
    // outside the mark map — nothing provisional ever enters the round-trip
    // spine. Reaping is lazy and runs on every pass: `loot new` stays
    // git-quiet, and the next ferry notices the lane's change id is now
    // signed (landed) or gone (abandoned/superseded) and retires the ref.
    let wip_path = ws.store().git_wip();
    let mut wip = WipState::parse(&read_or_empty(&wip_path));
    let dock_sel_wip = |name: &str| if name == "main" { None } else { Some(name.to_string()) };
    // This position's owner key: the isolation-lane id, empty on the primary.
    // Entries are owner-scoped (#281): only the position that projected an
    // entry can judge its liveness, because the judgment reads *positional*
    // state (the dock's current working change) and a foreign position's read
    // sees its own dock, not the owner's — the misjudgment that let one
    // lane's pass reap another's live review ref.
    let mine = ws.lane_id().unwrap_or("").to_string();
    wip.entries.retain(|e| {
        if e.owner != mine {
            // Foreign entry: keep it while its owner position still exists;
            // reap it (ref and all) once the owner lane is gone from the
            // registry — an abandoned lane's review lane dies with it. The
            // primary (empty owner) always exists.
            if e.owner.is_empty() || ws.store().lane_entry_exists(&e.owner) {
                return true;
            }
            let handle = e.review_handle();
            if let Ok(mut r) = git.find_reference(&format!("refs/heads/review/{handle}")) {
                let _ = r.delete();
            }
            report.notes.push(format!(
                "reaped review/{handle} (change {} — lane '{}' is gone)",
                &e.change[..8.min(e.change.len())],
                e.owner
            ));
            return false;
        }
        // A lane is live iff its dock's *current* working change still carries
        // this change id and is unfinalized (ADR 0033). The old change-id-wide
        // "a signed version exists" test reaped a reopened lane every pass:
        // after `loot edit`, the superseded signed X still exists under the
        // change id forever (ADR 0018), so it stayed true even though the dock
        // had reopened the change (as a live working change X′) to re-review.
        let current = ws
            .store()
            .read_working(dock_sel_wip(&e.dock).as_deref())
            .map(|w| wip_key(ws, &w));
        let live = current.as_deref() == Some(e.change.as_str());
        if !live {
            // Reap reason, for the note only: a signed version under this
            // change id means it landed; otherwise it was abandoned/superseded.
            let landed = ws.graph().ids_topo().iter().any(|c| {
                ws.graph().signature(c).is_some()
                    && ws.graph().author(c).is_some()
                    && wip_key(ws, c) == e.change
            });
            let handle = e.review_handle();
            if let Ok(mut r) = git.find_reference(&format!("refs/heads/review/{handle}")) {
                let _ = r.delete();
            }
            report.notes.push(format!(
                "reaped review/{handle} (change {} {})",
                &e.change[..8.min(e.change.len())],
                if landed { "landed" } else { "abandoned or superseded" }
            ));
        }
        live
    });

    if with_wip {
        // Ferry is a mutating verb in this mode: capture the ambient tree
        // first through the same proof-of-capture door every snapshotting verb
        // uses (ADR 0030, #182) — the tree-hash short-circuit makes an
        // unchanged tree a no-op, and the demotion guard applies exactly as on
        // any snapshot (#135). The handle drops immediately; the projection
        // below reads the captured working change.
        let _ = ws.snapshotted(&crate::workspace::SnapshotOpts::default())?;
        match ws.working_id().cloned() {
            None => {
                report.review =
                    Some("review: op=none (no working change to project)".to_string());
            }
            Some(wid) => {
                let key = wip_key(ws, &wid);
                let dock = ws.dock_name().to_string();
                // The projected ref carries the *position*, not the dock
                // (#281): every lane's home dock is `main`, so a dock-named
                // ref is one shared branch with N writers — the second lane's
                // ferry force-pushed over the first's in-flight PR head. The
                // owner token in the review line is `-` on the primary.
                let handle = crate::ledger::review_handle(&mine, &dock).to_string();
                let owner_tok = if mine.is_empty() { "-" } else { mine.as_str() };
                let version_hex = hex::encode(&wid.0);
                let existing = wip
                    .entries
                    .iter()
                    .find(|e| e.owner == mine && e.dock == dock && e.change == key)
                    .cloned();
                if existing.as_ref().is_some_and(|e| e.version == version_hex) {
                    let e = existing.as_ref().unwrap();
                    report.review = Some(format!(
                        "review: dock={dock} owner={owner_tok} branch=review/{handle} sha={} change={key} version={} round={} op=up-to-date",
                        e.sha, &version_hex[..8], e.round
                    ));
                } else {
                    // Round 1 parents = the working change's marked graph
                    // parents (so the PR diffs against main); later rounds
                    // append onto the previous provisional commit (#150).
                    let (parent_shas, round) = match &existing {
                        Some(e) => (vec![e.sha.clone()], e.round + 1),
                        None => {
                            let mut shas = Vec::new();
                            for p in ws.graph().parents(&wid) {
                                match marks.sha_for(&p) {
                                    Some(s) => shas.push(s.to_string()),
                                    None => {
                                        return Err(format!(
                                            "review: working parent {} has no mirrored commit — \
                                             run a plain `loot ferry` first",
                                            hex::short(&p.0, 8)
                                        ))
                                    }
                                }
                            }
                            (shas, 1u64)
                        }
                    };
                    // An empty first round is nothing reviewable yet.
                    let parent_tree_same = ws
                        .graph()
                        .parents(&wid)
                        .first()
                        .and_then(|p| ws.graph().tree(p))
                        == ws.graph().tree(&wid);
                    if existing.is_none() && parent_tree_same {
                        report.review = Some(
                            "review: op=none (working tree matches the anchor — nothing to review)"
                                .to_string(),
                        );
                    } else {
                        let (sha, skipped) = project_wip(
                            ws,
                            &git,
                            &wid,
                            &parent_shas,
                            &generations,
                            last_clean_tree.as_ref(),
                            &id_map,
                        )?;
                        if !skipped.is_empty() {
                            report.notes.push(format!(
                                "review projection omitted {} sealed path(s): {}",
                                skipped.len(),
                                skipped.join(", ")
                            ));
                        }
                        let ref_name = format!("refs/heads/review/{handle}");
                        git.reference(
                            &ref_name,
                            git2::Oid::from_str(&sha).map_err(|e| e.to_string())?,
                            true,
                            "loot ferry --with-wip",
                        )
                        .map_err(|e| format!("update {ref_name}: {e}"))?;
                        wip.entries
                            .retain(|e| !(e.owner == mine && e.dock == dock && e.change == key));
                        wip.entries.push(WipEntry {
                            change: key.clone(),
                            dock: dock.clone(),
                            sha: sha.clone(),
                            version: version_hex.clone(),
                            round,
                            owner: mine.clone(),
                        });
                        report.review = Some(format!(
                            "review: dock={dock} owner={owner_tok} branch=review/{handle} sha={sha} change={key} version={} round={round} op={}",
                            &version_hex[..8],
                            if round == 1 { "opened" } else { "appended" }
                        ));
                    }
                }
            }
        }
    }
    write_spine(&wip_path, &wip.encode())?;

    // --- persist the spine (full pass only) ---
    // A review pass writes the wip ledger above and nothing else: persisting
    // `state.git_main` without having ingested would teach the next full pass
    // to skip commits it never saw, and a rebuilt-in-memory mark map is
    // simply rebuilt again (ADR 0039's read-only pin).
    if !with_wip {
        state.git_main = git
            .find_reference(MAIN_REF)
            .ok()
            .and_then(|r| r.target())
            .map(|o| o.to_string());
        state.loot_heads = ws.heads();
        write_spine(&marks_path, &marks.encode())?;
        write_spine(&state_path, &state.encode())?;
        write_spine(&cfg_path, &crate::kv::encode(&cfg))?;
    }
    Ok(report)
}

// --- release tags (#256) ---

/// Mint an annotated tag in the git mirror pointing at the projected `main`
/// tip — the sealed-free commit `loot ferry` publishes (ADR 0028). This is the
/// mirror-side half of the tag-push ferry verb (#256): it creates the tag
/// *object* in the local harbor mirror; the single-ref push that carries it to
/// GitHub (so cargo-dist's `release.yml` fires) lives in `loot-first`, because
/// loot itself never talks to GitHub (workflow.md invariant).
///
/// The tag can only ever point at `refs/heads/main`, which projection builds
/// sealed-free (sealed paths are omitted from every projected commit), so a
/// pushed release tag never widens the public boundary — it references bytes
/// already published on `main`. Refuses when the mirror or its `main` is absent
/// (nothing has been projected yet), or when a tag of this name already exists
/// (a release tag is never clobbered). Returns the tagged commit sha.
pub fn tag_projected_main(ws: &Workspace, name: &str, message: &str) -> Result<String, String> {
    let cfg = crate::kv::parse(&read_or_empty(&ws.store().git_config()));
    let git_dir = resolve_gitdir(
        cfg.get("gitdir")
            .ok_or("no mirror bound — run `loot ferry` to project main before tagging")?,
        ws.store().dot(),
    );
    let git = git2::Repository::open(&git_dir)
        .map_err(|e| format!("open git mirror {git_dir}: {e}"))?;
    let main_oid = git
        .find_reference(MAIN_REF)
        .ok()
        .and_then(|r| r.target())
        .ok_or("mirror main has no tip — run `loot ferry` to project a change first")?;
    let tag_ref = format!("refs/tags/{name}");
    if git.find_reference(&tag_ref).is_ok() {
        return Err(format!(
            "tag '{name}' already exists in the mirror — pick a fresh version, \
             or delete the tag if you are re-cutting it"
        ));
    }
    let target = git
        .find_object(main_oid, Some(git2::ObjectType::Commit))
        .map_err(|e| format!("resolve main commit {main_oid}: {e}"))?;
    let (name_, email) = self_name_email(ws, &git);
    let tagger = git2::Signature::now(&name_, &email).map_err(|e| e.to_string())?;
    git.tag(name, &target, &tagger, message, /* force */ false)
        .map_err(|e| format!("create tag '{name}': {e}"))?;
    Ok(main_oid.to_string())
}

// --- ingest ---

/// The mirrored branch's commits not yet known to the bridge, parents first.
fn walk_new_commits(
    git: &git2::Repository,
    tip: &str,
    marks: &MarkMap,
    baseline: Option<&str>,
) -> Result<Vec<String>, String> {
    let mut rw = git.revwalk().map_err(|e| e.to_string())?;
    rw.set_sorting(git2::Sort::TOPOLOGICAL | git2::Sort::REVERSE)
        .map_err(|e| e.to_string())?;
    rw.push(git2::Oid::from_str(tip).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    for sha in marks.shas() {
        if let Ok(oid) = git2::Oid::from_str(sha) {
            let _ = rw.hide(oid);
        }
    }
    if let Some(sha) = baseline {
        if let Ok(oid) = git2::Oid::from_str(sha) {
            let _ = rw.hide(oid);
        }
    }
    let mut out = Vec::new();
    for oid in rw {
        out.push(oid.map_err(|e| e.to_string())?.to_string());
    }
    Ok(out)
}

/// Append the rollback's own outcome to an aborting pass's error: the abort
/// reason leads, and a rollback failure must not silently eat it (#307).
fn rollback_note(rollback: Result<(), String>, abort: String) -> String {
    match rollback {
        Ok(()) => abort,
        Err(re) => format!("{abort}\n(rolling back this pass's ingested changes also failed: {re})"),
    }
}

/// Ingest one new commit: a trailered commit maps straight back to its change
/// (lossless round-trip); a git-native commit becomes a loot change sealed at
/// ingest via `.lootattributes` (ADR 0028). A change recorded here is pushed
/// onto `minted` the moment it persists, so an aborting pass can roll it back
/// (#307) — even when the abort is this very call's signing step.
fn ingest_commit(
    ws: &mut Workspace,
    git: &git2::Repository,
    sha: &str,
    marks: &mut MarkMap,
    id_map: &BTreeMap<String, String>,
    minted: &mut Vec<Oid>,
    report: &mut FerryReport,
) -> Result<(), String> {
    if marks.contains_sha(sha) {
        return Ok(());
    }
    let commit = git
        .find_commit(git2::Oid::from_str(sha).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let message = String::from_utf8_lossy(commit.message_bytes()).to_string();

    // A provisional review commit must never enter the round-trip (map #148):
    // review/* sits outside ingest by construction, so meeting one on the
    // mirrored branch means a review branch was merged on the git side.
    if bridge::parse_trailer(&message, TRAILER_PROVISIONAL).is_some() {
        return Err(format!(
            "commit {}: carries {TRAILER_PROVISIONAL} — a provisional review commit reached the \
             mirrored branch; review lanes land through loot, never a git merge",
            &sha[..12]
        ));
    }

    // Trailer short-circuit: normally this commit *is* a loot change we still
    // hold, so re-mark it 1:1 (the lossless round-trip). If the change is *gone* —
    // pruned by gc after a land the primary never adopted (#263) — it cannot be
    // reconstructed byte-identically: a version-id hashes the tree's store-local,
    // randomly-addressed object oids (`sealed::seal` mints a fresh nonce per put),
    // which the projection does not carry. So instead of refusing, fall through to
    // the git-native path below and adopt the commit's *content* as a fresh change
    // marked as represented by this commit. Because it is marked, it is never
    // re-projected, so git `main` stays exactly where it is (no force-push); the
    // dock advances onto the recovered content and future work builds on it. This
    // is the baseline-anchor recovery — the same move the bootstrap makes for
    // pre-bridge history, extended to a trailered commit whose change was lost.
    if let Some(id_hex) = bridge::parse_trailer(&message, TRAILER_CHANGE_ID) {
        let id = bridge::parse_oid_hex(&id_hex)
            .ok_or_else(|| format!("commit {sha}: malformed {TRAILER_CHANGE_ID} trailer"))?;
        // The named change may sit outside this position's lineage-filtered
        // load (landed from a lane, #265) — pull its line in before judging it
        // absent, or a merely-out-of-view change re-mints as a duplicate (#307).
        if ws.load_shared_lineage(&id)? {
            marks.insert(sha.to_string(), id, MarkOrigin::Loot);
            return Ok(());
        }
        report.notes.push(format!(
            "loot change {} named by commit {} is absent (gc'd after an unadopted land, #263) — \
             adopting the commit's content as a fresh change; git main is unchanged",
            hex::short(&id.0, 8),
            &sha[..12]
        ));
        // fall through: adopt as git-native content
    }

    // Map git parents to loot parents (the pre-bridge baseline carries a mark
    // standing for the dock anchor it was adopted against).
    let mut parents_loot: Vec<Oid> = Vec::new();
    for parent in commit.parent_ids() {
        let p_sha = parent.to_string();
        if let Some((pid, _)) = marks.change_for(&p_sha) {
            parents_loot.push(pid.clone());
        } else {
            return Err(format!(
                "commit {}: parent {} is unknown to the bridge — \
                 delete .loot/git-mirror/marks to rebuild, or re-run after syncing",
                &sha[..12],
                &p_sha[..12]
            ));
        }
    }
    // The full parent tree is the base the diff composes over — every loot
    // change records its complete tree. A mapped parent outside the
    // lineage-filtered load (landed from a lane, #265) is pulled in from the
    // shared graph first; a parent whose tree still cannot be loaded is a
    // refusal, never a silent empty base: composing over nothing mints a
    // delta-only change that reads as a wipe of everything the diff did not
    // touch, and adopting or projecting it deletes the working tree (#307).
    let parent_tree: BTreeMap<PathBuf, (Oid, Visibility)> = match parents_loot.first() {
        None => BTreeMap::new(), // a true root commit composes over the empty tree
        Some(p) => {
            ws.load_shared_lineage(p)?;
            ws.graph().tree(p).ok_or_else(|| {
                format!(
                    "commit {}: mapped loot parent {} has no loadable tree — refusing to \
                     mint a delta-only change that would read as a tree wipe (#307); if \
                     the parent was pruned, delete .loot/git-mirror/marks to rebuild the \
                     spine from trailers",
                    &sha[..12],
                    hex::short(&p.0, 8)
                )
            })?
        }
    };

    // Diff against the first git parent — only touched paths re-seal (#98).
    let commit_tree = commit.tree().map_err(|e| e.to_string())?;
    let parent_git_tree = commit.parent(0).ok().and_then(|p| p.tree().ok());
    let diff = git
        .diff_tree_to_tree(parent_git_tree.as_ref(), Some(&commit_tree), None)
        .map_err(|e| e.to_string())?;

    // Classification happens at ingest under the *ingested commit's own*
    // policy files, so a commit that adds a sealing rule plus the file it
    // seals lands sealed (ADR 0028; the fresh-clone lesson from #62).
    let attrs_text = blob_text(git, &commit_tree, ".lootattributes");
    let ignore_text = blob_text(git, &commit_tree, ".lootignore");

    use crate::workspace::IngestAct as Act;
    // Git diff paths are `/`-separated; recorded tree keys are native (a disk
    // capture mints `\` on Windows). PathBuf comparison is component-wise, so
    // lookups match either spelling — but the keys this ingest *records* are
    // normalized to native components so an ingested change's manifest is
    // spelled exactly like a captured one (#307).
    let native = |p: &Path| -> PathBuf { p.components().collect() };
    let mut acts: Vec<(PathBuf, Act)> = Vec::new();
    for delta in diff.deltas() {
        let (old_path, new_path) = (delta.old_file().path(), delta.new_file().path());
        match delta.status() {
            git2::Delta::Deleted => {
                if let Some(p) = old_path {
                    acts.push((native(p), Act::Remove));
                }
            }
            git2::Delta::Added | git2::Delta::Modified | git2::Delta::Typechange
            | git2::Delta::Renamed | git2::Delta::Copied => {
                if delta.status() == git2::Delta::Renamed {
                    if let Some(p) = old_path {
                        if old_path != new_path {
                            acts.push((native(p), Act::Remove));
                        }
                    }
                }
                let Some(p) = new_path else { continue };
                let rel = p.to_string_lossy().replace('\\', "/");
                if crate::workspace::ignored_under(&ignore_text, &rel) {
                    continue;
                }
                let blob = match git.find_blob(delta.new_file().id()) {
                    Ok(b) => b,
                    Err(_) => {
                        report.notes.push(format!(
                            "commit {}: skipped non-blob entry at {rel} (submodule?)",
                            &sha[..12]
                        ));
                        continue;
                    }
                };
                let bytes = blob.content().to_vec();
                let vis = crate::workspace::visibility_under(&attrs_text, &rel);
                if let Some(old_entry) = parent_tree.get(p) {
                    let readable = ws.graph().content(&old_entry.0);
                    match readable {
                        Err(RepoError::Unauthorized(_)) | Err(RepoError::Embargoed(_)) => {
                            return Err(format!(
                                "commit {}: git edit would clobber sealed content at {rel} — \
                                 the mirror never held this path; refusing",
                                &sha[..12]
                            ));
                        }
                        Ok(old_bytes) => {
                            if demotes(&old_entry.1, &vis) {
                                return Err(format!(
                                    "commit {}: ingesting {rel} would demote its visibility — \
                                     restore the .lootattributes rule before ferrying",
                                    &sha[..12]
                                ));
                            }
                            if old_bytes == bytes && old_entry.1 == vis {
                                acts.push((native(p), Act::Reuse { entry: old_entry.clone() }));
                                continue;
                            }
                        }
                        Err(_) => {}
                    }
                }
                acts.push((native(p), Act::Put { bytes, vis }));
            }
            _ => {}
        }
    }

    // Authorship: the syncing identity when the git author resolves to it;
    // otherwise an unauthored change preserving the git author (ADR 0028).
    let author_sig = commit.author();
    let author_str = format!(
        "{} <{}>",
        author_sig.name().unwrap_or(""),
        author_sig.email().unwrap_or("")
    );
    let self_hex = ws.author_pubkey().map(|pk| hex::encode(&pk));
    let is_self = self_hex
        .as_ref()
        .and_then(|h| id_map.get(h))
        .is_some_and(|v| *v == author_str);

    let loot_message = if is_self {
        bridge::strip_trailers(&message)
    } else {
        bridge::append_trailers(
            &bridge::strip_trailers(&message),
            &[(TRAILER_GIT_AUTHOR, author_str.clone())],
        )
    };

    let change_id = ws.ingest_change(parent_tree, acts, parents_loot, &loot_message, is_self)?;
    minted.push(change_id.clone());
    marks.insert(sha.to_string(), change_id.clone(), MarkOrigin::Git);
    report.ingested += 1;
    if is_self {
        ws.sign_change(&change_id)?;
    }
    Ok(())
}

// --- project ---

/// Project one loot change as a git commit: **public-delta** tree (sealed
/// paths never published — no filename, no bytes), `Loot-*` trailers,
/// deterministic dates, SSHSIG-signed when the repo has a keypair. A path
/// with an unresolved conflict is held at its last clean git state
/// (ADR 0028). Returns the sha plus the sealed paths the delta omitted.
fn project_change(
    ws: &Workspace,
    git: &git2::Repository,
    id: &Oid,
    marks: &MarkMap,
    generations: &BTreeMap<Oid, u64>,
    last_clean: Option<&git2::Tree>,
    id_map: &BTreeMap<String, String>,
) -> Result<(String, Vec<String>), String> {
    let g = ws.graph();

    // Predecessor-conditional git threading (ADR 0033). A superseding version
    // X′ (predecessors = [X]) is a *sibling* of X in loot's DAG (both children
    // of P), but git wants a linear fix-up. Thread X′ onto X's commit when X is
    // *landed* — it has a mark and is an ancestor of the current git main — so
    // main stays a fast-forward and the amend reads as its own commit on top.
    // Otherwise (X unmarked / not on main: the local finalize→amend churn)
    // thread onto the loot sibling parent P, leaving X on refs/loot/heads/<X>.
    // The delta base tracks the git parent so the projected tree is exact: the
    // change's delta is computed against whichever line it threads onto. The
    // ordering wrinkle (X′ names X in predecessors, not parents, so ids_topo
    // need not place X first) resolves itself — "ancestor of the *current* main"
    // can only hold if X landed in a prior pass and so already has a mark.
    // (main is only moved *after* this projection loop, so reading it here
    // yields the pre-pass tip regardless of projection order.)
    let main_tip = git.find_reference(MAIN_REF).ok().and_then(|r| r.target());
    let loot_parents = g.parents(id);
    let landed_predecessor = g.predecessors(id).into_iter().find(|x| {
        let Some(xsha) = marks.sha_for(x) else { return false };
        let Ok(xoid) = git2::Oid::from_str(xsha) else { return false };
        main_tip.is_some_and(|tip| {
            tip == xoid || git.graph_descendant_of(tip, xoid).unwrap_or(false)
        })
    });
    let (git_parent_ids, delta_base): (Vec<Oid>, Option<Oid>) = match landed_predecessor {
        Some(x) => (vec![x.clone()], Some(x)),
        None => (loot_parents.clone(), loot_parents.first().cloned()),
    };

    let mut parent_commits = Vec::new();
    for p in &git_parent_ids {
        let sha = marks.sha_for(p).ok_or_else(|| {
            format!(
                "change {}: parent {} has no mirrored commit yet",
                hex::short(&id.0, 8),
                hex::short(&p.0, 8)
            )
        })?;
        parent_commits.push(
            git.find_commit(git2::Oid::from_str(sha).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?,
        );
    }
    let parent_refs: Vec<&git2::Commit> = parent_commits.iter().collect();

    let parent_git_tree = parent_commits.first().and_then(|c| c.tree().ok());
    let (tree, skipped) =
        public_delta_tree(ws, git, id, parent_git_tree.as_ref(), last_clean, delta_base.as_ref())?;

    let (name, email) = author_name_email(ws, g.author(id), id_map);
    let when = git2::Time::new(bridge::commit_timestamp(*generations.get(id).unwrap_or(&0)), 0);
    let sig = git2::Signature::new(&name, &email, &when).map_err(|e| e.to_string())?;

    let mut trailers: Vec<(&str, String)> = vec![(TRAILER_CHANGE_ID, hex::encode(&id.0))];
    if let Some(author) = g.author(id) {
        trailers.push((TRAILER_AUTHOR, hex::encode(&author)));
    }
    if let Some(sig64) = g.signature(id) {
        trailers.push((TRAILER_SIGNATURE, hex::encode(&sig64)));
    }
    let predecessors = g.predecessors(id);
    if !predecessors.is_empty() {
        trailers.push((
            TRAILER_PREDECESSORS,
            predecessors
                .iter()
                .map(|p| hex::encode(&p.0))
                .collect::<Vec<_>>()
                .join(" "),
        ));
    }
    let message = bridge::append_trailers(
        &g.message(id).unwrap_or_default(),
        &trailers,
    );

    let oid = if ws.author_pubkey().is_some() {
        let buf = git
            .commit_create_buffer(&sig, &sig, &message, &tree, &parent_refs)
            .map_err(|e| e.to_string())?;
        let content = std::str::from_utf8(&buf)
            .map_err(|_| "commit buffer is not utf-8".to_string())?;
        let ssh_sig = ws.ssh_sign(GIT_SIG_NAMESPACE, content.as_bytes())?;
        git.commit_signed(content, &ssh_sig, None)
            .map_err(|e| e.to_string())?
    } else {
        git.commit(None, &sig, &sig, &message, &tree, &parent_refs)
            .map_err(|e| e.to_string())?
    };
    Ok((oid.to_string(), skipped))
}

/// The **publication** tree of a change: the git first-parent tree plus this
/// change's *delta*, restricted to `Public` paths. Everything projected by
/// the bridge may end up pushed off-machine (review/*, the landed main), so
/// the filter is visibility, **not readability** — the dev's own identity can
/// read restricted content (the mirror's full-readable-tree contract,
/// ADR 0028), and exactly that tree must never be what gets published. Found
/// live on the #155 evidence run: the readable-tree projection put
/// `docs/pitch/` into a public PR diff.
///
/// Delta semantics also keep published history *git-shaped*: paths loot
/// tracks that git never carried (`.scratch/`, sealed paths) are untouched by
/// the delta and so never appear. Unresolved conflicts are held at their last
/// clean git state as before (ADR 0028). Returns the tree plus the sealed
/// paths the delta had to omit.
fn public_delta_tree<'g>(
    ws: &Workspace,
    git: &'g git2::Repository,
    id: &Oid,
    git_parent: Option<&git2::Tree>,
    last_clean: Option<&git2::Tree>,
    delta_base: Option<&Oid>,
) -> Result<(git2::Tree<'g>, Vec<String>), String> {
    let g = ws.graph();
    let change_tree = g
        .tree(id)
        .ok_or_else(|| format!("unknown change {}", hex::short(&id.0, 8)))?;
    // The loot change whose tree the delta is measured against — normally the
    // loot first parent, but an amend threaded onto its predecessor X measures
    // against X so the result lands exactly on X's git tree (ADR 0033).
    let parent_tree: BTreeMap<PathBuf, (Oid, Visibility)> =
        delta_base.and_then(|p| g.tree(p)).unwrap_or_default();
    let conflicts = g.conflicts();

    // Start from the git parent's flat path -> (blob, filemode) map. Modes
    // ride along untouched — loot does not track the executable bit, so the
    // git side owns it and an untouched path must keep it (found live on
    // #164: a rebuilt tree silently stripped 100755 from scripts).
    let mut flat: BTreeMap<String, (git2::Oid, i32)> = BTreeMap::new();
    if let Some(tree) = git_parent {
        tree.walk(git2::TreeWalkMode::PreOrder, |root, entry| {
            if entry.kind() == Some(git2::ObjectType::Blob) {
                flat.insert(
                    format!("{root}{}", entry.name().unwrap_or("")),
                    (entry.id(), entry.filemode()),
                );
            }
            git2::TreeWalkResult::Ok
        })
        .map_err(|e| e.to_string())?;
    }

    // Deletions: a path the change dropped leaves the published tree too.
    for (path, _) in parent_tree.iter().filter(|(p, _)| !change_tree.contains_key(*p)) {
        flat.remove(&path.to_string_lossy().replace('\\', "/"));
    }

    // Additions / edits: public-only, unchanged paths untouched (#98 keeps
    // (oid, visibility) stable for unchanged content, so equality is exact).
    let mut skipped: Vec<String> = Vec::new();
    for (path, entry) in &change_tree {
        if parent_tree.get(path) == Some(entry) {
            continue;
        }
        let rel = path.to_string_lossy().replace('\\', "/");
        if conflicts.contains_key(path.as_path()) {
            // Held back: keep the last clean content until resolved.
            if let Some(tree) = last_clean {
                if let Ok(e) = tree.get_path(Path::new(&rel)) {
                    flat.insert(rel, (e.id(), e.filemode()));
                }
            }
            continue;
        }
        let (oid, vis) = entry;
        if *vis != Visibility::Public {
            skipped.push(rel);
            continue;
        }
        match g.content(oid) {
            Ok(bytes) => {
                let blob = git.blob(&bytes).map_err(|e| e.to_string())?;
                // Content changed; a known mode carries over.
                let mode = flat.get(&rel).map(|(_, m)| *m).unwrap_or(0o100644);
                flat.insert(rel, (blob, mode));
            }
            Err(RepoError::Unauthorized(_)) | Err(RepoError::Embargoed(_)) => {
                skipped.push(rel);
            }
            Err(e) => return Err(e.to_string()),
        }
    }

    let entries: Vec<(String, git2::Oid, i32)> =
        flat.into_iter().map(|(p, (o, m))| (p, o, m)).collect();
    let tree_oid = write_git_tree(git, &entries)?;
    let tree = git.find_tree(tree_oid).map_err(|e| e.to_string())?;
    Ok((tree, skipped))
}

/// Project the ambient dock's *unfinalized* working change as a provisional
/// review commit (map #148): **public-delta** tree, `Loot-Provisional` trailer and
/// **no** `Loot-Signature` — unsigned in loot is the point, the missing
/// trailer is what marks it not-finalized — while the git commit itself is
/// still SSHSIG-signed so mirror history stays integrity-checked end to end.
fn project_wip(
    ws: &Workspace,
    git: &git2::Repository,
    id: &Oid,
    parent_shas: &[String],
    generations: &BTreeMap<Oid, u64>,
    last_clean: Option<&git2::Tree>,
    id_map: &BTreeMap<String, String>,
) -> Result<(String, Vec<String>), String> {
    let g = ws.graph();

    let mut parent_commits = Vec::new();
    for sha in parent_shas {
        parent_commits.push(
            git.find_commit(git2::Oid::from_str(sha).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?,
        );
    }
    let parent_refs: Vec<&git2::Commit> = parent_commits.iter().collect();

    let parent_git_tree = parent_commits.first().and_then(|c| c.tree().ok());
    // A provisional review commit measures its delta against the loot first
    // parent (round 1) and appends onto the previous provisional commit's git
    // tree in later rounds — supersession threading (ADR 0033) is a finalized-
    // projection concern; the review lane resumes as a new round regardless.
    let wip_base = g.parents(id).first().cloned();
    let (tree, skipped) =
        public_delta_tree(ws, git, id, parent_git_tree.as_ref(), last_clean, wip_base.as_ref())?;

    let (name, email) = author_name_email(ws, g.author(id), id_map);
    let when = git2::Time::new(bridge::commit_timestamp(*generations.get(id).unwrap_or(&0)), 0);
    let sig = git2::Signature::new(&name, &email, &when).map_err(|e| e.to_string())?;

    let mut trailers: Vec<(&str, String)> = vec![
        (TRAILER_CHANGE_ID, hex::encode(&id.0)),
        (TRAILER_PROVISIONAL, "true".to_string()),
    ];
    if let Some(author) = g.author(id) {
        trailers.push((TRAILER_AUTHOR, hex::encode(&author)));
    }
    let message =
        bridge::append_trailers(&g.message(id).unwrap_or_default(), &trailers);

    let oid = if ws.author_pubkey().is_some() {
        let buf = git
            .commit_create_buffer(&sig, &sig, &message, &tree, &parent_refs)
            .map_err(|e| e.to_string())?;
        let content =
            std::str::from_utf8(&buf).map_err(|_| "commit buffer is not utf-8".to_string())?;
        let ssh_sig = ws.ssh_sign(GIT_SIG_NAMESPACE, content.as_bytes())?;
        git.commit_signed(content, &ssh_sig, None).map_err(|e| e.to_string())?
    } else {
        git.commit(None, &sig, &sig, &message, &tree, &parent_refs)
            .map_err(|e| e.to_string())?
    };
    Ok((oid.to_string(), skipped))
}

/// The durable review-lane key of a change: its `change_id` (map #132, stable
/// across re-snapshots), falling back to the version id for legacy changes —
/// a legacy lane then re-keys every snapshot and simply reaps as superseded.
fn wip_key(ws: &Workspace, id: &Oid) -> String {
    ws.graph()
        .change_id(id)
        .map(|cid| hex::encode(&cid))
        .unwrap_or_else(|| hex::encode(&id.0))
}

/// One in-flight review lane (`.loot/git-mirror/wip`, local-only): durable
/// change key -> its latest provisional projection. Deliberately not part of
/// the mark map — provisional shas never enter the round-trip spine. `owner`
/// is the position that projected it (#281): an isolation-lane id, empty for
/// the primary — entries are owner-scoped because liveness is a *positional*
/// judgment only the owner can make, and the owner names the review ref.
#[derive(Clone)]
struct WipEntry {
    change: String,
    dock: String,
    sha: String,
    version: String,
    round: u64,
    owner: String,
}

impl WipEntry {
    /// The suffix of this entry's `review/<...>` ref: the owning lane's id,
    /// or the dock name on the primary (#281) — one position, one ref, so
    /// concurrent lanes never force-push over each other's PR heads. The rule
    /// itself lives in [`crate::ledger::review_handle`], shared with `land`.
    fn review_handle(&self) -> &str {
        crate::ledger::review_handle(&self.owner, &self.dock)
    }
}

/// The `wip` ledger. `ferry` owns writes; the loot-first orchestrator (#218)
/// reads it in-process through this same type — the single typed owner of the
/// on-disk format, so there is no parallel parser to drift against.
pub struct WipState {
    entries: Vec<WipEntry>,
}

impl WipState {
    pub fn parse(text: &str) -> Self {
        let mut entries = Vec::new();
        for line in text.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            // Five fields is the pre-#281 row (no owner column → primary);
            // six carries the owner, `-` meaning primary.
            if f.len() == 5 || f.len() == 6 {
                if let Ok(round) = f[4].parse() {
                    let owner = match f.get(5) {
                        None | Some(&"-") => String::new(),
                        Some(o) => (*o).to_string(),
                    };
                    entries.push(WipEntry {
                        change: f[0].into(),
                        dock: f[1].into(),
                        sha: f[2].into(),
                        version: f[3].into(),
                        round,
                        owner,
                    });
                }
            }
        }
        WipState { entries }
    }

    fn encode(&self) -> String {
        let mut out = String::new();
        for e in &self.entries {
            let owner = if e.owner.is_empty() { "-" } else { e.owner.as_str() };
            out.push_str(&format!(
                "{} {} {} {} {} {}\n",
                e.change, e.dock, e.sha, e.version, e.round, owner
            ));
        }
        out
    }

    /// The full version the review lane last projected for
    /// `(change, dock, owner)` — the reviewed version the land path compares
    /// the live version against (the review-currency guard, ADR 0033).
    /// Owner-keyed (#281): the same change reviewed from two positions is two
    /// review lanes. Full hex, not the 8-char review line truncation.
    pub fn reviewed_version(&self, change: &str, dock: &str, owner: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.change == change && e.dock == dock && e.owner == owner)
            .map(|e| e.version.as_str())
    }
}

#[cfg(test)]
mod wip_state_tests {
    use super::WipState;

    #[test]
    fn round_trips_and_reads_reviewed_version() {
        let text = "aabb ferry deadbeef cafef00d 3 -\nccdd list f00dcafe abadidea 1 t67\n";
        let wip = WipState::parse(text);
        assert_eq!(wip.entries.len(), 2);
        // Full version, not truncated.
        assert_eq!(wip.reviewed_version("aabb", "ferry", ""), Some("cafef00d"));
        assert_eq!(wip.reviewed_version("aabb", "other-dock", ""), None);
        // Owner participates in the key (#281).
        assert_eq!(wip.reviewed_version("ccdd", "list", "t67"), Some("abadidea"));
        assert_eq!(wip.reviewed_version("ccdd", "list", ""), None);
        assert_eq!(wip.encode(), text);
    }

    #[test]
    fn parses_legacy_five_field_rows_as_primary() {
        // Pre-#281 rows carried no owner column; they read as primary-owned
        // (and re-encode with the explicit `-`).
        let wip = WipState::parse("aabb ferry deadbeef cafef00d 3\n");
        assert_eq!(wip.entries.len(), 1);
        assert_eq!(wip.entries[0].owner, "");
        assert_eq!(wip.entries[0].review_handle(), "ferry");
        assert_eq!(wip.encode(), "aabb ferry deadbeef cafef00d 3 -\n");
    }

    #[test]
    fn review_handle_prefers_the_owning_lane() {
        let wip = WipState::parse("aabb main deadbeef cafef00d 1 t281\n");
        assert_eq!(wip.entries[0].review_handle(), "t281");
    }

    #[test]
    fn skips_short_rows() {
        // A 4-field row (missing round) is not a lane.
        assert_eq!(WipState::parse("aabb ferry deadbeef cafef00d\n").entries.len(), 0);
    }
}

/// Build a (possibly nested) git tree from flat `path -> (blob, filemode)`
/// entries. Modes come from the caller so the git parent's executable bits
/// survive the rebuild (loot does not track them).
fn write_git_tree(
    git: &git2::Repository,
    entries: &[(String, git2::Oid, i32)],
) -> Result<git2::Oid, String> {
    // Group this level's files and subdirectories.
    let mut files: Vec<(&str, git2::Oid, i32)> = Vec::new();
    let mut dirs: BTreeMap<&str, Vec<(String, git2::Oid, i32)>> = BTreeMap::new();
    for (path, oid, mode) in entries {
        match path.split_once('/') {
            None => files.push((path, *oid, *mode)),
            Some((dir, rest)) => {
                dirs.entry(dir).or_default().push((rest.to_string(), *oid, *mode))
            }
        }
    }
    let mut builder = git.treebuilder(None).map_err(|e| e.to_string())?;
    for (name, oid, mode) in files {
        builder.insert(name, oid, mode).map_err(|e| e.to_string())?;
    }
    for (dir, children) in dirs {
        let sub = write_git_tree(git, &children)?;
        builder.insert(dir, sub, 0o040000).map_err(|e| e.to_string())?;
    }
    builder.write().map_err(|e| e.to_string())
}

// --- refs ---

/// Point `refs/loot/heads/<id>` at every mirrored head (and prune stale ones).
/// Mechanical reachability handles, not branches (ADR 0022 stands).
///
/// The per-dock `refs/loot/docks/<name>` projection is retired with named docks
/// (#253/ADR 0034): the only other positions are sealed lanes, whose
/// finalized-but-unlanded tips live outside the mirror (a lane exports to the
/// mirror only when it lands, at which point it is on `main`), so there is
/// nothing extra to anchor here.
fn update_loot_refs(ws: &Workspace, git: &git2::Repository, marks: &MarkMap) -> Result<(), String> {
    let mut live: Vec<String> = Vec::new();
    for head in ws.heads() {
        if let Some(sha) = marks.sha_for(&head) {
            let name = format!("refs/loot/heads/{}", hex::encode(&head.0));
            let oid = git2::Oid::from_str(sha).map_err(|e| e.to_string())?;
            git.reference(&name, oid, true, "loot ferry").map_err(|e| e.to_string())?;
            live.push(name);
        }
    }
    if let Ok(refs) = git.references_glob("refs/loot/heads/*") {
        let stale: Vec<String> = refs
            .flatten()
            .filter_map(|r| r.name().map(String::from))
            .filter(|n| !live.contains(n))
            .collect();
        for name in stale {
            if let Ok(mut r) = git.find_reference(&name) {
                let _ = r.delete();
            }
        }
    }
    Ok(())
}

// --- marks rebuild ---

/// Rebuild the mark map from `Loot-Change-Id` trailers across every ref — the
/// recovery path for a lost `.loot/git-mirror/marks` (AC: loot-origin entries
/// rebuild with no data loss). Git-origin commits carry no trailer; they are
/// re-matched by mapped parents + message so a rebuild doesn't re-ingest them.
fn rebuild_marks(ws: &Workspace, git: &git2::Repository) -> Result<MarkMap, String> {
    let mut marks = MarkMap::new();
    let mut rw = match git.revwalk() {
        Ok(rw) => rw,
        Err(_) => return Ok(marks),
    };
    rw.set_sorting(git2::Sort::TOPOLOGICAL | git2::Sort::REVERSE)
        .map_err(|e| e.to_string())?;
    let _ = rw.push_glob("refs/*");
    let mut git_native: Vec<String> = Vec::new();
    for oid in rw.flatten() {
        let Ok(commit) = git.find_commit(oid) else { continue };
        let message = String::from_utf8_lossy(commit.message_bytes()).to_string();
        // Provisional review commits never enter the spine (#148).
        if bridge::parse_trailer(&message, TRAILER_PROVISIONAL).is_some() {
            continue;
        }
        match bridge::parse_trailer(&message, TRAILER_CHANGE_ID).and_then(|h| bridge::parse_oid_hex(&h)) {
            Some(id) if ws.graph().tree(&id).is_some() => {
                marks.insert(oid.to_string(), id, MarkOrigin::Loot);
            }
            _ => git_native.push(oid.to_string()),
        }
    }
    // Second pass: re-match ingested (git-origin) commits by parents + message.
    let all_changes = ws.graph().ids_topo();
    for sha in git_native {
        let Ok(commit) = git.find_commit(git2::Oid::from_str(&sha).map_err(|e| e.to_string())?) else {
            continue;
        };
        let parents: Option<Vec<Oid>> = commit
            .parent_ids()
            .map(|p| marks.change_for(&p.to_string()).map(|(id, _)| id.clone()))
            .collect();
        let Some(parents) = parents else { continue };
        let message = bridge::strip_trailers(&String::from_utf8_lossy(commit.message_bytes()));
        let candidates: Vec<&Oid> = all_changes
            .iter()
            .filter(|c| ws.graph().parents(c) == parents)
            .filter(|c| {
                ws.graph()
                    .message(c)
                    .is_some_and(|m| bridge::strip_trailers(&m) == message)
            })
            .collect();
        if candidates.len() == 1 {
            marks.insert(sha, candidates[0].clone(), MarkOrigin::Git);
        }
    }
    Ok(marks)
}

// --- small shared helpers ---
// (The pure DAG walks — ancestor closure, is-ancestor, generations — moved to
// `Workspace::graph()` in R1 #177: they are graph queries, not bridge logic.)

/// Same demotion rule as the engine's snapshot guard (#62): re-sealing more
/// readably is refused unless done deliberately.
fn demotes(old: &Visibility, new: &Visibility) -> bool {
    matches!(
        (old, new),
        (Visibility::Restricted(_), Visibility::Public)
            | (Visibility::Embargoed { .. }, Visibility::Public)
            | (Visibility::Embargoed { .. }, Visibility::Restricted(_))
    )
}

/// The syncing identity's git-facing name/email: git config when available
/// (native-looking history), else the loot identity (ADR 0028).
fn self_name_email(ws: &Workspace, git: &git2::Repository) -> (String, String) {
    let cfg = git.config().ok();
    let name = cfg
        .as_ref()
        .and_then(|c| c.get_string("user.name").ok())
        .unwrap_or_else(|| ws.identity().to_string());
    let email = cfg
        .as_ref()
        .and_then(|c| c.get_string("user.email").ok())
        .unwrap_or_else(|| format!("{}@loot.local", ws.identity()));
    (name, email)
}

/// Name/email for a mirrored commit's author: the identity map, then the peer
/// registry nickname (`<nick>@loot.local`), then a pubkey-derived stub.
fn author_name_email(
    ws: &Workspace,
    author: Option<[u8; 32]>,
    id_map: &BTreeMap<String, String>,
) -> (String, String) {
    let Some(pk) = author else {
        return (ws.identity().to_string(), format!("{}@loot.local", ws.identity()));
    };
    let pk_hex = hex::encode(&pk);
    if let Some(mapped) = id_map.get(&pk_hex) {
        if let Some((name, email)) = split_name_email(mapped) {
            return (name, email);
        }
    }
    let peers = loot_identity::PeerRegistry::load(ws.store().dot());
    for (nick, _) in peers.list() {
        if peers.pubkey_bytes(nick).ok().flatten() == Some(pk) {
            return (nick.to_string(), format!("{nick}@loot.local"));
        }
    }
    let short = hex::short(&pk, 8);
    (format!("loot-{short}"), format!("{short}@loot.local"))
}

/// The text of a top-level blob in a git tree, or empty if absent/non-utf8.
fn blob_text(git: &git2::Repository, tree: &git2::Tree, name: &str) -> String {
    tree.get_name(name)
        .and_then(|e| git.find_blob(e.id()).ok())
        .and_then(|b| String::from_utf8(b.content().to_vec()).ok())
        .unwrap_or_default()
}

fn split_name_email(value: &str) -> Option<(String, String)> {
    let (name, rest) = value.split_once(" <")?;
    let email = rest.strip_suffix('>')?;
    Some((name.to_string(), email.to_string()))
}

/// Read a spine file, tolerating the Windows rename-replace delete-pending
/// window ([`store::read_replaced`], #293 tail) — spine writes are atomic
/// rename-replaces (#307), and a transient `PermissionDenied` read as "empty
/// marks" would silently re-ingest/re-project everything.
fn read_or_empty(path: &Path) -> String {
    loot_core::store::read_replaced(path)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

/// Persist one spine file (marks/state/config/wip) atomically
/// ([`store::atomic_write`]): a crash mid-write must never truncate the spine
/// — a torn marks file that still parses is silently-missing marks, the
/// "persisted change without its mark" state #307 forbids.
fn write_spine(path: &Path, text: &str) -> Result<(), String> {
    loot_core::store::atomic_write(path, text.as_bytes())
        .map_err(|e| format!("write {}: {e}", path.display()))
}

/// Resolve the configured mirror `gitdir` to a path usable from any cwd. A
/// relative gitdir (the default `.loot/git-mirror/mirror.git`) is resolved
/// against the **shared store's repo root** (`dot`'s parent), never the process
/// cwd — so a `loot ferry` / land run from a lane directory reaches the one
/// shared harbor mirror instead of spawning a stray lane-local one (ADR 0036:
/// the harbor owns the single git-mirror). An absolute gitdir (a custom
/// `--git-dir`) passes through unchanged. For the primary, `dot`'s parent *is*
/// the cwd, so the resolved path is byte-identical to the old behaviour.
fn resolve_gitdir(raw: &str, dot: &Path) -> String {
    let p = Path::new(raw);
    if p.is_absolute() {
        return raw.to_string();
    }
    dot.parent().unwrap_or(dot).join(p).to_string_lossy().into_owned()
}

#[cfg(test)]
mod resolve_gitdir_tests {
    use super::resolve_gitdir;
    use std::path::Path;

    #[test]
    fn relative_gitdir_resolves_against_store_root_not_cwd() {
        // A lane's `dot` is the SHARED store's `.loot`; a relative gitdir must
        // land beside it, wherever the lane process is running.
        let dot = std::env::temp_dir().join("repo").join(".loot");
        let got = resolve_gitdir(".loot/git-mirror/mirror.git", &dot);
        let want = dot.parent().unwrap().join(".loot/git-mirror/mirror.git");
        assert_eq!(got, want.to_string_lossy());
    }

    #[test]
    fn absolute_gitdir_passes_through() {
        // A custom `--git-dir` (absolute) is used verbatim.
        let abs = std::env::temp_dir().join("custom-mirror.git");
        let raw = abs.to_string_lossy().into_owned();
        assert_eq!(resolve_gitdir(&raw, Path::new("/anywhere/.loot")), raw);
    }
}

/// `key = value` files under `.loot/git-mirror/` (config, identity map).

#[cfg(test)]
mod tests {
    use super::*;
    use loot_core::Repo;

    /// A fresh keyed loot repo + a mirror path, isolated per test.
    fn setup(tag: &str) -> (Workspace, PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("loot-ferry-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let repo_dir = base.join("repo");
        let mirror = base.join("mirror.git");
        Workspace::init_at(&repo_dir, "alice").unwrap();
        loot_identity::generate_and_save(&repo_dir.join(".loot"), "alice@loot").unwrap();
        let ws = Workspace::open_at(&repo_dir).unwrap();
        (ws, repo_dir, mirror)
    }

    fn put_file(dir: &Path, rel: &str, content: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    /// Snapshot + finalize: one signed change from the working tree.
    fn seal_change(ws: &mut Workspace, msg: &str) -> Oid {
        let (id, _) = ws.snapshot(msg).unwrap();
        ws.finalize_working().unwrap();
        id
    }

    fn ferry(ws: &mut Workspace, mirror: &Path) -> FerryReport {
        run(ws, Some(mirror.to_str().unwrap()), None, false).unwrap()
    }

    fn ferry_wip(ws: &mut Workspace, mirror: &Path) -> FerryReport {
        run(ws, Some(mirror.to_str().unwrap()), None, true).unwrap()
    }

    /// All blob paths in a commit's tree, recursively (unix-style).
    fn tree_paths(git: &git2::Repository, tree: &git2::Tree) -> Vec<String> {
        let mut out = Vec::new();
        tree.walk(git2::TreeWalkMode::PreOrder, |root, entry| {
            if entry.kind() == Some(git2::ObjectType::Blob) {
                out.push(format!("{root}{}", entry.name().unwrap_or("")));
            }
            git2::TreeWalkResult::Ok
        })
        .unwrap();
        let _ = git;
        out
    }

    fn main_commit(git: &git2::Repository) -> git2::Commit<'_> {
        let oid = git.find_reference(MAIN_REF).unwrap().target().unwrap();
        git.find_commit(oid).unwrap()
    }

    /// Append a git-native commit on main: parent tree + `files`, as `author`.
    fn git_native_commit(
        git: &git2::Repository,
        files: &[(&str, &str)],
        author: (&str, &str),
        message: &str,
    ) -> String {
        let parent = main_commit(git);
        let mut builder = git2::build::TreeUpdateBuilder::new();
        for (rel, content) in files {
            let blob = git.blob(content.as_bytes()).unwrap();
            builder.upsert(rel, blob, git2::FileMode::Blob);
        }
        let tree = git
            .find_tree(builder.create_updated(git, &parent.tree().unwrap()).unwrap())
            .unwrap();
        let sig = git2::Signature::now(author.0, author.1).unwrap();
        git.commit(Some(MAIN_REF), &sig, &sig, message, &tree, &[&parent])
            .unwrap()
            .to_string()
    }

    #[test]
    fn projection_omits_sealed_paths_signs_and_sets_refs() {
        let (mut ws, dir, mirror) = setup("project");
        put_file(&dir, ".lootattributes", "secret/** restricted=bob\n");
        put_file(&dir, "readme.md", "hello\n");
        put_file(&dir, "src/lib.rs", "pub fn a() {}\n");
        put_file(&dir, "secret/pitch.md", "the plan\n");
        seal_change(&mut ws, "first");

        let report = ferry(&mut ws, &mirror);
        assert!(report.projected >= 1, "projects the finalized change");

        let git = git2::Repository::open(&mirror).unwrap();
        let commit = main_commit(&git);
        let paths = tree_paths(&git, &commit.tree().unwrap());
        assert!(paths.contains(&"readme.md".to_string()));
        assert!(paths.contains(&"src/lib.rs".to_string()), "nested trees work");
        assert!(
            !paths.iter().any(|p| p.contains("secret") || p.contains("pitch")),
            "sealed path leaves no filename and no bytes: {paths:?}"
        );

        // Trailers make the round trip lossless.
        let msg = commit.message().unwrap();
        let head = ws.finalized_anchor().unwrap();
        assert_eq!(
            bridge::parse_trailer(msg, TRAILER_CHANGE_ID),
            Some(hex::encode(&head.0))
        );
        assert!(bridge::parse_trailer(msg, TRAILER_AUTHOR).is_some());
        assert!(bridge::parse_trailer(msg, TRAILER_SIGNATURE).is_some());

        // SSHSIG verifies against the repo's own key.
        let (sig, signed) = git.extract_signature(&commit.id(), None).unwrap();
        let pub_line = ws.public_key_openssh().unwrap();
        loot_identity::ssh_verify(
            &pub_line,
            GIT_SIG_NAMESPACE,
            &signed,
            std::str::from_utf8(&sig).unwrap(),
        )
        .expect("mirrored commit signature verifies with loot's key");

        // Every head reachable under refs/loot/heads/*; main tracks the dock.
        let head_ref = format!("refs/loot/heads/{}", hex::encode(&head.0));
        assert!(git.find_reference(&head_ref).is_ok(), "head ref present");
        assert_eq!(
            git.find_reference(&head_ref).unwrap().target(),
            git.find_reference(MAIN_REF).unwrap().target(),
            "main tracks the designated dock tip"
        );

        // Deterministic dates: BASE_EPOCH + generation.
        assert_eq!(commit.time().seconds(), bridge::commit_timestamp(0));
    }

    #[test]
    fn tag_projects_an_annotated_tag_onto_sealed_free_main() {
        let (mut ws, dir, mirror) = setup("tag");
        put_file(&dir, ".lootattributes", "secret/** restricted=bob\n");
        put_file(&dir, "readme.md", "hello\n");
        put_file(&dir, "secret/pitch.md", "the plan\n");
        seal_change(&mut ws, "first");
        ferry(&mut ws, &mirror);

        let target = super::tag_projected_main(&ws, "v0.1.0", "loot v0.1.0").unwrap();

        let git = git2::Repository::open(&mirror).unwrap();
        // The annotated tag exists and peels to the projected main commit.
        let tag_oid = git.find_reference("refs/tags/v0.1.0").unwrap().target().unwrap();
        let tag = git.find_tag(tag_oid).unwrap();
        assert_eq!(tag.target_id().to_string(), target, "tag targets the returned sha");
        assert_eq!(target, main_commit(&git).id().to_string(), "…which is the projected main tip");
        assert_eq!(tag.message().unwrap().trim(), "loot v0.1.0");

        // The tagged commit is the sealed-free projection — the secret path that
        // projection omitted is absent from the tree a pushed tag would carry.
        let tagged = git.find_commit(git2::Oid::from_str(&target).unwrap()).unwrap();
        let paths = tree_paths(&git, &tagged.tree().unwrap());
        assert!(paths.contains(&"readme.md".to_string()));
        assert!(
            !paths.iter().any(|p| p.contains("secret") || p.contains("pitch")),
            "sealed path never rides a release tag: {paths:?}"
        );

        // A release tag is never clobbered: a second mint of the same name refuses.
        let err = super::tag_projected_main(&ws, "v0.1.0", "again").unwrap_err();
        assert!(err.contains("already exists"), "{err}");
    }

    #[test]
    fn tag_refuses_before_anything_is_projected() {
        // No ferry pass has run, so the mirror is unbound — tagging must refuse
        // rather than mint a tag pointing at nothing.
        let (ws, _dir, _mirror) = setup("tag-unbound");
        let err = super::tag_projected_main(&ws, "v0.1.0", "loot v0.1.0").unwrap_err();
        assert!(err.contains("no mirror bound") || err.contains("no tip"), "{err}");
    }

    #[test]
    fn designating_a_non_main_dock_for_git_main_is_retired() {
        // #253/ADR 0034: named docks are gone, so git-main tracks the primary.
        // `--dock <other>` can no longer name a live position, so ferry refuses
        // it outright rather than silently retargeting main — the #201 hazard the
        // old designated-dock FF-guard protected against, now impossible to enter.
        let (mut ws, dir, mirror) = setup("ffguard");
        put_file(&dir, "a.txt", "one\n");
        seal_change(&mut ws, "first");
        ferry(&mut ws, &mirror);

        let err = run(&mut ws, Some(mirror.to_str().unwrap()), Some("side"), false)
            .err()
            .expect("designating a non-main dock refuses");
        assert!(err.contains("retired") && err.contains("side"), "{err}");
        // `--dock main` (the default) is still accepted — a harmless no-op.
        assert!(run(&mut ws, Some(mirror.to_str().unwrap()), Some("main"), false).is_ok());
    }

    #[test]
    fn a_failed_pass_persists_no_config_rebind() {
        let (mut ws, dir, mirror) = setup("cfgfail");
        put_file(&dir, "a.txt", "one\n");
        seal_change(&mut ws, "first");
        ferry(&mut ws, &mirror);
        let before = read_or_empty(&ws.store().git_config());

        // A pass that dies after flag parsing (an existing path that is not a
        // git repository) must not rebind the mirror config (#201). The config
        // persists at the END of a successful pass, never at flag-parse time.
        let bogus = dir.join("not-a-repo");
        std::fs::write(&bogus, "x").unwrap();
        let err = match run(&mut ws, Some(bogus.to_str().unwrap()), None, false) {
            Err(e) => e,
            Ok(_) => panic!("pass against a non-repo path unexpectedly succeeded"),
        };
        assert!(err.contains("open git mirror"), "{err}");
        assert_eq!(
            read_or_empty(&ws.store().git_config()),
            before,
            "the failed pass left the binding untouched"
        );
    }

    #[test]
    fn second_run_is_a_no_op_and_marks_rebuild_from_trailers() {
        let (mut ws, dir, mirror) = setup("idem");
        put_file(&dir, "a.txt", "one\n");
        seal_change(&mut ws, "first");
        put_file(&dir, "a.txt", "two\n");
        seal_change(&mut ws, "second");

        let first = ferry(&mut ws, &mirror);
        assert_eq!(first.projected, 2);
        let git = git2::Repository::open(&mirror).unwrap();
        let tip_before = main_commit(&git).id();

        let second = ferry(&mut ws, &mirror);
        assert_eq!((second.ingested, second.projected), (0, 0), "idempotent");
        assert_eq!(main_commit(&git).id(), tip_before, "no duplicate commits");

        // Lose the spine; rebuild recovers loot-origin marks from trailers and
        // a third run still changes nothing (round-trip to the same ids).
        let marks_before = read_or_empty(&ws.store().git_marks());
        std::fs::remove_file(ws.store().git_marks()).unwrap();
        std::fs::remove_file(ws.store().git_state()).unwrap();
        let third = ferry(&mut ws, &mirror);
        assert_eq!((third.ingested, third.projected), (0, 0), "rebuild, not re-ingest");
        assert_eq!(main_commit(&git).id(), tip_before);
        assert_eq!(
            read_or_empty(&ws.store().git_marks()),
            marks_before,
            "rebuilt marks match the lost ones exactly"
        );
    }

    #[test]
    fn git_native_commit_ingests_as_unauthored_with_git_author() {
        let (mut ws, dir, mirror) = setup("ingest");
        put_file(&dir, "a.txt", "base\n");
        seal_change(&mut ws, "base");
        ferry(&mut ws, &mirror);

        let git = git2::Repository::open(&mirror).unwrap();
        git_native_commit(&git, &[("b.txt", "from git\n")], ("Bob", "bob@example.com"), "add b");

        let report = ferry(&mut ws, &mirror);
        assert_eq!(report.ingested, 1);

        // The change is unauthored (never forge another identity) and keeps
        // the git author; the dock fast-forwarded and materialized the file.
        let head = ws.finalized_anchor().unwrap();
        assert!(ws.repo().change_author(&head).is_none(), "unauthored ingest");
        let msg = ws.repo().change_message(&head).unwrap();
        assert_eq!(
            bridge::parse_trailer(&msg, TRAILER_GIT_AUTHOR),
            Some("Bob <bob@example.com>".to_string())
        );
        assert_eq!(std::fs::read_to_string(dir.join("b.txt")).unwrap(), "from git\n");

        // Round-trip: the ingested change is marked, never re-emitted.
        let after = ferry(&mut ws, &mirror);
        assert_eq!((after.ingested, after.projected), (0, 0));
    }

    #[test]
    fn ingest_composes_the_full_tree_when_the_mapped_parent_is_outside_the_loaded_lineage() {
        // #307, in miniature: a lane lands a child into the shared graph (the
        // primary's heads never move), the landed commit is marked on the git
        // side, and a break-glass commit lands on top of it. The primary's
        // lineage-filtered load has never seen the child, so the ingest's
        // parent-tree lookup came back None and `unwrap_or_default()` silently
        // composed the new change over an EMPTY tree — a delta-only change
        // that reads as a tree wipe. (The suspected separator mechanism was
        // falsified: PathBuf comparison is component-wise, so `/`- and
        // `\`-keyed lookups match on Windows. The hole was the missing
        // lineage, not the separators — nested paths here keep that pinned.)
        let (mut ws, dir, mirror) = setup("ingest-307");
        put_file(&dir, "top.txt", "top\n");
        put_file(&dir, "src/a.txt", "a v1\n");
        put_file(&dir, "src/deep/b.txt", "b v1\n");
        seal_change(&mut ws, "base");
        ferry(&mut ws, &mirror);
        let git = git2::Repository::open(&mirror).unwrap();

        // A lane lands a child in the shared graph; the primary stays behind.
        let lane_dir = dir.parent().unwrap().join("lane-307");
        let spawned = ws.spawn_lane(None, Some(&lane_dir)).unwrap();
        let mut lw = Workspace::open_at(&spawned.dir).unwrap();
        put_file(&spawned.dir, "src/a.txt", "a v2\n");
        lw.snapshot("child: touch src/a.txt").unwrap();
        lw.finalize_working().unwrap();
        let child = lw.heads()[0].clone();

        // The landed child reaches git main, and the spine records the mark —
        // the state a lane-side land leaves behind for the primary.
        let sha_child =
            git_native_commit(&git, &[("src/a.txt", "a v2\n")], ("Alice", "alice@loot"), "child");
        let marks_path = ws.store().git_marks();
        let seeded = format!(
            "{}{sha_child} {} git\n",
            read_or_empty(&marks_path),
            hex::encode(&child.0)
        );
        std::fs::write(&marks_path, seeded).unwrap();

        // Break-glass on top, touching a different nested path.
        let sha_fix = git_native_commit(
            &git,
            &[("src/deep/b.txt", "b v2 from git\n")],
            ("Bob", "bob@example.com"),
            "hotfix b",
        );

        // Fresh primary open — the child is outside the loaded lineage.
        let mut ws = Workspace::open_at(&dir).unwrap();
        assert!(
            ws.repo().change_tree(&child).is_none(),
            "precondition: the landed child is outside the loaded lineage"
        );

        let report = ferry(&mut ws, &mirror);
        assert_eq!(report.ingested, 1);

        // The ingested change records the FULL tree — parent carry + diff,
        // never the delta alone. A modify-only commit ingests as mods-only
        // against its parent: same key set, exactly one entry changed.
        let marks = MarkMap::parse(&read_or_empty(&marks_path)).unwrap();
        let (ingested, _) = marks.change_for(&sha_fix).expect("the hotfix ingested").clone();
        let tree = ws.repo().change_tree(&ingested).expect("ingested change is loaded");
        let child_tree = ws.repo().change_tree(&child).expect("lineage was pulled in");
        assert_eq!(
            tree.keys().collect::<Vec<_>>(),
            child_tree.keys().collect::<Vec<_>>(),
            "a modify-only commit keeps its parent's whole manifest"
        );
        let changed: Vec<&PathBuf> = tree
            .iter()
            .filter(|(k, v)| child_tree.get(k.as_path()) != Some(v))
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            changed,
            vec![&PathBuf::from("src/deep/b.txt")],
            "mods-only: exactly the touched path differs from the parent"
        );

        // And the reconcile materialized the full tree — nothing was wiped.
        assert_eq!(std::fs::read_to_string(dir.join("top.txt")).unwrap(), "top\n");
        assert_eq!(std::fs::read_to_string(dir.join("src/a.txt")).unwrap(), "a v2\n");
        assert_eq!(
            std::fs::read_to_string(dir.join("src/deep/b.txt")).unwrap(),
            "b v2 from git\n"
        );
    }

    #[test]
    fn ingest_refuses_a_mapped_parent_whose_tree_cannot_be_loaded() {
        // The refusal arm of the #307 guard: a mark that names a change nobody
        // holds (pruned after an unadopted land, a corrupted spine) must stop
        // the pass — composing over a silently-empty parent tree mints the
        // delta-only wipe the guard exists to prevent.
        let (mut ws, dir, mirror) = setup("ingest-307-refuse");
        put_file(&dir, "a.txt", "base\n");
        seal_change(&mut ws, "base");
        ferry(&mut ws, &mirror);
        let base_heads = ws.heads();
        let git = git2::Repository::open(&mirror).unwrap();

        // Corrupt the spine: the marked tip now names an absent change.
        let sha_base = main_commit(&git).id().to_string();
        std::fs::write(
            ws.store().git_marks(),
            format!("{sha_base} {} git\n", "ab".repeat(32)),
        )
        .unwrap();
        git_native_commit(&git, &[("b.txt", "from git\n")], ("Bob", "bob@example.com"), "add b");

        let err = match run(&mut ws, Some(mirror.to_str().unwrap()), None, false) {
            Err(e) => e,
            Ok(_) => panic!("a parent with no loadable tree must refuse the pass"),
        };
        assert!(err.contains("no loadable tree") && err.contains("#307"), "{err}");
        assert_eq!(ws.heads(), base_heads, "nothing was minted onto the line");
    }

    #[test]
    fn ingested_manifest_keys_are_native_spelled() {
        // #307's separator hygiene: PathBuf comparison is component-wise, so a
        // `/`-spelled key *works* on Windows — but the keys an ingest records
        // are normalized to native components, so an ingested manifest is
        // spelled exactly like a captured one and manifests never mix spellings.
        let (mut ws, dir, mirror) = setup("ingest-307-sep");
        put_file(&dir, "src/a.txt", "base\n");
        seal_change(&mut ws, "base");
        ferry(&mut ws, &mirror);

        let git = git2::Repository::open(&mirror).unwrap();
        git_native_commit(
            &git,
            &[("src/deep/new.txt", "added\n")],
            ("Bob", "bob@example.com"),
            "add nested",
        );
        ferry(&mut ws, &mirror);

        let head = ws.finalized_anchor().unwrap();
        let tree = ws.repo().change_tree(&head).unwrap();
        let native = Path::new("src").join("deep").join("new.txt");
        let spelled = tree
            .keys()
            .find(|k| ***k == *native)
            .expect("the added path is in the manifest");
        assert_eq!(
            spelled.to_string_lossy(),
            native.to_string_lossy(),
            "the recorded key is spelled with native separators, like a capture"
        );
    }

    /// Recursive directory copy (no std one-liner exists).
    fn copy_dir(src: &Path, dst: &Path) {
        std::fs::create_dir_all(dst).unwrap();
        for entry in std::fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            let target = dst.join(entry.file_name());
            if entry.path().is_dir() {
                copy_dir(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), &target).unwrap();
            }
        }
    }

    #[test]
    fn adopts_a_gc_pruned_change_as_content_when_its_object_is_gone() {
        // #263: a landed change pruned from the store (gc after a land the primary
        // never adopted) cannot be reconstructed byte-identically — a version-id
        // hashes the tree's store-local, randomly-addressed oids. So ferry adopts
        // the commit's *content* as a fresh change marked as represented by the
        // commit: git `main` never moves (no force-push) and the dock gains the
        // recovered content. Modeled by a store frozen at the parent state.
        let (mut a, adir, mirror) = setup("adopt-a");
        put_file(&adir, "a.txt", "base\n");
        seal_change(&mut a, "base");
        ferry(&mut a, &mirror);

        // B = A frozen at base: it holds `base` (and its mark) but not the child.
        let bdir = adir.parent().unwrap().join("repo-b");
        let _ = std::fs::remove_dir_all(&bdir);
        copy_dir(&adir.join(".loot"), &bdir.join(".loot"));
        // A frozen primary has its tree on disk too — without it, the empty dir
        // reads as a delete-everything edit against the base anchor (#289:
        // deletions are real work, so an empty capture no longer evaporates).
        put_file(&bdir, "a.txt", "base\n");
        let mut b = Workspace::open_at(&bdir).unwrap();

        // A lands a change (CRLF content and message — the byte-identical case that
        // is impossible) and projects it.
        put_file(&adir, "a.txt", "landed\r\ncontent\r\n");
        seal_change(&mut a, "add feature (#999)\r\n");
        ferry(&mut a, &mirror);
        let git = git2::Repository::open(&mirror).unwrap();
        let landed_sha = main_commit(&git).id();

        // B ferries: the landed change is loot-origin but absent, so B adopts its
        // content as a fresh git-native change rather than refusing.
        let report = ferry(&mut b, &mirror);
        assert_eq!(report.ingested, 1, "adopted the absent change as content");

        // The content came through — B's dock materialized the recovered file.
        assert_eq!(
            std::fs::read_to_string(bdir.join("a.txt")).unwrap(),
            "landed\r\ncontent\r\n"
        );

        // And git `main` never moved: the adopted change is marked, so it is not
        // re-projected — no force-push, no divergence. A second pass is a no-op.
        let second = ferry(&mut b, &mirror);
        assert_eq!(main_commit(&git).id(), landed_sha, "git main is untouched");
        assert_eq!((second.ingested, second.projected), (0, 0), "and stable");
    }

    #[test]
    fn uncaptured_disk_wip_survives_ingest() {
        let (mut ws, dir, mirror) = setup("wip");
        put_file(&dir, "a.txt", "base\n");
        seal_change(&mut ws, "base");
        ferry(&mut ws, &mirror);

        // Disk edits with no `status` behind them — no working change exists —
        // while git advances. The adopt/merge path re-materializes the full
        // tree, so ferry must capture these first or they are overwritten.
        put_file(&dir, "wip.txt", "uncaptured\n");
        let git = git2::Repository::open(&mirror).unwrap();
        git_native_commit(&git, &[("b.txt", "from git\n")], ("Bob", "bob@example.com"), "add b");

        // The merge would seal this WIP as its signed parent, so it needs a name
        // first (#275). The refusal is the subject of the #275 tests; here it is
        // the setup for the real assertion — that the capture is what saves the
        // edits, and refusing costs only the signature.
        let refused = match run(&mut ws, Some(mirror.to_str().unwrap()), None, false) {
            Err(e) => e,
            Ok(_) => panic!("un-described WIP must hold the merge (#275)"),
        };
        assert!(refused.contains("describe"), "un-described WIP holds the merge: {refused}");
        assert_eq!(
            std::fs::read_to_string(dir.join("wip.txt")).unwrap(),
            "uncaptured\n",
            "the refusal never clobbers the disk"
        );
        // The refused pass rolled its ingest back (#307): the mark never
        // persisted AND the ingested change is no dangling live head. Before
        // the rollback, the orphan head survived for the *next snapshot* to
        // fold under the working change — after which `anchor()` claimed the
        // dock covered git main while the disk never materialized it.
        assert!(
            !read_or_empty(&ws.store().git_marks()).contains(&main_commit(&git).id().to_string()),
            "an aborted pass leaves the spine untouched (#201/#307)"
        );
        // The capture is durable across the refusal — loot is process-per-command,
        // so "your edits are captured and safe" only means anything if it survives
        // the erroring process. Re-open to prove it does.
        let mut ws = Workspace::open_at(&dir).unwrap();
        assert!(ws.working_id().is_some(), "the capture outlived the refused pass");
        assert_eq!(
            ws.heads().len(),
            1,
            "the rolled-back ingest left no dangling head beside the capture (#307)"
        );
        ws.snapshot("wip: my uncaptured work, now named").unwrap();

        // Re-running after naming completes the pass. The refused pass's ingest
        // was rolled back with the refusal, so it is simply redone here — the
        // pass is idempotent, which is why refusing mid-ferry is safe rather
        // than a half-applied mess.
        let report = ferry(&mut ws, &mirror);
        assert_eq!(report.ingested, 1, "the refused pass's ingest is redone, not lost");
        assert!(
            !report.outcomes.values().any(|o| matches!(o, MergeOutcome::Conflict { .. })),
            "disjoint paths merge cleanly: {:?}",
            report.outcomes
        );
        assert_eq!(std::fs::read_to_string(dir.join("wip.txt")).unwrap(), "uncaptured\n");
        assert_eq!(std::fs::read_to_string(dir.join("b.txt")).unwrap(), "from git\n");
        let head = ws.finalized_anchor().unwrap();
        let tree = ws.repo().change_tree(&head).unwrap();
        assert!(tree.contains_key(Path::new("wip.txt")), "WIP captured into loot");
        assert!(tree.contains_key(Path::new("b.txt")), "git edit ingested");

        let after = ferry(&mut ws, &mirror);
        assert_eq!((after.ingested, after.projected), (0, 0));
    }

    #[test]
    fn reconcile_merge_does_not_resurrect_files_deleted_on_the_spine() {
        // The #288 live incident, in miniature: a file deleted long ago on the
        // spine — every line involved forked AFTER the deletion — reappeared in
        // a ferry reconcile merge ("ferry: reconcile git main", d3ca4b8) and
        // was published to origin/main. Neither merge parent held it; the
        // merge did. Root cause: loot-core computed a tip's tree by unioning
        // every ancestor's manifest child-wins (delta semantics), but every
        // recorded change carries a FULL manifest — so a path deleted anywhere
        // in the ancestry re-entered `tree_at` forever, and `merge_tips` fed
        // those polluted trees to the converge classifier.
        let (mut ws, dir, mirror) = setup("resurrect-288");
        put_file(&dir, "a.txt", "keep\n");
        put_file(&dir, "b.txt", "doomed\n");
        seal_change(&mut ws, "base: a and b");
        ferry(&mut ws, &mirror);

        // A later landed change deletes b — ancient history on the spine…
        std::fs::remove_file(dir.join("b.txt")).unwrap();
        seal_change(&mut ws, "delete b");
        ferry(&mut ws, &mirror);
        // …and the spine moves on, so the eventual fork base sits well after
        // the deletion (as in the incident: months after).
        put_file(&dir, "spacer.txt", "later\n");
        seal_change(&mut ws, "spacer");
        ferry(&mut ws, &mirror);

        let git = git2::Repository::open(&mirror).unwrap();
        assert!(
            !tree_paths(&git, &main_commit(&git).tree().unwrap()).contains(&"b.txt".to_string()),
            "precondition: the deletion landed"
        );

        // A concurrent land moves git main (theirs) while this line holds its
        // own new work (ours) — the #281-land shape that minted d3ca4b8.
        git_native_commit(
            &git,
            &[("c.txt", "from git\n")],
            ("Bob", "bob@example.com"),
            "concurrent land",
        );
        put_file(&dir, "d.txt", "local\n");
        ws.snapshot("local work").unwrap();

        // The pass ingests the git commit and reconciles by merging. A plain
        // ferry (not `--with-wip`): the review path now refuses to fold a live
        // WIP into a catch-up merge (#292), so the merge-manifest property #288
        // guards is exercised on the ordinary reconcile-merge path, which is
        // where a described line still folds.
        let report = ferry(&mut ws, &mirror);
        assert_eq!(report.ingested, 1);

        // The merged loot manifest must NOT re-raise b.txt…
        let anchor = ws.finalized_anchor().unwrap();
        let tree = ws.repo().change_tree(&anchor).unwrap();
        assert!(
            !tree.contains_key(Path::new("b.txt")),
            "merge manifest resurrected b.txt (#288): {:?}",
            tree.keys().collect::<Vec<_>>()
        );
        assert!(tree.contains_key(Path::new("a.txt")));
        assert!(tree.contains_key(Path::new("c.txt")), "their side folded in");
        assert!(tree.contains_key(Path::new("d.txt")), "our side kept");

        // …and neither must the projected merge commit's git tree.
        let paths = tree_paths(&git, &main_commit(&git).tree().unwrap());
        assert!(
            !paths.contains(&"b.txt".to_string()),
            "projected merge resurrected b.txt (#288): {paths:?}"
        );
        assert!(paths.contains(&"c.txt".to_string()));
        assert!(paths.contains(&"d.txt".to_string()));

        // The deleted file must not rematerialize on disk either.
        assert!(!dir.join("b.txt").exists(), "b.txt rematerialized on disk");
    }

    #[test]
    fn pulled_content_is_not_recaptured() {
        let (mut ws, dir, mirror) = setup("colo");
        put_file(&dir, "a.txt", "base\n");
        seal_change(&mut ws, "base");
        ferry(&mut ws, &mirror);

        // Co-located checkout: git advances AND the pull already wrote the
        // same content to disk before the ferry pass runs.
        let git = git2::Repository::open(&mirror).unwrap();
        let sha =
            git_native_commit(&git, &[("b.txt", "from git\n")], ("Bob", "bob@example.com"), "add b");
        put_file(&dir, "b.txt", "from git\n");

        let report = ferry(&mut ws, &mirror);
        assert_eq!(
            (report.ingested, report.projected),
            (1, 0),
            "pure ingest — no spurious capture or merge"
        );
        assert!(report.outcomes.is_empty(), "{:?}", report.outcomes);

        // main must not walk ahead of the ingested commit, or the co-located
        // checkout's next mirror-sync push stops fast-forwarding.
        assert_eq!(main_commit(&git).id().to_string(), sha);

        let ws2 = Workspace::open_at(&dir).unwrap();
        assert_eq!(ws2.repo().change_ids_topo().len(), 2, "base + ingested only");
        assert_eq!(ws2.repo().heads().len(), 1, "single head");
    }

    #[test]
    fn clean_tree_capture_mints_no_redundant_change() {
        let (mut ws, dir, mirror) = setup("clean");
        put_file(&dir, "a.txt", "base\n");
        seal_change(&mut ws, "base");
        ferry(&mut ws, &mirror);

        // git advances while the loot tree is untouched: the pre-ingest capture
        // snapshot is identical to the anchor and must evaporate, leaving only
        // the ingested change — no redundant capture, no stale fork.
        let git = git2::Repository::open(&mirror).unwrap();
        git_native_commit(&git, &[("b.txt", "from git\n")], ("Bob", "bob@example.com"), "add b");
        let report = ferry(&mut ws, &mirror);
        assert_eq!((report.ingested, report.projected), (1, 0));

        let ws2 = Workspace::open_at(&dir).unwrap();
        assert_eq!(
            ws2.repo().change_ids_topo().len(),
            2,
            "base + ingested only — the identical capture snapshot evaporated"
        );
        assert_eq!(ws2.repo().heads().len(), 1, "single head: no stale fork left behind");
    }

    #[test]
    fn deletion_only_change_finalizes_and_projects_the_removal_onto_main() {
        // #289 end-to-end: describe a deletion-only change, finalize through the
        // land path (`finalize_capturing`, where the tip-duplicate drop lives),
        // then ferry — main's new commit tree must lack the deleted path.
        let (mut ws, dir, mirror) = setup("del289");
        put_file(&dir, "keep.txt", "k\n");
        put_file(&dir, "gone.txt", "g\n");
        seal_change(&mut ws, "base");
        ferry(&mut ws, &mirror);
        let git = git2::Repository::open(&mirror).unwrap();
        let before = main_commit(&git).id();

        std::fs::remove_file(dir.join("gone.txt")).unwrap();
        ws.snapshot("chore: delete gone.txt").unwrap(); // describe -m
        let finalized = ws.finalize_capturing(&[], false).unwrap();
        assert!(finalized.is_some(), "the deletion-only change was signed, not dropped (#289)");

        let report = ferry(&mut ws, &mirror);
        assert_eq!((report.ingested, report.projected), (0, 1), "one commit projected");
        let tip = main_commit(&git);
        assert_ne!(tip.id(), before, "git main moved — no #195 false-stall");
        let paths = tree_paths(&git, &tip.tree().unwrap());
        assert!(paths.contains(&"keep.txt".to_string()), "kept content survives: {paths:?}");
        assert!(!paths.contains(&"gone.txt".to_string()), "the deleted path left main: {paths:?}");
    }

    #[test]
    fn git_author_matching_self_ingests_authored_and_signed() {
        let (mut ws, dir, mirror) = setup("self");
        put_file(&dir, "a.txt", "base\n");
        seal_change(&mut ws, "base");
        ferry(&mut ws, &mirror);

        // Commit as exactly the name/email the bridge seeded for self in the
        // identity map (it prefers git config, so read it back from disk).
        let id_map = crate::kv::parse(&read_or_empty(&ws.store().git_identity_map()));
        let self_entry = id_map[&hex::encode(&ws.author_pubkey().unwrap())].clone();
        let (name, email) = split_name_email(&self_entry).unwrap();
        let git = git2::Repository::open(&mirror).unwrap();
        git_native_commit(&git, &[("c.txt", "mine\n")], (&name, &email), "add c");

        let report = ferry(&mut ws, &mirror);
        assert_eq!(report.ingested, 1);
        let head = ws.finalized_anchor().unwrap();
        assert_eq!(ws.repo().change_author(&head), ws.author_pubkey(), "authored as self");
        assert!(ws.repo().change_signature(&head).is_some(), "signed at ingest");
    }

    #[test]
    fn concurrent_edits_converge_and_conflicts_hold_git_clean() {
        let (mut ws, dir, mirror) = setup("conflict");
        put_file(&dir, "shared.txt", "clean\n");
        put_file(&dir, "other.txt", "orig\n");
        seal_change(&mut ws, "base");
        ferry(&mut ws, &mirror);
        let git = git2::Repository::open(&mirror).unwrap();
        let clean_tip = main_commit(&git).id();

        // Both sides advance: loot edits shared.txt, git edits it differently
        // (and touches other.txt, which loot left alone).
        put_file(&dir, "shared.txt", "loot side\n");
        seal_change(&mut ws, "loot edit");
        git_native_commit(
            &git,
            &[("shared.txt", "git side\n"), ("other.txt", "git touch\n")],
            ("Bob", "bob@example.com"),
            "git edit",
        );

        let report = ferry(&mut ws, &mirror);
        assert_eq!(report.ingested, 1);
        assert!(
            matches!(report.outcomes.get(Path::new("shared.txt")), Some(MergeOutcome::Conflict { .. })),
            "same-path divergence surfaces as a conflict: {:?}",
            report.outcomes
        );
        assert!(
            ws.repo().conflicts().contains_key(Path::new("shared.txt")),
            "conflict visible to `loot conflicts`"
        );

        // ADR 0039: a conflicted reconcile BOUNCES — no merge change is
        // minted, so nothing new reaches git `main`: it simply stays at the
        // git-native tip until the operator resolves. (The pre-0039 pass
        // minted a signed "ferry: reconcile git main" merge here and published
        // it with the conflicted path held at its last clean state.)
        let after_bounce = main_commit(&git);
        assert_eq!(
            after_bounce.summary(),
            Some("git edit"),
            "a bounce publishes nothing — main stays at git's own tip"
        );
        let tree = after_bounce.tree().unwrap();
        let other = tree.get_name("other.txt").unwrap();
        assert_eq!(git.find_blob(other.id()).unwrap().content(), b"git touch\n");
        let _ = clean_tip;

        // Pre-dock resolve must sign the resolution on the spot — unsigned it
        // (and every descendant) is stranded as untravelable working history,
        // and the next projection dies on "parent has no mirrored commit"
        // (found live on the dogfood repo).
        ws.resolve_conflict(Path::new("shared.txt"), b"resolved\n", Visibility::Public)
            .unwrap();
        assert!(ws.repo().conflicts().is_empty());
        let heads = ws.repo().heads();
        assert_eq!(heads.len(), 1, "resolution is the sole head");
        assert!(ws.repo().change_author(&heads[0]).is_some());
        assert!(ws.repo().change_signature(&heads[0]).is_some(), "resolution signed at resolve");

        let after = ferry(&mut ws, &mirror);
        assert!(after.projected >= 1, "the resolution projects: {}", after.projected);
        let resolved_tip = main_commit(&git);
        let resolved_tree = resolved_tip.tree().unwrap();
        let blob = resolved_tree.get_name("shared.txt").unwrap();
        assert_eq!(git.find_blob(blob.id()).unwrap().content(), b"resolved\n");
    }

    #[test]
    fn review_from_a_stale_anchor_is_a_pure_projection() {
        // ADR 0039 (#362): git `main` moving under a lane no longer strands its
        // review. The old pass ran a full catch-up ferry, whose reconcile had
        // to fold (finalize) the WIP — #292's `REFUSE_REVIEW_STALE_ANCHOR`
        // refused that and stranded the lane instead. Review is now a pure
        // projection: it mints the provisional commit from the lane's own
        // anchor marks and touches nothing else, so a review off a stale
        // anchor opens normally — un-described, even (review stays the
        // pre-`describe` verb).
        let (mut ws, dir, mirror) = setup("wip-review-0039");
        put_file(&dir, "a.txt", "base\n");
        seal_change(&mut ws, "base");
        ferry(&mut ws, &mirror);
        let git = git2::Repository::open(&mirror).unwrap();
        let anchor_sha = main_commit(&git).id();

        // Main moves under the dock (a git-native commit — the out-of-wave
        // land shape), and un-described WIP sits on the tree.
        git_native_commit(&git, &[("b.txt", "from git\n")], ("Bob", "bob@example.com"), "add b");
        let moved_sha = main_commit(&git).id();
        put_file(&dir, "wip.txt", "unnamed\n");

        let anchor_before = ws.finalized_anchor();
        let marks_before = read_or_empty(&ws.store().git_marks());
        let state_before = read_or_empty(&ws.store().git_state());

        let r = ferry_wip(&mut ws, &mirror);
        let line = r.review.expect("the stale-anchor review projects");
        assert!(line.contains("op=opened") && line.contains("round=1"), "{line}");
        assert_eq!((r.ingested, r.projected), (0, 0), "a review pass ingests and projects nothing");
        assert!(r.outcomes.is_empty(), "and reconciles nothing");

        // The PR diff is the lane's anchor..WIP: the provisional commit
        // parents at the anchor's mark, not at the moved main.
        let dock = ws.dock_name().to_string();
        let rev = git.find_reference(&format!("refs/heads/review/{dock}")).unwrap();
        let c1 = git.find_commit(rev.target().unwrap()).unwrap();
        assert_eq!(c1.parent_id(0).unwrap(), anchor_sha, "review bases on the lane's own anchor");

        // Read-only pin (ADR 0039): dock tip, mirror main, and the bridge
        // spine are all byte-identical after the pass.
        assert_eq!(ws.finalized_anchor(), anchor_before, "dock tip untouched");
        assert_eq!(main_commit(&git).id(), moved_sha, "mirror main untouched");
        assert_eq!(read_or_empty(&ws.store().git_marks()), marks_before, "mark spine untouched");
        assert_eq!(read_or_empty(&ws.store().git_state()), state_before, "ferry state untouched");

        // Round 2+ still appends from the stale anchor.
        put_file(&dir, "wip.txt", "revised\n");
        let r2 = ferry_wip(&mut ws, &mirror);
        let line2 = r2.review.unwrap();
        assert!(line2.contains("op=appended") && line2.contains("round=2"), "{line2}");
        let rev2 = git.find_reference(&format!("refs/heads/review/{dock}")).unwrap();
        let c2 = git.find_commit(rev2.target().unwrap()).unwrap();
        assert_eq!(c2.parent_id(0).unwrap(), c1.id(), "round 2 appends onto round 1");
        assert_eq!(main_commit(&git).id(), moved_sha, "main still untouched after round 2");
    }

    /// Walk `main` first-parent from the tip, newest first, returning each
    /// commit's subject line — the shape assertions for the ADR 0039 land
    /// criterion read from this.
    fn main_subjects(git: &git2::Repository) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = Some(main_commit(git));
        while let Some(c) = cur {
            out.push(c.summary().unwrap_or("").to_string());
            cur = c.parent(0).ok();
        }
        out
    }

    #[test]
    fn a_stale_lane_lands_exactly_one_commit_per_change() {
        // ADR 0039's hard criterion: a lane whose anchor fell behind git
        // `main` (a sibling landed mid-flight) still lands as exactly one
        // commit per change — linear history, no "ferry: reconcile git main"
        // merge node.
        let (mut ws, repo_dir, mirror) = setup("stale-land-linear");
        put_file(&repo_dir, "a.txt", "base\n");
        seal_change(&mut ws, "base");
        ferry(&mut ws, &mirror);

        // Two lanes fork at the same anchor.
        let l1 = ws.spawn_lane(None, Some(&repo_dir.parent().unwrap().join("l1"))).unwrap();
        let l2 = ws.spawn_lane(None, Some(&repo_dir.parent().unwrap().join("l2"))).unwrap();

        // Sibling lane l1 lands first — main moves past l2's anchor.
        let mut w1 = Workspace::open_at(&l1.dir).unwrap();
        put_file(&l1.dir, "b.txt", "sibling\n");
        seal_change(&mut w1, "landed: sibling change");
        run(&mut w1, None, None, false).unwrap();
        let git = git2::Repository::open(&mirror).unwrap();
        let sibling_sha = main_commit(&git).id();

        // l2 finalizes its own (disjoint) change from the stale anchor and
        // lands — the ferry `loot-first land` runs.
        let mut w2 = Workspace::open_at(&l2.dir).unwrap();
        put_file(&l2.dir, "c.txt", "mine\n");
        seal_change(&mut w2, "landed: stale-lane change");
        let stale = w2.finalized_anchor().unwrap();
        let r = run(&mut w2, None, None, false).unwrap();
        assert!(w2.conflicts().is_empty(), "disjoint paths: no bounce");
        assert!(r.projected >= 1, "the carried change projected");

        // Linear, one commit per change, both contents present.
        let tip = main_commit(&git);
        assert_eq!(tip.summary(), Some("landed: stale-lane change"), "the change's own subject");
        assert_eq!(tip.parent_ids().count(), 1, "not a merge commit");
        assert_eq!(tip.parent_id(0).unwrap(), sibling_sha, "sits directly on the sibling's land");
        let subjects = main_subjects(&git);
        assert!(
            !subjects.iter().any(|s| s.contains("ferry: reconcile")),
            "no reconcile-merge noise on landed history: {subjects:?}"
        );
        let paths = tree_paths(&git, &tip.tree().unwrap());
        assert!(paths.contains(&"b.txt".to_string()), "the sibling's content is under the tip");
        assert!(paths.contains(&"c.txt".to_string()), "this lane's content landed");
        // And in loot the landed tip supersedes the stale original.
        let tip_change = w2.finalized_anchor().unwrap();
        assert_ne!(tip_change, stale);
        assert!(w2.repo().supersedes(&tip_change, &stale), "carried as a supersession");
    }

    #[test]
    fn a_conflicted_stale_land_bounces_then_relands_as_one_commit() {
        // The other half of the ADR 0039 criterion: a genuinely conflicted
        // stale land bounces (nothing minted, main unmoved), resolves in-lane
        // via `loot resolve`, and the re-land still projects ONE commit whose
        // tree carries the resolution — no resolution-commit trail on main.
        let (mut ws, repo_dir, mirror) = setup("stale-land-bounce");
        put_file(&repo_dir, "base.txt", "base\n");
        seal_change(&mut ws, "base");
        ferry(&mut ws, &mirror);

        let l1 = ws.spawn_lane(None, Some(&repo_dir.parent().unwrap().join("l1"))).unwrap();
        let l2 = ws.spawn_lane(None, Some(&repo_dir.parent().unwrap().join("l2"))).unwrap();

        // Sibling lands an edit of base.txt.
        let mut w1 = Workspace::open_at(&l1.dir).unwrap();
        put_file(&l1.dir, "base.txt", "theirs\n");
        seal_change(&mut w1, "landed: sibling edit");
        run(&mut w1, None, None, false).unwrap();
        let git = git2::Repository::open(&mirror).unwrap();
        let sibling_sha = main_commit(&git).id();

        // This lane edits the same path from the stale anchor — the land's
        // ferry bounces: conflicts recorded, nothing minted, main unmoved.
        let mut w2 = Workspace::open_at(&l2.dir).unwrap();
        put_file(&l2.dir, "base.txt", "ours\n");
        seal_change(&mut w2, "fix: base edit");
        let stale = w2.finalized_anchor().unwrap();
        let r = run(&mut w2, None, None, false).unwrap();
        assert!(
            matches!(r.outcomes[&PathBuf::from("base.txt")], MergeOutcome::Conflict { .. }),
            "the same-path divergence bounced"
        );
        assert!(!w2.conflicts().is_empty(), "conflict recorded for loot resolve");
        assert_eq!(main_commit(&git).id(), sibling_sha, "a bounce moves nothing onto main");
        assert_eq!(
            w2.finalized_anchor(),
            Some(stale.clone()),
            "a bounce mints nothing — the signed change is untouched"
        );

        // Resolve in-lane, then re-land: the resolution folds into the carried
        // change instead of trailing it as its own commit.
        w2.resolve_conflict(Path::new("base.txt"), b"resolved\n", loot_core::Visibility::Public)
            .unwrap();
        let r2 = run(&mut w2, None, None, false).unwrap();
        assert!(w2.conflicts().is_empty(), "nothing left to resolve");
        assert!(r2.projected >= 1);

        let tip = main_commit(&git);
        assert_eq!(tip.summary(), Some("fix: base edit"), "the change's own subject, not a resolution placeholder");
        assert_eq!(tip.parent_ids().count(), 1, "not a merge commit");
        assert_eq!(tip.parent_id(0).unwrap(), sibling_sha, "linear on top of the sibling's land");
        let subjects = main_subjects(&git);
        assert!(
            !subjects.iter().any(|s| s.contains("(conflict resolution:") || s.contains("ferry: reconcile")),
            "no resolution or merge noise on landed history: {subjects:?}"
        );
        // The landed tree carries the operator's resolution.
        let blob = tip
            .tree()
            .unwrap()
            .get_path(Path::new("base.txt"))
            .and_then(|e| git.find_blob(e.id()))
            .unwrap();
        assert_eq!(blob.content(), b"resolved\n");
    }

    #[test]
    fn with_wip_projects_provisional_review_lane_then_reaps_on_finalize() {
        let (mut ws, dir, mirror) = setup("wip-review");
        // Two sealed classes: restricted to a peer (unreadable here) AND
        // restricted to *alice herself* (readable — the #155 live-run leak:
        // publication must filter on visibility, not readability).
        put_file(&dir, ".lootattributes", "secret/** restricted=bob\npitch/** restricted=alice\n");
        put_file(&dir, "a.txt", "base\n");
        seal_change(&mut ws, "base");
        ferry(&mut ws, &mirror);

        // Round 1: unfinalized WIP (incl. both sealed paths) -> a provisional
        // commit on review/<dock>; main and the mark spine stay untouched.
        put_file(&dir, "a.txt", "wip round 1\n");
        put_file(&dir, "secret/pitch.md", "sealed wip\n");
        put_file(&dir, "pitch/plan.md", "dev-readable sealed wip\n");
        let (wid, _) = ws.snapshot("feature wip").unwrap();
        let marks_before = read_or_empty(&ws.store().git_marks());
        let git = git2::Repository::open(&mirror).unwrap();
        let main_before = main_commit(&git).id();

        let r1 = ferry_wip(&mut ws, &mirror);
        let line = r1.review.expect("review line");
        assert!(line.contains("op=opened") && line.contains("round=1"), "{line}");
        let dock = ws.dock_name().to_string();
        let rev = git
            .find_reference(&format!("refs/heads/review/{dock}"))
            .expect("review ref exists");
        let c1 = git.find_commit(rev.target().unwrap()).unwrap();
        let msg = c1.message().unwrap();
        assert_eq!(bridge::parse_trailer(msg, TRAILER_PROVISIONAL), Some("true".into()));
        assert_eq!(bridge::parse_trailer(msg, TRAILER_CHANGE_ID), Some(hex::encode(&wid.0)));
        assert!(
            bridge::parse_trailer(msg, TRAILER_SIGNATURE).is_none(),
            "provisional = no loot signature"
        );
        let paths = tree_paths(&git, &c1.tree().unwrap());
        assert!(paths.contains(&"a.txt".to_string()));
        assert!(
            !paths.iter().any(|p| p.contains("secret")),
            "review lane omits unreadable sealed paths: {paths:?}"
        );
        assert!(
            !paths.iter().any(|p| p.contains("pitch")),
            "review lane omits DEV-READABLE sealed paths (the #155 leak): {paths:?}"
        );
        assert!(
            r1.notes.iter().any(|n| n.contains("omitted") && n.contains("pitch/plan.md")),
            "omission surfaced as a note: {:?}",
            r1.notes
        );
        assert_eq!(main_commit(&git).id(), main_before, "main untouched by WIP");
        assert_eq!(
            read_or_empty(&ws.store().git_marks()),
            marks_before,
            "mark spine untouched by WIP"
        );

        // Same tree again -> idempotent, no new round.
        let r2 = ferry_wip(&mut ws, &mirror);
        assert!(r2.review.unwrap().contains("op=up-to-date"));

        // Revise -> round 2 appends onto round 1 (same durable lane, #150).
        put_file(&dir, "a.txt", "wip round 2\n");
        let r3 = ferry_wip(&mut ws, &mirror);
        let line3 = r3.review.unwrap();
        assert!(line3.contains("op=appended") && line3.contains("round=2"), "{line3}");
        let rev = git.find_reference(&format!("refs/heads/review/{dock}")).unwrap();
        let c2 = git.find_commit(rev.target().unwrap()).unwrap();
        assert_eq!(c2.parent_ids().count(), 1);
        assert_eq!(c2.parent_id(0).unwrap(), c1.id(), "append-per-round");

        // Finalize (git-quiet), then the next plain ferry lands the signed
        // change on main AND lazily reaps the provisional lane.
        ws.finalize_working().unwrap();
        let r4 = ferry(&mut ws, &mirror);
        assert!(r4.projected >= 1, "signed change lands on main");
        assert!(
            r4.notes.iter().any(|n| n.contains("reaped review/") && n.contains("landed")),
            "reap note missing: {:?}",
            r4.notes
        );
        assert!(
            git.find_reference(&format!("refs/heads/review/{dock}")).is_err(),
            "review ref retired"
        );
        let landed = main_commit(&git);
        assert!(
            bridge::parse_trailer(landed.message().unwrap(), TRAILER_SIGNATURE).is_some(),
            "landed commit is the signed projection"
        );
        assert!(bridge::parse_trailer(landed.message().unwrap(), TRAILER_PROVISIONAL).is_none());
        let landed_paths = tree_paths(&git, &landed.tree().unwrap());
        assert!(
            !landed_paths.iter().any(|p| p.contains("secret") || p.contains("pitch")),
            "landed main never publishes sealed paths either: {landed_paths:?}"
        );

        // And the pass after that is a full no-op.
        let r5 = ferry(&mut ws, &mirror);
        assert_eq!((r5.ingested, r5.projected), (0, 0));
    }

    #[test]
    fn lane_review_projections_are_position_scoped() {
        // #281: every lane's home dock is `main`, so dock-named review refs
        // made N concurrent lanes share one branch — the second lane's ferry
        // force-pushed over the first's in-flight PR head, and either pass
        // could misjudge (and reap) the other's live entry. The ref must carry
        // the *position*: `review/<lane-id>` from a lane, `review/<dock>` on
        // the primary.
        let (mut ws, dir, mirror) = setup("wip-lane-281");
        put_file(&dir, "a.txt", "base\n");
        seal_change(&mut ws, "base");
        ferry(&mut ws, &mirror);

        // The primary opens a review lane on the home dock, dock-named.
        put_file(&dir, "a.txt", "primary wip\n");
        ws.snapshot("primary wip").unwrap();
        let line = ferry_wip(&mut ws, &mirror).review.unwrap();
        assert!(line.contains("branch=review/main") && line.contains("owner=-"), "{line}");

        // A lane over the same store (same dock!) projects to its own ref.
        let spawned = ws
            .spawn_lane_as(None, Some(&dir.parent().unwrap().join("lane-281")), Some("t281"))
            .unwrap();
        let mut lw = Workspace::open_at(&spawned.dir).unwrap();
        put_file(&spawned.dir, "b.txt", "lane wip\n");
        lw.snapshot("lane wip").unwrap();
        let rl = ferry_wip(&mut lw, &mirror);
        let line = rl.review.unwrap();
        assert!(
            line.contains(&format!("branch=review/{}", spawned.id))
                && line.contains(&format!("owner={}", spawned.id)),
            "{line}"
        );

        // Both refs exist side by side — no shared mutable ref (ADR 0034).
        let git = git2::Repository::open(&mirror).unwrap();
        assert!(git.find_reference("refs/heads/review/main").is_ok());
        let lane_ref = format!("refs/heads/review/{}", spawned.id);
        assert!(git.find_reference(&lane_ref).is_ok());

        // Neither position's pass judged (or reaped) the other's live entry:
        // the lane's pass kept the primary's, and vice versa.
        assert!(!rl.notes.iter().any(|n| n.contains("reaped")), "{:?}", rl.notes);
        let rp = ferry_wip(&mut ws, &mirror);
        assert!(rp.review.unwrap().contains("op=up-to-date"));
        assert!(!rp.notes.iter().any(|n| n.contains("reaped")), "{:?}", rp.notes);
        assert!(git.find_reference("refs/heads/review/main").is_ok());
        assert!(git.find_reference(&lane_ref).is_ok());
    }

    #[test]
    fn a_gone_lanes_review_ref_is_reaped_by_any_pass() {
        // The flip side of owner-scoping (#281): only the owner can judge its
        // entry's liveness, so an abandoned lane (reaped from the registry
        // without landing) would leak its entry and ref forever. A foreign
        // pass reaps exactly the entries whose owner lane no longer exists.
        let (mut ws, dir, mirror) = setup("wip-lane-gone-281");
        put_file(&dir, "a.txt", "base\n");
        seal_change(&mut ws, "base");
        ferry(&mut ws, &mirror);

        let spawned = ws
            .spawn_lane_as(None, Some(&dir.parent().unwrap().join("lane-gone")), Some("t9"))
            .unwrap();
        let mut lw = Workspace::open_at(&spawned.dir).unwrap();
        put_file(&spawned.dir, "b.txt", "lane wip\n");
        lw.snapshot("lane wip").unwrap();
        ferry_wip(&mut lw, &mirror);
        let git = git2::Repository::open(&mirror).unwrap();
        let lane_ref = format!("refs/heads/review/{}", spawned.id);
        assert!(git.find_reference(&lane_ref).is_ok());

        // While the owner lane exists, a primary pass keeps its entry intact.
        let keep = ferry(&mut ws, &mirror);
        assert!(!keep.notes.iter().any(|n| n.contains("reaped")), "{:?}", keep.notes);
        assert!(git.find_reference(&lane_ref).is_ok());

        // Remove the lane from the registry; the next pass — any position —
        // retires the orphaned review lane, ref and all.
        ws.store().remove_lane_entry(&spawned.id).unwrap();
        let swept = ferry(&mut ws, &mirror);
        assert!(
            swept
                .notes
                .iter()
                .any(|n| n.contains(&format!("review/{}", spawned.id)) && n.contains("gone")),
            "{:?}",
            swept.notes
        );
        assert!(git.find_reference(&lane_ref).is_err());
    }


    /// Reopen the change carrying version `v`, amend `a.txt`, finalize; returns
    /// the superseding version X′.
    fn amend_change(ws: &mut Workspace, dir: &Path, v: &Oid, content: &str) -> Oid {
        let cid = ws.graph().change_id(v).unwrap();
        ws.edit(&loot_core::hex::letters(&cid)).unwrap();
        put_file(dir, "a.txt", content);
        ws.snapshot("feature").unwrap();
        ws.finalize_working().unwrap();
        ws.liveness()
            .live_of(&cid)
            .into_iter()
            .next()
            .unwrap()
    }

    #[test]
    fn amend_of_landed_threads_onto_predecessor_as_a_fast_forward() {
        // ADR 0033: amending a *landed* change X projects X′ as a linear
        // fix-up on top of X's commit — main fast-forwards, no fork, no
        // force-push — and the commit records the supersession in a trailer.
        let (mut ws, dir, mirror) = setup("amend-landed");
        put_file(&dir, "a.txt", "base\n");
        seal_change(&mut ws, "base"); // P, on the primary
        ferry(&mut ws, &mirror);
        // The primary tracks its tip (the post-land state) so `loot edit`
        // re-anchors to a *sibling* amend — named docks that gave the old test
        // this for free are retired (#253/ADR 0034).
        ws.pin_tip_at_anchor();
        put_file(&dir, "a.txt", "feature\n");
        put_file(&dir, "b.txt", "added\n");
        let x = seal_change(&mut ws, "feature"); // X, child of P
        ferry(&mut ws, &mirror);
        let git = git2::Repository::open(&mirror).unwrap();
        let x_sha = main_commit(&git).id(); // main == X

        // Reopen X and amend it, then finalize the superseding sibling X′.
        let xprime = amend_change(&mut ws, &dir, &x, "feature amended\n");
        assert_ne!(xprime, x, "the amend minted a new version");
        assert_eq!(ws.graph().predecessors(&xprime), vec![x.clone()], "X′ supersedes X");
        assert_eq!(ws.graph().parents(&xprime), ws.graph().parents(&x), "X′ is a sibling (parent P)");

        let rep = ferry(&mut ws, &mirror);
        assert!(rep.projected >= 1, "X′ projects");
        let head = main_commit(&git);
        // Threaded onto X: X′'s single git parent is X's commit, and main is a
        // fast-forward (it descends from X) even though X′ is a loot *sibling*.
        assert_eq!(head.parent_ids().count(), 1);
        assert_eq!(head.parent_id(0).unwrap(), x_sha, "X′ threads onto X, not the loot parent P");
        assert!(
            git.graph_descendant_of(head.id(), x_sha).unwrap(),
            "main fast-forwards over X"
        );
        // The projected tree is exactly X′'s public tree (delta vs X): the
        // amended path lands and the unchanged path carries.
        let tree = head.tree().unwrap();
        assert_eq!(
            git.find_blob(tree.get_name("a.txt").unwrap().id()).unwrap().content(),
            b"feature amended\n"
        );
        assert!(tree.get_name("b.txt").is_some(), "unchanged path carried onto X");
        // The supersession travels as a trailer naming X's version id.
        let msg = head.message().unwrap();
        assert_eq!(
            bridge::parse_trailer(msg, TRAILER_PREDECESSORS),
            Some(hex::encode(&x.0)),
            "Loot-Predecessors names the superseded version"
        );
        assert_eq!(
            bridge::parse_trailer(msg, TRAILER_CHANGE_ID),
            Some(hex::encode(&xprime.0))
        );
    }

    #[test]
    fn local_finalize_then_amend_collapses_onto_the_sibling_parent() {
        // ADR 0033: when X was finalized but never ferried (not on git main),
        // the amend threads onto the loot sibling parent P — main fast-forwards
        // P -> X′ and the intermediate X stays reachable on a loot head ref.
        let (mut ws, dir, mirror) = setup("amend-local");
        put_file(&dir, "a.txt", "base\n");
        seal_change(&mut ws, "base"); // P, on the primary
        ferry(&mut ws, &mirror);
        // The primary tracks its tip (post-land state) so `loot edit` re-anchors
        // to a sibling amend — #253 retired the dock that gave this for free.
        ws.pin_tip_at_anchor();
        let git = git2::Repository::open(&mirror).unwrap();
        let p_sha = main_commit(&git).id(); // main == P

        // Finalize X locally, do NOT ferry it, then amend to the sibling X′.
        put_file(&dir, "a.txt", "feature\n");
        let x = seal_change(&mut ws, "feature");
        let xprime = amend_change(&mut ws, &dir, &x, "feature amended\n");
        assert_eq!(ws.graph().parents(&xprime), ws.graph().parents(&x), "X′ is a sibling of X");

        ferry(&mut ws, &mirror);
        let head = main_commit(&git);
        // X′ threads onto P (its sibling parent), NOT onto the unmarked X.
        assert_eq!(head.parent_id(0).unwrap(), p_sha, "X′ collapses onto P");
        assert!(git.graph_descendant_of(head.id(), p_sha).unwrap());
        assert_eq!(
            git.find_blob(head.tree().unwrap().get_name("a.txt").unwrap().id())
                .unwrap()
                .content(),
            b"feature amended\n"
        );
        // The superseded intermediate X is parked reachable off-main.
        assert!(
            git.find_reference(&format!("refs/loot/heads/{}", hex::encode(&x.0))).is_ok(),
            "the superseded intermediate stays reachable on a loot head ref"
        );
    }

    #[test]
    fn a_reopened_review_lane_survives_a_ferry_pass() {
        // ADR 0033: a review lane is live iff the dock's current working change
        // still carries its change id. After landing X and reopening it with
        // `loot edit`, the reopened lane must NOT be reaped — the old
        // change-id-wide "a signed version exists" test reaped it every pass.
        let (mut ws, dir, mirror) = setup("reopen-lane");
        put_file(&dir, "a.txt", "base\n");
        seal_change(&mut ws, "base"); // P, on the primary
        ferry(&mut ws, &mirror);
        let dock = ws.dock_name().to_string(); // the primary's handle: "main"
        let git = git2::Repository::open(&mirror).unwrap();

        // Open a review lane for a feature, then finalize + land it (lane reaps).
        put_file(&dir, "a.txt", "feature\n");
        let (xw, _) = ws.snapshot("feature").unwrap();
        let cid = ws.graph().change_id(&xw).unwrap();
        ferry_wip(&mut ws, &mirror);
        assert!(git.find_reference(&format!("refs/heads/review/{dock}")).is_ok());
        ws.finalize_working().unwrap();
        let x = ws
            .liveness()
            .live_of(&cid)
            .into_iter()
            .next()
            .unwrap();
        let landed = ferry(&mut ws, &mirror);
        assert!(
            landed.notes.iter().any(|n| n.contains("reaped review/") && n.contains("landed")),
            "the landed lane reaps: {:?}",
            landed.notes
        );
        assert!(
            git.find_reference(&format!("refs/heads/review/{dock}")).is_err(),
            "lane retired on land"
        );

        // Reopen X (amend), re-open the review lane, then a plain ferry pass
        // must LEAVE the lane in place — the reopened change is live WIP again.
        ws.edit(&loot_core::hex::letters(&cid)).unwrap();
        put_file(&dir, "a.txt", "feature amended\n");
        ws.snapshot("feature").unwrap();
        assert_eq!(ws.store().read_working(None).map(|w| ws.graph().change_id(&w)), Some(Some(cid)),
            "the reopened working change carries X's handle");
        let _ = x;
        let reopened = ferry_wip(&mut ws, &mirror);
        assert!(
            reopened.review.unwrap().contains("op="),
            "the lane re-opens for the reopened change"
        );
        assert!(git.find_reference(&format!("refs/heads/review/{dock}")).is_ok());

        let pass = ferry(&mut ws, &mirror);
        assert!(
            !pass.notes.iter().any(|n| n.contains("reaped review/")),
            "the reopened lane must survive the pass: {:?}",
            pass.notes
        );
        assert!(
            git.find_reference(&format!("refs/heads/review/{dock}")).is_ok(),
            "reopened review lane survives the ferry pass"
        );
    }

    #[test]
    fn projection_preserves_git_filemodes() {
        let (mut ws, dir, mirror) = setup("modes");
        put_file(&dir, "a.txt", "base\n");
        seal_change(&mut ws, "base");
        ferry(&mut ws, &mirror);

        // A git-native commit adds an executable script (100755).
        let git = git2::Repository::open(&mirror).unwrap();
        {
            let parent = main_commit(&git);
            let mut builder = git.treebuilder(Some(&parent.tree().unwrap())).unwrap();
            let blob = git.blob(b"#!/bin/sh\n").unwrap();
            builder.insert("run.sh", blob, 0o100755).unwrap();
            let tree = git.find_tree(builder.write().unwrap()).unwrap();
            let sig = git2::Signature::now("Bob", "bob@example.com").unwrap();
            git.commit(Some(MAIN_REF), &sig, &sig, "add exec script", &tree, &[&parent])
                .unwrap();
        }
        ferry(&mut ws, &mirror);

        // A loot edit of a DIFFERENT file projects on top; the untouched
        // script must keep its executable bit (found live on PR #164).
        put_file(&dir, "a.txt", "edited\n");
        seal_change(&mut ws, "edit a");
        ferry(&mut ws, &mirror);
        let tip = main_commit(&git);
        let tree = tip.tree().unwrap();
        let entry = tree.get_name("run.sh").expect("script present");
        assert_eq!(entry.filemode(), 0o100755, "exec bit survives projection");
    }

    #[test]
    fn bootstrap_adopts_prebridge_history_without_ingesting() {
        let (mut ws, dir, mirror) = setup("bootstrap");
        // A pre-existing git mirror with its own (trailerless) history.
        let git = git2::Repository::init_bare(&mirror).unwrap();
        {
            let blob = git.blob(b"old\n").unwrap();
            let mut builder = git.treebuilder(None).unwrap();
            builder.insert("old.txt", blob, 0o100644).unwrap();
            let tree = git.find_tree(builder.write().unwrap()).unwrap();
            let sig = git2::Signature::now("Old", "old@example.com").unwrap();
            git.commit(Some(MAIN_REF), &sig, &sig, "pre-bridge", &tree, &[]).unwrap();
        }
        let heads_before = {
            put_file(&dir, "a.txt", "loot\n");
            seal_change(&mut ws, "loot base");
            ws.repo().heads()
        };

        let report = ferry(&mut ws, &mirror);
        assert_eq!(report.ingested, 0, "pre-bridge history is baseline, not ingested");
        assert!(report.notes.iter().any(|n| n.contains("baseline")));
        assert_eq!(ws.repo().heads(), heads_before, "loot history untouched");
    }

    /// #265: `loot-first tag` runs a bare ferry from the primary. When the
    /// primary dock is strictly behind a lane-landed main — the landed change
    /// outside its lineage-filtered load — that ferry must catch the dock up
    /// and project NOTHING: never re-mint the landed tree as a duplicate line
    /// or move the mirror's main off the landed tip.
    #[test]
    fn bare_ferry_from_a_dock_behind_a_lane_land_adopts_and_projects_nothing() {
        let (mut ws, repo_dir, mirror) = setup("behind-dock");
        put_file(&repo_dir, "a.txt", "one");
        seal_change(&mut ws, "c1");
        let r1 = ferry(&mut ws, &mirror);
        assert_eq!(r1.projected, 1, "c1 projects to git-main");

        // A lane lands c2 — finalize there, then ferry from the lane exactly
        // as `loot-first land` does. The shared spine now names c2 as main.
        let lane_dir = repo_dir.parent().unwrap().join("l1");
        let spawned = ws.spawn_lane(None, Some(&lane_dir)).unwrap();
        let mut lw = Workspace::open_at(&spawned.dir).unwrap();
        put_file(&spawned.dir, "b.txt", "landed");
        seal_change(&mut lw, "landed c2");
        let c2 = lw.heads()[0].clone();
        let r2 = run(&mut lw, None, None, false).unwrap();
        assert_eq!(r2.projected, 1, "the lane's land projected c2");
        let landed_sha = git2::Repository::open(&mirror)
            .unwrap()
            .find_reference(MAIN_REF)
            .unwrap()
            .target()
            .unwrap();

        // The primary reopens fresh: strictly behind, c2 out of its lineage.
        let mut ws = Workspace::open_at(&repo_dir).unwrap();
        let r3 = run(&mut ws, None, None, false).unwrap();
        assert_eq!(r3.ingested, 0, "the landed commit is already marked — nothing to ingest");
        assert_eq!(r3.projected, 0, "a catch-up projects nothing");
        assert!(r3.notes.is_empty(), "no refusals — the catch-up is clean: {:?}", r3.notes);
        assert_eq!(ws.finalized_anchor(), Some(c2), "the dock caught up to landed main");
        assert!(
            repo_dir.join("b.txt").exists(),
            "the landed content materialized into the primary tree"
        );
        let now_sha = git2::Repository::open(&mirror)
            .unwrap()
            .find_reference(MAIN_REF)
            .unwrap()
            .target()
            .unwrap();
        assert_eq!(now_sha, landed_sha, "the mirror's main stayed on the landed tip");
    }
}
