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
    TRAILER_PROVISIONAL, TRAILER_SIGNATURE,
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

/// Run one bidirectional reconcile pass. `git_dir_flag`/`dock_flag` override
/// the mirror config under `.loot/git-mirror/config`; the override persists
/// only when the pass succeeds (#201 — a failed probe must not rebind).
/// `with_wip` additionally projects the ambient dock's *unfinalized* working
/// change to `refs/heads/review/<dock>` as a provisional commit (map #148);
/// provisional lifecycle reaping runs on every pass regardless of the flag.
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
    let mut cfg = parse_kv(&read_or_empty(&cfg_path));
    if let Some(dir) = git_dir_flag {
        cfg.insert("gitdir".into(), dir.into());
    }
    if let Some(dock) = dock_flag {
        let prev = cfg.insert("dock".into(), dock.into());
        if let Some(prev) = prev.filter(|p| p != dock) {
            report.notes.push(format!("mirror main now tracks dock '{dock}' (was '{prev}')"));
        }
    }
    let git_dir = cfg
        .get("gitdir")
        .cloned()
        .ok_or("no mirror bound — run `loot ferry --git-dir <path>` once to bind one")?;
    let main_dock = cfg.get("dock").cloned().unwrap_or_else(|| "main".to_string());
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
    let mut id_map = parse_kv(&read_or_empty(&ws.store().git_identity_map()));
    if let Some(pk) = ws.author_pubkey() {
        let pk_hex = hex::encode(&pk);
        if !id_map.contains_key(&pk_hex) {
            let (name, email) = self_name_email(ws, &git);
            id_map.insert(pk_hex, format!("{name} <{email}>"));
            write_kv(&ws.store().git_identity_map(), &id_map)?;
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
    if !had_state && marks.is_empty() {
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
    if let Some(tip) = &main_tip {
        let new_shas = walk_new_commits(&git, tip, &marks, state.git_main.as_deref())?;
        // The loot side of the divergence check, pinned before ingest — an
        // ingested change becomes a graph head itself, so the post-ingest
        // anchor can't tell fast-forward from true divergence.
        let ours = ws.finalized_anchor();
        let had_new = !new_shas.is_empty();
        for sha in new_shas {
            ingest_commit(ws, &git, &sha, &mut marks, &id_map, &mut report)?;
        }
        let target = marks.change_for(tip).cloned().map(|(t, _)| t);

        // --- reconcile: advance the ambient dock to cover the git side ---
        // The whole decision — capture-vs-not (ingesting first lets the
        // capture recognize and drop a snapshot matching the incoming target,
        // the co-located checkout after a `git pull`), adopt-vs-merge, which
        // tip advances — lives in Workspace::reconcile_onto (R2, #178); the
        // bridge only supplies the incoming line and its pinned anchor.
        report.outcomes = ws.reconcile_onto(
            target.as_ref(),
            ours.as_ref(),
            had_new,
            "ferry: reconcile git main",
        )?;
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
    let represented = ws.graph().ancestor_closure(marks.change_ids());
    for id in ws.graph().ids_topo() {
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

    // --- refs: heads, docks, and the designated-dock main ---
    update_loot_refs(ws, &git, &marks)?;
    let dock_sel = |name: &str| if name == "main" { None } else { Some(name.to_string()) };
    let main_target = if ws.dock_name() == main_dock {
        ws.finalized_anchor()
    } else {
        ws.store().read_tip(dock_sel(&main_dock).as_deref())
    };
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
                // means the designated dock is stale or freshly rebound, so say
                // so instead of silently moving main backward.
                report.notes.push(format!(
                    "main NOT moved to {} — it does not descend from the current tip {}; \
                     is the designated dock ('{main_dock}') stale? see .loot/git-mirror/config",
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
    wip.entries.retain(|e| {
        let landed = ws.graph().ids_topo().iter().any(|c| {
            ws.graph().signature(c).is_some()
                && wip_key(ws, c) == e.change
                && ws.graph().author(c).is_some()
        });
        let current = ws
            .store()
            .read_working(dock_sel_wip(&e.dock).as_deref())
            .map(|w| wip_key(ws, &w));
        let live = !landed && current.as_deref() == Some(e.change.as_str());
        if !live {
            let ref_name = format!("refs/heads/review/{}", e.dock);
            if let Ok(mut r) = git.find_reference(&ref_name) {
                let _ = r.delete();
            }
            report.notes.push(format!(
                "reaped review/{} (change {} {})",
                e.dock,
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
                let version_hex = hex::encode(&wid.0);
                let existing = wip
                    .entries
                    .iter()
                    .find(|e| e.dock == dock && e.change == key)
                    .cloned();
                if existing.as_ref().is_some_and(|e| e.version == version_hex) {
                    let e = existing.as_ref().unwrap();
                    report.review = Some(format!(
                        "review: dock={dock} branch=review/{dock} sha={} change={key} version={} round={} op=up-to-date",
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
                        let ref_name = format!("refs/heads/review/{dock}");
                        git.reference(
                            &ref_name,
                            git2::Oid::from_str(&sha).map_err(|e| e.to_string())?,
                            true,
                            "loot ferry --with-wip",
                        )
                        .map_err(|e| format!("update {ref_name}: {e}"))?;
                        wip.entries.retain(|e| !(e.dock == dock && e.change == key));
                        wip.entries.push(WipEntry {
                            change: key.clone(),
                            dock: dock.clone(),
                            sha: sha.clone(),
                            version: version_hex.clone(),
                            round,
                        });
                        report.review = Some(format!(
                            "review: dock={dock} branch=review/{dock} sha={sha} change={key} version={} round={round} op={}",
                            &version_hex[..8],
                            if round == 1 { "opened" } else { "appended" }
                        ));
                    }
                }
            }
        }
    }
    std::fs::write(&wip_path, wip.encode()).map_err(|e| format!("write wip: {e}"))?;

    // --- persist the spine ---
    state.git_main = git
        .find_reference(MAIN_REF)
        .ok()
        .and_then(|r| r.target())
        .map(|o| o.to_string());
    state.loot_heads = ws.heads();
    std::fs::write(&marks_path, marks.encode()).map_err(|e| format!("write marks: {e}"))?;
    std::fs::write(&state_path, state.encode()).map_err(|e| format!("write state: {e}"))?;
    write_kv(&cfg_path, &cfg)?;
    Ok(report)
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

/// Ingest one new commit: a trailered commit maps straight back to its change
/// (lossless round-trip); a git-native commit becomes a loot change sealed at
/// ingest via `.lootattributes` (ADR 0028).
fn ingest_commit(
    ws: &mut Workspace,
    git: &git2::Repository,
    sha: &str,
    marks: &mut MarkMap,
    id_map: &BTreeMap<String, String>,
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

    // Trailer short-circuit: this commit *is* a loot change we projected.
    if let Some(id_hex) = bridge::parse_trailer(&message, TRAILER_CHANGE_ID) {
        let id = bridge::parse_oid_hex(&id_hex)
            .ok_or_else(|| format!("commit {sha}: malformed {TRAILER_CHANGE_ID} trailer"))?;
        if ws.graph().tree(&id).is_none() {
            return Err(format!(
                "commit {} names loot change {} which this repo does not have — \
                 is the mirror bound to a different loot repo?",
                &sha[..12],
                hex::short(&id.0, 8)
            ));
        }
        marks.insert(sha.to_string(), id, MarkOrigin::Loot);
        return Ok(());
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
    let parent_tree: BTreeMap<PathBuf, (Oid, Visibility)> = parents_loot
        .first()
        .and_then(|p| ws.graph().tree(p))
        .unwrap_or_default();

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
    let mut acts: Vec<(PathBuf, Act)> = Vec::new();
    for delta in diff.deltas() {
        let (old_path, new_path) = (delta.old_file().path(), delta.new_file().path());
        match delta.status() {
            git2::Delta::Deleted => {
                if let Some(p) = old_path {
                    acts.push((p.to_path_buf(), Act::Remove));
                }
            }
            git2::Delta::Added | git2::Delta::Modified | git2::Delta::Typechange
            | git2::Delta::Renamed | git2::Delta::Copied => {
                if delta.status() == git2::Delta::Renamed {
                    if let Some(p) = old_path {
                        if old_path != new_path {
                            acts.push((p.to_path_buf(), Act::Remove));
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
                                acts.push((p.to_path_buf(), Act::Reuse { entry: old_entry.clone() }));
                                continue;
                            }
                        }
                        Err(_) => {}
                    }
                }
                acts.push((p.to_path_buf(), Act::Put { bytes, vis }));
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
    if is_self {
        ws.sign_change(&change_id)?;
    }
    marks.insert(sha.to_string(), change_id, MarkOrigin::Git);
    report.ingested += 1;
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

    let mut parent_commits = Vec::new();
    for p in g.parents(id) {
        let sha = marks.sha_for(&p).ok_or_else(|| {
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
    let (tree, skipped) = public_delta_tree(ws, git, id, parent_git_tree.as_ref(), last_clean)?;

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
) -> Result<(git2::Tree<'g>, Vec<String>), String> {
    let g = ws.graph();
    let change_tree = g
        .tree(id)
        .ok_or_else(|| format!("unknown change {}", hex::short(&id.0, 8)))?;
    let parent_tree: BTreeMap<PathBuf, (Oid, Visibility)> = g
        .parents(id)
        .first()
        .and_then(|p| g.tree(p))
        .unwrap_or_default();
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
    let (tree, skipped) = public_delta_tree(ws, git, id, parent_git_tree.as_ref(), last_clean)?;

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
/// the mark map — provisional shas never enter the round-trip spine.
#[derive(Clone)]
struct WipEntry {
    change: String,
    dock: String,
    sha: String,
    version: String,
    round: u64,
}

struct WipState {
    entries: Vec<WipEntry>,
}

impl WipState {
    fn parse(text: &str) -> Self {
        let mut entries = Vec::new();
        for line in text.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() == 5 {
                if let Ok(round) = f[4].parse() {
                    entries.push(WipEntry {
                        change: f[0].into(),
                        dock: f[1].into(),
                        sha: f[2].into(),
                        version: f[3].into(),
                        round,
                    });
                }
            }
        }
        WipState { entries }
    }

    fn encode(&self) -> String {
        let mut out = String::new();
        for e in &self.entries {
            out.push_str(&format!(
                "{} {} {} {} {}\n",
                e.change, e.dock, e.sha, e.version, e.round
            ));
        }
        out
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

/// Point `refs/loot/heads/<id>` at every mirrored head (and prune stale ones),
/// plus `refs/loot/docks/<name>` at each dock's mirrored tip. Mechanical
/// reachability handles, not branches (ADR 0022 stands).
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
    for info in ws.dock_list() {
        let Some(head) = info.head else { continue };
        if let Some(sha) = marks.sha_for(&head) {
            let name = format!("refs/loot/docks/{}", info.name);
            let oid = git2::Oid::from_str(sha).map_err(|e| e.to_string())?;
            git.reference(&name, oid, true, "loot ferry").map_err(|e| e.to_string())?;
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

fn read_or_empty(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// `key = value` files under `.loot/git-mirror/` (config, identity map).
fn parse_kv(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            out.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    out
}

fn write_kv(path: &Path, entries: &BTreeMap<String, String>) -> Result<(), String> {
    let mut out = String::new();
    for (k, v) in entries {
        out.push_str(&format!("{k} = {v}\n"));
    }
    std::fs::write(path, out).map_err(|e| format!("write {}: {e}", path.display()))
}

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
        let mut builder = git.treebuilder(Some(&parent.tree().unwrap())).unwrap();
        for (rel, content) in files {
            let blob = git.blob(content.as_bytes()).unwrap();
            builder.insert(rel, blob, 0o100644).unwrap();
        }
        let tree = git.find_tree(builder.write().unwrap()).unwrap();
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
    fn a_stale_designated_dock_cannot_drag_main_backward() {
        let (mut ws, dir, mirror) = setup("ffguard");
        put_file(&dir, "a.txt", "one\n");
        seal_change(&mut ws, "first");
        ferry(&mut ws, &mirror);

        // Fork a side dock at the current tip, then advance main past it.
        ws.dock_goto("side").unwrap();
        ws.dock_goto("main").unwrap();
        put_file(&dir, "a.txt", "two\n");
        seal_change(&mut ws, "second");
        ferry(&mut ws, &mirror);
        let git = git2::Repository::open(&mirror).unwrap();
        let tip = main_commit(&git).id();

        // Rebinding main onto the stale fork must not rewind the published
        // branch (#201) — the pass says so and leaves the ref alone.
        let report = run(&mut ws, Some(mirror.to_str().unwrap()), Some("side"), false).unwrap();
        assert_eq!(main_commit(&git).id(), tip, "main did not move backward");
        assert!(
            report.notes.iter().any(|n| n.contains("NOT moved")),
            "the skipped update is loud: {:?}",
            report.notes
        );
    }

    #[test]
    fn a_failed_pass_persists_no_config_rebind() {
        let (mut ws, dir, mirror) = setup("cfgfail");
        put_file(&dir, "a.txt", "one\n");
        seal_change(&mut ws, "first");
        ferry(&mut ws, &mirror);
        let before = read_or_empty(&ws.store().git_config());

        // A pass that dies after flag parsing (an existing path that is not a
        // git repository) must not rebind the designated dock (#201).
        let bogus = dir.join("not-a-repo");
        std::fs::write(&bogus, "x").unwrap();
        let err = match run(&mut ws, Some(bogus.to_str().unwrap()), Some("side"), false) {
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

        let report = ferry(&mut ws, &mirror);
        assert_eq!(report.ingested, 1);
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
    fn git_author_matching_self_ingests_authored_and_signed() {
        let (mut ws, dir, mirror) = setup("self");
        put_file(&dir, "a.txt", "base\n");
        seal_change(&mut ws, "base");
        ferry(&mut ws, &mirror);

        // Commit as exactly the name/email the bridge seeded for self in the
        // identity map (it prefers git config, so read it back from disk).
        let id_map = parse_kv(&read_or_empty(&ws.store().git_identity_map()));
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

        // The merge commit exists in git, but the conflicted path is held at
        // its last clean state; the non-conflicting edit synced normally.
        let merge = main_commit(&git);
        assert_ne!(merge.id(), clean_tip, "merge projected");
        let tree = merge.tree().unwrap();
        let shared = tree.get_name("shared.txt").unwrap();
        let held = git.find_blob(shared.id()).unwrap();
        assert_eq!(held.content(), b"clean\n", "conflicted path held at last clean state");
        let other = tree.get_name("other.txt").unwrap();
        assert_eq!(git.find_blob(other.id()).unwrap().content(), b"git touch\n");

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
}
