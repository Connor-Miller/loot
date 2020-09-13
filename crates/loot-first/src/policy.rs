//! Land policy, extracted from `tools/loot-first.ps1` into pure, tested
//! `decide`-shaped functions. Each takes already-read facts (never a Workspace,
//! never a Forge) and returns a verdict; the orchestrator does the I/O and then
//! consults these. That split is the whole point of #218 — the ps1's policy was
//! only ever exercised by running a real land; here it is unit-tested against
//! the [`crate::forge::FakeForge`] and against literal inputs.

use crate::forge::{PrState, ReviewDecision};

/// The approval rule (#152). GitHub forbids approving your own PR, so a
/// self-authored PR lands on the weaker signal "no changes requested".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    /// `reviewDecision == APPROVED`.
    Approved,
    /// Self-authored (author is the viewer) and not `CHANGES_REQUESTED`.
    SelfAuthoredFastPath,
    /// Neither — the land refuses.
    Refused,
}

pub fn approval(decision: ReviewDecision, author: &str, viewer: &str) -> Approval {
    if decision == ReviewDecision::Approved {
        Approval::Approved
    } else if author == viewer && decision != ReviewDecision::ChangesRequested {
        Approval::SelfAuthoredFastPath
    } else {
        Approval::Refused
    }
}

/// The review-currency guard (ADR 0033). `loot edit` can amend an already
/// reviewed change; landing must refuse a working change whose version differs
/// from the one the review lane last projected — the reviewer approved a now
/// stale version. An empty working change (already finalized) has no live
/// version and skips the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Currency {
    /// The live version matches what was reviewed (or there is nothing to
    /// compare — no reviewed version, or an empty working change).
    Current,
    /// The working change was amended since the last review round.
    Stale,
}

pub fn review_currency(reviewed_version: Option<&str>, current_version: Option<&str>) -> Currency {
    match (reviewed_version, current_version) {
        (Some(r), Some(c)) if r != c => Currency::Stale,
        _ => Currency::Current,
    }
}

/// The dock-targeting guard (#153): finalize must hit the PR's dock, not
/// whatever is ambient. The orchestrator resolves the ambient dock in-process
/// (`Workspace::current_dock`, normalizing the main dock to `"main"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockTarget {
    Match,
    Mismatch,
}

pub fn dock_targeting(ambient_dock: &str, lane_dock: &str) -> DockTarget {
    if ambient_dock == lane_dock {
        DockTarget::Match
    } else {
        DockTarget::Mismatch
    }
}

/// The pre-land gate (#155): the review approved *projected WIP*, but nothing
/// has yet proven the commit about to land builds. `cargo test` runs at the
/// point of no return (before finalize); `-SkipTests` is the break-glass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreLand {
    /// Run `cargo test`; a failure aborts the land.
    RunTests,
    /// Break-glass — skip the gate (non-code lands).
    Skip,
}

pub fn pre_land(skip_tests: bool) -> PreLand {
    if skip_tests {
        PreLand::Skip
    } else {
        PreLand::RunTests
    }
}

/// Landing-signal interpretation (#150/#166). After finalize + ferry, the
/// orchestrator fast-forwards main and collapses the PR head onto the landed
/// sha. GitHub reacts asynchronously; this maps the observed outcome to the
/// audit status:
///
/// - main could not fast-forward (diverged, #151) → close with a pointer;
/// - main advanced and GitHub marked the PR `MERGED` by reachability → merged;
/// - main advanced and GitHub auto-closed on the zero-diff collapse (the live
///   #166 finding — that close *is* the landing signal) → closed-by-collapse;
/// - main advanced but the PR is still `OPEN` after polling → close with a
///   pointer anyway (the signed commit on main is the authoritative record).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandingStatus {
    Merged,
    ClosedByCollapse,
    ClosedWithPointer,
}

pub fn interpret_landing(main_fast_forwarded: bool, polled_state: PrState) -> LandingStatus {
    if !main_fast_forwarded {
        return LandingStatus::ClosedWithPointer;
    }
    match polled_state {
        PrState::Merged => LandingStatus::Merged,
        PrState::Closed => LandingStatus::ClosedByCollapse,
        PrState::Open => LandingStatus::ClosedWithPointer,
    }
}

/// How the loot mirror's projected `main` stands against the real `origin/main`
/// (#243, Deliverable 2). The mirror pushes its `main` to *become* `origin/main`,
/// so a healthy repo is one of two shapes — the two agree ([`Same`]), or the
/// mirror leads a not-yet-fetched `origin/main` ([`MirrorAhead`]). The other two
/// are drift the guard surfaces loudly:
///
/// - [`MirrorBehind`] — `origin/main` has commits the mirror never ingested (a
///   break-glass git land): reconcile before landing, or a lane spawned now
///   projects backward over that work.
/// - [`Diverged`] — neither is an ancestor of the other: the mirror projected a
///   `main` that never reached origin (the #241 backward projection). The
///   loudest case — the guard warns hardest, though it stays advisory
///   (break-glass is never blocked, per loot's philosophy).
///
/// [`MirrorAhead`] is quiet because it is the *normal* state between a land and
/// the checkout's next `git fetch`: the tip is pushed, only the local
/// remote-tracking ref trails. Folding it into [`Diverged`] made the guard cry
/// wolf on the most common healthy path, which is how a real divergence gets
/// scrolled past (#273). Telling it apart needs the mirror as the ancestry
/// oracle, not the checkout — see `orchestrator::mirror_ancestry`.
///
/// [`Same`]: Ancestry::Same
/// [`MirrorAhead`]: Ancestry::MirrorAhead
/// [`MirrorBehind`]: Ancestry::MirrorBehind
/// [`Diverged`]: Ancestry::Diverged
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ancestry {
    Same,
    MirrorAhead,
    MirrorBehind,
    Diverged,
}

/// Render the operator warning for a mirror/origin comparison, or `None` for the
/// healthy shapes ([`Ancestry::Same`] and [`Ancestry::MirrorAhead`]). Pure over
/// the two shas and the ancestry the caller reads from git, so the exact wording
/// — the message that would have stopped PR #241 before projection — is
/// unit-tested without a repo.
pub fn mirror_drift_warning(mirror: &str, origin: &str, ancestry: Ancestry) -> Option<String> {
    let (m, o) = (short(mirror), short(origin));
    Some(match ancestry {
        Ancestry::Same | Ancestry::MirrorAhead => return None,
        Ancestry::MirrorBehind => format!(
            "loot mirror is behind origin/main ({m} vs {o}) — reconcile before landing (#243)."
        ),
        Ancestry::Diverged => format!(
            "loot mirror has DIVERGED from origin/main ({m} vs {o}) — do NOT land: a lane off \
             this mirror would project backward over landed work. Reconcile the mirror to \
             origin/main first (#243)."
        ),
    })
}

/// First 12 chars of a sha for a warning line (git's default short length).
fn short(sha: &str) -> &str {
    &sha[..sha.len().min(12)]
}

/// A parsed `review:` line from `ferry`'s `FerryReport`. Once in-process this is
/// the typed contract the orchestrator consumes instead of a regex over stdout;
/// the string is kept as `ferry`'s stable machine line so the ps1 shadow-run
/// reads the identical bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewLine {
    pub dock: String,
    /// The position that projected the lane (#281): an isolation-lane id,
    /// empty for the primary (`owner=-` on the wire).
    pub owner: String,
    pub branch: String,
    pub sha: String,
    pub change: String,
    pub version: String,
    pub round: u64,
    pub op: String,
}

/// What one `ferry --with-wip` review pass did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewOutcome {
    /// Nothing to review (`op=none`): no working change, or the tree matches the
    /// anchor.
    Nothing,
    /// A provisional review lane was projected/refreshed.
    Projected(ReviewLine),
}

/// Parse `ferry`'s review line. `op=none` short-circuits to
/// [`ReviewOutcome::Nothing`]; otherwise every field must be present.
pub fn parse_review_line(line: &str) -> Result<ReviewOutcome, String> {
    let body = line.strip_prefix("review:").unwrap_or(line).trim();
    let mut kv = std::collections::HashMap::new();
    for tok in body.split_whitespace() {
        if let Some((k, v)) = tok.split_once('=') {
            kv.insert(k, v);
        }
    }
    if kv.get("op") == Some(&"none") {
        return Ok(ReviewOutcome::Nothing);
    }
    let get = |k: &str| kv.get(k).copied().ok_or_else(|| format!("review line missing {k}: {line:?}"));
    let round = get("round")?
        .parse()
        .map_err(|_| format!("review line: bad round: {line:?}"))?;
    // `owner` is `-` on the primary; tolerate its absence (pre-#281 line).
    let owner = match kv.get("owner").copied() {
        None | Some("-") => String::new(),
        Some(o) => o.to_string(),
    };
    Ok(ReviewOutcome::Projected(ReviewLine {
        dock: get("dock")?.into(),
        owner,
        branch: get("branch")?.into(),
        sha: get("sha")?.into(),
        change: get("change")?.into(),
        version: get("version")?.into(),
        round,
        op: get("op")?.into(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drift_same_is_quiet() {
        // Mirror main == origin/main (the happy path right after a land+push):
        // no warning at all.
        assert_eq!(mirror_drift_warning("abc123", "abc123", Ancestry::Same), None);
    }

    #[test]
    fn drift_ahead_is_quiet() {
        // The mirror pushed and the checkout has not fetched yet, so its
        // origin/main trails by a commit. This is the normal post-land state,
        // not drift — warning here is the #273 wolf-cry that trains the
        // operator to scroll past the real divergence.
        assert_eq!(
            mirror_drift_warning("bbbbbbbbbbbb", "aaaaaaaaaaaa", Ancestry::MirrorAhead),
            None
        );
    }

    #[test]
    fn drift_behind_warns_reconcile() {
        // origin/main advanced past the mirror (a break-glass git land the
        // mirror never ingested) — the #243 case the guard exists to catch.
        let w = mirror_drift_warning("bbbbbbbbbbbb", "aaaaaaaaaaaa", Ancestry::MirrorBehind)
            .expect("behind must warn");
        assert!(w.contains("behind origin/main"), "{w}");
        assert!(w.contains("bbbbbbbbbbbb") && w.contains("aaaaaaaaaaaa"), "{w}");
        assert!(w.contains("reconcile"), "{w}");
    }

    #[test]
    fn drift_diverged_warns_do_not_land() {
        // The actual #243 shape: the mirror projected a `main` that never
        // reached origin (the #241 backward projection), so neither is an
        // ancestor of the other. This is the loudest, land-blocking case.
        let w = mirror_drift_warning("bc282ff", "e2cb01e", Ancestry::Diverged)
            .expect("diverged must warn");
        assert!(w.to_uppercase().contains("DIVERGED"), "{w}");
        assert!(w.contains("do NOT land") || w.contains("DO NOT LAND"), "{w}");
    }

    #[test]
    fn approval_takes_explicit_approved() {
        assert_eq!(approval(ReviewDecision::Approved, "someone", "connor"), Approval::Approved);
        // APPROVED wins even when self-authored (no fast-path note needed).
        assert_eq!(approval(ReviewDecision::Approved, "connor", "connor"), Approval::Approved);
    }

    #[test]
    fn approval_self_authored_fast_path() {
        // Self-authored + no CHANGES_REQUESTED (empty decision) → fast path.
        assert_eq!(approval(ReviewDecision::Other, "connor", "connor"), Approval::SelfAuthoredFastPath);
    }

    #[test]
    fn approval_refuses_changes_requested_even_self() {
        assert_eq!(approval(ReviewDecision::ChangesRequested, "connor", "connor"), Approval::Refused);
    }

    #[test]
    fn approval_refuses_unapproved_from_other_author() {
        assert_eq!(approval(ReviewDecision::Other, "someone", "connor"), Approval::Refused);
    }

    #[test]
    fn review_currency_stale_only_when_both_present_and_differ() {
        assert_eq!(review_currency(Some("aa"), Some("bb")), Currency::Stale);
        assert_eq!(review_currency(Some("aa"), Some("aa")), Currency::Current);
        // Empty working change (no current version) skips.
        assert_eq!(review_currency(Some("aa"), None), Currency::Current);
        // No reviewed version recorded skips.
        assert_eq!(review_currency(None, Some("bb")), Currency::Current);
        assert_eq!(review_currency(None, None), Currency::Current);
    }

    #[test]
    fn dock_targeting_matches_exactly() {
        assert_eq!(dock_targeting("ferry", "ferry"), DockTarget::Match);
        assert_eq!(dock_targeting("main", "ferry"), DockTarget::Mismatch);
    }

    #[test]
    fn pre_land_gate_honours_break_glass() {
        assert_eq!(pre_land(false), PreLand::RunTests);
        assert_eq!(pre_land(true), PreLand::Skip);
    }

    #[test]
    fn landing_signal_interpretation() {
        // Diverged main → pointer regardless of PR state.
        assert_eq!(interpret_landing(false, PrState::Merged), LandingStatus::ClosedWithPointer);
        // Fast-forwarded main, GitHub outcomes:
        assert_eq!(interpret_landing(true, PrState::Merged), LandingStatus::Merged);
        assert_eq!(interpret_landing(true, PrState::Closed), LandingStatus::ClosedByCollapse);
        // Poll exhausted, still open → pointer close.
        assert_eq!(interpret_landing(true, PrState::Open), LandingStatus::ClosedWithPointer);
    }

    #[test]
    fn parse_review_line_op_none() {
        assert_eq!(
            parse_review_line("review: op=none (no working change to project)").unwrap(),
            ReviewOutcome::Nothing
        );
    }

    #[test]
    fn parse_review_line_projected() {
        let line = "review: dock=ferry owner=- branch=review/ferry sha=abc123 change=deadbeef version=cafef00d round=2 op=appended";
        let ReviewOutcome::Projected(r) = parse_review_line(line).unwrap() else {
            panic!("expected projected");
        };
        assert_eq!(r.dock, "ferry");
        assert_eq!(r.owner, "", "`owner=-` is the primary");
        assert_eq!(r.branch, "review/ferry");
        assert_eq!(r.change, "deadbeef");
        assert_eq!(r.version, "cafef00d");
        assert_eq!(r.round, 2);
        assert_eq!(r.op, "appended");
    }

    #[test]
    fn parse_review_line_carries_the_owning_lane() {
        // From an isolation lane the branch is lane-named (#281) and `owner`
        // carries the lane id; a pre-#281 line without the token parses too.
        let line = "review: dock=main owner=t281 branch=review/t281 sha=abc123 change=deadbeef version=cafef00d round=1 op=opened";
        let ReviewOutcome::Projected(r) = parse_review_line(line).unwrap() else {
            panic!("expected projected");
        };
        assert_eq!(r.owner, "t281");
        assert_eq!(r.branch, "review/t281");

        let legacy = "review: dock=main branch=review/main sha=abc123 change=deadbeef version=cafef00d round=1 op=opened";
        let ReviewOutcome::Projected(r) = parse_review_line(legacy).unwrap() else {
            panic!("expected projected");
        };
        assert_eq!(r.owner, "", "missing owner token reads as primary");
    }

    #[test]
    fn parse_review_line_rejects_missing_field() {
        assert!(parse_review_line("review: dock=ferry op=appended").is_err());
    }
}
