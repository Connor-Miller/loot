//! `loot bisect` — binary-search history to find the change that introduced a
//! regression (#390), loot's answer to `git bisect`.
//!
//! This module owns the two halves that need no [`Workspace`](crate::workspace):
//!
//! - [`BisectSession`] — the on-disk session state at `.loot/bisect` (the
//!   known-good/known-bad/skipped changes, the midpoint currently materialized,
//!   and the change to restore on `reset`), plus its versioned codec. Persisted
//!   like `.loot/abandoned`: lane-owned, local-only, captured by the oplog so a
//!   step is undoable.
//! - [`next_step`] — the pure search: given the session and a parent-lookup, it
//!   computes the next change to test, or the first bad change once the search
//!   converges. A function of ancestry alone, so it is unit-tested against a
//!   hand-built graph with no repo.
//!
//! The [`Workspace`](crate::workspace) bisect verbs drive these: they resolve
//! selectors, materialize the midpoint's tree, and record each step as an
//! operation.

use crate::emit::{self, Emit};
use crate::error::CliError;
use crate::workspace::Workspace;
use loot_core::{Oid, RepoStore};
use std::collections::BTreeSet;

/// One in-progress bisect session, persisted at `.loot/bisect`.
///
/// Changes are identified by **version id** ([`Oid`]) — the same trees the
/// selector grammar resolves to — so the search walks the version graph the
/// engine already stores.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BisectSession {
    /// Changes proven good (the regression is strictly after each of these).
    pub good: Vec<Oid>,
    /// The change proven bad (the regression is at or before it). The search
    /// narrows this toward the first bad change.
    pub bad: Option<Oid>,
    /// Changes the tester could not judge (`git bisect skip`); excluded as
    /// midpoints but still bound the range.
    pub skip: Vec<Oid>,
    /// The midpoint currently materialized in the working tree, if any. `None`
    /// before both bounds are known, and once the search is done.
    pub current: Option<Oid>,
    /// The change the working tree sat on when the bisect began — restored by
    /// `loot bisect reset`.
    pub start: Option<Oid>,
}

/// The one-byte session format marker (local-only artifact; bumped if the layout
/// changes, so an older binary rejects a newer session rather than misreading).
const SESSION_VERSION: u8 = 1;

impl BisectSession {
    /// Load the session for `store`, or `None` when no bisect is in progress (or
    /// the file is malformed — best-effort, like [`RepoStore::read_abandoned`]).
    pub fn load(store: &RepoStore) -> Option<Self> {
        let bytes = std::fs::read(store.bisect()).ok()?;
        Self::decode(&bytes)
    }

    /// Persist the session as `.loot/bisect`.
    pub fn save(&self, store: &RepoStore) -> std::io::Result<()> {
        std::fs::write(store.bisect(), self.encode())
    }

    /// Remove the session file (end a bisect). Best-effort; an absent file is
    /// already "no bisect".
    pub fn clear(store: &RepoStore) -> std::io::Result<()> {
        match std::fs::remove_file(store.bisect()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// True once both bounds are known — the point from which [`next_step`] can
    /// pick a midpoint (or declare the first bad change).
    pub fn has_bounds(&self) -> bool {
        self.bad.is_some() && !self.good.is_empty()
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = vec![SESSION_VERSION];
        put_oids(&mut out, &self.good);
        put_oids(&mut out, &self.skip);
        put_opt_oid(&mut out, self.bad.as_ref());
        put_opt_oid(&mut out, self.current.as_ref());
        put_opt_oid(&mut out, self.start.as_ref());
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let mut c = Reader { b: bytes, i: 0 };
        if c.u8()? != SESSION_VERSION {
            return None;
        }
        let good = c.oids()?;
        let skip = c.oids()?;
        let bad = c.opt_oid()?;
        let current = c.opt_oid()?;
        let start = c.opt_oid()?;
        Some(BisectSession { good, bad, skip, current, start })
    }
}

/// The outcome of a search step (`git bisect`'s "N revisions left" / "first bad
/// commit is …"), computed by [`next_step`] from ancestry alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BisectProgress {
    /// Materialize `midpoint`, run the test, then mark it good or bad.
    /// `remaining` is the size of the current suspect range (for the "roughly N
    /// steps left" hint).
    Test { midpoint: Oid, remaining: usize },
    /// The search converged: `first_bad` is the change that introduced the
    /// regression.
    Done { first_bad: Oid },
    /// Every untested suspect was skipped, so no single first-bad change can be
    /// named. The remaining candidates are reported for the operator.
    Blocked { candidates: Vec<Oid> },
}

/// Which bound a `loot bisect good|bad|skip` records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BisectMark {
    Good,
    Bad,
    Skip,
}

impl BisectMark {
    /// The verb word, for messages.
    pub fn word(self) -> &'static str {
        match self {
            BisectMark::Good => "good",
            BisectMark::Bad => "bad",
            BisectMark::Skip => "skip",
        }
    }
}

/// What a bisect verb did, for the CLI to render. Carries the marked change (if
/// any) alongside the resulting [`BisectProgress`]-shaped state, so the CLI
/// reports both "recorded X good" and "now testing Y".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BisectOutcome {
    /// A bound was recorded but the search cannot proceed yet — the other bound
    /// is still missing.
    AwaitingBounds,
    /// `midpoint` is now materialized in the working tree; run the test and mark
    /// it. `remaining` is the current suspect-range size.
    Testing { midpoint: Oid, remaining: usize },
    /// The search converged: `first_bad` introduced the regression (materialized
    /// for inspection; `loot bisect reset` restores the starting tree).
    Found { first_bad: Oid },
    /// Every untested suspect was skipped — `candidates` are all that is left.
    Blocked { candidates: Vec<Oid> },
}

/// The pure binary search (#390): given a bounded session and a parent lookup,
/// decide the next change to test — or the first bad change once the range
/// collapses. Mirrors `git bisect`'s midpoint heuristic (maximize the smaller
/// side of the split), so a linear history halves each step.
///
/// Errors only on an ill-formed range: no bounds, or a "good" that is not an
/// ancestor of the "bad" (the two bounds must straddle the regression).
pub fn next_step(
    session: &BisectSession,
    parents_of: impl Fn(&Oid) -> Vec<Oid>,
) -> Result<BisectProgress, String> {
    let bad = session
        .bad
        .clone()
        .ok_or_else(|| "no bad change marked — `loot bisect bad <selector>`".to_string())?;
    if session.good.is_empty() {
        return Err("no good change marked — `loot bisect good <selector>`".to_string());
    }

    // The suspect range: changes reachable from `bad` that are *not* an
    // ancestor-or-self of any known-good change. The first bad change lives here,
    // and `bad` itself is always a suspect (its parent might be the boundary).
    let from_bad = ancestors(&bad, &parents_of);
    let mut good_closure: BTreeSet<Oid> = BTreeSet::new();
    for g in &session.good {
        if !from_bad.contains(g) {
            return Err(format!(
                "good change {} is not an ancestor of the bad change — the two must \
                 straddle the regression",
                short(g)
            ));
        }
        good_closure.extend(ancestors(g, &parents_of));
    }
    let suspects: BTreeSet<Oid> = from_bad.difference(&good_closure).cloned().collect();

    // Candidates to actually test: suspects minus `bad` (never re-test the known
    // bad) and minus anything already skipped.
    let skip: BTreeSet<Oid> = session.skip.iter().cloned().collect();
    let candidates: Vec<Oid> = suspects
        .iter()
        .filter(|s| **s != bad && !skip.contains(*s))
        .cloned()
        .collect();

    if candidates.is_empty() {
        // Nothing left to test. If untested suspects remain they were all
        // skipped, so the first bad change is indeterminate; otherwise `bad` is
        // the first bad change (its every suspect ancestor is good).
        let unskipped: Vec<Oid> = suspects.iter().filter(|s| **s != bad).cloned().collect();
        let all_skipped: Vec<Oid> =
            unskipped.into_iter().filter(|s| skip.contains(s)).collect();
        if all_skipped.is_empty() {
            return Ok(BisectProgress::Done { first_bad: bad });
        }
        let mut candidates = all_skipped;
        candidates.push(bad);
        candidates.sort();
        return Ok(BisectProgress::Blocked { candidates });
    }

    // Midpoint: the candidate whose in-range ancestor count splits the suspect
    // set most evenly (max of the smaller side). Ties break by id for
    // determinism.
    let total = suspects.len();
    let best = candidates
        .into_iter()
        .map(|c| {
            let rank = ancestors(&c, &parents_of).intersection(&suspects).count();
            let score = rank.min(total - rank);
            (score, c)
        })
        .max_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1)))
        .map(|(_, c)| c)
        .expect("candidates is non-empty");

    Ok(BisectProgress::Test { midpoint: best, remaining: total })
}

/// Every ancestor of `start`, `start` included, walked over parent edges. The
/// version graph is a DAG, so `seen` bounds the walk.
fn ancestors(start: &Oid, parents_of: &impl Fn(&Oid) -> Vec<Oid>) -> BTreeSet<Oid> {
    let mut seen = BTreeSet::new();
    let mut stack = vec![start.clone()];
    while let Some(id) = stack.pop() {
        if seen.insert(id.clone()) {
            stack.extend(parents_of(&id));
        }
    }
    seen
}

/// Eight-hex-digit short form of a version id, for messages.
pub fn short(id: &Oid) -> String {
    loot_core::hex::encode(&id.0).chars().take(8).collect()
}

// --- CLI dispatch (`loot bisect …`) ---
//
// The `loot` binary dispatches `bisect` ahead of its flag gate (like `buoy`) so
// `bisect run <cmd…>` can pass flags through to the test command, then hands the
// argument tail here. Every subcommand is a thin call into a [`Workspace`] verb
// plus rendering — the session state and search live above.

/// Route `loot bisect <sub> …` to its handler and render the result. `args` is
/// the tail after `bisect` (the subcommand and its own arguments).
pub fn dispatch(args: &[String]) -> Result<Box<dyn Emit>, CliError> {
    match args.first().map(String::as_str) {
        None | Some("status") => {
            no_flags(&args[args.len().min(1)..])?;
            status()
        }
        Some("start") => {
            no_flags(&args[1..])?;
            start()
        }
        Some(k @ ("good" | "bad" | "skip")) => {
            no_flags(&args[1..])?;
            let kind = match k {
                "good" => BisectMark::Good,
                "bad" => BisectMark::Bad,
                _ => BisectMark::Skip,
            };
            mark(kind, args.get(1).map(String::as_str))
        }
        Some("reset") => {
            no_flags(&args[1..])?;
            reset()
        }
        Some("run") => run(&args[1..]),
        Some(other) => Err(format!(
            "unknown bisect subcommand '{other}' — use \
             start | good | bad | skip | reset | status | run"
        )
        .into()),
    }
}

/// Reject a flag on a subcommand that takes none (the #67 rule; `run` is exempt,
/// its flags belong to the test command).
fn no_flags(args: &[String]) -> Result<(), CliError> {
    if let Some(f) = args.iter().find(|a| a.starts_with('-') && a.as_str() != "-") {
        return Err(format!(
            "unknown flag '{f}' — `loot bisect` subcommands take a selector, not flags"
        )
        .into());
    }
    Ok(())
}

fn open() -> Result<Workspace, CliError> {
    Workspace::open().map_err(CliError::no_repo)
}

fn msg(text: impl Into<String>) -> Result<Box<dyn Emit>, CliError> {
    Ok(Box::new(emit::Message::new(text)))
}

fn start() -> Result<Box<dyn Emit>, CliError> {
    let mut ws = open()?;
    ws.bisect_start()?;
    msg(
        "bisect started — now mark the two bounds:\n  \
         loot bisect bad <selector>   a change that HAS the regression\n  \
         loot bisect good <selector>  a change that does NOT\n",
    )
}

fn mark(kind: BisectMark, selector: Option<&str>) -> Result<Box<dyn Emit>, CliError> {
    let mut ws = open()?;
    let outcome = ws.bisect_mark(kind, selector)?;
    msg(render_outcome(&outcome))
}

fn reset() -> Result<Box<dyn Emit>, CliError> {
    let mut ws = open()?;
    match ws.bisect_reset()? {
        Some(id) => msg(format!("bisect reset — working tree restored to {}\n", short(&id))),
        None => msg("bisect reset\n"),
    }
}

fn status() -> Result<Box<dyn Emit>, CliError> {
    let ws = open()?;
    match ws.bisect_session() {
        Some(s) => msg(render_status(&s)),
        None => msg("no bisect in progress — `loot bisect start` to begin\n"),
    }
}

fn run(cmd: &[String]) -> Result<Box<dyn Emit>, CliError> {
    if cmd.is_empty() {
        return Err("usage: loot bisect run <cmd> [args...]".into());
    }
    let program = cmd[0].clone();
    let rest: Vec<String> = cmd[1..].to_vec();
    let mut ws = open()?;
    let outcome = ws.bisect_run(|root, _midpoint| {
        let status = std::process::Command::new(&program)
            .args(&rest)
            .current_dir(root)
            .status()
            .map_err(|e| CliError::from(format!("bisect run: cannot execute `{program}`: {e}")))?;
        // git-bisect convention: 0 good, 125 skip, any other nonzero bad.
        Ok(status.code().unwrap_or(1))
    })?;
    msg(render_outcome(&outcome))
}

/// Render a [`BisectOutcome`] as the human-facing report each verb prints.
pub fn render_outcome(outcome: &BisectOutcome) -> String {
    match outcome {
        BisectOutcome::AwaitingBounds => {
            "recorded — mark the other bound (`loot bisect good`/`bad`) to begin the search\n"
                .to_string()
        }
        BisectOutcome::Testing { midpoint, remaining } => format!(
            "testing {} — {} change(s) in range, ~{} step(s) left\n  \
             run your test, then `loot bisect good` or `loot bisect bad`\n",
            short(midpoint),
            remaining,
            steps_left(*remaining),
        ),
        BisectOutcome::Found { first_bad } => format!(
            "{} is the first bad change\n  \
             its tree is checked out for inspection; `loot bisect reset` restores your \
             starting tree\n",
            short(first_bad),
        ),
        BisectOutcome::Blocked { candidates } => {
            let ids: Vec<String> = candidates.iter().map(short).collect();
            format!(
                "cannot narrow further — every remaining suspect was skipped: {}\n",
                ids.join(", "),
            )
        }
    }
}

/// Render an in-progress session for `loot bisect status`.
pub fn render_status(s: &BisectSession) -> String {
    let mut out = String::from("bisect in progress\n");
    match &s.bad {
        Some(b) => out.push_str(&format!("  bad:     {}\n", short(b))),
        None => out.push_str("  bad:     (unset — `loot bisect bad <selector>`)\n"),
    }
    if s.good.is_empty() {
        out.push_str("  good:    (unset — `loot bisect good <selector>`)\n");
    } else {
        let ids: Vec<String> = s.good.iter().map(short).collect();
        out.push_str(&format!("  good:    {}\n", ids.join(", ")));
    }
    if !s.skip.is_empty() {
        let ids: Vec<String> = s.skip.iter().map(short).collect();
        out.push_str(&format!("  skip:    {}\n", ids.join(", ")));
    }
    if let Some(c) = &s.current {
        out.push_str(&format!("  testing: {} (checked out)\n", short(c)));
    }
    out
}

/// The classic bisect estimate: `floor(log2(range))` remaining steps.
fn steps_left(remaining: usize) -> u32 {
    (usize::BITS - remaining.max(1).leading_zeros()).saturating_sub(1)
}

// --- session codec plumbing ---

fn put_oids(out: &mut Vec<u8>, ids: &[Oid]) {
    out.extend_from_slice(&(ids.len() as u32).to_le_bytes());
    for id in ids {
        out.extend_from_slice(&id.0);
    }
}

fn put_opt_oid(out: &mut Vec<u8>, id: Option<&Oid>) {
    match id {
        Some(id) => {
            out.push(1);
            out.extend_from_slice(&id.0);
        }
        None => out.push(0),
    }
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl Reader<'_> {
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.i)?;
        self.i += 1;
        Some(v)
    }

    fn u32(&mut self) -> Option<usize> {
        let end = self.i.checked_add(4)?;
        let bytes = self.b.get(self.i..end)?;
        self.i = end;
        Some(u32::from_le_bytes(bytes.try_into().ok()?) as usize)
    }

    fn oid(&mut self) -> Option<Oid> {
        let end = self.i.checked_add(32)?;
        let bytes = self.b.get(self.i..end)?;
        self.i = end;
        Some(Oid(bytes.try_into().ok()?))
    }

    fn oids(&mut self) -> Option<Vec<Oid>> {
        let n = self.u32()?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.oid()?);
        }
        Some(out)
    }

    fn opt_oid(&mut self) -> Option<Option<Oid>> {
        match self.u8()? {
            0 => Some(None),
            _ => Some(Some(self.oid()?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn oid(n: u8) -> Oid {
        Oid([n; 32])
    }

    /// A hand-built parent map: `id -> parents`. `parents_of` closes over it.
    fn parents(map: &HashMap<Oid, Vec<Oid>>) -> impl Fn(&Oid) -> Vec<Oid> + '_ {
        move |id| map.get(id).cloned().unwrap_or_default()
    }

    /// A linear chain 1<-2<-3<-4<-5 (2's parent is 1, etc.).
    fn linear() -> HashMap<Oid, Vec<Oid>> {
        let mut m = HashMap::new();
        m.insert(oid(1), vec![]);
        m.insert(oid(2), vec![oid(1)]);
        m.insert(oid(3), vec![oid(2)]);
        m.insert(oid(4), vec![oid(3)]);
        m.insert(oid(5), vec![oid(4)]);
        m
    }

    #[test]
    fn session_round_trips_through_the_codec() {
        let s = BisectSession {
            good: vec![oid(1), oid(2)],
            bad: Some(oid(9)),
            skip: vec![oid(4)],
            current: Some(oid(6)),
            start: Some(oid(7)),
        };
        let back = BisectSession::decode(&s.encode()).expect("decodes");
        assert_eq!(s, back);
    }

    #[test]
    fn empty_session_round_trips() {
        let s = BisectSession::default();
        assert_eq!(BisectSession::decode(&s.encode()), Some(s));
    }

    #[test]
    fn malformed_session_reads_as_none() {
        assert_eq!(BisectSession::decode(&[]), None);
        assert_eq!(BisectSession::decode(&[9, 9, 9]), None, "wrong version byte");
        assert_eq!(BisectSession::decode(&[SESSION_VERSION, 1]), None, "truncated");
    }

    #[test]
    fn linear_search_picks_the_middle_then_converges_on_the_first_bad() {
        let m = linear();
        // good=1, bad=5: suspects {2,3,4,5}, candidates {2,3,4}; midpoint is 3
        // (splits {2,3} vs {4,5} — the evenest cut).
        let s = BisectSession { good: vec![oid(1)], bad: Some(oid(5)), ..Default::default() };
        match next_step(&s, parents(&m)).unwrap() {
            BisectProgress::Test { midpoint, remaining } => {
                assert_eq!(midpoint, oid(3));
                assert_eq!(remaining, 4);
            }
            other => panic!("expected a midpoint, got {other:?}"),
        }

        // Say 3 tested good: the regression is in {4,5}; next midpoint is 4.
        let s = BisectSession { good: vec![oid(1), oid(3)], bad: Some(oid(5)), ..Default::default() };
        assert_eq!(
            next_step(&s, parents(&m)).unwrap(),
            BisectProgress::Test { midpoint: oid(4), remaining: 2 }
        );

        // Say 4 tested bad: bad narrows to 4, good is 3 — 4 is the first bad.
        let s = BisectSession { good: vec![oid(1), oid(3)], bad: Some(oid(4)), ..Default::default() };
        assert_eq!(
            next_step(&s, parents(&m)).unwrap(),
            BisectProgress::Done { first_bad: oid(4) }
        );
    }

    #[test]
    fn adjacent_bounds_name_the_bad_immediately() {
        let m = linear();
        // good=3, bad=4: nothing between them, so 4 is the first bad change.
        let s = BisectSession { good: vec![oid(3)], bad: Some(oid(4)), ..Default::default() };
        assert_eq!(
            next_step(&s, parents(&m)).unwrap(),
            BisectProgress::Done { first_bad: oid(4) }
        );
    }

    #[test]
    fn a_skipped_sole_suspect_blocks_rather_than_guesses() {
        let m = linear();
        // good=3, bad=5, skip=4: the only untested suspect (4) is skipped, so the
        // first bad change is indeterminate — {4,5} reported, not a false answer.
        let s = BisectSession {
            good: vec![oid(3)],
            bad: Some(oid(5)),
            skip: vec![oid(4)],
            ..Default::default()
        };
        match next_step(&s, parents(&m)).unwrap() {
            BisectProgress::Blocked { candidates } => {
                assert_eq!(candidates, vec![oid(4), oid(5)]);
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    #[test]
    fn a_good_off_the_bad_ancestry_is_refused() {
        let mut m = linear();
        // Add a sibling 6 off root 1 that is not an ancestor of 5.
        m.insert(oid(6), vec![oid(1)]);
        let s = BisectSession { good: vec![oid(6)], bad: Some(oid(5)), ..Default::default() };
        let err = next_step(&s, parents(&m)).unwrap_err();
        assert!(err.contains("not an ancestor"), "explains the bad bound: {err}");
    }

    #[test]
    fn missing_bounds_are_refused() {
        let m = linear();
        let no_bad = BisectSession { good: vec![oid(1)], ..Default::default() };
        assert!(next_step(&no_bad, parents(&m)).unwrap_err().contains("bad"));
        let no_good = BisectSession { bad: Some(oid(5)), ..Default::default() };
        assert!(next_step(&no_good, parents(&m)).unwrap_err().contains("good"));
    }
}
