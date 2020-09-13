//! The GitHub seam. Every `gh` / `git push` the orchestrator makes goes through
//! the [`Forge`] trait — nothing else in loot-first (and, by the workflow
//! invariant, nothing in `loot` itself) touches GitHub. The production adapter
//! [`GhForge`] shells out to `gh` and single-ref `git push` exactly as the ps1
//! did; the test adapter [`FakeForge`] records intents in memory so land policy
//! can be driven end-to-end without a network.

use std::path::PathBuf;

/// A PR's review decision, as GitHub reports it (`gh pr view --json
/// reviewDecision`). The empty string, `REVIEW_REQUIRED`, and anything else
/// collapse to [`Other`](ReviewDecision::Other) — the approval rule (#152)
/// only needs to tell `APPROVED` and `CHANGES_REQUESTED` apart from the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewDecision {
    Approved,
    ChangesRequested,
    Other,
}

impl ReviewDecision {
    pub fn parse(s: &str) -> Self {
        match s.trim() {
            "APPROVED" => ReviewDecision::Approved,
            "CHANGES_REQUESTED" => ReviewDecision::ChangesRequested,
            _ => ReviewDecision::Other,
        }
    }
}

/// A PR's lifecycle state (`gh pr view --json state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrState {
    Open,
    Merged,
    Closed,
}

impl PrState {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "OPEN" => Some(PrState::Open),
            "MERGED" => Some(PrState::Merged),
            "CLOSED" => Some(PrState::Closed),
            _ => None,
        }
    }
}

/// The land-relevant snapshot of a PR (`gh pr view --json
/// state,reviewDecision,author`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrView {
    pub state: PrState,
    pub review_decision: ReviewDecision,
    pub author_login: String,
}

/// The GitHub seam. All fallible calls return `Result<_, String>` to match the
/// loot-cli engine convention.
pub trait Forge {
    /// The authenticated viewer's login (`gh api user -q .login`), for the
    /// self-authored approval fast path (#152).
    fn viewer_login(&self) -> Result<String, String>;

    /// Push one ref from the local mirror to origin. `refspec` is a full
    /// `<src>:<dst>` (a leading `:` deletes the remote ref). Errors on a
    /// non-fast-forward so the land path can fall back (diverged main, #151).
    fn push_ref(&self, refspec: &str, force: bool) -> Result<(), String>;

    /// Open a PR for `head` against `base`; returns the new PR number.
    fn create_pr(&self, head: &str, base: &str, title: &str, body: &str) -> Result<u64, String>;

    /// The land-relevant snapshot of a PR.
    fn pr_view(&self, pr: u64) -> Result<PrView, String>;

    /// A PR's state only — cheap, for polling the landing signal (#166).
    fn pr_state(&self, pr: u64) -> Result<PrState, String>;

    /// Close a PR, attaching an audit comment.
    fn close_pr(&self, pr: u64, comment: &str) -> Result<(), String>;

    /// Attach an audit comment to a PR.
    fn comment_pr(&self, pr: u64, body: &str) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// Production adapter: `gh` + single-ref `git push`.
// ---------------------------------------------------------------------------

/// Shells out to `gh` / `git`, exactly as `tools/loot-first.ps1` did. `root` is
/// the **shared store's checkout** (for `remote get-url origin` *and* the cwd
/// every `gh` runs in) — so a land driven from a lane directory, which is not
/// itself a git repo, still resolves `origin` and the GitHub repo through the
/// primary's git context (ADR 0036). `mirror` is the bare private mirror the
/// pushes originate from (`.loot/git-mirror/mirror.git`).
pub struct GhForge {
    root: PathBuf,
    mirror: PathBuf,
}

impl GhForge {
    pub fn new(root: PathBuf, mirror: PathBuf) -> Self {
        GhForge { root, mirror }
    }

    /// The publish target — `git remote get-url origin` on the checkout. All
    /// pushes are single-ref to this inline URL (never `git remote add`). Not on
    /// the [`Forge`] trait: only the production adapter needs a real origin, and
    /// [`push_ref`](GhForge::push_ref) is its sole caller.
    fn origin_url(&self) -> Result<String, String> {
        let url = run(
            "git remote get-url origin",
            std::process::Command::new("git")
                .arg("-C")
                .arg(&self.root)
                .args(["remote", "get-url", "origin"]),
        )?;
        if url.is_empty() {
            return Err("no origin remote on the checkout — cannot publish to GitHub".into());
        }
        Ok(url)
    }
}

/// Run a command, returning trimmed stdout on success or a stderr-bearing error.
fn run(what: &str, cmd: &mut std::process::Command) -> Result<String, String> {
    let out = cmd
        .output()
        .map_err(|e| format!("{what}: spawn failed: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("{what}: {}", stderr.trim()));
    }
    Ok(stdout)
}

impl Forge for GhForge {
    fn viewer_login(&self) -> Result<String, String> {
        run(
            "gh api user",
            std::process::Command::new("gh").current_dir(&self.root).args(["api", "user", "-q", ".login"]),
        )
    }

    fn push_ref(&self, refspec: &str, force: bool) -> Result<(), String> {
        let url = self.origin_url()?;
        let mut cmd = std::process::Command::new("git");
        cmd.arg("-C").arg(&self.mirror).arg("push");
        if force {
            cmd.arg("--force");
        }
        cmd.arg("--quiet").arg(&url).arg(refspec);
        run("git push", &mut cmd)?;
        Ok(())
    }

    fn create_pr(&self, head: &str, base: &str, title: &str, body: &str) -> Result<u64, String> {
        let out = run(
            "gh pr create",
            std::process::Command::new("gh").current_dir(&self.root).args([
                "pr", "create", "--head", head, "--base", base, "--title", title, "--body", body,
            ]),
        )?;
        parse_pr_number(&out)
            .ok_or_else(|| format!("could not parse PR number from gh output: {out}"))
    }

    fn pr_view(&self, pr: u64) -> Result<PrView, String> {
        // One call, tab-separated, to keep the round-trips down.
        let out = run(
            "gh pr view",
            std::process::Command::new("gh").current_dir(&self.root).args([
                "pr",
                "view",
                &pr.to_string(),
                "--json",
                "state,reviewDecision,author",
                "-q",
                "[.state, .reviewDecision, .author.login] | @tsv",
            ]),
        )?;
        let cols: Vec<&str> = out.split('\t').collect();
        if cols.len() < 3 {
            return Err(format!("unexpected gh pr view output: {out:?}"));
        }
        let state = PrState::parse(cols[0])
            .ok_or_else(|| format!("unknown PR state {:?}", cols[0]))?;
        Ok(PrView {
            state,
            review_decision: ReviewDecision::parse(cols[1]),
            author_login: cols[2].trim().to_string(),
        })
    }

    fn pr_state(&self, pr: u64) -> Result<PrState, String> {
        let out = run(
            "gh pr view",
            std::process::Command::new("gh").current_dir(&self.root).args([
                "pr",
                "view",
                &pr.to_string(),
                "--json",
                "state",
                "-q",
                ".state",
            ]),
        )?;
        PrState::parse(&out).ok_or_else(|| format!("unknown PR state {out:?}"))
    }

    fn close_pr(&self, pr: u64, comment: &str) -> Result<(), String> {
        run(
            "gh pr close",
            std::process::Command::new("gh").current_dir(&self.root).args([
                "pr",
                "close",
                &pr.to_string(),
                "--comment",
                comment,
            ]),
        )?;
        Ok(())
    }

    fn comment_pr(&self, pr: u64, body: &str) -> Result<(), String> {
        run(
            "gh pr comment",
            std::process::Command::new("gh").current_dir(&self.root).args([
                "pr",
                "comment",
                &pr.to_string(),
                "--body",
                body,
            ]),
        )?;
        Ok(())
    }
}

/// Pull the PR number out of a `gh pr create` URL (`.../pull/123`).
pub fn parse_pr_number(text: &str) -> Option<u64> {
    let idx = text.find("/pull/")?;
    let tail = &text[idx + "/pull/".len()..];
    let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

// ---------------------------------------------------------------------------
// Test adapter: an in-memory forge that records every intent.
// ---------------------------------------------------------------------------

/// A fake [`Forge`] for policy/flow tests. It never touches the network: it
/// returns programmed PR snapshots and records every side-effecting call (push,
/// create, close, comment) in [`calls`](FakeForge::calls), in order — so a test
/// can assert on the *intent stream* the orchestrator would emit. This is also
/// the substrate for the shadow-run comparison (#218): the same intents the ps1
/// shells out, captured instead of executed.
#[cfg(test)]
pub struct FakeForge {
    pub viewer: String,
    /// Response for [`Forge::pr_view`].
    pub view: std::cell::RefCell<Option<PrView>>,
    /// Successive [`Forge::pr_state`] answers (poll sequence); the last repeats
    /// once exhausted.
    pub states: std::cell::RefCell<Vec<PrState>>,
    state_idx: std::cell::Cell<usize>,
    /// PR number handed out by the next [`Forge::create_pr`].
    pub next_pr: std::cell::Cell<u64>,
    /// Refspec substrings whose push should fail (simulating a diverged main).
    pub failing_pushes: std::cell::RefCell<Vec<String>>,
    /// Ordered log of every intent, for assertions.
    pub calls: std::cell::RefCell<Vec<String>>,
}

#[cfg(test)]
impl FakeForge {
    pub fn new() -> Self {
        FakeForge {
            viewer: "connor".into(),
            view: std::cell::RefCell::new(None),
            states: std::cell::RefCell::new(vec![PrState::Merged]),
            state_idx: std::cell::Cell::new(0),
            next_pr: std::cell::Cell::new(300),
            failing_pushes: std::cell::RefCell::new(Vec::new()),
            calls: std::cell::RefCell::new(Vec::new()),
        }
    }

    pub fn with_viewer(mut self, login: &str) -> Self {
        self.viewer = login.into();
        self
    }

    pub fn with_view(self, view: PrView) -> Self {
        *self.view.borrow_mut() = Some(view);
        self
    }

    pub fn with_poll(self, states: Vec<PrState>) -> Self {
        *self.states.borrow_mut() = states;
        self
    }

    /// Make any push whose refspec contains `needle` fail (diverged main).
    pub fn failing_push(self, needle: &str) -> Self {
        self.failing_pushes.borrow_mut().push(needle.into());
        self
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }

    fn record(&self, call: impl Into<String>) {
        self.calls.borrow_mut().push(call.into());
    }
}

#[cfg(test)]
impl Default for FakeForge {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl Forge for FakeForge {
    fn viewer_login(&self) -> Result<String, String> {
        Ok(self.viewer.clone())
    }
    fn push_ref(&self, refspec: &str, force: bool) -> Result<(), String> {
        self.record(format!("push {refspec} force={force}"));
        if self.failing_pushes.borrow().iter().any(|n| refspec.contains(n.as_str())) {
            return Err(format!("push {refspec}: non-fast-forward (simulated)"));
        }
        Ok(())
    }
    fn create_pr(&self, head: &str, base: &str, title: &str, _body: &str) -> Result<u64, String> {
        let pr = self.next_pr.get();
        self.record(format!("create_pr head={head} base={base} title={title:?} -> #{pr}"));
        Ok(pr)
    }
    fn pr_view(&self, pr: u64) -> Result<PrView, String> {
        self.record(format!("pr_view #{pr}"));
        self.view
            .borrow()
            .clone()
            .ok_or_else(|| "FakeForge: no programmed pr_view".to_string())
    }
    fn pr_state(&self, pr: u64) -> Result<PrState, String> {
        let states = self.states.borrow();
        let i = self.state_idx.get().min(states.len().saturating_sub(1));
        self.state_idx.set(self.state_idx.get() + 1);
        let st = *states.get(i).unwrap_or(&PrState::Open);
        self.record(format!("pr_state #{pr} -> {st:?}"));
        Ok(st)
    }
    fn close_pr(&self, pr: u64, comment: &str) -> Result<(), String> {
        self.record(format!("close_pr #{pr} comment={comment:?}"));
        Ok(())
    }
    fn comment_pr(&self, pr: u64, body: &str) -> Result<(), String> {
        self.record(format!("comment_pr #{pr} body={body:?}"));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_review_decisions() {
        assert_eq!(ReviewDecision::parse("APPROVED"), ReviewDecision::Approved);
        assert_eq!(ReviewDecision::parse("CHANGES_REQUESTED"), ReviewDecision::ChangesRequested);
        assert_eq!(ReviewDecision::parse(""), ReviewDecision::Other);
        assert_eq!(ReviewDecision::parse("REVIEW_REQUIRED"), ReviewDecision::Other);
    }

    #[test]
    fn parses_pr_states() {
        assert_eq!(PrState::parse("OPEN"), Some(PrState::Open));
        assert_eq!(PrState::parse("MERGED"), Some(PrState::Merged));
        assert_eq!(PrState::parse("CLOSED"), Some(PrState::Closed));
        assert_eq!(PrState::parse("weird"), None);
    }

    #[test]
    fn parses_pr_number_from_url() {
        assert_eq!(parse_pr_number("https://github.com/o/r/pull/218"), Some(218));
        assert_eq!(parse_pr_number("https://github.com/o/r/pull/218\n"), Some(218));
        assert_eq!(parse_pr_number("no url here"), None);
    }
}
