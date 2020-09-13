//! `loot resolve --tool <cmd> <path>` — resolve a conflict with an external
//! three-way merge tool (#401), the way `git mergetool` / `jj resolve --tool`
//! do: materialize the three sides as temp files, exec the tool, read back the
//! merged result, and file it through the same [`Workspace::resolve_conflict`]
//! the manual `loot resolve <path> <file>` uses.
//!
//! Three invariants shape the flow:
//!
//! 1. **Key oracle BEFORE any temp file.** The three sides are opened (decrypted
//!    to plaintext) *first*; a side this identity cannot open aborts with
//!    `cannot open <side> — request a grant first` before a single byte touches
//!    disk. So a missing grant never leaks a partial scratch dir.
//! 2. **Plaintext never persists.** The scratch dir holds DECRYPTED content, so
//!    it is removed on every exit — success, `?`, or panic — by an RAII guard
//!    ([`Scratch`]'s `Drop`).
//! 3. **git-mergetool compatibility.** Each side is exposed both as an env var
//!    (`LOOT_BASE`/`LOOT_OURS`/`LOOT_THEIRS`/`LOOT_OUTPUT`) and as a positional
//!    token in the command string (`$BASE`/`$LOCAL`/`$REMOTE`/`$MERGED`), so an
//!    existing mergetool invocation works unchanged.

use crate::error::CliError;
use crate::workspace::Workspace;
use loot_core::{Oid, RepoError, Visibility};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// What a `--tool` resolution produced, for the CLI to report.
#[derive(Debug)]
pub struct ResolveToolReport {
    /// The resolution content's address (the "new oid" line).
    pub new_oid: Oid,
    /// The minted resolution subject (`(conflict resolution: <path>)`, #337).
    pub message: String,
    /// A visibility-mismatch note when ours/theirs were sealed under different
    /// policies (#401) — surfaced as a `warning:` line, never fatal.
    pub vis_warning: Option<String>,
}

/// The three decrypted sides, plus any visibility-mismatch note — everything
/// gathered by the key-oracle pass, before the scratch dir exists.
struct Sides {
    base: Option<Vec<u8>>,
    ours: Vec<u8>,
    theirs: Vec<u8>,
    vis_warning: Option<String>,
}

/// Resolve the conflict at `path` with external `tool` (a shell command string
/// or a predefined token). See the module docs for the ordering guarantees.
pub fn run(ws: &mut Workspace, path: &Path, tool: &str) -> Result<ResolveToolReport, CliError> {
    run_impl(ws, path, tool, scratch_dir())
}

/// The body, with the scratch directory injected so a test can name it and
/// assert it is gone afterward. `run` supplies a per-invocation unique dir.
fn run_impl(
    ws: &mut Workspace,
    path: &Path,
    tool: &str,
    scratch_dir: PathBuf,
) -> Result<ResolveToolReport, CliError> {
    // The recorded conflict — cloned so the immutable borrow of `ws` is released
    // before we open content (also a `&self` call) and, later, resolve (`&mut`).
    let (base_oid, ours_oid, theirs_oid) = ws
        .conflicts()
        .get(path)
        .cloned()
        .ok_or_else(|| {
            CliError::from(format!(
                "no conflict at {} — run `loot conflicts` to list them",
                path.display()
            ))
        })?;

    // (1) Key-oracle pass FIRST — no scratch dir yet. An unopenable side aborts
    // here, before any plaintext is written.
    let sides = open_sides(ws, base_oid.as_ref(), &ours_oid, &theirs_oid)?;

    // (2) Only now materialize the scratch dir (RAII-cleaned on every exit).
    let scratch = Scratch::create(scratch_dir)?;
    let merged = drive_tool(&scratch, tool, &sides)?;

    // (3) File the resolution under the path's configured visibility, exactly as
    // manual `loot resolve <path> <file>` does.
    let vis = ws.visibility_for(&path.to_string_lossy());
    let (new_oid, message) = ws.resolve_conflict(path, &merged, vis)?;
    Ok(ResolveToolReport { new_oid, message, vis_warning: sides.vis_warning })
    // `scratch` drops here — the plaintext temp dir is removed.
}

/// Open all three sides as the ambient identity. Any side that cannot be opened
/// (`Unauthorized`/`Embargoed`) aborts with an actionable grant hint; a genuine
/// read failure propagates. Also computes the visibility-mismatch note.
fn open_sides(
    ws: &Workspace,
    base_oid: Option<&Oid>,
    ours_oid: &Oid,
    theirs_oid: &Oid,
) -> Result<Sides, CliError> {
    let ours = open_side(ws, ours_oid, "ours")?;
    let theirs = open_side(ws, theirs_oid, "theirs")?;
    let base = match base_oid {
        Some(oid) => Some(open_side(ws, oid, "base")?),
        None => None,
    };
    let vis_warning = visibility_mismatch(ws, ours_oid, theirs_oid);
    Ok(Sides { base, ours, theirs, vis_warning })
}

/// Decrypt one side, or refuse with the grant hint the ticket specifies.
fn open_side(ws: &Workspace, oid: &Oid, side: &str) -> Result<Vec<u8>, CliError> {
    match ws.graph().content(oid) {
        Ok(bytes) => Ok(bytes),
        Err(RepoError::Unauthorized(_) | RepoError::Embargoed(_)) => {
            Err(format!("cannot open {side} — request a grant first").into())
        }
        Err(e) => Err(format!("cannot open {side}: {e}").into()),
    }
}

/// Warn when ours and theirs were sealed under different visibility *policies*
/// (#401) — Public vs Restricted vs Embargoed. Membership differences within
/// `Restricted` are not flagged (grant/maroon own that audit trail), matching
/// the engine's demotion check.
fn visibility_mismatch(ws: &Workspace, ours: &Oid, theirs: &Oid) -> Option<String> {
    let ov = ws.visibility_of(ours)?;
    let tv = ws.visibility_of(theirs)?;
    if std::mem::discriminant(&ov) != std::mem::discriminant(&tv) {
        Some(format!(
            "ours and theirs were sealed under different visibility policies ({} vs {}) — \
             the resolution is sealed under this path's `.lootattributes` policy",
            vis_label(&ov),
            vis_label(&tv),
        ))
    } else {
        None
    }
}

fn vis_label(v: &Visibility) -> &'static str {
    match v {
        Visibility::Internal => "internal",
        Visibility::Restricted(_) => "restricted",
        Visibility::Embargoed { .. } => "embargoed",
    }
}

/// Write the three sides + an empty output file, exec the tool with both env
/// vars and positional expansion, and read the merged bytes back. A non-zero
/// exit or an empty output file aborts (the conflict is left unresolved) so a
/// tool that failed or was cancelled never silently applies a wrong/empty
/// resolution.
fn drive_tool(scratch: &Scratch, tool: &str, sides: &Sides) -> Result<Vec<u8>, CliError> {
    let base_path = scratch.file("base");
    let ours_path = scratch.file("ours");
    let theirs_path = scratch.file("theirs");
    let output_path = scratch.file("output");

    // The base file is always present (empty when there was no common ancestor)
    // so `$BASE`/`$LOOT_BASE` always name a readable file, like git's mergetool.
    std::fs::write(&base_path, sides.base.as_deref().unwrap_or(&[]))
        .map_err(|e| CliError::from(format!("write base temp: {e}")))?;
    std::fs::write(&ours_path, &sides.ours)
        .map_err(|e| CliError::from(format!("write ours temp: {e}")))?;
    std::fs::write(&theirs_path, &sides.theirs)
        .map_err(|e| CliError::from(format!("write theirs temp: {e}")))?;
    std::fs::write(&output_path, b"")
        .map_err(|e| CliError::from(format!("write output temp: {e}")))?;

    let command = expand(&resolve_template(tool), &base_path, &ours_path, &theirs_path, &output_path);

    let status = build_shell(&command)
        .env("LOOT_BASE", &base_path)
        .env("LOOT_OURS", &ours_path)
        .env("LOOT_THEIRS", &theirs_path)
        .env("LOOT_OUTPUT", &output_path)
        .status()
        .map_err(|e| CliError::from(format!("cannot execute merge tool `{command}`: {e}")))?;

    if !status.success() {
        return Err(format!(
            "merge tool exited with status {} — conflict left unresolved",
            status.code().map(|c| c.to_string()).unwrap_or_else(|| "signal".into())
        )
        .into());
    }

    let merged = std::fs::read(&output_path)
        .map_err(|e| CliError::from(format!("read merged output: {e}")))?;
    if merged.is_empty() {
        return Err(
            "merge tool wrote nothing to the output ($MERGED / $LOOT_OUTPUT) — \
             conflict left unresolved"
                .into(),
        );
    }
    Ok(merged)
}

/// Map a predefined token to its tool invocation, or pass a literal shell
/// command string through unchanged. Templates use the same `$BASE/$LOCAL/
/// $REMOTE/$MERGED` tokens [`expand`] substitutes, so a token and a hand-written
/// command travel the identical path. (Tool discovery/`$PATH` scanning is out of
/// scope for v1 — an unknown token is simply treated as a shell command.)
fn resolve_template(tool: &str) -> String {
    match tool {
        "vimdiff" => "vimdiff $LOCAL $BASE $REMOTE $MERGED".into(),
        "code" => "code --wait --merge $REMOTE $LOCAL $BASE $MERGED".into(),
        "idea" => "idea merge $LOCAL $REMOTE $BASE $MERGED".into(),
        "kaleidoscope" => {
            "ksdiff --merge --output $MERGED --base $BASE -- $LOCAL --snapshot $REMOTE --snapshot"
                .into()
        }
        other => other.to_string(),
    }
}

/// Substitute the four git-mergetool positional tokens with quoted temp paths.
fn expand(cmd: &str, base: &Path, ours: &Path, theirs: &Path, output: &Path) -> String {
    let q = |p: &Path| format!("\"{}\"", p.display());
    cmd.replace("$BASE", &q(base))
        .replace("$LOCAL", &q(ours))
        .replace("$REMOTE", &q(theirs))
        .replace("$MERGED", &q(output))
}

/// Build the platform shell command so a shell command string (pipes, tokens,
/// builtins like `copy`/`cp`) runs as written, and an interactive tool inherits
/// this process's stdio. On Windows the expanded line is handed to `cmd /C`
/// *verbatim* via `raw_arg` — bypassing Rust's argv quoting, which mis-quotes
/// for `cmd.exe`. On Unix it goes to `sh -c`.
#[cfg(windows)]
fn build_shell(command: &str) -> std::process::Command {
    use std::os::windows::process::CommandExt;
    let mut c = std::process::Command::new("cmd");
    c.arg("/C");
    c.raw_arg(command);
    c
}

#[cfg(not(windows))]
fn build_shell(command: &str) -> std::process::Command {
    let mut c = std::process::Command::new("sh");
    c.arg("-c").arg(command);
    c
}

/// A per-invocation scratch directory holding decrypted plaintext, removed on
/// `Drop` so an early return, `?`, or panic never leaves plaintext on disk.
struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn create(dir: PathBuf) -> Result<Scratch, CliError> {
        // A stale dir from a crashed prior run with a colliding name would leak
        // its plaintext into this session; clear it first.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)
            .map_err(|e| CliError::from(format!("create scratch dir {}: {e}", dir.display())))?;
        Ok(Scratch { dir })
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A unique scratch path under the system temp dir: `loot-resolve-<pid>-<n>`.
/// The counter keeps concurrent invocations in one process from colliding
/// (the pid alone would).
fn scratch_dir() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("loot-resolve-{}-{}-{}", std::process::id(), n, nanos))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::Workspace;
    use loot_core::{Repo as _, Visibility};
    use std::collections::BTreeMap;

    const DOT: &str = ".loot";

    fn authored_ws(dir: &Path) -> Workspace {
        let _ = std::fs::remove_dir_all(dir);
        Workspace::init_at(dir, "connor").unwrap();
        loot_identity::generate_and_save(&dir.join(DOT), "connor@loot").unwrap();
        let mut ws = Workspace::open_at(dir).unwrap();
        ws.start_fresh_change().unwrap();
        ws
    }

    /// Seed a conflict at `path` by putting the sides directly and recording
    /// them — the merge machinery is exercised elsewhere; here we want a
    /// controlled `(base, ours, theirs)` with chosen visibilities.
    fn seed_conflict(
        ws: &mut Workspace,
        path: &str,
        base: Option<(&[u8], Visibility)>,
        ours: (&[u8], Visibility),
        theirs: (&[u8], Visibility),
    ) {
        ws.with_repo_mut(|repo| {
            let base_oid = match base {
                Some((b, v)) => Some(repo.put(b, v).map_err(CliError::from)?),
                None => None,
            };
            let ours_oid = repo.put(ours.0, ours.1).map_err(CliError::from)?;
            let theirs_oid = repo.put(theirs.0, theirs.1).map_err(CliError::from)?;
            let mut m = BTreeMap::new();
            m.insert(PathBuf::from(path), (base_oid, ours_oid, theirs_oid));
            repo.record_conflicts(m);
            Ok(())
        })
        .unwrap();
    }

    /// A portable "merge tool": copy the LOCAL (ours) side onto MERGED. On
    /// Windows via cmd's `copy` builtin, elsewhere via `cp`. Both read the
    /// positional tokens the handler expands, so this exercises the real
    /// expansion + exec + read-back path.
    fn copy_tool() -> &'static str {
        if cfg!(windows) {
            "copy /Y $LOCAL $MERGED"
        } else {
            "cp $LOCAL $MERGED"
        }
    }

    #[test]
    fn tool_resolution_is_read_back_and_applied_then_scratch_is_gone() {
        let dir = std::env::temp_dir().join(format!("loot-mergetool-happy-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        seed_conflict(
            &mut ws,
            "a.txt",
            Some((b"base\n", Visibility::Internal)),
            (b"ours side\n", Visibility::Internal),
            (b"theirs side\n", Visibility::Internal),
        );

        let scratch = std::env::temp_dir().join(format!("loot-mergetool-scratch-happy-{}", std::process::id()));
        let report =
            run_impl(&mut ws, Path::new("a.txt"), copy_tool(), scratch.clone()).unwrap();

        // The tool copied ours -> output, so the resolution is ours' content.
        assert_eq!(
            ws.graph().content(&report.new_oid).unwrap(),
            b"ours side\n",
            "the merged output ($MERGED) is read back and filed as the resolution"
        );
        assert!(ws.conflicts().is_empty(), "the conflict is cleared after a tool resolve");
        assert!(!scratch.exists(), "the plaintext scratch dir is removed after a successful resolve");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unopenable_side_aborts_before_writing_temp_files() {
        let dir = std::env::temp_dir().join(format!("loot-mergetool-sealed-{}", std::process::id()));
        let mut ws = authored_ws(&dir);
        // `theirs` is sealed to another identity — connor cannot open it, so the
        // key-oracle pass must refuse before any scratch dir is created.
        seed_conflict(
            &mut ws,
            "a.txt",
            None,
            (b"ours side\n", Visibility::Internal),
            (b"secret\n", Visibility::Restricted(vec!["other".into()])),
        );

        let scratch = std::env::temp_dir().join(format!("loot-mergetool-scratch-sealed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        let err = run_impl(&mut ws, Path::new("a.txt"), copy_tool(), scratch.clone())
            .expect_err("an unopenable side must abort");
        assert!(
            err.to_string().contains("cannot open theirs")
                && err.to_string().contains("request a grant first"),
            "actionable grant hint: {err}"
        );
        assert!(
            !scratch.exists(),
            "no scratch dir is created when a side cannot be opened (oracle check is first)"
        );
        assert!(!ws.conflicts().is_empty(), "the conflict is left unresolved on abort");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scratch_guard_removes_the_dir_on_drop() {
        let dir = std::env::temp_dir().join(format!("loot-mergetool-guard-{}", std::process::id()));
        {
            let s = Scratch::create(dir.clone()).unwrap();
            std::fs::write(s.file("secret"), b"plaintext").unwrap();
            assert!(dir.exists(), "scratch dir exists while the guard is alive");
        }
        assert!(!dir.exists(), "the guard removes the scratch dir (and its plaintext) on drop");
    }

    #[test]
    fn expand_substitutes_all_four_positional_tokens() {
        let out = expand(
            "tool $BASE $LOCAL $REMOTE $MERGED",
            Path::new("/b"),
            Path::new("/o"),
            Path::new("/t"),
            Path::new("/m"),
        );
        assert_eq!(out, "tool \"/b\" \"/o\" \"/t\" \"/m\"");
    }

    #[test]
    fn known_tokens_map_to_tool_invocations() {
        assert!(resolve_template("vimdiff").contains("$LOCAL") && resolve_template("vimdiff").contains("$MERGED"));
        assert!(resolve_template("code").contains("--merge"));
        // An unknown token is a literal shell command, unchanged.
        assert_eq!(resolve_template("my --custom cmd"), "my --custom cmd");
    }
}
