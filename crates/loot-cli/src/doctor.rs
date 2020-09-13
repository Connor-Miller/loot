//! `loot doctor` (#22) — a read-only setup self-check.
//!
//! Diagnoses the common "why doesn't sync/grant work?" setup gaps by reading
//! the `.loot/` store by layout alone (never loading the engine, like
//! `loot verify`), reporting each check with a concrete fix command, and
//! exiting 1 if ANY check fails so CI can gate on a clean setup.
//!
//! The check logic lives in [`run_checks`], a pure function over explicit paths
//! (the store's `.loot/` and the global-config file), so every failure mode is
//! unit-testable in a tempdir without touching the ambient repo. [`run`] is the
//! thin CLI verb that resolves those paths and turns the report into an exit
//! code.
//!
//! **Grounding on the real store (`loot_core::store` layout).** The ticket names
//! a `changes` file; the change DAG is actually `.loot/graph`, so that check
//! reads `graph`. The keypair is `.loot/id`, peers are `.loot/peers`, named
//! remotes (incl. `origin`) live in `.loot/config`, objects in `.loot/objects/`.
//! The global config (`~/.config/loot/config`, XDG) treats a *missing* file as a
//! valid empty config (identity can instead come from `loot init --identity`),
//! so — unlike the ticket's literal "not found" wording — an absent global
//! config is a pass; only a present-but-malformed one (non-UTF-8, or a
//! non-comment line without `=`) fails.

use crate::emit::{self, Emit};
use crate::error::CliError;
use crate::kv;
use crate::workspace::{self, GlobalConfig};
use loot_core::RepoStore;
use loot_identity::PeerRegistry;
use std::fmt::Write as _;
use std::path::Path;

/// The outcome of one diagnostic check.
enum Outcome {
    /// The check passed; the string is the reassuring detail line.
    Pass(String),
    /// The check failed; `detail` explains what's wrong and `fix` is the exact
    /// command (or edit) that resolves it.
    Fail { detail: String, fix: String },
}

/// One named diagnostic and its outcome.
pub struct Check {
    label: &'static str,
    outcome: Outcome,
}

impl Check {
    fn pass(label: &'static str, detail: impl Into<String>) -> Self {
        Check { label, outcome: Outcome::Pass(detail.into()) }
    }

    fn fail(label: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Check { label, outcome: Outcome::Fail { detail: detail.into(), fix: fix.into() } }
    }

    fn passed(&self) -> bool {
        matches!(self.outcome, Outcome::Pass(_))
    }
}

/// Every check's outcome for one `loot doctor` run.
pub struct DoctorReport {
    checks: Vec<Check>,
}

impl DoctorReport {
    /// True when no check failed — the exit-0 condition.
    pub fn healthy(&self) -> bool {
        self.checks.iter().all(Check::passed)
    }

    /// How many checks failed (drives the exit-1 summary).
    pub fn failures(&self) -> usize {
        self.checks.iter().filter(|c| !c.passed()).count()
    }

    /// Render the human report: one aligned line per check, a `fix:` line under
    /// each failure, and a closing verdict.
    pub fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "loot doctor — setup self-check\n");
        for c in &self.checks {
            match &c.outcome {
                Outcome::Pass(detail) => {
                    let _ = writeln!(out, "  [ok]   {:<14} {detail}", c.label);
                }
                Outcome::Fail { detail, fix } => {
                    let _ = writeln!(out, "  [FAIL] {:<14} {detail}", c.label);
                    let _ = writeln!(out, "         {:<14} fix: {fix}", "");
                }
            }
        }
        let _ = writeln!(out);
        if self.healthy() {
            let _ = writeln!(out, "all checks passed");
        } else {
            let _ = writeln!(out, "{} problem(s) found — run the fixes above", self.failures());
        }
        out
    }
}

/// Run every setup check against the store rooted at `dot` and the global-config
/// file at `global_config`. Pure over its inputs (reads only those paths), so
/// each failure mode is testable in isolation.
pub fn run_checks(dot: &Path, global_config: &Path) -> DoctorReport {
    let store = RepoStore::new(dot);
    let mut checks = Vec::new();

    // 1. keypair — `.loot/id` (loot_identity, ADR 0014). Absent until `keygen`.
    checks.push(if loot_identity::keypair_exists(dot) {
        Check::pass("keypair", "identity keypair present (.loot/id)")
    } else {
        Check::fail("keypair", "no identity keypair — .loot/id is missing", "loot keygen")
    });

    // 2. peers — `.loot/peers` (name = pubkey). Grants need at least one.
    let peers = PeerRegistry::load(dot);
    let peer_count = peers.list().len();
    checks.push(if peer_count == 0 {
        Check::fail(
            "peers",
            "no peers registered — grants and sealed delivery have no recipients",
            "loot peer add <name> <pubkey>",
        )
    } else {
        Check::pass("peers", format!("{peer_count} peer(s) registered"))
    });

    // 3. origin remote — a named remote `origin` in `.loot/config` (ADR 0013).
    let config_text = std::fs::read_to_string(store.config()).unwrap_or_default();
    let remotes = kv::parse(&config_text);
    checks.push(if let Some(url) = remotes.get("origin") {
        Check::pass("origin remote", format!("origin → {url}"))
    } else {
        Check::fail(
            "origin remote",
            "no `origin` remote configured — push/pull have no default relay",
            "loot remote add origin <url>",
        )
    });

    // 4. change graph — `.loot/graph`, the change DAG (the ticket's "changes").
    checks.push(if store.graph().exists() {
        Check::pass("change graph", "change DAG present (.loot/graph)")
    } else {
        Check::fail(
            "change graph",
            ".loot/graph is missing — the change DAG is gone or the store is corrupt",
            "restore .loot/ from a backup, or re-clone with `loot clone <url> <dir>`",
        )
    });

    // 5. object store — `.loot/objects/`, the content-addressed store (ADR 0012).
    checks.push(if store.objects_dir().is_dir() {
        Check::pass("object store", "object store present (.loot/objects/)")
    } else {
        Check::fail(
            "object store",
            ".loot/objects/ is missing — content-addressed objects are gone or the store is corrupt",
            "restore .loot/ from a backup, or re-clone with `loot clone <url> <dir>`",
        )
    });

    // 6. global config — `~/.config/loot/config` (XDG). Missing is fine (identity
    //    may come from `--identity`); only a present-but-malformed file fails.
    checks.push(global_config_check(global_config));

    DoctorReport { checks }
}

/// Inspect the global config file: absent is a pass (optional), present-and-parses
/// is a pass, present-but-non-UTF-8 or holding a non-comment line without `=` is
/// a malformed-config failure.
fn global_config_check(path: &Path) -> Check {
    let bytes = match std::fs::read(path) {
        Err(_) => {
            return Check::pass(
                "global config",
                "not present (optional — identity may come from `loot init --identity`)",
            );
        }
        Ok(b) => b,
    };
    let text = match std::str::from_utf8(&bytes) {
        Err(_) => {
            return Check::fail(
                "global config",
                format!("{} is not valid UTF-8", path.display()),
                format!("repair or remove {}", path.display()),
            );
        }
        Ok(t) => t,
    };
    // A well-formed line is blank, a `#` comment, or holds a `key = value` pair.
    // kv::parse silently drops a `=`-less line, so a self-check must flag it.
    let malformed = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#') && !l.contains('='));
    match malformed {
        Some(line) => Check::fail(
            "global config",
            format!("malformed line in {}: `{line}`", path.display()),
            format!("edit {} so every line is `key = value`", path.display()),
        ),
        None => Check::pass("global config", format!("parses cleanly ({})", path.display())),
    }
}

/// `loot doctor` — resolve the ambient store + global-config paths, run every
/// check, print the report, and map the verdict to an exit code (0 healthy,
/// 1 if any check failed). The per-check detail prints to stdout; the exit-1
/// summary rides the standard error channel via the dispatcher (like `verify`).
pub fn run(_args: &[String]) -> Result<Box<dyn Emit>, CliError> {
    // Resolve the store by layout alone (never load the engine) so a corrupt
    // store is still diagnosable — the same path `loot verify` takes (#19).
    let dot = workspace::resolve_store_dot(Path::new("."))?;
    let global = GlobalConfig::load();
    let report = run_checks(&dot, global.path());
    print!("{}", report.render());
    if report.healthy() {
        Ok(Box::new(emit::Message::new(String::new())))
    } else {
        Err(format!("doctor found {} setup problem(s)", report.failures()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static N: AtomicU64 = AtomicU64::new(0);

    /// A fresh, empty tempdir unique per (process, call) — no ambient `.loot`
    /// is ever touched (the test-cwd shared-store hazard).
    fn tmp(tag: &str) -> PathBuf {
        let n = N.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir()
            .join(format!("loot-doctor-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// Build a fully-healthy `.loot/` under a fresh tempdir and return the dot
    /// path. Every later test starts from this and breaks exactly one thing.
    fn healthy_dot(tag: &str) -> PathBuf {
        let dot = tmp(tag).join(".loot");
        std::fs::create_dir_all(&dot).unwrap();
        // keypair, change graph, objects store
        std::fs::write(dot.join("id"), b"PRIVATE-KEY-BYTES").unwrap();
        std::fs::write(dot.join("id.pub"), b"ssh-ed25519 AAAA test@loot\n").unwrap();
        std::fs::write(dot.join("graph"), b"").unwrap();
        std::fs::create_dir_all(dot.join("objects")).unwrap();
        // one registered peer
        std::fs::write(dot.join("peers"), b"alice = ssh-ed25519 AAAApeerkey alice@loot\n").unwrap();
        // an origin remote
        std::fs::write(dot.join("config"), b"origin = https://relay.example/loot\n").unwrap();
        dot
    }

    /// A global-config path that does not exist (the common healthy case).
    fn absent_global(tag: &str) -> PathBuf {
        tmp(tag).join("config")
    }

    fn find<'a>(r: &'a DoctorReport, label: &str) -> &'a Check {
        r.checks.iter().find(|c| c.label == label).expect("check present")
    }

    #[test]
    fn healthy_repo_passes_all_checks() {
        let dot = healthy_dot("healthy");
        let report = run_checks(&dot, &absent_global("healthy"));
        assert!(report.healthy(), "expected all checks to pass:\n{}", report.render());
        assert_eq!(report.failures(), 0);
        assert!(report.render().contains("all checks passed"));
    }

    #[test]
    fn missing_keypair_fails() {
        let dot = healthy_dot("nokey");
        std::fs::remove_file(dot.join("id")).unwrap();
        let report = run_checks(&dot, &absent_global("nokey"));
        assert!(!report.healthy());
        assert_eq!(report.failures(), 1);
        let c = find(&report, "keypair");
        assert!(!c.passed());
        match &c.outcome {
            Outcome::Fail { fix, .. } => assert_eq!(fix, "loot keygen"),
            _ => panic!("expected keypair failure"),
        }
    }

    #[test]
    fn no_peers_fails() {
        let dot = healthy_dot("nopeers");
        std::fs::remove_file(dot.join("peers")).unwrap();
        let report = run_checks(&dot, &absent_global("nopeers"));
        assert!(!report.healthy());
        assert_eq!(report.failures(), 1);
        let c = find(&report, "peers");
        assert!(!c.passed());
        match &c.outcome {
            Outcome::Fail { fix, .. } => assert!(fix.starts_with("loot peer add")),
            _ => panic!("expected peers failure"),
        }
    }

    #[test]
    fn no_origin_remote_fails() {
        let dot = healthy_dot("noorigin");
        // A config with some other remote but no `origin`.
        std::fs::write(dot.join("config"), b"upstream = https://x/y\n").unwrap();
        let report = run_checks(&dot, &absent_global("noorigin"));
        assert!(!report.healthy());
        assert_eq!(report.failures(), 1);
        let c = find(&report, "origin remote");
        assert!(!c.passed());
        match &c.outcome {
            Outcome::Fail { fix, .. } => assert_eq!(fix, "loot remote add origin <url>"),
            _ => panic!("expected origin failure"),
        }
    }

    #[test]
    fn missing_change_graph_fails() {
        let dot = healthy_dot("nograph");
        std::fs::remove_file(dot.join("graph")).unwrap();
        let report = run_checks(&dot, &absent_global("nograph"));
        assert!(!report.healthy());
        assert_eq!(report.failures(), 1);
        assert!(!find(&report, "change graph").passed());
    }

    #[test]
    fn missing_objects_dir_fails() {
        let dot = healthy_dot("noobjects");
        std::fs::remove_dir_all(dot.join("objects")).unwrap();
        let report = run_checks(&dot, &absent_global("noobjects"));
        assert!(!report.healthy());
        assert_eq!(report.failures(), 1);
        assert!(!find(&report, "object store").passed());
    }

    #[test]
    fn absent_global_config_passes() {
        let dot = healthy_dot("noglobal");
        let report = run_checks(&dot, &absent_global("noglobal"));
        assert!(find(&report, "global config").passed());
        assert!(report.healthy());
    }

    #[test]
    fn well_formed_global_config_passes() {
        let dot = healthy_dot("goodglobal");
        let g = tmp("goodglobal").join("config");
        std::fs::write(&g, b"# my settings\nidentity = connor\n").unwrap();
        let report = run_checks(&dot, &g);
        assert!(find(&report, "global config").passed());
        assert!(report.healthy());
    }

    #[test]
    fn malformed_global_config_fails() {
        let dot = healthy_dot("badglobal");
        let g = tmp("badglobal").join("config");
        // A non-comment line with no `=` — kv::parse would silently drop it.
        std::fs::write(&g, b"identity = connor\nthis line is broken\n").unwrap();
        let report = run_checks(&dot, &g);
        assert!(!report.healthy());
        assert_eq!(report.failures(), 1);
        assert!(!find(&report, "global config").passed());
    }

    #[test]
    fn multiple_problems_are_all_reported() {
        let dot = healthy_dot("multi");
        std::fs::remove_file(dot.join("id")).unwrap();
        std::fs::remove_file(dot.join("peers")).unwrap();
        std::fs::remove_file(dot.join("config")).unwrap();
        let report = run_checks(&dot, &absent_global("multi"));
        assert!(!report.healthy());
        assert_eq!(report.failures(), 3);
        let rendered = report.render();
        assert!(rendered.contains("3 problem(s) found"), "{rendered}");
    }
}
