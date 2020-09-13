//! `loot-first` — the land-policy orchestrator binary (map #148, #218),
//! successor to `tools/loot-first.ps1`.
//!
//! ```text
//! loot-first review [--title <t>] [--dry-run]   project WIP → PR
//! loot-first land --pr <n> [--skip-tests] [--dry-run]   land an approved PR
//! loot-first status                             show in-flight review lanes
//! ```
//!
//! Args are parsed by hand (no clap), matching loot-cli's dependency-light
//! style. GitHub is reached only through [`loot_first::forge::GhForge`]; loot
//! state is driven in-process via `loot_cli`'s Workspace.

use loot_first::forge::GhForge;
use loot_first::orchestrator;
use loot_cli::workspace::Workspace;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    let rest = &args[args.len().min(1)..];
    match cmd {
        "review" => {
            let title = flag_value(rest, "--title");
            let dry_run = has_flag(rest, "--dry-run");
            let mut ws = Workspace::open()?;
            let forge = gh_forge(&ws);
            orchestrator::review(&mut ws, &forge, title.as_deref(), dry_run)
        }
        "land" => {
            let pr = flag_value(rest, "--pr")
                .ok_or("usage: loot-first land --pr <n> [--skip-tests] [--dry-run]")?
                .parse::<u64>()
                .map_err(|_| "--pr must be a number".to_string())?;
            let skip_tests = has_flag(rest, "--skip-tests");
            let dry_run = has_flag(rest, "--dry-run");
            let mut ws = Workspace::open()?;
            let forge = gh_forge(&ws);
            orchestrator::land(&mut ws, &forge, pr, skip_tests, dry_run)
        }
        "status" => {
            let ws = Workspace::open()?;
            orchestrator::status(&ws)
        }
        "init-hook" => {
            let ws = Workspace::open()?;
            orchestrator::init_hook(&ws)
        }
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => Err(format!(
            "unknown command '{other}' (try: review, land, status, init-hook)"
        )),
    }
}

fn gh_forge(ws: &Workspace) -> GhForge {
    let root = ws.dot().parent().unwrap_or_else(|| std::path::Path::new(".")).to_path_buf();
    let mirror = ws.store().git_mirror_dir().join("mirror.git");
    GhForge::new(root, mirror)
}

/// The value following `name`, e.g. `--pr 218` or `--title "x"`.
fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn print_help() {
    println!(
        "loot-first — the loot land-policy orchestrator (#218)\n\n\
         USAGE:\n\
         \x20 loot-first review [--title <t>] [--dry-run]\n\
         \x20 loot-first land --pr <n> [--skip-tests] [--dry-run]\n\
         \x20 loot-first status\n\
         \x20 loot-first init-hook\n\n\
         loot itself never talks to GitHub; every gh/push call lives here.\n\
         See docs/agents/workflow.md for the full loop."
    );
}
