//! `loot-cli` library face — the CLI's engine-facing modules, exposed so
//! sibling binaries in the workspace (the `loot-first` orchestrator, #218) can
//! drive loot state **in-process** rather than scraping `loot` stdout. The
//! `loot` binary itself is [`main`](../main.rs); it consumes these same modules.
//!
//! Only the modules the orchestrator needs are re-exported: [`workspace`] (the
//! Workspace face over the engine, R1 #177) and [`ferry`] (the git-interop
//! reconcile pass, ADR 0028 / map #148). [`render`] rides along because
//! `ferry` and the bin depend on it.

pub mod ferry;
pub mod render;
pub mod workspace;
