//! `loot-cli` library face — the CLI's engine-facing modules, exposed so
//! sibling binaries in the workspace (the `loot-first` orchestrator, #218) can
//! drive loot state **in-process** rather than scraping `loot` stdout. The
//! `loot` binary itself is [`main`](../main.rs); it consumes these same modules.
//!
//! Only the modules the orchestrator needs are re-exported: [`workspace`] (the
//! Workspace face over the engine, R1 #177), [`ferry`] (the git-interop
//! reconcile pass, ADR 0028 / map #148), [`ledger`] (the `pr-map` review
//! ledger — written by the orchestrator, read by `loot lanes`, #232), and
//! [`flags`] (the argument gate both binaries dispatch through, #67).
//! [`render`] rides along because `ferry` and the bin depend on it. [`emit`]
//! (#321) holds the one rendering seam over the Verdict output contract (ADR
//! 0023) — it lives here rather than in `main.rs` so its [`emit::OutFmt`]
//! type is available to both the bin and (eventually) `loot-first`.

pub mod emit;
pub mod ferry;
pub mod flags;
pub mod ledger;
mod position;
pub mod render;
pub mod workspace;
