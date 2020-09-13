//! `loot-first` — the land-policy orchestrator (map #148, #218).
//!
//! loot leads; git main is a downstream projection; the GitHub PR is a review
//! view built from projected unfinalized loot WIP. This crate is the successor
//! to `tools/loot-first.ps1`: same rituals (`review` / `land` / `status` /
//! `init-hook`), but the land *policy* is Rust — tested, not scraped.
//!
//! The invariant the ps1 protected survives the rewrite: **loot itself never
//! talks to GitHub.** Every `gh` / `git push` call lives behind the [`forge`]
//! seam; loot state is read **in-process** through the `loot-cli` library face
//! ([`loot_cli::workspace::Workspace`], [`loot_cli::ferry`]) rather than by
//! parsing `loot` stdout.
//!
//! - [`ledger`] — typed owners of the on-disk `pr-map` and `wip` ledgers.
//! - [`forge`] — the GitHub seam: the [`forge::Forge`] trait, a `gh`-shelling
//!   production adapter, and a fake for policy tests.
//! - [`policy`] — the land decisions, each a pure `decide`-shaped function.
//! - [`orchestrator`] — the `review` / `land` / `status` flows that compose
//!   Workspace + ferry + Forge + ledgers + policy.

pub mod forge;
pub mod ledger;
pub mod orchestrator;
pub mod policy;
