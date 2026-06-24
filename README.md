# loot

A from-scratch source-control system.

**Thesis:** visibility and permissions belong to *content and changes*, not to
the *repository*. Commit your `.env`. Keep files private inside a shared repo.
Embargo a security fix: merge it, cut the release, reveal the source later.

This is the unsolved problem in modern version control. Ergonomics
(jj already nails them) and live sync are layers we add later — the foundation
exists to make per-change permissioning clean and fast.

## Status: early. Deciding the foundation.

Two storage models implement the same [`Repo`](crates/loot-core/src/lib.rs)
contract so we can compare them apples-to-apples on speed and feel:

- [`crates/spike-dag`](crates/spike-dag) — encrypted content-addressed DAG,
  packed (not git-style loose files), in-memory capable.
- [`crates/spike-crdt`](crates/spike-crdt) — CRDT document store, filesystem as
  a projection.

The winner graduates into [`crates/loot-core`](crates/loot-core); the loser is
deleted. See [CONTEXT.md](CONTEXT.md) for the glossary and decisions.

## Build

```bash
cargo build
cargo test
```
