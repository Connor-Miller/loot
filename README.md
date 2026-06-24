# loot

A from-scratch source-control system.

**Thesis:** visibility and permissions belong to *content and changes*, not to
the *repository*. Commit your `.env`. Keep files private inside a shared repo.
Embargo a security fix: merge it, cut the release, reveal the source later.

This is the unsolved problem in modern version control. Ergonomics
(jj already nails them) are a layer we add later. Sync, however, is part of the
foundation bake-off: the hardest question in loot is how concurrent offline
edits converge when content may be encrypted to peers who lack the key.

## Status: early — deciding the foundation

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
