# PR: git interop bridge — design + spec (ADR 0028)

**Planning/spec only — no implementation.** Adds the design for a bidirectional
loot ↔ git mirror, charted via wayfinder.

## Summary

Specifies a `loot ferry` command that keeps a loot repo and a private git repo
continuously in step. git is a plaintext mirror of the **syncing identity's
readable tree**; loot stays canonical and permission-authoritative. Resolves the
long-standing "git interop bridge" placeholder in `CONTEXT.md` into an
implementation-ready spec.

## What's included

- `docs/adr/0028-git-interop-bridge.md` — decision record (symmetry & visibility
  boundary, change↔commit/DAG mapping, identity + SSH signing, reconciliation,
  mechanism; with alternatives + consequences).
- `issues/GB1-git-interop-bridge.md` — implementation-ready ticket: what to build,
  acceptance criteria, Rust+git test plan.
- `.scratch/git-interop-bridge/` — the wayfinder map and its seven resolved tickets
  (audit trail).

## Key decisions

- **Symmetry:** loot→git = `surface` for the syncing identity (sealed paths omitted
  entirely); git→loot = write + normal `.lootattributes` snapshot (seal at ingest).
  Trusted-remote constraint — not for a public host.
- **History:** 1:1 change=commit with `Loot-Change-Id` / `Loot-Author` /
  `Loot-Signature` trailers; deterministic dates; every head under `refs/loot/*`,
  `main` at a designated dock. Reverse via trailer short-circuit; mark map carries
  `origin`.
- **Identity:** identity map auto-seeded from git config; git-native commits →
  syncing-identity-or-legacy; SSH-signed with loot's ed25519 key.
- **Reconciliation:** loot is the merge authority (converge classifier, ADR 0001);
  divergence via last-synced pointers; conflicts resolved in loot; sealed content
  never surfaces into git.
- **Mechanism:** one-shot `loot ferry` over git2; mark map in `.loot/git-mirror/`
  (local-only, rebuildable).

## Out of scope (named follow-ons)

Public-host (ANYONE-only) projection · `--watch`/daemon + git-hook triggers ·
remote-helper (`git-remote-loot`) · attestations → git notes/tags · gitoxide swap.

## Notes for reviewers

- Amends nothing, but sits alongside ADR 0022 (no-branches thesis) — the
  `refs/loot/*` refs are mechanical reachability handles, not loot branches.
- Prior-art basis (jj git backend, git-cinnabar, fast-import marks) in
  `.scratch/git-interop-bridge/assets/04-mechanism-survey.md`.
- No code; implementation tracked by `issues/GB1-git-interop-bridge.md`.
