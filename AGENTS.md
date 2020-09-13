# Working loot as an agent

Entry point for any agent (or human) doing work in this repo. loot is a
from-scratch, encrypted-DAG source-control system, and it hosts its own
development — **loot leads, git `main` is a downstream projection.** Read the
doc that matches what you are about to do, then act.

## Read before you work

- **[docs/agents/workflow.md](docs/agents/workflow.md)** — how one change reaches
  `main`: open a lane → work → `loot ferry` → PR → `loot new` (sign) →
  `loot-first land`. The daily loop.
- **[docs/agents/concurrent.md](docs/agents/concurrent.md)** — when your session
  overlaps another: one lane per agent, what is parallel-safe vs. what serializes
  at the harbor, the land flow, and the drift discipline (ferry after break-glass,
  adopt after lane-lands).
- **[docs/agents/issue-tracker.md](docs/agents/issue-tracker.md)** — the tracker
  contract (GitHub via `gh`) and the claim ritual: assign the ticket, then spawn
  its lane.
- **[docs/agents/identity.md](docs/agents/identity.md)** — when a task needs its
  own keyring, it is a *clone*, not a lane (ADR 0026).
- **[CONTEXT.md](CONTEXT.md)** — the domain glossary (Change, Lane, Dock, Harbor,
  Adopt, Shared store, …). The source of truth for the vocabulary.
- **[docs/adr/](docs/adr/)** — the decisions behind all of the above.

## The two things to never get wrong

- **Don't commit straight to git `main`.** git `main` is a projection of loot; a
  direct commit is **break-glass**. If you must, run `loot ferry` immediately
  after so loot ingests it (concurrent.md — this is how the #243 drift started).
- **Never give the mirror a remote.** `.loot/git-mirror/mirror.git` is local-only
  and holds sealed content in plaintext (ADR 0028). Publishing to GitHub is always
  a single-ref push of a sealed-free branch — never a wholesale mirror push.

## Build & test

```bash
cargo build --release
cargo test                # full suite (~25s, includes relay integration tests)
cargo test -p loot-core   # fast, no I/O
```
