# loot improvement issues — borrowing from Epic's *lore*

Nine tracer-bullet slices distilled from a comparison of loot with Epic Games'
open-source VCS *lore* (`../docs/lore-comparison.md`), then filtered through a
grill session for what is **feasible and meaningful** given loot's code-first,
encryption-first thesis.

Each slice cuts end-to-end (engine → net/relay → CLI → tests) and is verifiable
on its own. All are AFK — no open design questions remain. Publish them to GitHub
with `./create-issues.sh` (requires an authenticated `gh`).

## Slices

| # | Title | Priority | Blocked by |
|---|---|---|---|
| S1 | Format versioning + compatibility gate | near (foundational) | — |
| S2 | Compress public content (Zstd) | near | S1 |
| S3 | Signed changes: author in id + validity | near | S1 |
| S4 | Attestation metadata lane | mid | S3 |
| S5 | Object-level "wants" negotiation | near | S1 |
| S6 | Resumable transfer | mid | S5 |
| S7 | Pluggable relay backend + S3 driver | mid | — |
| S8 | Sparse views (materialize-only) | low | — |
| S9 | Relay fault-injection test harness | optional | S5, S6 |

Independent starters (grab first): **S1, S7, S8**.

## Dependency order

```
S1 ─┬─> S2
    ├─> S3 ──> S4
    └─> S5 ──> S6
                └─(with S5)─> S9
S7   (independent)
S8   (independent)
```

## Concurrent-agents epic (CA)

A second epic distilled from a grill-with-docs session (2026-07-06) on the devX
of multiple AI agents working one repository at once. Four tracer-bullet slices,
all AFK. Publish with `./create-agent-issues.sh`. Decisions recorded in ADR 0022
(model) and ADR 0023 (machine output); glossary terms **Dock**, **Harbor**,
**Buoy** in `../CONTEXT.md`.

| # | Title | Priority | Blocked by |
|---|---|---|---|
| CA1 | Docks: isolated working trees over one object store | near (foundational) | — |
| CA2 | Local `dock merge` + harbor convention | near | CA1 |
| CA3 | Porcelain + JSON output for reconciliation verbs | near | — |
| CA4 | Buoys: navigational-role resolver over the attestation lane | near | — |

Independent starters (grab first): **CA1, CA3, CA4**.

```
CA1 ──> CA2
CA3   (independent — targets verbs that exist today)
CA4   (independent — attestation lane already ships)
```

### CA epic: decided but intentionally NOT issues

- **Soft advisory claims** — an append-only, advisory "working-on `<paths>`"
  signal to cut redundant agent work. HITL (record shape + TTL undecided) and a
  deliberate later phase: concurrency is optimistic by default (docks fork, the
  harbor serializes, conflicts surface as porcelain verdicts) and work-assignment
  is the orchestrator's job. Add only if real thrashing shows up. See
  `../CONTEXT.md` Open/undecided.
- **No tag / bookmark / branch primitive** — the anti-thesis (branches) and a
  race-prone mutable ref (tags) are replaced by the moving Dock handle and the
  append-only, derived Buoy. Recorded in ADR 0022, not scheduled.

## Decided but intentionally NOT issues

Design stances captured in `../CONTEXT.md` and ADR 0018, not scheduled as work:

- **Chunking large files** — deferred, benchmark-driven (reopens ADR 0004's
  equality-oracle problem; needs encryption-aware fragment trees).
- **Named bookmarks + relay CAS** — later ergonomics layer; ungated only.
- **Packfile compaction, zero-copy records, tiering/replication** — later,
  scale-driven.
- **C ABI + language SDKs** — deferred until the format (S1) is frozen.

## Dropped

- **Lazy / selective fetch** — structurally leaks access patterns.
- **Gated (repository-level) branches** — anti-thesis, permanent non-goal.
- **Scalable file locking** — a binary-first (lore) concern; loot is code-first.

## Related

- Comparison writeup: `../docs/lore-comparison.md`
- Decision record: `../docs/adr/0018-signed-changes-authored-history.md`
