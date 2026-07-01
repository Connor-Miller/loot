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
