# CA2 — Local `dock merge` + harbor convention

**Type:** AFK · **Priority:** near · **Source:** docs/adr/0022-concurrent-agent-model-docks.md; grill-with-docs 2026-07-06

## What to build

Bring two docks back together locally. `loot dock merge <name>` applies one
dock's tip onto the current dock's working change **in-process**, reusing the
existing `apply`/converge path (ADR 0001) with no relay hop and no bundle file —
docks share one object store, so merging is a local fork collapse, not a network
operation. Per-path outcomes (Converged / Merged / Conflict / RelayedUnmerged)
and conflict handling (`loot conflicts` / `loot resolve`) are exactly the
existing machinery.

Add the **harbor** convention: a plain dock with a well-known name and no
permissions attached, serving as the default integrator agents merge into and
re-base from. It is a coordination convention, not a gated branch — nothing in
the engine treats it specially.

The relay path stays for *remote* agents only and is unchanged by this slice.

## Acceptance criteria

- [ ] `loot dock merge <name>` collapses another dock's tip into the current working change in-process, with no relay call.
- [ ] Concurrent disjoint edits across two docks converge/merge cleanly; a genuine same-path divergence surfaces as a `Conflict` via the existing `conflicts`/`resolve` flow (no side dropped).
- [ ] A `RelayedUnmerged` path (current identity lacks the key) is carried forward untouched, matching ADR 0001.
- [ ] The harbor is an ordinary dock by a conventional name; merging into it and re-basing from it round-trips.
- [ ] No new engine convergence logic — the slice reuses `apply`/converge.

## Blocked by

- CA1 — Docks: isolated working trees over one object store
