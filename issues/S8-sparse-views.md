# S8 — Sparse views (materialize-only)

**Type:** AFK · **Priority:** low · **Source:** docs/lore-comparison.md (lore: sparse workspaces / views); grill 2026-07-01

## What to build

Let a working tree materialize only a subset of paths **without changing what is
fetched** (so there is no new relay-visible access-pattern signal — lazy/selective
fetch was rejected for exactly that leak). Add a `.loot/view` inbound path filter;
`surface` writes to disk only the paths matching the view, still holding the full
closure as ciphertext in `.loot/`. A path outside the view is not materialized but
is carried forward untouched on snapshot — the same visibility-aware rule already
used for sealed content (ADR 0006).

## Acceptance criteria

- [ ] A `.loot/view` glob filter scopes what `surface` materializes to disk.
- [ ] Paths outside the view are not written but are preserved on snapshot (never seen → never changed), consistent with ADR 0006.
- [ ] What is fetched from the relay is unchanged by the view (no per-path fetch, so no new access-pattern leak).
- [ ] Switching or clearing the view re-materializes correctly.

## Blocked by

- None — can start immediately.
