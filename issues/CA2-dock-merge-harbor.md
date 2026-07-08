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

- [x] `loot dock merge <name>` collapses another dock's tip into the current dock in-process, with no relay call.
- [x] Concurrent disjoint edits across two docks converge/merge cleanly; a genuine same-path divergence surfaces as a `Conflict` via the existing `conflicts`/`resolve` flow (no side dropped).
- [x] A `RelayedUnmerged` path (current identity lacks the key) is carried forward untouched, matching ADR 0001.
- [x] The harbor is an ordinary dock by a conventional name; merging into it and re-basing from it round-trips.
- [x] No new engine convergence *rule* — the slice reuses the ADR 0001 classifier.

## Implementation notes (as built on the tip/anchor dock model, CA1)

The tip/anchor dock model reconciles a dock's snapshot against *its own line*
(`snapshot(base = tip)` forks from `tree_at(tip)` with `parents = [tip]`), so a
merge cannot be left as a dangling second parent on a working change — a later
`status` would re-fork from `[tip]` and drop it. `dock merge` therefore produces
a real **merge change**:

- `converge::merge_trees(ours, theirs, oracle, now)` — extends the ADR 0001
  module (its home) to *assemble* the reconciled tree, not just label paths. It
  reuses the same `classify`/line-set primitives (refactored to expose which
  side wins a clean merge); it adds no new merge rule. Converged/cleanly-merged
  paths take the other (or superset) side; a genuine `Conflict` keeps **ours**
  and is recorded (`theirs` survives via the merge change's second parent, for
  `loot resolve`); a sealed `RelayedUnmerged` path is carried forward untouched.
- `DagRepo::merge_tips(ours, theirs, msg, now)` — builds an (unsigned) merge
  change parented on both finalized tips with that tree, recording conflicts.
  Engine stays verify-only (ADR 0018); the Workspace signs it.
- `Workspace::merge_dock(name)` — captures & finalizes any WIP so both merge
  parents are signed (bundle-safe), merges the source dock's finalized `tip`,
  signs the merge change and makes it this dock's tip, then `materialize`s the
  merged tree. Conflicts flow through the existing `conflicts`/`resolve` path.
- `loot dock merge <name>` — CLI verb with `--porcelain`/`--json` (matches the
  CA3 reconciliation verbs). `harbor` is a plain dock by convention; the engine
  treats it as ordinary.

**Verified:** `converge` unit tests (disjoint/superset-either-side/conflict/
relay/identical) and Workspace integration tests (disjoint converge, same-path
conflict keeps both sides, harbor round-trip). No toolchain in the authoring
sandbox — logic cross-checked with a Python model; `cargo test` handed to Connor.

## Blocked by

- CA1 — Docks: isolated working trees over one object store *(done: `02cb99c`)*
