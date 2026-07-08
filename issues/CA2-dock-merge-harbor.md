# CA2 — Local `dock merge` + harbor convention

**Type:** AFK · **Priority:** near · **Source:** docs/adr/0022-concurrent-agent-model-docks.md; grill-with-docs 2026-07-06

## What to build

Bring two docks back together locally. `loot dock merge <name>` collapses one
dock's tip into the current dock **in-process**, reusing the ADR 0001
convergence *rule* (the shared per-path classifier) — with no relay hop and no
bundle file. Docks share one object store, so merging is a local fork collapse,
not a network operation, and it is not the bundle-oriented `apply` code path: it
adds a thin engine seam that assembles the merge change from the same rule (see
implementation notes). Per-path outcomes (Converged / Merged / Conflict /
RelayedUnmerged) and conflict handling (`loot conflicts` / `loot resolve`) are
exactly the existing machinery.

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
- [x] No new convergence *rule* — `classify` and `merge_trees` share one per-path decision (`converge::reconcile_path`); the slice adds only the tree-assembly plumbing (`merge_trees`/`merge_tips`) that builds the merge change, not a new merge rule.

## Implementation notes (as built on the tip/anchor dock model, CA1)

The tip/anchor dock model reconciles a dock's snapshot against *its own line*
(`snapshot(base = tip)` forks from `tree_at(tip)` with `parents = [tip]`), so a
merge cannot be left as a dangling second parent on a working change — a later
`status` would re-fork from `[tip]` and drop it. `dock merge` therefore produces
a real **merge change**:

- `converge::merge_trees(ours, theirs, oracle, now)` — extends the ADR 0001
  module (its home) to *assemble* the reconciled tree, not just label paths. Both
  it and `classify` route every path through one shared `reconcile_path` decision
  (which also exposes which side wins a clean merge), so the label and the
  tree-building can never drift — it adds no new merge rule. Converged/cleanly-
  merged paths take the other (or superset) side; a genuine `Conflict` keeps
  **ours** and is recorded (`theirs` survives via the merge change's second
  parent, for `loot resolve`); a sealed `RelayedUnmerged` path is carried forward
  untouched.
- `DagRepo::merge_tips(ours, theirs, msg, now)` — builds an (unsigned) merge
  change parented on both finalized tips with that tree, recording conflicts.
  Engine stays verify-only (ADR 0018); the Workspace signs it.
- `Workspace::merge_dock(name)` — short-circuits when the source tip is already
  our finalized tip (an up-to-date no-op that never seals pending WIP), else
  captures & finalizes any WIP so both merge parents are signed (bundle-safe),
  merges the source dock's finalized `tip`, signs the merge change and makes it
  this dock's tip, then `materialize`s the merged tree.
- `Workspace::resolve_conflict(path, bytes, vis)` — resolves onto the dock's tip:
  the resolution is built on the conflicted merge change (`resolve(base = tip)`),
  signed, and made the new dock tip, then materialized to disk — so a later
  `status` builds on the resolution rather than orphaning it. On the pre-dock home
  dock it keeps the original behavior (resolve against all heads; `loot new`).
- `loot dock merge <name>` — CLI verb with `--porcelain`/`--json` (matches the
  CA3 reconciliation verbs). `harbor` is a plain dock by convention; the engine
  treats it as ordinary.

**Verified:** `cargo test` green. `converge` unit tests (disjoint/superset-
either-side/conflict/relay/identical) and Workspace integration tests (disjoint
converge, same-path conflict keeps both sides, conflict resolution advances the
dock tip, harbor round-trip from a neutral base).

## Blocked by

- CA1 — Docks: isolated working trees over one object store *(done: `02cb99c`)*
