# RepoStore owns the `.loot/` layout

## Status

accepted

## Context

The set of files under a repo's `.loot/` directory, and their names, were spread
across three crates. The engine's `save`/`load` hardcoded `dir.join("identity")`,
`dir.join("graph")`, `dir.join("keyring")`, `escrow`, `manifest`, `purges`,
`conflicts`, plus the loose `objects/` dir (via `persist_codec`, ADR 0012). The
Workspace hardcoded `dot.join("working")`, `dot.join("tree-hash")`, and the
per-repo `config`, and inlined the small on-disk encodings for those process
files (the 32-byte working-change id; the snapshot tree-hash). loot-identity
wrote `id`, `id.pub`, and `peers` from its own `dot` argument (ADR 0014).

No module owned the question "what lives in `.loot/`, under what name." The
filenames were string literals repeated at each call site, so the layout could
only be learned by grepping three crates, and a rename risked missing a site. The
architecture review flagged this as a locality defect: knowledge that should sit
behind one interface was smeared across callers.

## Decision

Introduce `loot_core::store::RepoStore` (re-exported as `loot_core::RepoStore`) as
the single source of truth for the `.loot/` layout. It owns **where every
artifact lives** — path construction for every file, plus the small process-file
encodings — behind one small interface:

- Path accessors for every artifact: `identity`, `graph`, `keyring`, `escrow`,
  `manifest`, `purges`, `conflicts`, `working`, `tree_hash`, `config`,
  `objects_dir`, `id`, `id_pub`, `peers`. The module doc enumerates the whole
  layout in one place.
- Typed read/write for the process files whose encoding was previously inlined in
  the Workspace: `read_working`/`write_working` (the 32-byte id, or remove on
  `None`) and `read_tree_hash`/`write_tree_hash`/`clear_tree_hash`.
- The engine's `save`/`load` and the Workspace route their filenames through
  `RepoStore` instead of joining string literals.

`RepoStore` owns **layout, not policy**. Which identity holds the repo, when a
snapshot happens, what a change means — those stay with the engine and the
Workspace. `RepoStore` is only the filesystem adapter between logical artifacts
and paths, cheap to construct from a `.loot` path.

## Considered alternatives

**Leave the filenames inline.** The status quo. Zero code, but the layout has no
home and every new `.loot/` file adds another scattered literal. Rejected: this
is exactly the locality defect the review identified.

**A `RepoStore` that also performs all byte I/O for every artifact** (graph,
keyring, escrow, manifest, …), so the engine hands it typed values and never
touches `std::fs`. More thorough, but it would pull the engine's persistence
codecs and loot-identity's keypair I/O behind one type, cutting across the
content/process/credential ownership lines that ADRs 0005/0006/0014 drew. Rejected
for this slice as too large to land safely in one step; the path-and-process-file
seam captures most of the locality win without moving those responsibilities.

**Make loot-identity depend on loot-core to use `RepoStore` for `id`/`peers`.**
Would give the keypair files the same single-source treatment, but inverts a
clean dependency (identity is currently pure crypto with no loot-core dep).
Rejected for now: `RepoStore` *names* the `id`/`id.pub`/`peers` paths for
documentation, and loot-identity keeps writing them from its `dot` argument. A
future change can route them through `RepoStore` if the dependency is warranted.

## Consequences

- `loot_core::RepoStore` is the one place the `.loot/` layout is defined; adding a
  file means adding one accessor, and a rename happens in one spot.
- The engine `save`/`load` and the Workspace no longer hardcode filenames; the
  Workspace's inline working-id and tree-hash encodings move behind `RepoStore`.
- On-disk paths and encodings are unchanged, so existing repos load unmodified.
- `objects/` stays owned by `persist_codec` (ADR 0012) and the keypair/peers files
  by loot-identity (ADR 0014); `RepoStore` names their paths but does not perform
  their I/O. Migrating those fully behind `RepoStore` is a possible follow-up.
