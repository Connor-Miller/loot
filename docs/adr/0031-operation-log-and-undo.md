# Operation log and undo

## Status

accepted (spec — jj-ergonomics trio, wayfinder map #132; references ADR 0011,
ADR 0017; implementation is a follow-on build map)

## Context

loot has no undo. jj's third ergonomic pillar is an **operation log**: every
command that changes the repo's *view* is recorded, and `jj undo` / `jj op
restore` step the view backward or to any past point — the safety net that makes
jj's aggressive auto-snapshot safe to trust. With implicit snapshot landing (ADR
0030), loot needs the same net: if every mutating command silently records, the
user must be able to walk it back. This ADR specifies loot's operation model and,
crucially, **where undo stops** — because loot, unlike jj, has permission and key
state that cannot be un-published.

## Decision

### An operation captures the view

An **operation** is a recorded transition capturing the resulting **view** — the
change-graph **heads**, each dock's **`working`/tip pointers**, and the
**`conflicts`** set — plus metadata (timestamp, command, dock, description) and a
parent-op reference. The view is **repo-wide** (one view over all docks, like jj's
single view with per-workspace working copies). One operation is logged for **every
view-changing command**: auto-snapshot, `new`, `describe`, `merge` / `dock merge`,
`resolve`, `abandon`, `apply`, `pull`, `converge`, `ferry`, dock create/switch —
jj-parity, one command, one op. Read-only verbs (ADR 0030) record nothing.

### Undo is a pointer reset over an append-only graph

- `loot undo` steps back one operation; `loot op restore <op>` jumps to any
  operation's view; `loot op log` lists them.
- Restoring is a **new compensating operation** whose view equals the target's —
  **nothing is deleted** from the change graph or object store. The oplog is
  append-only, so **`op log` grows on undo** (an undo is itself an op); this is
  what lets "undo the undo" (redo) land on something, rather than popping a stack.
- A **signed, finalized change survives undo**: it may already have travelled, so
  undo merely moves the head pointer off it (it stops being current); ADR 0018's
  authored history is untouched. Undo changes *which changes are current*, never
  *what changes exist*.

### Barriers undo will not cross

loot has state that is not a view and cannot be retracted. Undo treats these as
**barriers**:

- The **`keyring` / `manifest` / `escrow` / `purges`** are permission and key
  state — **never touched by undo**. Undo only ever moves view pointers.
- Operations that mutate **restricted keys** (`grant`, `maroon`, `pull-grants`) or
  **`push`** to a relay are recorded as **non-undoable barrier operations**: undo
  **refuses to step across them**, because they are one-way (Manifest-audited, and
  a granted key or a pushed change may already be at a peer). The refusal names the
  barrier op and points at the real remedy — reverse a permission with
  `maroon`/re-grant, not undo; a published change is reversed by recording a new
  change, not by un-publishing. (Regular `pull`/`apply` file only **public** keys —
  non-secret, harmless to retain — so they stay ordinary undoable ops; only
  restricted-key operations are barriers.)

### Local-only, never synced (ADR 0011)

The operation log is **local, per-machine history** — never bundled, never synced.
Undo resets *your* view; a pushed change stays on the relay. This makes loot's
existing "push discloses, and disclosure is one-way" philosophy explicit for undo:
the oplog is a local convenience layer over the shared, append-only, permissioned
history, not part of it.

### Storage (ADR 0017)

A new **`.loot/ops`** artifact owned by `RepoStore` (ADR 0017): an append-only log
of operation records (parent-op ref; the view = heads + per-dock `working`/tip +
`conflicts`; metadata). Repo-wide, not per-dock, and **local-only** like
`keyring`/`escrow`/the git mark map — it gets a path accessor and lives beside the
graph but never enters a bundle. Concurrency starts simple (append; last-writer-
wins); jj's lock-free **divergent-operations** model is a recorded future
refinement (map #132 fog), not v1.

## Considered alternatives

- **Undo that also reverses grants/pushes.** Rejected: you cannot un-disclose. A
  granted key or pushed ciphertext may already be at a peer; pretending undo
  retracts it would be a security lie. Barriers make the one-way boundary explicit.
- **Sync the oplog (shared history of operations).** Rejected: the shared history
  is already the append-only permissioned DAG (ADR 0011); a synced oplog would
  duplicate it, leak local workflow, and reintroduce the un-publish fantasy. Local-
  only is the honest scope.
- **Undo as destructive rollback (delete the change).** Rejected: it would break
  ADR 0018 (a signed change that travelled cannot be unmade) and risks silent data
  loss. Undo moves pointers; the graph only grows.
- **Per-dock oplogs.** Rejected for v1: a repo-wide view matches jj and keeps undo
  reasoning simple; per-dock granularity is parked as fog until a concrete need
  appears.

## Consequences

- Auto-snapshot (ADR 0030) becomes safe to trust: every implicit snapshot is one
  undoable operation, so "it recorded something I didn't mean" is always walk-back-
  able.
- loot gains `loot undo`, `loot op log`, `loot op restore <op>`, backed by
  `.loot/ops` in `RepoStore`. The append-on-undo semantics give redo for free.
- The barrier boundary is a **security-load-bearing** part of the design: it is the
  line between reversible local view state and irreversible disclosure, and it is
  stated in one place here.
- The oplog is local-only and rebuildable-from-nothing (losing it loses undo
  history, not repo data), matching the git mark map's stance (ADR 0028).
- Divergent-operations (concurrent lock-free oplog) and per-dock undo granularity
  are explicitly deferred to the follow-on build.
