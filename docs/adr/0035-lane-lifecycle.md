# Lane lifecycle: ephemeral-unless-named, land-marks / gc-reaps

## Status

accepted (concurrency map #227, ticket #231; builds on ADR 0034 — the sealed-
lane seam — and graduates the map's gc-sweep fog: heartbeat cadence and reap
threshold are set here)

## Context

ADR 0034 pinned the physical model — a lane is a directory whose `.loot/`
carries every lane-owned mutable file over the shared store — and deferred the
lifecycle by name: spawn, naming, heartbeat cadence, reap threshold. This ADR
records the lifecycle decisions the build made. The harbor does not exist yet
(#229), so where a rule needs "the harbor's tip" the build uses its stand-in:
the primary's finalized anchor.

## Decision

### The seam is a two-root `RepoStore`

`RepoStore` carries a **store root** (append-only / single-writer artifacts)
and a **lane root** (this position's private state), equal on the primary —
lane #0's disk shape is unchanged, byte for byte. Every lane-owned file from
ADR 0034's ownership table (`working`, `working-change`, `tree-hash`,
`next-change`, `tip`, `heads`, `ops`, `abandoned`, `conflicts`, the dock
pointer and `docks/`) routes to the lane root. Because the engine's
`save`/`load` and the op log already go through `RepoStore`, the seal and
per-lane undo fall out mechanically: a lane's unsigned WIP and its op views
physically cannot touch shared state.

### Lifecycle verbs

- **`loot lane new [--name <n>] [--at <dir>]`** — spawn: primary-only and
  **keyed-repo-only** (only signed changes cross the seal; a keyless lane
  could never land anything). The lane is born already-adopted at the
  primary's finalized anchor with its tree materialized; uncaptured primary
  edits are captured first and do *not* ride along. Default placement is the
  `<repo>-lanes/<handle>` sibling (ADR 0034); a `--at` directory inside the
  primary's working tree is refused (the primary's snapshot walks must not
  see foreign trees). The auto-handle — which becomes the registry id — is
  dir-derived when the directory name is a valid name, else generated,
  suffixed until free against both ids and promoted names (the two share the
  `lane rm <id-or-name>` lookup space). The spec's *ticket*-derived handle is
  #232's wayfinder claim-to-lane wiring.
- **`loot lane name <n>`** — mid-flight promotion, run *inside* the lane (its
  registry entry is per-entry single-writer, and the entry's writer is its own
  lane). A named lane is a dock in the ADR 0034 sense and persists until an
  explicit removal. Names share the lookup space with ids, so both must be
  free.
- **`loot lane list`** — every entry with id, name, path, heartbeat age, and
  landed/stale markers. (`--porcelain` is #232's.)
- **`loot lane rm <id-or-name>`** — explicit reap, primary-only: delete the
  lane directory and its entry. Unsigned WIP dies with the directory; signed
  changes are already in the shared graph and survive, the same rationale as
  `loot dock rm`.
- **`loot lane gc [--stale-hours <h>]`** — the sweep, primary-only. Unnamed
  lanes reap when **landed** (immediately) or **stale**; named lanes never
  sweep.

### Heartbeat cadence and reap threshold (the map fog, graduated)

- **Cadence: every workspace open from the lane** — every loot verb run there
  refreshes `.loot/lanes/<id>/heartbeat`. No daemon, no timer, no config; a
  lane an agent is working in is by construction fresh. The touch is
  best-effort and self-healing (it recreates a swept entry, path included).
- **Reap threshold: 24 hours** (`--stale-hours` overrides). Agent sessions
  run hours; an unnamed lane silent for a day with nothing landed is
  abandoned, and dropping its unsigned WIP is the map's stated stance. The
  threshold only bounds how long abandoned WIP lingers — landed lanes don't
  wait, named lanes don't reap.

### Land marks, gc reaps

`loot-first land`, on success from a lane, writes the entry's `landed` marker
instead of deleting the directory — the landing process's cwd *is* the lane
(undeletable on Windows, unwise anywhere). The next `loot lane gc` reaps it.
Splitting mark from reap also keeps the reaper single: the registry's only
deleter stays the sweep/rm path.

### Reaping is guarded and **not undoable**

The reaper deletes a directory only if its `.loot/lane-id` matches the entry,
so a corrupted or hand-edited `path` file can never point it at an innocent
tree. The registry is deliberately outside the op log's view: an undo in one
lane must never rewind another lane's entry, and reap-by-directory-deletion
has no pointer-reset representation anyway. `loot lane rm` says so.

### Single-owner refusals from a lane

`loot gc` (a lane's view is a subgraph — pruning by it could drop objects
other lanes reference), `loot remote add/remove` (shared `config`, one
writer), the dock family (`dock`, `dock merge`, `dock rm` — position verbs of
the primary), and lane spawn/rm/gc all refuse from inside a lane, naming the
primary.

## Consequences

- *Claim → work → land → discard* now has its mechanics: spawn, sealed work,
  land-marks, gc-reaps. What still blocks the frictionless default is the
  harbor (#229): `loot adopt`, land-from-lane serialization (pr-map/mirror
  writes from concurrent lanes), and bounce-back reconcile all live there.
  Meanwhile `loot-first land` from a lane is **allowed but unserialized** —
  the harbor-owned mirror/ledgers have no lock yet, so one land at a time is
  the operator's responsibility until #229.
- Legacy in-place dock switching **survives in the primary for now** — ADR
  0034 retires it, but the retirement rides the harbor ticket: today's landing
  ritual (loot-first review/land from the git-main-tracked dock) still runs on
  it. When #229 lands, `loot dock <name>` becomes the naming verb; until then
  `loot lane name` is the promotion path.
- The spawn DevX — one-command agent spawn, `loot lanes --porcelain`,
  wayfinder claim-to-lane — is #232, layered on these verbs.
- A lane crash or gc of an abandoned lane loses unsigned WIP with no
  shared-side copy (ADR 0034's accepted stance, now enforced by the sweep).
