# Sealed lanes over a shared store

## Status

accepted (architecture keystone — concurrency map #227, ticket #228;
supersedes the ADR 0022 *physical* model of docks-as-switchable-positions;
extends ADR 0022's convergence model unchanged; references ADR 0028, 0031,
0033)

## Context

ADR 0022 shipped docks as the fork *primitive* and proved cross-agent
convergence end-to-end, but its isolation is shallow: docks switch **one
shared working tree in place**, and the state that says *where a workspace
is* stays repo-wide. Concurrent agents in one repo flip that state under each
other — one `loot dock` parks another session's WIP and re-materializes the
tree it is standing on.

The full repo-wide mutable surface (from `store.rs`, the layout's one home):

- the **ambient-dock pointer** (`.loot/dock`) and the home dock's process
  files at `.loot/` root (`working`, `tree-hash`, `next-change`, `tip`);
- the engine's **`heads` and `working-change` files** — written whole on
  every save, so a parked dock's *unsigned* WIP lives in the shared heads;
- the **`ops` undo log** (ADR 0031) — an op view captures the heads file,
  the shared working-change blob, and *every* dock's pointer files, so
  `loot undo` in one session can rewind another's view;
- `abandoned` (view filter) and `conflicts` (unresolved merges) — positional
  state stored globally;
- the whole **`git-mirror/`** surface (ADR 0028): `config` (`dock=main`),
  `mirror.git`, `marks`, `state`, and the `pr-map`/`wip` review-lane ledgers
  (ADR 0033) — all single files mutated by ferry/review/land.

The map's grilling (2026-07-12) locked **model C**: share only the immutable
store; every mutable thing is per-lane. This ADR pins what that means
physically — which files move where, what the seam is, and how a lane takes
another lane's landed work.

## Decision

### The rule: no mutable file has more than one writer

**This amends model C's phrasing.** The grilled premise reads "share only
the immutable store; every mutable thing is per-lane" — taken literally that
forbids the remote `config`, the lane registry, and a harbor-owned mirror.
The rule this ADR records (and the one #230 audits against) is the sharpened
form: *shared things may be mutable if exactly one writer owns them*. Three
ownership classes partition `.loot/`:

| class | contents | writers |
|---|---|---|
| **shared, append-only** | `objects/`, `graph`, `keyring`, `escrow`, `manifest`, `purges`, `attestations`, `identity`, `id`/`id.pub`, `peers`; `config` (see below) | any lane appends *finalized* changes; audited by #230 |
| **lane-owned** | `working`, `working-change`, `tree-hash`, `next-change`, `tip`, `heads` (the lane's view frontier), `ops`, `abandoned`, `conflicts` | exactly the one lane whose `.loot/` holds them |
| **harbor-owned** | the entire `git-mirror/` dir: `config`, `mirror.git`, `marks`, `state`, `identity`, `allowed-signers`, `pr-map`, `wip` | the harbor, the sole serialized integrator (ADR 0022's harbor, promoted from convention to owner) |

`config` (named remotes) is a repo-level fact, so it stays shared — but
single-writer holds: **lanes read it; writes refuse from a lane** ("run from
the primary"). Remote changes are rare operator actions.

> **Amendment (#336, 2026-07-18).** "The harbor serializes" undersold one
> file: the `pr-map` ledger is written by `loot-first review` and `land` from
> *any* position, and review never enters the harbor's locked section — a land
> holding a copy read before sibling reviews wrote their rows rewrote the file
> and erased them (a classic lost-update, hit live). The class stands, but its
> serialization for this file is now explicit: every ledger write holds
> `git-mirror/pr-map.lock`, re-reads fresh, applies only its own row
> add/remove, and replaces the file atomically. One writer *at a time*,
> enforced by a lock rather than by layout — the exception that keeps the
> rule honest.

### A lane is a directory; position is place, not state

A **lane** is a working directory whose `.loot` is a *directory* (evolving
ADR 0022's `--at` pointer *file*) containing a `store` pointer at the owning
repo's shared `.loot/` **plus every lane-owned file above**. `Workspace::open`
resolves everything from the cwd's `.loot`; there is **no ambient pointer and
no environment binding** (`$LOOT_DOCK` was considered and rejected: an env
var is process-global and single-repo — it cannot express one agent's
position in several repos at once).

The **primary directory is lane #0**: its lane-owned files stay at `.loot/`
root exactly where they are today, so a repo that never spawns a lane is
**byte-for-byte unchanged on disk** (the same backcompat move ADR 0022 made
for the home dock). Cost, accepted: the root `.loot/` is two things at once —
shared store *and* lane #0's private state — so shared-surface tooling (#230)
must exclude the lane-owned file set **by name**, not by directory.

**Placement:** lane directories default to a sibling of the repo root
(`<repo>-lanes/<id>/`), never nested inside the primary's working tree (the
primary's own snapshot walks must not see foreign trees). The path is
overridable at spawn — which is what composes **multi-repo agent
workspaces**: one directory of co-located lanes, each `.loot` pointing at its
own repo's store, sealed against every other agent in all of them.

### Dock becomes the *name* of a lane; in-place switching dies

Lanes are **ephemeral-unless-named** (map premise). The noun call the map's
fog demanded: **a dock is a *named* lane.** `loot dock <name>` stops meaning
"switch this tree in place" and becomes "name/persist this lane" — naming is
promotable mid-flight. The ambient-dock pointer, in-place dock switching, and
WIP-parking are **retired**; a second position is a second lane. Existing
named docks (`.loot/docks/<name>/` — `tip`, `tree-hash`, and any `working`/
`next-change`) migrate by being re-spawned as lanes; the harbor and the
git-main-tracked main position are docks in the new sense.

Naming note: "lane" here is the *isolation* unit — distinct from the
**review lane** of ADR 0033 (a `pr-map` entry: an open review round on a
change). The two coexist: a lane opens a review lane when it ferries for
review.

### The seal: only signed changes cross, at finalize

A lane's unsigned working change — the WIP node, `working`,
`working-change`, `tree-hash` — lives **only** in the lane's `.loot`. It
never enters the shared graph or any shared heads file. At finalize
(describe/sign) the signed change and its objects are appended to the shared
store+graph — that is where adopt's "objects already present" cheapness comes
from — but **visibility stays lane-scoped**: each lane's `heads` file is its
own view frontier, so a finalized-but-unlanded change from lane A is simply
not in lane B's frontier. Isolation is *by view*, not by absence.

This makes three locked premises structural instead of bookkept:

- **reap = delete the directory** — unsigned WIP vanishes with the lane,
  zero graph surgery (the gc-sweep semantics the map wants);
- **no live cross-agent visibility** — B physically cannot see A's WIP;
- the shared graph's writers only ever **append signed, immutable changes**,
  which shrinks #230's audit surface to concurrent appends.

Accepted consequences: a lane crash loses unsigned WIP with no shared-side
copy — already the premise's stance for abandoned lanes. And a new
user-facing constraint minted here on purpose: **lanes require a keyed
repo** — a keyless repo cannot finalize (sign), so nothing could ever cross
its seal; keyless stays a single-position legacy mode.

### `loot adopt`: catch-up converge onto the harbor lineage

*(No-arg arm shipped #250, 2026-07-14: a `loot-cli` composition — `fold_line_in`,
shared with `dock merge`, folds `mirror_main_change()` into the dock's line; a
clean fast-forward when strictly behind, a signed merge when the local line
diverged. No new engine machinery, allowed from a lane.)*

**`loot adopt`** extends the lane's view frontier with the harbor's landed
heads and runs the existing in-process `apply`/converge onto the lane's
working change — today's `dock merge` pointed the other way, no new engine
machinery, no network (single-*writer* does not forbid multi-*reader*: lanes
may read the harbor's heads).

- **Target is the harbor lineage as a whole** — "catch me up to everything
  landed." Per-change adoption is **refused on purpose**: the harbor
  serializes landings into a line; partial adoption would reintroduce the
  divergence the model just paid to remove.
- Adopt is defined against the **harbor's lineage only** — never "whatever is
  in the shared graph" — otherwise a lane could build on an unreviewed signed
  change and quietly violate the after-it-lands premise.
- **Spawn** is the degenerate case: a new lane is born already-adopted at the
  harbor's tip. **Bounce-back reconcile** (map premise) is compositionally
  free: adopt → resolve → re-land.

#### Amendment (#244, 2026-07-14): `loot adopt <version>` — the take-wholesale arm

The no-arg `loot adopt` above **merges** the harbor lineage in. A dock can also
end up on a **divergent local line that must be discarded** in favour of a
landed change (the state #243 found: the primary's `main` dock on a stale fork
while `origin/main` had moved on). Merging that fork is exactly wrong — it
*resurrects files deleted upstream*. So `loot adopt` gains an optional
`<version>` argument for the **discard-and-settle** case:

| arm | target | mechanism | keeps local line? |
|---|---|---|---|
| `loot adopt` (no arg) | harbor lineage **as a whole** | **merge** (converge onto WIP) | yes — folds it in |
| `loot adopt <version>` | one **landed** change | **take-wholesale** (abandon competing heads) | **no** — replaces it |

This does **not** contradict the "per-change adoption is refused on purpose"
rule above. That refusal guards a lane *merging a partial slice and continuing
to build on its own line* — reintroducing divergence. `adopt <version>` does the
opposite: it **discards** the local line entirely, so no divergence can survive
it. The invariant that makes both safe is the same one — **the target must be on
the harbor/main lineage** (reachable from the mirror's `main` projection), never
"any signed change in the shared graph."

Mechanically it is a `loot-cli` composition of shipped parts (no new engine
machinery): abandon every competing head to a fixpoint (`abandon_head`, dropping
a transient ferry merge resurfaces its parents, so the whole divergent line is
walked into the abandoned set), settle the dock's tip on the target, and
materialize its tree via the existing `resurface` checkout — one undoable op
(ADR 0031). WIP is refused by default (mirrors `loot edit`); **`--discard-wip`**
drops a dirty tree and is the sanctioned override of the #219 tree-write
chokepoint (adopt is the one verb whose *intent* is to replace the tree). Full
spec: [`docs/specs/loot-adopt-target.md`](../specs/loot-adopt-target.md).

### The registry: `.loot/lanes/<id>/`, per-entry single-writer

The shared store carries one entry directory per live lane —
`.loot/lanes/<lane-id>/` — holding the lane's path, its dock-name if
promoted, and its heartbeat. Writer discipline: **each entry is written only
by its own lane** (spawn creates, heartbeat touches, naming updates) — the
per-entry pattern that already keeps `.loot/docks/<name>/` race-free. The
**reaper** is the only *deleter*, and only of entries whose heartbeat says
dead. Heartbeat cadence and reap threshold are the lifecycle ticket's
(named map fog).

### Harbor ownership is pinned here; its mechanism is not

The git-mirror surface is **integration state, not lane state** — per-lane
mirrors would pay a full history re-export per ephemeral spawn and fragment
`marks`/`pr-map`/`wip` into shards the land path must re-aggregate anyway.
It stays physically where it is (the primary directory is the harbor's
position — zero file moves) and gains one owner. `loot-first review` and
`land` from a lane become **in-process requests through the harbor seam**:
the lane hands its tip/WIP over the shared store; the harbor serializes
projection and push. Review projection briefly serializes (seconds) — a wait
on a mechanism, not on another agent's unfinished work. Whether the harbor is
a daemon or an on-demand lock is #229's decision.

## Consequences

- *Claim → work → land → discard* becomes the frictionless default: spawn a
  lane (born at harbor tip), work sealed, land through the harbor, delete the
  directory. N agents in one repo stop being able to flip state under each
  other, because the state that could be flipped no longer has two writers.
- The `Workspace` open seam moves from "discover `.loot/` + read ambient
  pointer" to "cwd's `.loot` *is* the position": `RepoStore` grows a lane
  root alongside the store root (equal for the primary), and the engine's
  `save`/`load` splits heads/working-change writes lane-side. The
  `dock: Option<&str>` parameter threading dissolves — a store instance *is*
  lane-scoped.
- `loot undo` becomes safe under concurrency by construction: per-lane `ops`
  can only capture per-lane state. A reaped lane's undo history dies with it
  — nothing outside the lane ever referenced it.
- Known seam, deferred to a build ticket: **abandonment ride-along at land**
  — a lane's `abandoned` set is lane-view state, but the harbor's set governs
  git projection, so a land request must carry the lander's abandonments or
  the mirror could project a version the lander thought dead.
- Deferred by name: harbor daemon-vs-lock (#229); spawn/observe verbs,
  heartbeat cadence, reap threshold (lane-lifecycle ticket); per-lane
  identity (#87, out of scope — all lanes author as the one identity);
  cross-lane live visibility (a non-goal, not a deferral).
- Lane siblings escape the repo root: backup/IDE tooling scoped to the repo
  will not see lane trees, and deleting a repo can orphan its `<repo>-lanes/`
  sibling. Accepted as the price of keeping foreign trees out of the
  primary's snapshot walks.

## Amendment (#253, 2026-07-17): `.loot/docks/` retired — merge resolves a lane

The "dock becomes the *name* of a lane" decision above landed in two layers.
Layer 1 (#3b, `9308e40`) retired in-place dock *switching* from the CLI but left
mergeable positions living as `.loot/docks/<name>/` subtrees, created by `loot
dock <name> --at <dir>` and read by `loot dock merge`. This layer finishes the
retirement: **`.loot/docks/` is gone entirely**, and the merge source resolves
from the **lane registry** (`.loot/lanes/`) plus the lane's **own tip pointer**.

What moved:

- **`loot dock merge <name>` → `loot lane merge <id-or-name>`.** The verb folds a
  named lane's finalized line into the primary. It resolves the source with
  `find_lane` (id or promoted name) and reads the tip from `<lane>/.loot/tip`
  (the same read-only peek `loot lanes` does) instead of `.loot/docks/<name>/tip`.
- **The seam is real merge-source machinery, not a rename.** A lane's `heads`
  are lane-owned, so its finalized tip is a *sibling outside the primary's
  lineage-filtered view* (the seal). `merge_lane` therefore first pulls the
  tip's lineage in from the shared graph via `ingest_shared_lineage` (the #265
  catch-up primitive) so the ancestry/supersession checks in `fold_line_in` —
  shared with the no-arg `loot adopt` — can reason about it. `fold_line_in`
  itself is unchanged.
- **`loot dock <name> --at`, `loot dock rm`, and `loot docks` are removed.** A
  second position is a `loot lane new`; a lane is reaped with `loot lane rm` and
  the registry is surfaced by `loot lanes`. In-place switching (`dock_goto`) and
  the `--at` worktree binder (`bind_dock_dir`) are gone; a dangling `--at`
  `.loot` pointer file now opens with an error naming the remedy.
- **The store's named-dock API is deleted:** `list_docks`, `ensure_dock_dir`,
  `remove_dock_dir`, `dock_exists`, `docks_dir`, `write_dock`, and the `DOCKS`
  layout constant. `dock_dir`'s `Some(name)` arm is gone (the selector is always
  home); the `dock: Option<&str>` *parameter* survives — its full dissolution
  (a consequence above) stays deferred, as this ticket is a source-resolution
  change, not a mechanical migration. The oplog captures only the home position
  (a lane's undo history is lane-local), keeping its on-disk format.
- **Follow-on retirements the removal forced:** `liveness()` no longer collects
  sibling docks' parked WIP (lanes seal their WIP — nothing cross-position is
  visible), so the `!`-marker view feeds an empty parked set; ferry drops the
  `refs/loot/docks/<name>` projection (a lane's unlanded tip is never in the
  mirror) and refuses a non-`main` `--dock` designation (git-main tracks the
  primary — there is no other position's tip to designate).

Amend-topology note: `loot edit` re-anchors to a *sibling* amend only when the
position `tracks_tip()` (a lane, or a primary that `adopt`/`lane merge` seeded).
Pre-#253 the old `--at`/switched dock made `docks_active()` true and gave the
amend-projection path (ADR 0033) that re-anchor for free; a plain primary that
never pinned a tip still produces a *child* amend, unchanged from before.
