# Workspace with JJ-style, visibility-aware auto-snapshot

## Status

accepted

## Context

The CLI (ADR 0005) gave each command its own copy of the same setup: discover
`.loot/`, read the ambient identity, get the clock, and `load -> mutate -> save`.
The architecture review flagged the "process-bound repo with ambient
identity/clock/home" as a real concept with no module. Separately, the source
material (Theo's video) is emphatic that git's commit/branch ceremony is wasted
motion and that JJ's model — the working copy *is* the current change, snapshot
automatically — is the ergonomic win worth copying.

A naive auto-snapshot is unsafe under loot's thesis. The working tree is an
**identity-filtered** view: a non-keyholder's tree does not contain the sealed
files they cannot decrypt. "Snapshot whatever is in the tree" would read those
absences as deletions and silently destroy content the user was supposed to
relay — the exact silent-data-loss failure that disqualified the CRDT (ADR 0002).

## Decision

Introduce a **Workspace** module in `loot-cli` that owns the ambient context
(home discovery, identity, clock, persistence), and adopt JJ-style auto-snapshot
as loot's history model. The CLI vocabulary becomes:

- `status` — snapshot the working tree, show the working change
- `describe -m <msg>` — name the working change
- `new` — finalize the current change and start a fresh one on top
- `checkout`, `log`, `bundle`, `apply` — unchanged

### The snapshot invariant (visibility-aware reconcile)

Snapshotting reconciles the working tree against the **full** tree of the last
change, computed at time `now`:

- `visible = { path in base : the current identity can open it now }`
- for `path in visible`: present in tree → update; absent → **delete** (a
  keyholder legitimately removing content they own)
- for `path not in visible`: **carry forward unchanged** (we never could see it,
  so we cannot have changed or deleted it)
- a working-tree write (new file, or a rename target) landing on a base path
  that is **not visible** to us is **refused** with a clear error — never a
  silent overwrite of sealed content. This leaks only existence-of-something,
  which the change tree already implies; never contents.

Edge cases this rule handles without special-casing: a keyholder deleting a
restricted file (it is in `visible`); embargo windows (a path moves between the
buckets as `now` crosses `reveal_at`, so "visible" must be evaluated at `now`,
not cached); loot's all-or-nothing per-path visibility (no partial-read, so no
sub-file ambiguity).

### Seam

The reconcile is **policy** and lives in the engine: `DagRepo::snapshot(entries,
identity, now)` owns the visible-slice diff and collision refusal (it already
holds the base tree, the keys, and the merger/relay reasoning). The Workspace
only reads the working tree into memory and hands the entries over. This keeps
visibility reasoning out of the CLI — the duplication prior reviews removed.

## Considered alternatives

- **Keep git-style ceremony, just dedupe the wiring.** Rejected as the headline:
  it captures the save-safety win but not the ergonomic leap the source material
  actually asks for. (The Workspace still delivers the dedupe as a side effect.)
- **Explicit `loot rm` instead of inferring deletions.** Safe, but diverges from
  the JJ "tree is truth" feel and still needs the visible-slice rule for sealed
  paths, so it adds a command without removing the hard part.
- **Workspace computes the reconcile itself.** Rejected: re-implements per-path
  visibility in the CLI — the exact policy duplication ADR 0001/0003 fought.
- **Shadow or hide invisible collisions.** Rejected: shadowing defers a
  guaranteed conflict and warts the tree model; hiding *is* the silent-loss
  failure mode.

## Consequences

- loot's unit of history is now an always-present *working change*, snapshotted
  on demand, not a manually staged commit. `commit` as a verb goes away.
- The clock becomes an injected value the Workspace supplies, so embargo timing
  (the project's last spike-honest gap, ADR 0003) finally gets a test surface.
- `DagRepo::snapshot` is unit-testable in core with a fake working tree and fake
  identities, including the non-keyholder-preserves-sealed-content case.
- The engine gains a base-tree-aware snapshot entry point; `checkout` is
  unchanged. Sync semantics (ADR 0001) are untouched — a snapshot produces a
  normal change.
