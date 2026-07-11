# Stable change-ids: a durable handle beside the content id

## Status

accepted (spec — jj-ergonomics trio, wayfinder map #132; implementation is a
follow-on build map)

## Context

loot's change id is `compute_change_id(author ‖ message ‖ parents ‖ tree)` — a
blake3 over authored content (ADR 0018). It is a genuine strength: content-
addressed integrity, cross-author non-forgeability, DAG parent edges, dedup, and
sync addressing all key on it. But it has one ergonomic cost that the jj-
ergonomics milestone (#132) exists to fix: **it rewrites on every snapshot.**
Because the working tree *is* the change (ADR 0006), every edit that changes the
tree changes the id. So while you are editing a change, it has no durable name —
you cannot say "the change I'm working on" and have that reference survive the
next keystroke. jj solves this with two ids per commit: a **content hash**
(`commit id`, changes on rewrite) and a **change id** (random, stable across
rewrites) — the durable handle you rebase, describe, and undo *by*.

The keystone risk (why #132 called this out): unlike jj, loot **signs** its id
(ADR 0018) and **syncs** it (ADR 0011). A durable id cannot be a purely local,
uncoordinated convenience — it rides across the wire and must be tamper-evident.
This ADR is the data-model decision the rest of the trio (auto-snapshot ADR 0030,
oplog/undo ADR 0031) builds on.

## Decision

### Two ids per change

- **version id** — the existing `compute_change_id(author ‖ message ‖ parents ‖
  tree)`. **Role unchanged**: content-addressed integrity, dedup, **DAG parent
  edges**, sync addressing. It changes on every snapshot/rewrite. (This is what
  ADRs 0006/0018/0028 have been calling "the change id"; henceforth it is the
  *version id* — see the terminology note in Consequences.)
- **change id** — NEW. A **random 16-byte** id minted at change **creation**,
  stored on `ChangeNode`, **carried unchanged across every rewrite/amend** of
  that change, and travelling in the sync bundle. This is the durable handle jj
  gives you — the part of a working change a caller can hold onto.

The version id stays a pure function of authored content; the change id is a
*label*, never folded into any hash. They are orthogonal: content addressing and
a stable handle are different jobs, and conflating them is exactly what forces
the rewrite-churn today.

### Minting and preservation

The Workspace mints a fresh random `change_id` when a new change begins — at
`loot new` (which mints the *next* change's id eagerly, ADR 0030) and at the
first snapshot of a fresh working change. It **carries that same `change_id`
across every re-snapshot** of the working change: each re-snapshot computes a new
version id but keeps the change id. So a change has a durable handle *while you
edit it* — precisely what content-derived ids cannot provide.

### Signing binds both (amends ADR 0018)

The finalize signature at `loot new` covers **`version_id ‖ change_id`**, not the
version id alone. This makes "(this change id → this exact version, by this
author)" unforgeable: a relay or peer cannot relabel signed content under a
different change id, nor claim a different version is the same change id. The
version-id hash itself stays pure content+author (dedup/integrity untouched); the
signature — a proof *over* both ids — still sits **beside** the node, not folded
into the version id, so re-signing never forces extra descendant rewriting (the
ADR 0018 principle is preserved, only the signed message widens by 16 bytes).

### Parents and convergence are unchanged

DAG parents keep referencing **version ids** — a specific version *is* the
history edge, and the convergence classifier (ADR 0001) still keys on decrypted
trees. The change id is a handle, never a graph edge. Nothing in sync addressing,
dedup, or the merge engine changes shape; the change id rides as additive
metadata on the node.

### Divergence is the honest answer, and it is a first-class data state

Two writers independently rewriting the same change id produce two `ChangeNode`s
with **equal `change_id`, different `version_id`** — a **divergent change**. This
is data, not an error: loot already reasons about multi-head forks. But note it
is **not** the same as a diverged *graph*: a divergent change can exist under a
**single graph head** (one change id, two versions, both reachable), so it is not
detected by head-counting and not resolved by a tree merge (the two versions may
even have identical trees). The data model therefore defines a divergent change
as *"a change id mapped to more than one non-abandoned version id"*; how it is
displayed and which verb collapses it is ADR 0030's verb-surface decision, and
abandoning a version is an ADR 0031 operation.

### Sync (ADR 0011)

The `change_id` rides in the change body in bundles; peers agree on it because it
*travels with the change* — no coordination protocol, no id-allocation service.
A peer that already holds a change keeps its change id on re-receipt (idempotent).

### Display: letters for the handle, digits for the version

Render the **change id as reverse-hex letters** (nibbles → `k l m n o p q r s t
u v w x y z`, e.g. `qsouzmpr`) and the **version id as hex digits** (e.g.
`3f9a1c02`). The prototype (#137) validated that the two alphabets do the
disambiguation *for free* — a reader never has to ask which id they are looking
at, with no prefix or label. This is jj's convention and it transfers cleanly. Do
not render both as hex.

### Legacy changes and the format gate

Pre-format changes carry **`change_id = None`**, mirroring today's `author =
None` / `signature = None` for pre-ADR-0018 changes. **No retroactive backfill.**
A `FORMAT_MAJOR` bump **5 → 6** (ADR 0019) gates the new node field and the wider
signed message; a v6 reader accepts a v≤5 change as a legacy change with no
change id (its `log` row shows only the version id). Clean cutover, no migration
pass — consistent with how ADR 0018's authorship landed.

## Considered alternatives

- **Copy jj wholesale (random, local, uncoordinated, unsigned).** Rejected: loot
  signs and syncs its ids, so an unsigned local-only handle would be a relabelling
  vector across the wire. Binding the change id into the signature is the loot-
  shaped version of jj's idea.
- **Make the content hash itself stable** (hash only immutable fields, e.g. a
  birth nonce + author). Rejected: it either stops being content-addressed
  (breaking dedup/integrity) or stops being stable across the very rewrites we
  need it to survive. Two ids with two jobs is cleaner than one id doing both
  badly.
- **Derive the change id from the first version id.** Rejected: then it is not
  independent of content, and two peers creating "the same" change diverge
  immediately with no shared handle; a random id shared by travelling with the
  change is simpler and is what jj proved.
- **Forbid divergence (last-writer-wins on a change id).** Rejected: silent data
  loss, the failure mode that disqualified the CRDT (ADR 0002). A labelled
  divergent change is the honest surface.

## Consequences

- A working change finally has a **durable name while you edit it** — the
  precondition for auto-snapshot (ADR 0030) and undo-by-change (ADR 0031).
- **Terminology migration (documentation debt, called out deliberately):** what
  ADRs 0006, 0018, 0022, 0028 call "change id" is henceforth the **version id**;
  "change id" now means the durable handle. These ADRs are not rewritten (they are
  immutable records), but new prose and the code use the two-term vocabulary. The
  ferry's `Loot-Change-Id` trailer (ADR 0028) today carries the version id;
  whether it should instead carry the durable change id is a **deferred git-bridge
  decision** (map #132 fog), out of scope here.
- `ChangeNode` gains an additive `change_id: Option<[u8; 16]>` field; the signed
  message widens to `version_id ‖ change_id`; the bundle body carries the change
  id. All gated behind FORMAT_MAJOR 6.
- Divergent changes become a state `log`/`status` must render and a verb must
  collapse (ADR 0030) — new surface, but reusing loot's existing multi-version
  reasoning rather than a new failure mode.
- No change to dedup, DAG edges, the convergence classifier, or sync addressing —
  the version id carries all of those exactly as before.
