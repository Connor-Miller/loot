# 05 — Divergence, source-of-truth & reconciliation

Type: grilling
Status: resolved
Blocked by: 01, 02

## Question

Bidirectional means both sides can gain commits between syncs. Define how the
mirror stays consistent:

- **Divergence detection.** How a sync detects that loot and git each advanced
  since the last common point (uses the mark map / last-synced pointers).
- **Source of truth on conflict.** Does loot win, git win, or a three-way merge?
  Can loot's converge classifier (ADR 0001) be reused for the content merge, or is
  git's merge authoritative for the git side?
- **What a conflict looks like to the user**, and where it's resolved (in loot, in
  git, or surfaced in both).
- **Visibility during reconciliation** — merging must not surface sealed content
  into git or clobber a sealed path (per 01's boundary).

## Notes

Blocked by 01 (the symmetry/visibility model) and 02 (the change↔commit mapping),
which together define what "the same state" even means. This is the heart of the
"divergence pain" the dual-run milestone flagged.

## Answer

**loot is the reconciliation authority; a git edit is just another fork.** When
both sides advanced, ingest git-native commits as loot changes (per 02/03), then
run loot's existing converge classifier (ADR 0001, decrypt-then-merge) to merge
them against loot's heads — structurally identical to reconciling two concurrent
loot forks. Re-project the converged result to git. There is **one** merge engine
(loot's, visibility-aware); git never performs the merge. Thesis-aligned and
reuses shipped machinery.

**Divergence detection: mark-map last-synced pointers.** Each successful sync
records the loot heads and git refs that were in agreement. Divergence = both sides
have advanced past those recorded points. Incremental (O(delta)), reusing the mark
map from ticket 02 (which already carries change-id↔sha + origin).

**Conflicts surface and resolve in loot; git holds at last clean state.** A
converge `Conflict` is surfaced via the shipped `loot conflicts` / `loot resolve` +
CA3 porcelain. A conflicted path is **not** projected to git until resolved in loot
(git stays at its last clean state for that path); non-conflicting paths sync
normally. Conflicts live in exactly one place — loot — with no git-marker injection
that could round-trip into content.

**Visibility invariant (inherited from 01, must hold through reconciliation):**
ingest seals per `.lootattributes` (never writes a sealed path as public);
projection surfaces only readable content (sealed omitted); and the converge
classifier's **relay role** carries content the syncing identity can't read as
ciphertext without merging it — so reconciliation can never surface sealed content
into git nor clobber a sealed path.

**Feeds:** the sync-mechanism / mark-map ticket (last-synced pointers) and the
final spec.

