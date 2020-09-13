# Projecting amended changes to the git mirror

## Status

accepted (spec + build — amend/divergence map #169, ticket #199; extends
ADR 0028 (git interop bridge) and ADR 0032 (amend/supersession); references
ADR 0018, 0022, 0029)

## Context

ADR 0032 gave loot an amend: `loot edit X` reopens a finalized change and
finalizing signs a superseding sibling X′ under the same `change_id`, with
`predecessors = [X]`. In loot's DAG X′ is a **sibling** of X — both are
children of X's parent P — so the two versions fan out from P, and liveness
(not the graph shape) is what makes X′ replace X.

The git mirror (ADR 0028) is downstream: `loot ferry` projects each
travel-worthy loot change to a git commit and `refs/heads/main` fast-forwards
to the designated dock's tip. That projection walks loot's **parent** edges —
`git_parents(change) = mark(loot_parents(change))` — so a naive pass would
project X′ as a second child of P's commit, a git **fork** off main. main
could not fast-forward to it (it does not descend from X, which is already on
main), and the loot-first land (a clean FF push, ADR 0028) would break for
every amend of a landed change. Supersession is loot-native; git has no notion
of it, only ancestry. So the bridge must **thread** an amend onto the git
history rather than mirror its loot parentage literally.

A second-order effect sits in the review lane (map #148). A `review/<dock>`
branch is reaped once its change is no longer a live working change. The reap
tested "does a **signed** version of this `change_id` exist?" — but after
`loot edit`, the superseded signed X still exists under the handle forever
(ADR 0018), so that test stays true and the reopened lane is reaped every
pass, even though the dock has reopened the change to re-review it.

## Decision

### Predecessor-conditional git threading

When projecting a superseding version X′ (`predecessors = [X]`), the bridge
chooses X′'s **git parent** by X's standing in git, not by loot's DAG:

- **X is landed** — X has a mark *and* is an ancestor of the current git
  `main` (equivalently, `main` descends from X, or is X). Thread X′ onto
  **X's commit**: `P → X → X′`, linear. `main` stays a fast-forward, and the
  amend reads as its own fix-up commit on top of the version it replaces —
  the git-shaped rendering of "X′ supersedes X."
- **otherwise** — X is unmarked or not on `main` (the ordinary local
  `finalize → edit → finalize` churn, where X was signed but never ferried).
  Thread X′ onto **P's commit** (loot's sibling parent), exactly as today.
  `main` fast-forwards `P → X′`; X, if it was ever projected, stays reachable
  on `refs/loot/heads/<X>` but never reaches `main`.

Loot's DAG is **untouched** — X′ remains P's child with `predecessors = [X]`.
Only the *git projection* threads after X. The two representations agree on
content and disagree only on parent shape, which is the bridge's job to
reconcile (loot leads, git is downstream).

**The delta base tracks the git parent.** A projected commit's tree is the git
parent's tree plus the change's *public delta* (ADR 0028: sealed paths never
published). That delta must be computed against whichever line X′ threads onto
— against **X** when threading onto X, against **P** otherwise — so the
resulting tree is exactly X′'s public tree either way (`X_tree + (X′ − X) =
X′`; `P_tree + (X′ − P) = X′`). Threading onto X while diffing against P would
mis-render any path X changed that X′ reset to P's value.

**The projection-ordering wrinkle resolves itself.** X′ names X in
*predecessors*, not *parents*, so `ids_topo()` (a parent-edge sort) does not
guarantee X is projected before X′. It need not: the landed branch requires X
to be an ancestor of the *current* `main`, which can only be true if X landed
in a **prior** pass and therefore already has a mark. A freshly-projected X in
the same pass is not yet on `main`, so the condition is false and X′ threads
onto P. No on-demand predecessor projection is needed; the "ancestor of git
main" test is what makes the ordering safe.

### Reconcile treats a superseded git target as dead

The git `main` still points at X's commit until the amend lands. On the landing
pass the bridge's reconcile step compares its **loot anchor** (X′) against the
change the git tip maps to (X) and, seeing neither an ancestor of the other
(they are siblings), would otherwise **merge** them — resurrecting the very
content the amend removed and producing a two-parent commit instead of a
fast-forward. So reconcile gains one guard: when our line **supersedes** the
git target (`repo.supersedes(anchor, target)` — the anchor or an ancestor names
the target in `predecessors`), the target is dead downstream; keep our line and
let projection thread the amend onto the stale tip. This is the reconcile twin
of dock-merge's existing `supersedes` short-circuit and converge's
superseded-head drop (ADR 0032) — the same "a superseded version is never a
merge target" rule, applied where git meets loot.

### `Loot-Predecessors` trailer

A projected commit carries `Loot-Predecessors: <hex> <hex> …` — the superseded
version ids, space-separated — alongside `Loot-Author` / `Loot-Signature`.
This is **faithfulness only**, not a mechanism: projection reads supersession
from loot's graph, and the mark-map rebuild keys on `Loot-Change-Id` (which
carries the *version* id, ADR 0028 — the trailer name is not renamed). The
predecessors trailer lets a mirrored commit round-trip losslessly and lets a
reader see the supersession without loot. Ordinary changes (empty
predecessors) carry no such trailer.

### Amend-aware review-lane reap

A `review/<dock>` lane is **live** iff the dock's *current working change* still
carries the lane's `change_id` and is unfinalized — the reap now reads the
dock's live working pointer, not "does a signed version exist." After a normal
finalize the working change moves on to a fresh handle, so the lane reaps
(landed). After `loot edit` the working change is the reopened X′ under the
same handle, so the lane **survives** and the next `loot-first review`
appends a new round onto it (same `change_id`, new `version_id` — "changes
since your last review," map #148).

### Land review-currency guard

`loot edit` reopens a *finalized* change, so an approved review can be
amended and then landed without the reviewer seeing the amendment. The land
orchestrator (`crates/loot-first`, not loot core — loot stays git-agnostic)
therefore checks, before it finalizes: the dock's current working-change
version (read in-process via `Workspace::live_working_row`, no snapshot —
#218 retired the `loot status --porcelain` scrape) against the version the
review lane last projected (`ferry::WipState`). If they differ, `land`
refuses — "run `loot-first review` and re-approve before landing."
An **empty** working change (already finalized, nothing pending) skips the
check; the guard exists to catch a *reopened* lane, which is always non-empty.

## Consequences

- Amending a **landed** change lands as a linear fast-forward on `main`; the
  loot-first clean-FF push (ADR 0028) holds for amends. No force-push, no merge
  commit. main gets one more clean commit per amend.
- The local `finalize → edit → finalize` churn collapses to the sibling on
  `main` (`P → X′`) with the intermediate X parked on a head ref — git sees
  only what landed, as it does for any un-ferried loot version.
- A reopened review lane resumes as a new round instead of vanishing; the PR
  shows the amendment, and the reviewer re-approves before it can land.
- X′'s git commit shares X's deterministic date when threaded onto X (both sit
  at the same loot generation — siblings of P; ADR 0028 already tolerates
  sibling-equal dates). Ancestry, not date, orders them.
- Scope held to **tip-only, single-predecessor** amends (ADR 0032 v1). A
  multi-predecessor collapse (one X′ naming both live versions of a divergent
  handle) and descendant rebase remain map #169 fog; the `Vec<Oid>` field and
  the space-separated trailer already carry more than one id when they graduate.

## Amendment (#281): review refs carry the position, not the dock

This ADR named review branches `review/<dock>`. Sealed lanes (ADR 0034/0035)
broke that quietly: every lane's home dock is `main`, so N concurrent lanes
shared **one** `review/main` — a mutable ref with N writers, exactly what ADR
0034 forbids. Hit live twice on 2026-07-15: a second lane's `ferry --with-wip`
force-pushed its content over the first lane's in-flight PR head (#281, the
visible half), and either position's reap pass could misjudge the other's
entry — liveness reads the *positional* working pointer, which a foreign
position cannot see — and retire a live ref (the same root as the #280 data
loss).

The fix keys the whole review lane by its **owner position**:

- The projected ref is `review/<lane-id>` from a lane, `review/<dock>` on the
  primary. One position, one ref, one PR — no shared mutable ref.
- The `wip` and `pr-map` ledgers gain an owner column (`-` = primary;
  pre-#281 short rows parse as primary-owned), and `ferry`'s review line
  carries `owner=`. Liveness (this section above) and review-currency (the
  land guard) are judged per `(change, dock, owner)`.
- Reap is owner-scoped: only the owner judges liveness. A foreign pass reaps
  exactly the entries whose owner lane is **gone from the registry** — an
  abandoned lane's review ref dies with it instead of leaking.
- `land` refuses to run from a position other than the PR's owner: it
  finalizes the *current* position's working change, and the dock guard can't
  catch the mismatch when every lane's dock is `main`.
- Lane ids and dock names share the review-ref namespace, so lane spawn
  suffixes past existing dock names (and `main`), and dock binding refuses a
  live lane's id.

**Mixed-version window.** A pre-#281 binary parses only the short rows, so a
pass from a not-yet-rebuilt position silently drops the new 6-field `wip` /
4-field `pr-map` rows when it rewrites those files. Nothing is corrupted —
the owning position's next `review` re-mints its row (a fresh round 1) and
`land` refuses on the missing pr-map row rather than misfiring — but rebuild
every live position promptly after this lands. The other legacy edge: a
5-field row that was actually written *by a lane* reads as primary-owned, so
the primary's next pass reaps it exactly as the pre-#281 code would have —
migration makes nothing worse, but an in-flight lane review opened with the
old binary should be re-run with the new one.
