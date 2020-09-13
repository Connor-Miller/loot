# Review is a pure projection: reconcile happens at land, never at review

## Status

accepted (wave-proof-lanes map #354, ticket #355 — the map's keystone
grilling; resolves the stale-anchor lane stranding lived end-to-end in the
trust-hardening wave, map #339). Builds on ADR 0018 (signed changes), ADR
0028 (the git bridge), ADR 0033 (review lanes), ADR 0034 (sealed lanes over
a shared store), ADR 0036 (the harbor as serialized integrator). Amends the
review half of ADR 0028's ferry pass; supersedes the #292/#302 stale-anchor
refusal (`REFUSE_REVIEW_STALE_ANCHOR`).

## Context

A lane is born at the finalized anchor and reviews its unsigned WIP through
`ferry --with-wip` / `loot-first review`. Until now that review pass was a
*full* ferry: ingest new git-`main` commits, **reconcile the ambient dock over
them**, then project. The reconcile is the trap: folding a lane onto a moved
`main` is a merge, a merge parent must be signed (ADR 0018), and signing the
WIP leaves nothing to review (#275). #302 made the pass refuse instead
(`REFUSE_REVIEW_STALE_ANCHOR`) — safe, but it strands the lane: one land
anywhere (a sibling's, or an out-of-wave land) stales every open lane, and
the only remedies were respawn-plus-hand-copy or a deliberate seal. In the
#339 wave this forced full serialization of five agents with manual
orchestrator surgery between every land.

The grounding observation (this ticket): **the review branch never needed the
lane caught up.** Round-1 review parents are the working change's own graph
parents mapped through the mark map — the projection already bases on the
lane's anchor, an *ancestor* of `main`, and GitHub renders a PR against
`main` from its merge-base. The reconcile step the review pass ran was
maintenance of the `git main == projection(dock tip)` invariant — a concern
of projecting *main*, which review does not do. It also *advanced* mirror
`main` with any unprojected signed history as a side effect, which is the
trigger half of the #349 pre-projection trap.

Meanwhile the land side already tolerates a stale anchor: ADR 0036's queued
land ferries against whatever `main` the previous land moved, converges, and
bounces on genuine conflicts. Review was the only stranded verb.

## Decision

**Review mode is a pure projection.** `ferry --with-wip` (and therefore
`loot-first review`):

1. mints the provisional commit(s) for the current working change from the
   lane's own anchor marks — exactly as today;
2. updates and pushes **only** its `review/<position>` ref (single-ref,
   inline URL, ADR 0028);
3. performs **no dock reconcile** and **no mirror-`main` advance** — it does
   not ingest-and-fold, it does not project other travel-worthy changes, and
   it cannot finalize anything. A review pass is read-only with respect to
   the dock tip and the mirror's `main`.

**Reconcile lives only where signing is legitimate:** plain `loot ferry`,
`loot adopt`, and `loot-first land` (under the harbor lock, with the bounce
for genuine conflicts, ADR 0036). A lane behind `main` reviews normally; it
reconciles exactly once, at land.

**Main hygiene is a hard criterion:** a land from a behind-anchor lane must
still project **exactly one commit per change** onto `main`. No
`ferry: reconcile git main` merge noise, no resolution-commit trails, on the
landed history. The build pins this with an integration test that lands from
a deliberately stale lane (clean converge) and asserts the single-commit
shape; a genuinely conflicted land resolves in-lane and then still lands as
one commit per change.

## Consequences

- `REFUSE_REVIEW_STALE_ANCHOR` becomes dead code — the fold it guards
  against is unrepresentable in review mode — and is deleted with it the
  respawn-and-copy recovery folklore in docs/agents/concurrent.md. The
  neighbouring "working parent has no mirrored commit — run a plain
  `loot ferry` first" error remains: it is the missing-mark case, not the
  stale-anchor case.
- A PR opened from a stale anchor shows GitHub's merge-base diff and may wear
  a cosmetic "conflicts with base" badge. Display-only: loot is the merger
  (ADR 0028); the harbor bounce is where a real conflict stops the land.
- The #349 trap loses its review-mode trigger (review can no longer
  pre-project signed history onto mirror `main`). A *plain* ferry before a
  land can still arm it, so #349 stays open on its own merits.
- The primary's `loot-first review` stops doubling as a catch-up. Catching a
  position up is `adopt`/plain-`ferry`'s job, stated plainly, and the drift
  guard on `status`/`review` keeps warning when the *mirror* trails
  `origin/main` — that guard is about the harbor's truth, not the lane's
  anchor, and is untouched by this ADR.
- N-agent waves stop serializing at review time: every lane can open and
  refresh its PR regardless of what landed meanwhile; lands queue on the
  harbor lock as they already do. `lane renew` (#357) is demoted from
  necessity to convenience — a lane re-anchors only when it *wants* the new
  code under its feet, never because review demands it.

## Rejected

- **Unsigned-WIP rebase** (re-anchor by parent rewrite): heavier surgery on
  ADR 0018/0031's model for a problem the projection mechanics already solve;
  the review fix costs a subtraction, the rebase costs a new primitive.
  Revisit only if a lane needs to *execute* against post-anchor code as a
  matter of course.
- **Skip the reconcile only when it would fold** (keep the clean-fast-forward
  arm in review mode): leaves review with two personalities and keeps the
  mirror-`main` advance — and with it the #349 trigger — alive inside a verb
  that only needs to write one review ref.
