# Evidence: a wave of lanes lands without orchestrator surgery

The concrete, checkable proof for the wave-proof-lanes map (wayfinder
[#354](https://github.com/Connor-Miller/loot/issues/354)). The claim:

> **N agents each hold one sealed lane over one shared store; they open reviews
> and land in any order — interleaved with each other and with out-of-wave
> lands — and the _mechanism_, not a human orchestrator, absorbs every
> collision.** No respawn-and-copy, no hand-merge, no folklore recovery steps.

Like the rest of `docs/evidence/`, the proof is a **re-runnable script** whose
captured output is committed beside it: script
[`scripts/wave-proof-lanes-demo.ps1`](scripts/wave-proof-lanes-demo.ps1),
output [`runs/wave-proof-lanes-demo.txt`](runs/wave-proof-lanes-demo.txt)
(run 2026-07-21, **all checks passed**). It runs a three-lane wave in seven
acts.

This was **proof + landing**, not construction: the keystone (ADR 0039
pure-projection review + carry-at-land, #355/#362), the #349 pre-projection
fix, and the #418 seal-WIP guard were already built. Running the wave live is
what closes the map's destination.

## What the script drives

One identity, one shared store, one base change, a bound bare git mirror. Three
lanes (`t1`, `t2`, `t3`) fork **from the base before anything moves**, so each is
a genuine single-writer tip (ADR 0034) behind the wave. `t1` edits the shared
file (it will collide); `t2` and `t3` add disjoint files.

- [x] **Three reviews open concurrently, each a pure projection** (ACT 1, run
      lines 58–69). `loot ferry --with-wip` from each lane mints its provisional
      commit from that lane's **own** anchor and pushes only its `review/<lane>`
      ref — three distinct refs, each `op=opened`. Opening reviews does **not**
      advance `main` (a review is not a land). ADR 0039, #362/#281.
- [x] **An interleaved out-of-wave land moves `main` mid-wave** (ACT 2, lines
      75–78). The primary finalizes + ferries an edit to the shared file — a land
      from outside the three lanes. Every open review's anchor is now stale.
- [x] **Reviews never go stale** (ACT 3, lines 84–93). `t1` refreshes its review
      after the out-of-wave land moved `main` — the review's base — out from
      under it (a "stale-anchor" PR in loot's terms, ADR 0039): the projection is
      **byte-identical** (`op=up-to-date`, the same review sha), and `t1`'s
      described working change is untouched. The old `REFUSE_REVIEW_STALE_ANCHOR` → respawn-and-copy
      failure family (#275/#289/#292/#302) is structurally gone — a pure
      projection cannot go stale.
- [x] **The seal-WIP guard refuses to seal described WIP** (ACT 4, lines
      99–116). On `t2`'s live described change, a **bare** `loot ferry` _and_ a
      no-arg `loot adopt` each refuse with the typed `RepoError::SealWip`.
      `--seal-wip` seals on purpose and prints the follow-up-round recovery
      recipe — the tool owns the round, not folklore (#418, #356's "Prevent +
      hint").
- [x] **A colliding lane bounces and reconciles in-lane** (ACT 5, lines
      122–138). `t1` catches up onto the moved `main`; its same-path collision on
      the shared file surfaces as a conflict — a **bounce**, nothing dropped.
      `loot resolve` reconciles it in the lane, and the resolution inherits the
      change's subject as `<subject> (conflict resolution: shared.txt)` (#337) —
      it folds in rather than trailing.
- [x] **A disjoint lane catches up clean** (ACT 6, lines 144–157). `t3` catches
      up over the same moved `main` with **no conflict at all** — the wave
      charges a merge cost only to the lanes that actually overlap.

## The `loot-first` land layer (cited, run live)

The harbor **land-bounce** refusal and the **#349** "already-projected → proceed"
path live inside `loot-first land`, which shells out to `gh` and a git `origin`;
they cannot run in a hermetic script. They are proven instead by `loot-first`'s
own tests, which drive the land policy end-to-end through the `FakeForge` seam
with no network. ACT 7 (lines 171–245) runs `cargo test -p loot-first --lib`
live — **69 passed, 0 failed** — including:

- `harbor_guard_refuses_a_no_op_land` / `harbor_guard_passes_when_main_advances`
  — the #195 harbor guard the bounce rides on.
- `already_projected_line_ahead_of_origin_reads_as_landable` — the #349 fix: a
  land whose signed line an earlier ferry already projected proceeds to the owed
  push + PR collapse instead of wedging.
- `gate_proceeds_on_approved` / `gate_refuses_*` — the approval + dock-targeting
  land gate (#152/#153).
- `a_land_finishing_after_sibling_reviews_keeps_their_rows` — the #336 pr-map
  ledger under a concurrent wave.

## Honesty

One machine, one identity, one shared store. "Concurrent" here is the wave's
**data model** — N sealed lanes over that store, each a single-writer of its own
tip (ADR 0034) — exercised by driving the lanes in sequence; the interleaved
out-of-wave land in ACT 2 is what makes every later catch-up a real
"behind the moved tip" reconcile, which is the whole point. The one-commit
carry-at-land (`DagRepo::carry_line`, superseding versions) is a
`loot-first land` behavior; the no-arg catch-up shown live here folds via a
merge ([concurrent.md](../agents/concurrent.md)), which is why ACTs 5/6 cross
the #418 guard with `--seal-wip` — in a real wave `loot-first land` is the
authorized finalizer and crosses it for you.

## Done

- [x] The three-lane wave passes in a committed, re-runnable script
      ([run](runs/wave-proof-lanes-demo.txt), 2026-07-21) — the map's destination
      holds: reviews open, an out-of-wave land interleaves, one review refreshes
      without going stale, the seal-WIP guard fires with its recovery round, the
      colliding lane bounces and reconciles in-lane, the disjoint lane catches up
      free.
- [x] The "Running a wave" framing is in
      [`docs/agents/concurrent.md`](../agents/concurrent.md) (#358's
      **Nothing new** decision — the harbor lock _is_ the wave protocol — proven
      here rather than asserted).
- [x] Map [#354](https://github.com/Connor-Miller/loot/issues/354) destination
      satisfied; terminal #359 closed under this doc.
