# The harbor: an on-demand lock serializes landing to git-main

## Status

accepted (concurrency map #227, ticket #229; closes #195 — the false-`landed`
verdict — and graduates the map's "daemon vs on-demand lock" fog). Builds on
ADR 0022 (docks/harbor as a convention), ADR 0028 (the git bridge / ferry),
ADR 0033 (loot-first landing), and ADR 0034/0035 (sealed lanes, lifecycle).

## Context

ADR 0022 named the **harbor** as a *convention*: a well-known dock the agents
converge into, with landing "serialized at the harbor" left as prose. The lane
model (ADR 0034/0035) then made N agents real — each in a sealed directory over
one shared store — but its landing ritual still ran on that convention, and the
convention had no teeth. Two failures fell out:

1. **The false land (#195).** `loot-first land` finalizes the lane's change,
   ferries, reads the mirror's `main` tip, collapses the PR head onto it, and
   reports `landed:`. But when the lane's change never actually reaches `main`
   — a side-lane never merged into the harbor, or a bare ferry that no-op'd —
   `main` never moves, the FF push and the zero-diff collapse both "succeed" as
   no-ops, GitHub auto-closes the PR, and the operator gets a green verdict over
   a `main` that does not contain the change. Observed live on PR #194.
2. **The land race.** Every lane's ferry reads git-`main`, projects its change
   onto it, and pushes. Two lands running at once both read the same tip, both
   project a sibling, and both push — GitHub accepts the first (fast-forward)
   and rejects the second (non-fast-forward). Nothing is *lost* (loot converges
   the sides on the next ferry), but the workflow doc's promise that landing
   "serializes at the harbor" was unbacked: the serialization did not exist.

The map fixed the *nature* question by grilling (2026-07-12): the harbor is an
**on-demand lock**, not a background daemon. There is no process to run, no
queue to drain, no crash-recovery or Windows-service surface — the wrong weight
for a solo-dev, code-first repo. A lock the lander briefly holds gives the same
one-at-a-time guarantee for a few seconds' serialize.

The convergence engine underneath already does the hard part. Ferry's pass is
**ingest → reconcile → project**: it ingests any git-origin movement of `main`,
reconciles it into the ambient line through loot's converge classifier (ADR
0001) — so a second lander's change merges with the first's on its own ferry —
and only then projects. The race was never a *merge* problem; it was the
*absence of a critical section* around the git-`main`-touching steps. So the
harbor is small: a lock around those steps, plus the guard #195 always needed.

## Decision

### The harbor is an on-demand lock, held only across the git-main section

A single lock file, `\.loot/git-mirror/harbor.lock`, lives at the **shared store
root** (`RepoStore::harbor_lock`) — never the lane root — so every lane over one
store contends on the same file. A land takes it **after** the slow pre-land
`cargo test` and the git-quiet finalize (`loot new`), and holds it only across:

1. `loot ferry` — ingest any git-origin `main` movement, reconcile/converge, and
   project this signed change onto `main` in the local mirror;
2. the fast-forward push of `main` to GitHub;
3. the PR-head collapse.

It releases before the relay push and the lane-landed bookkeeping, which do not
touch git-`main`. A concurrent land from another lane blocks on the lock, then
ferries against the `main` this one just moved — so its converge is against the
*landed* tip, and its push is a clean fast-forward. The lock removes the race,
not the merge.

The lock is **RAII**: the guard releases on drop, so any early return in the
land flow — a conflict-bounce, a failed push, a guard refusal — frees the harbor
for the next agent with no manual unlock. A lock older than a staleness horizon
(default 10 min) is presumed a crashed land and broken on sight, so the harbor
can never wedge permanently; a live holder past the wait budget (default 2 min)
is refused with a clear message rather than false-succeeding.

The lock-holder *is* the harbor for the duration. "Agents never touch git-main"
(the map premise) holds in the sense that matters: they touch it only through
this one serialized door, one at a time, exactly as a daemon would have drained
its queue — without the daemon.

For the lock to serialize anything, every lane must contend on — and project
into — the **same** mirror. Ferry's configured `gitdir` is relative by default
(`.loot/git-mirror/mirror.git`), and resolving it against the process cwd made a
land from a lane directory spawn a stray *lane-local* mirror and move nothing on
the real git-main (caught by dogfooding this ADR). Ferry now resolves a relative
gitdir against the **shared store root** (`dot`'s parent), never cwd, so a land
from any lane reaches the one shared harbor mirror. For the primary, `dot`'s
parent is the cwd, so the resolved path is unchanged.

### The land verifies main actually moved (closes #195)

Under the lock, a land captures the mirror's `main` tip **before** ferry and
compares it **after**. If the tip is unchanged, the change was not integrated
into the harbor — there is nothing to collapse the PR onto — and the land
**refuses loudly** (`harbor: git-main did not move …`) instead of collapsing a
stale head into a green lie. The empty-mirror first land (no `before` tip) can
never read as unmoved, so it is unaffected. This is the guard #195 asked for,
now unconditional.

#195 phrased the guard as "`main` moved **and contains the projected commit**";
this land checks the weaker "`main` moved". The gap between them — `main` moves
because ferry *ingested* another lane's landed commit, yet this change is not
itself projected — cannot arise on the sanctioned path: the review-currency gate
(ADR 0033) refuses a land whose reviewed change is empty, and ferry's projection
loop projects *every* travel-worthy (signed, non-empty) change, so a real land
always projects its own change and `main` advances to contain it (directly, or
via the converge that threads it under a merge tip). "Moved" therefore implies
"contains" for every land that reaches this line; the stronger walk would add a
marks read and an ancestry check to close a hole the upstream gate already
closes.

> **Amendment (#349, 2026-07-19).** "Did not move within this invocation" turned
> out not to imply "nothing to land": a bare `loot ferry` run between describe
> and land projects the lane's signed line onto mirror `main` *then*, so the
> land's own ferry finds nothing to do while the push + PR collapse are still
> owed — and the refusal wedged (re-running land could never move `main` again;
> the live workaround was describing a dummy edit). The guard now consults an
> escape hatch before refusing: if mirror `main` is **strictly ahead** of the
> real `origin/main` (fresh — land's drift guard fetches it) *and* a commit
> reachable from mirror `main` carries this land's finalized tip as its
> `Loot-Change-Id` trailer, the projection already happened and the land
> proceeds to the owed publication. This is exactly the "contains the projected
> commit" walk the paragraph above declined, now paid for only on the not-moved
> path. Anything unprovable — no origin ref, mirror behind or diverged, tip
> absent from `main` (e.g. only a *sibling's* unpushed projection made the
> mirror ahead) — still refuses.

### A conflicted change bounces back to its agent, never blocking the queue

If ferry's reconcile surfaces a conflict — this change collides on some path
with work that landed on `main` while the lane worked — ferry holds the
conflicted paths at their last clean state (ADR 0028) and cannot cleanly
integrate the change. The land **bounces**: it pushes nothing, leaves the signed
change untouched in the store, releases the harbor, and returns an operator
message naming the conflicted paths and the reconcile path (`loot resolve …`
then re-run `loot-first land`). The bounce is the map's conflict-bounce protocol:
the signal is the land's error, the re-submit is a re-run after resolving, and a
bounce never holds the lock or blocks another lane's land.

### Where loot-first fits

Unchanged in shape — `review` / `land` still drive the PR — but `land` now lands
*into the harbor*: it takes the lock, ferries, checks the bounce and the
moved-main guard, publishes, and releases. The off-tracked-dock guard (#226)
stays as the pre-finalize refusal for the legacy named-dock ritual; the harbor
lock is the post-finalize serializer for the lane ritual. Both can hold at once.

## Considered alternatives

**A background drainer daemon.** Agents submit their signed tip to an in-store
queue and walk away; a long-running process projects to git-`main` one at a
time. Rejected as the wrong weight: a persistent process, its lifecycle,
crash-recovery, and a Windows-service surface, all to serialize an operation
that already takes seconds. Fire-and-forget submit buys nothing here — the
lander is a human-or-agent session that wants to *see* its land land. Kept on
the map's fog only as the escalation if true async submit is ever wanted.

**An explicit harbor merge step** (`loot dock main` → `loot dock merge <lane>`
→ `loot ferry`, #195's manual completion). Rejected as redundant: ferry's
ingest→reconcile already converges the lane's line with git-`main` on the next
pass, so the only thing missing was serialization and the moved-main check —
not a second merge verb. Reusing the existing pass keeps one convergence path.

**A store-graph lock (serialize all writes).** Rejected: the loose object store
is already lock-free for disjoint objects (ADR 0012) and the whole point of
lanes is that unsigned work never contends. Only the git-`main` projection needs
a critical section; the lock is scoped to exactly that.

## Consequences

### Positive

- N agents land into one linear git-`main` with no race and no manual git/loot
  surgery — the map's "claim → work → land → discard" default is now backed.
- #195 cannot recur: a land that does not move `main` refuses instead of lying.
- A conflicting land fails safe and reversible — nothing pushed, change intact,
  a named reconcile path — rather than pushing a partial land.
- No process, no daemon, no new long-lived state: one lock file under
  `git-mirror/`, local-only like the rest of the mirror spine.

### Negative / accepted costs

- The lock serializes lands, so a queue of agents finishing at once lands one
  behind another (seconds each). Accepted — that linearity *is* the guarantee.
- A crashed land leaves a lock file until the staleness horizon or a manual
  remove. Bounded by the horizon; the message tells the operator the file is
  removable when no land is running. The horizon is mtime-only (no process
  liveness probe — that would need platform-specific pid checks this
  dependency-light repo avoids), so a land that genuinely *hangs* past the
  horizon (10 min, versus a critical section of seconds) could be broken by a
  waiter and briefly overlap a second land. That overlap fails safe rather than
  corrupting: the second land's `main` fast-forward push is a **non-force** FF,
  which GitHub rejects the moment `main` has already moved, routing it to the
  diverged close-with-pointer path (ADR 0033) — no two-writer fork reaches
  `main`. The `pid=` written into the lock is human provenance for debugging a
  wedged lock, not a liveness oracle.
- The harbor lock covers *local* lanes over one store (the map's scope). A
  cross-machine push race remains the relay's domain (ADR 0011), not the
  harbor's.
