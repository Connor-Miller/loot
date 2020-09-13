# Amend and supersession: the `loot edit` model

## Status

accepted (spec — amend/divergence map #169, keystone #170; references ADR 0018,
0019, 0029, 0030, 0031; implementation is the build ticket #171)

## Context

The jj-ergonomics trio (ADR 0029/0030/0031) made a divergent change renderable
(the `!` marker) and collapsible (`loot abandon`), but nothing *produces* one
from ordinary work: there is no verb that amends a finalized change while
keeping its durable handle. `loot edit <change-id>` is that verb, and this ADR
locks its model.

The naive shape — reopen X as a sibling (parent = X's parent) and *locally*
mark X replaced — has a real defect, found by grounding in the S3 mechanics:
the `.loot/abandoned` set is **local-only and never travels**, while liveness
is computed by scanning every in-graph node per `change_id`. So a peer that
already holds X and then pulls the amended X′ would see two live versions of
one handle — a **solo amend rendering as divergence at every peer**, violating
the map's "divergence is cross-writer" premise — and that peer's converge
would treat X and X′ as an ordinary sibling fork and **content-merge them**,
resurrecting exactly what the amend removed. Since rewriting signed history is
forbidden (ADR 0018), "X′ supersedes X" must itself travel as signed data.

## Decision

### Amending mints a sibling that names its predecessor

`loot edit <change-id>` reopens the finalized change X as the working change:
**parent = X's parent** (clean parentage — X′ is a sibling, not a child),
**tree = X's tree**, `change_id` carried (the engine primitive is
`DagRepo::record_carrying`, surfaced as a named `Workspace` mutation).
Finalizing signs a **new** version X′ under the same `change_id` with a
**`predecessors`** entry naming X's version id. X is untouched: if it already
travelled, it survives everywhere, permanently (ADR 0018).

### `predecessors: Vec<Oid>`, folded into the version id — FORMAT_MAJOR 7

`ChangeNode` gains `predecessors`: the version ids this version supersedes,
**canonically sorted when hashed, empty = ordinary change**. Like `parents` —
and deliberately unlike the `change_id` label (ADR 0029) — predecessors are
authored content: they enter the version-id computation
(`author ‖ message ‖ parents ‖ tree ‖ predecessors`), so the finalize
signature (over `version_id ‖ change_id`) covers them and a relay or peer
cannot forge or strip a supersession claim. Unauthored / bridge-ingested
nodes carry an empty list, exactly as they carry no `change_id`.

It is a `Vec`, not a single optional id, because the multi-predecessor case
is already visible: an amend that names *both* live versions of a divergent
change would collapse the divergence in one signed, travelling move — the
cross-writer sibling of `loot abandon`'s local collapse. That flow is fog,
not v1, but the format is being bumped exactly once.

This is a breaking node/wire change: **FORMAT_MAJOR 6 → 7** (ADR 0019), the
same motion as the v5→v6 change-id bump — a v7 reader treats a v≤6 node as
predecessors-empty; the relay redeploys.

### Liveness: superseded is a third filter beside abandoned

A version is **superseded** iff any in-graph version of the same `change_id`
names it as a predecessor — **regardless of that supersessor's own abandoned
or superseded state** (the graph is append-only, so direct naming suffices;
no transitive closure). Then:

> **live** = in-graph ∧ not abandoned ∧ not superseded
> **divergent** = a `change_id` with ≥ 2 live versions

This amends ADR 0029's definition ("more than one non-abandoned version id")
by the superseded filter. `log`/`status` hide superseded versions exactly as
they hide abandoned ones. The "regardless" clause is deliberate: **abandon
means kill, never revert** — abandoning X′ does not resurrect X (locally
"reverting" a travelled supersession would silently disagree with every
peer). A change whose every version is abandoned or superseded is simply
gone from the live view.

### Converge drops superseded heads, then merges as today

Converge gains exactly one new behavior: **discard superseded heads before
collapsing forks**. A solo amend therefore lands at peers as a clean
supersession (no divergence, no accidental content-merge). Two writers
amending the same change concurrently produce two live same-cid versions,
which converge collapses under a content-merge node like any sibling fork —
both versions stay live beneath it (liveness scans all nodes, not heads), so
the `!` marker persists, `loot abandon` picks the loser, `loot undo` restores.
Known wart, pre-existing from S3's design: the merge already combined both
amendments' content, so abandoning a version clears the marker but does not
un-merge the tree. Whether divergence resolution should eventually be an
explicit multi-predecessor amend instead is map fog.

### `loot edit` refuses rather than guesses

Three guard clauses, no magic:

- **Dirty tree / unfinalized working change → refuse** ("finalize or describe
  your work first — edit replaces the working change"). `edit` deliberately
  does *not* ride ADR 0030's implicit capture: capture-first would strand the
  WIP as an unsigned stray head and swap it out of view (the `e6fde8e`
  dirty-tree sweep with extra steps), and carrying the WIP into the reopened
  change would silently mix in-flight work into old content. This creates a
  documented **exception class to ADR 0030**: *verbs that replace the working
  change refuse on dirt instead of capturing.*
- **Divergent `change_id` → refuse** ("X is divergent — `loot abandon` a
  version first, then edit"). Addressing is by `change_id` only; no
  version-id disambiguator in v1. Post-converge both divergent versions have
  children anyway (they parent the merge node), so this guard mostly exists
  to give the state its truthful message.
- **X has children → refuse.** v1 amends only a tip/childless change — in
  practice the change you just finalized, which is the actual use case.
  Amending mid-history would leave live descendants building on a superseded
  node's tree; the fix (rebasing descendants, jj-style) cascades new versions
  down the graph and is its own effort (fog).

### Composition and undo (ADR 0031)

`loot edit` is one **ordinary undoable, non-barrier operation** (it is local
until a later push; pushes are already barrier ops). Between `edit` and
finalize, the pending supersession rides in the **reservation state**
(`.loot/next-change` territory) and is **part of the recorded view**, so undo
restores the prior reservation without leaking a stray predecessors entry
into the next finalize. Once the amend finalizes, `predecessors` is signed
graph data — undo moves pointers, never unmakes graph (ADR 0031), so **undo
cannot un-supersede X**. Regret flows are forward-only, and the liveness rule
makes them coherent: `loot abandon X′` kills the change outright; "fix it
again" is `loot edit` on the handle, which resolves to X′ (the sole live
version) and chains `predecessors = [X′]`. `abandon` stays version-addressed;
`resolve` and `dock merge` are untouched.

## Considered alternatives

- **Sibling + local abandon (no travelling supersession).** Rejected: the
  abandoned set never syncs, so every solo amend renders as divergence at
  peers and converge content-merges X with X′ — see Context.
- **Supersession by ancestry (X′ a child of X).** No format bump —
  supersession travels as the parent edge. Rejected in favour of clean
  parentage: it makes a change's graph parent its own prior version, so the
  version's diff-against-parent is just the fix-up, and history rendering
  permanently interleaves versions with changes. Worth a format bump to avoid.
- **`Option<Oid>` single predecessor.** Rejected: collapsing a divergent pair
  by amend — already visible fog — would force a second FORMAT_MAJOR bump.
- **Converge holds same-cid forks side-by-side (jj-style).** Rejected: breaks
  the single-tip invariant (ADR 0006 — the working change forks from *the*
  tip); every downstream verb would need a "which head" answer and dock merge
  would stop guaranteeing convergence.
- **Converge auto-heals divergence** (emit a same-cid merge version naming
  both as predecessors). Rejected: the `!` marker would never appear for
  exactly the scenario the surface exists to show; silent content-combination
  becomes the norm.
- **Capture or carry uncaptured WIP on `edit`.** Rejected: the pre-land-gate
  scar (`e6fde8e`) — see the guards section.
- **Rebase descendants now.** Right end-state, wrong map: cascading
  re-versioning of descendants is bigger than the amend verb itself.

## Consequences

- `loot edit <change-id>` is fully specified for the build ticket (#171):
  reopen semantics, the `predecessors` field, the liveness change in
  divergence detection, the converge tweak, three guards, oplog integration.
- **FORMAT_MAJOR 6 → 7** and a relay redeploy ride along with the build —
  the second exercise of the ADR 0019 gate.
- ADR 0029's divergence definition is amended (superseded filter); ADR 0030
  gains the refuse-on-dirt exception class; ADR 0031's view grows the
  reservation's pending-predecessors component. None of those ADRs are
  rewritten (immutable records); this ADR is the amendment.
- A solo amend is invisible to peers (clean supersession); divergence arises
  **only** cross-writer — the map's destination shape.
- Deferred to map fog: multi-predecessor divergence resolution, descendant
  rebase, a stash/park flow if refuse-on-dirt proves annoying, and the
  git-bridge amend mapping (an amended change projects to a new commit).
