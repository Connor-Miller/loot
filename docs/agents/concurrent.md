# Concurrent agents: one lane each, land through the harbor

How several agents (or a human plus agents) work this repo **at the same time**
without flipping state under each other. Read this before running a session that
will overlap another one. It sits beside [workflow.md](workflow.md) (how a single
change reaches `main`) and [identity.md](identity.md) (who agents are), and it is
the operational face of ADRs 0034 (sealed lanes), 0035 (lane lifecycle) and 0036
(the harbor).

> **Status (2026-07-14): LIVE, with one known build gap.** Lanes, the lane
> registry, `loot lanes`, `loot lane new --ticket`, the harbor lock, and both
> `loot adopt` arms — `<version>` take-wholesale and the no-arg catch-up merge —
> are shipped (#231/#232/#229/#244/#250). Still pending: retiring legacy in-place
> dock *switching* from the primary (it survives only because today's landing
> ritual runs on the `main` dock). Where a gap bites, this doc says so and gives
> the workaround.

## The one rule everything else follows

**No mutable file has more than one writer** (ADR 0034). Concurrency safety here
is not a lock you remember to take — it is a layout. Three ownership classes
partition `.loot/`:

- **shared, append-only** — the object store, change graph, keyring, attestations,
  peers, `config`. Any lane may *append* a finalized (signed) change; nobody
  rewrites.
- **lane-owned** — `working`, `working-change`, `tree-hash`, `next-change`, `tip`,
  the lane's `heads` view frontier, `ops`, `abandoned`, `conflicts`. Exactly one
  lane — the one whose `.loot` holds them — writes these.
- **harbor-owned** — the entire `git-mirror/` surface (`mirror.git`, `marks`,
  `state`, `pr-map`, `wip`, the `dock=` config). Only the harbor writes it, and it
  serializes.

If you ever find yourself wanting two sessions to edit one of these at once, that
is the bug — spawn a second **lane** instead.

## One lane per agent

A **lane** is a sealed working directory over the shared store (ADR 0034). It is
the isolation unit; a session gets its own tree and tip without a second clone.

```
loot lane new --ticket <n> --porcelain    # from the primary; prints: L  id  name  path ...
cd <path from the row>                     # work here until the ticket lands
```

- **One in-flight change per lane.** A lane hosts one change → PR at a time.
  Parallel work = more lanes, not more changes in one lane.
- **Spawn from the primary, into a keyed repo.** Spawn is primary-only (a
  single-writer verb — it is refused from inside a lane) and needs a keyed repo
  (a keyless repo cannot sign, so nothing could cross the seal, ADR 0034).
- **Lanes are ephemeral unless named.** Reap = delete the directory; unsigned WIP
  vanishes with it (ADR 0034). `loot lane name <n>` promotes a lane to a
  persistent **dock** (a dock *is* a named lane now); until then it is fair game
  for `loot lane gc`.
- **The claim board is `loot lanes`.** `loot lanes --porcelain` reports every live
  lane — id, name, path, tip, in-flight PR, dirty/clean, heartbeat age — and it is
  **read-only**: observing never touches another lane's heartbeat (the entry's one
  writer is its own lane, #232). The ticket-derived handle (`t<n>`) makes it double
  as a who-has-what board.

The full claim ritual (assign the issue, then spawn) is in
[issue-tracker.md](issue-tracker.md).

## What is parallel-safe vs. what must serialize

**Parallel-safe — run freely from any lane, no coordination:**

- Editing files, auto-snapshot, `describe`, `new` (finalize/sign). Finalize is
  **git-quiet** — no mirror I/O — so two lanes signing at once never contend
  (workflow.md).
- `loot ferry --with-wip` / `loot-first review` to open a PR. Review projection
  briefly serializes on the harbor (seconds — a wait on a mechanism, not on
  another agent's unfinished work, ADR 0034).
- Reading anything, including another lane's landed heads (single-*writer* does
  not forbid multi-*reader*).

**Serializes at the harbor — safe to fire concurrently, but they queue:**

- `loot-first land`. Each land takes the brief shared-store harbor lock
  (`.loot/git-mirror/harbor.lock`, ADR 0036) across the git-`main` critical
  section — projection, the fast-forward push, the PR-head collapse — then
  releases. A second lane's land blocks on the lock, then ferries against the
  `main` this one moved, so its converge is against the *landed* tip and its push
  is a clean fast-forward. Two lanes finishing at once land one behind the other;
  `main` stays linear. **No manual one-at-a-time discipline is needed** — the lock
  is the discipline.

**Must run from the primary only — refused from inside a lane (single-writer):**

- `loot lane new` / `rm` / `gc`, the `loot dock` family, `loot gc`,
  `loot remote add`/`rm`, and `config` writes. These touch shared or harbor-owned
  state. Do them from the primary directory (lane #0), and check
  `loot lanes --porcelain` first so you are not reaping or gc-ing under a live
  agent.

## The harbor land flow

Landing is the single serialized funnel. From the lane:

1. Finalize — `loot new` signs the change (git-quiet).
2. `loot-first land --pr <n>` — detects approval, runs the pre-land gate
   (`cargo test`), takes the harbor lock, projects the one signed commit onto
   `main`, collapses the PR head, releases. Full mechanics: workflow.md.
3. If the change conflicts with what landed while the lane worked, the land
   **bounces** — nothing is pushed, the signed change is safe. Reconcile
   (`loot resolve …`, or `loot adopt` to take the landed line) and re-run `land`.
   The queue is never blocked by a bounce.
4. After the land, mark-and-reap the lane: the land marks the entry; run
   `loot lane gc` **from the primary** afterwards to reap it. Don't `rm -rf` the
   directory by hand — gc verifies the `lane-id` first (reaping is not undoable,
   ADR 0035).

### Catch the primary up after a lane lands

A clean lane-land moves git `main` and the harbor, but it does **not**
auto-forward the *primary's* `main` dock — that omission is one of the two ways
drift crept in (#243). After a lane lands, settle the primary onto the landed
line:

```
# from the primary
loot adopt <landed-version>     # take-wholesale onto the landed change (#244)
```

`loot adopt <version>` abandons the primary's competing heads down to the shared
anchor and materializes the landed tree — no content merge (the merge is what
resurrects files deleted upstream). Use it when the primary sits on a **divergent**
head that must be discarded. When the primary is merely *behind* landed main, the
no-arg **`loot adopt`** catches it up by folding the harbor lineage in — a clean
fast-forward when there is no local work, a merge when there is (#250). Reach for
`adopt <version>` to replace a divergent line, plain `adopt` to catch up.

`loot ferry` also catches the primary up as a side effect: a pass ingests any
git-origin commits and converges the dock against them, so a primary only *behind*
the landed line settles through a plain `loot ferry` too. The three, in short:
**`adopt <version>`** to discard a divergent line, **`adopt`** (no arg) to fold
the harbor lineage in, and **`ferry`** when there are also git-origin commits to
ingest.

Both catch-up paths hold even when the landed change was never in the primary's
view (a position's load is lineage-filtered, ADR 0022): the catch-up ingests the
harbor lineage from the shared graph before it reasons, so a lane-landed change
the primary never adopted is a clean fast-forward — not a duplicate merge line
(#265). A checkout already `git reset` onto landed main is recognized as landed
content, not re-captured as local work. And `loot gc` roots every change in the
shared graph file plus every live lane's WIP, so a landed-but-unadopted change
can never be pruned (#263's root cause, prevented).

## Recovery playbook

### A break-glass git commit landed on `main` → `loot ferry`

git `main` is a projection of loot (workflow.md). A direct commit to git `main`
is **break-glass**, not routine — but when it happens (a browser typo fix, an
external PR merged on GitHub, or a deliberate raw-git land), loot must ingest it
or it drifts behind. **After any break-glass git land, run `loot ferry`.** The
ferry ingests the git-origin commit *before* it projects anything, absorbing it as
a loot change and converging the dock. Skipping this step is exactly how the #243
drift started: #230, #233, and the loot-site docs were landed with raw git and
never ferried, so the loot mirror fell behind `origin/main`.

### `loot adopt`/`ferry` after lane-lands (the primary drifts otherwise)

See "Catch the primary up" above. The two habits are the same discipline stated
twice because they fail the same way: **the loot mirror silently falls behind git
`origin/main`**, and the next lane spawned from the stale position projects a
*revert* of landed work. A drift guard now warns loudly on
`loot-first status`/`review`/`land`/`tag` when the shared mirror's `main` has
fallen *behind* real `origin/main`, or *diverged* from it (#243) — treat that
warning as a hard stop: reconcile before you land.

A mirror **ahead** of `origin/main` is quiet: that is the normal state between a
land and the checkout's next `git fetch`, when only the local tracking ref
trails. The guard used to shout DIVERGED there, on the most common healthy path
(#273) — a guard that cries wolf is one you learn to scroll past, and its whole
value is its rarity. Because *ahead* is now quiet, a stale tracking ref could
hide a `main` that moved under you, so `land` and `tag` fetch `main` before
judging (they already push, so the round-trip is free) — `status` and `review`
stay local and cheap.

### Parking / clobber gotchas (legacy in-place switching)

Under the retired ADR 0022 model, `loot dock <name>` switched **one shared working
tree in place**: switching *parked* the outgoing session's unsigned WIP into the
shared heads and re-materialized the tree, so two sessions sharing one checkout
would yank the tree out from under each other, and `loot resolve` could
re-materialize and **clobber another file's uncommitted edits**. Lanes make this
unrepresentable — WIP lives only inside its lane and never enters the shared heads,
so there is nothing to park.

Until legacy switching is fully retired from the primary, the safe rules are:

- **Don't drive loot verbs from two sessions in one checkout.** If a second
  session must act, give it its own lane (`loot lane new`), never a `loot dock`
  switch in the shared primary.
- **Resolve one conflict at a time.** `loot resolve` writes only the resolved path
  now (#233), but treat a dirty tree with respect: capture or finalize before you
  reconcile.
- If you find a parked working change from an older session, it is that dock's
  in-flight WIP — `loot dock rm <name>` drops it with its dock (#212). Confirm the
  dock is stale (its work landed) first.

## The drift discipline in one line

**git `origin/main` is the source of truth; the loot mirror must never fall
behind it and must never project backward onto it.** Every rule above is a
corollary: ferry after break-glass, adopt after lane-lands, heed the drift guard,
never let a lane spawn from a stale position.

## See also

- [workflow.md](workflow.md) — how one change reaches `main` (loot leads, git
  downstream).
- [issue-tracker.md](issue-tracker.md) — the claim ritual (assign → spawn lane).
- [identity.md](identity.md) — when an agent needs its own keyring (a clone, not a
  lane).
- [CONTEXT.md](../../CONTEXT.md) — glossary: **Lane**, **Dock**, **Harbor**,
  **Adopt**, **Shared store**, **Parked working change**.
- ADRs: 0034 (sealed lanes over a shared store), 0035 (lane lifecycle), 0036
  (harbor as serialized integrator), 0022 (the docks model these supersede).
- Map [#227](https://github.com/Connor-Miller/loot/issues/227) and its tickets for
  the reasoning behind each decision.
