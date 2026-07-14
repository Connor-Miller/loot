# Spec: `loot adopt <version>` — settle a dock onto a landed change

Status: proposed (2026-07-14). Child of the concurrency map ([#227]) — the
primitive the [#243] mirror re-baseline needs to finish, and the explicit-target
arm of ADR 0034's `loot adopt`. Amends **ADR 0034** (adds the `<version>` form)
and the CONTEXT.md **Adopt** entry.

[#227]: https://github.com/Connor-Miller/loot/issues/227
[#243]: https://github.com/Connor-Miller/loot/issues/243

## 0. What we are building

A dock can end up on a **divergent local line** that must be discarded in favour
of a landed change — the exact state [#243] found: the primary's `main` dock sat
on a stale fork (`ktmzqltv` loot-site WIP + a `sloowzlp` "ferry: reconcile git
main" projection under a stray working change) while `origin/main` had moved on
to `e2cb01e`. Loot has no verb that says *"drop my divergent line and settle this
dock exactly on that landed change."* The tools it has both do the wrong thing:

- **`apply` / converge** *merges* the lines — which, against a stale fork,
  **resurrects files deleted upstream** (proved live in [#243]: `ferry` merged
  the fork and brought back `tools/loot-first.ps1` and
  `crates/loot-first/src/ledger.rs`).
- **`loot abandon --head <version>`** (shipped, `042b54c`) drops a *signed* fork
  tip, but cannot drop the dock's **working-change** head, so it can't chain down
  a line to the shared anchor.

`loot adopt <version>` fills the gap: **take the target wholesale, abandon every
competing fork, no merge.** It is the mechanical core of a re-baseline, and it
composes with the drift guard (`442c530`): after adopt, `mirror.git` main can be
reset to `origin/main` and the guard goes quiet.

## 1. Verb surface

```text
loot adopt                          catch this lane up to the harbor lineage (ADR 0034 — unbuilt)
loot adopt <version> [--discard-wip]   settle this dock onto <version>, discarding the divergent line
```

The two arms are **one concept** ("settle the dock onto landed work") with a
deliberate split in *how*:

| arm | target | mechanism | keeps local line? |
|---|---|---|---|
| `loot adopt` (no arg) | harbor lineage **as a whole** | **merge** (converge onto WIP) | yes — folds it in |
| `loot adopt <version>` | one **landed** change | **take-wholesale** (discard forks) | **no** — replaces it |

This does **not** contradict ADR 0034's "per-change adoption is refused on
purpose." That refusal guards against a lane *merging a partial slice of the
harbor and continuing to build on its own line* — which reintroduces divergence.
`adopt <version>` does the opposite: it **discards** the local line entirely and
settles on the landed point, so no divergence can survive it. The invariant that
makes both safe is the same — **the target must be on the harbor/main lineage**
(§4), never "any signed change in the shared graph."

## 2. Semantics

Let `T` = the resolved target version, `D` = the ambient dock.

1. **Resolve `T`** among the dock's live, *finalized* changes (§4 refuses an
   unsigned working change or a non-lineage target).
2. **WIP gate** (§3): refuse if `D` has a live working change or uncaptured disk
   edits, unless `--discard-wip`.
3. **Abandon every competing live head.** For each live head `h ≠ T` that is not
   an ancestor of `T`, record `h` in the local **abandoned set** (ADR 0031) —
   the same durable, undoable mechanism `abandon --head` uses (the node is
   union-preserved on disk; the abandoned set hides it from the live view). No
   node is deleted; `loot undo` restores the pre-adopt view.
4. **Settle `D` on `T`.** `heads := {T}` (plus any surviving live head that is an
   ancestor of `T`, which is already implied), `tip := T`, `working := ∅`
   (fresh — the always-present working change, ADR 0006, is empty on `T`).
5. **Materialize `T`'s tree** to the working directory (the existing
   checkout/resurface path), visibility-aware as always.
6. **One op** in the log (`adopt`, undoable): it captures the heads, the
   abandoned set, and the dock pointers — a pure view + pointer reset, no object
   store or graph mutation.

There is **no content merge** at any point — that is the whole point (it is what
avoids the resurrection). Merge stays the no-arg arm and `dock merge`/`apply`.

## 3. WIP handling (decided)

Default: **refuse a dirty dock**, mirroring `loot edit`'s three refusals — an
in-progress working change or uncaptured edits means the operator has work adopt
would silently eat. The message names the remedy (`loot new` / `loot undo`).

`--discard-wip` opts into dropping it: the working change is abandoned as part of
the op (recorded, undoable) and `T`'s tree is materialized over the disk. This is
the flag the [#243] repair uses, where the WIP (`qskqprns`) is stale garbage.

`--discard-wip` is also the sanctioned override of the [#219] tree-write
chokepoint ("never materialize over uncaptured dirt") — adopt is the one verb
whose *intent* is to replace the tree, so the override is explicit, not implicit.

## 4. Guards & refusals

- **Not a live change** → refuse (`no live change matching '<prefix>'`).
- **Unsigned working change as target** → refuse. Adopt settles on *landed*
  work; a target must be finalized (signed) — you cannot adopt onto WIP.
- **Not on the harbor/main lineage** → refuse. `T` must be reachable from the
  designated dock's git-main projection (mirror `refs/heads/main`), the same
  "harbor lineage only" fence ADR 0034 draws — otherwise adopt could settle a
  dock on an unreviewed signed change and violate the after-it-lands premise.
  (Mechanically: `T` has a mark and is an ancestor of, or equal to, the mirror's
  main tip.)
- **Dirty without `--discard-wip`** → refuse with the finalize/undo remedy (§3).
- **Already there** (`T` is the sole live head) → no-op with a note; not an error.
- Adopt can never leave the dock with zero heads (`T` remains a head), so the
  `abandon --head` last-head guard is subsumed, not repeated.

## 5. Engine / workspace mechanics

No new engine machinery — this is a Workspace-level composition of parts that
already exist and are tested:

- **`Workspace::abandon_fork`** (`042b54c`) already drops one live head into the
  abandoned set, undoably. `adopt` calls it (or its inner helper) once per
  competing head, then does the settle in step 4.
- **Materialize** reuses the `checkout`/`resurface` path (visibility-aware,
  #219-guarded).
- **Undo** reuses the op log (ADR 0031): the op captures heads + abandoned set +
  the dock's `working`/`tip` pointers as raw bytes, so `loot undo` is a pure
  pointer reset — no object or graph surgery, nothing deleted.
- **Resolution** for `<version>` needs a live-head-inclusive resolver (the
  existing `resolve_live_version` excludes the working change; adopt targets a
  *finalized* change so the standard resolver is fine, but the target-on-lineage
  check is new).

The only genuinely new code is the target-on-lineage guard, the multi-head
abandon loop, and the CLI wiring — an estimated ~80 lines plus tests, entirely in
`loot-cli`.

## 6. The [#243] reconcile, using adopt

The end-to-end repair the map has been blocked on becomes a short, safe script
(local-only — `ferry` never pushes; the mirror reset is a local `update-ref`):

1. **Re-baseline the mirror**: fetch `origin/main` into `mirror.git`, reset its
   `refs/heads/main` to `e2cb01e`, clear the stale `marks`/`state`.
2. **`loot ferry`** — ingests the git-native gap (#230/#233/loot-site) as loot
   changes; `E` = the change mapped to `e2cb01e` in the rebuilt marks. (Ferry's
   converge still produces a transient merge — that's fine, adopt discards it.)
3. **`loot adopt <E> --discard-wip`** — the primary's `main` dock settles exactly
   on `E`, abandoning the two forks and the merge; the disk materializes to
   `e2cb01e`'s tree, working change empty.
4. **Reset `mirror.git` main → `e2cb01e`** again (drop the transient merge
   projection), clear `marks`/`state`, and **`loot ferry`** once more: single
   head `E == e2cb01e`, so it ingests nothing and **projects nothing** — the
   #195 / #201 no-backward-projection guards hold trivially.
5. **Assert**: `loot log` shows one clean head; the dock's tree `== e2cb01e`; the
   drift guard (`loot-first status`) is **quiet**. Nothing reached GitHub.

`git origin/main` never moves; if adopt cannot be made safe, the documented
fallback (raw dock-pointer reset) stands, but adopt makes it a supported verb.

## 7. Tests

- `adopt_settles_on_target_and_abandons_forks` — seed a fork (two heads off a
  root); `adopt(a)` leaves `a` the sole live head, `b` abandoned, tree == a's;
  `undo` restores both heads.
- `adopt_refuses_dirty_without_discard` — a live working change → refuse; message
  names the remedy.
- `adopt_discard_wip_drops_the_working_change` — with `--discard-wip`, WIP is
  dropped and the target tree materializes; undoable.
- `adopt_refuses_a_non_lineage_target` — a signed change not on the mirror-main
  lineage → refuse.
- `adopt_refuses_an_unsigned_target` — a working-change version as target →
  refuse.
- An integration walk of §6 on a seeded fork+ingest, asserting no projection.

## 8. Non-goals / follow-ons

- **No merge.** Folding two lines stays `apply`/`dock merge` and the no-arg
  `adopt` (ADR 0034). `adopt <version>` is strictly discard-and-settle.
- **No git/mirror mutation.** Adopt touches loot state only; the `mirror.git`
  reset in §6 is a separate, explicit step (keeps the git side operator-visible).
- **No network.**
- **Build the no-arg `loot adopt`** (ADR 0034 harbor catch-up) is *not* in this
  spec — this is the explicit-target arm only; they share the verb and the
  lineage fence but ship independently.
- After this lands, the map's **#234** land-flow playbook documents "after a
  break-glass git land, `loot adopt <landed>` to catch the primary's main dock
  up" — the discipline that prevents the drift recurring.

## 9. Execution order

1. Land `cm/243-mirror-drift-guard` (guard `442c530` + `abandon --head`
   `042b54c`) — the guard makes drift loud; `abandon_fork` is adopt's building
   block. (Blocked on reconciling its own branch drift first, or merge via git.)
2. Add the target-on-lineage guard + multi-head abandon + `loot adopt <version>
   [--discard-wip]` CLI, with §7 tests.
3. Amend **ADR 0034** (the `<version>` arm + the discard-vs-merge table) and the
   CONTEXT.md **Adopt** entry.
4. Run the §6 reconcile to finish [#243]; assert §6.5.
5. Write **#234** with the "break-glass → adopt" playbook.
