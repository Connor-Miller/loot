# Implicit auto-snapshot and the reconciled verb surface

## Status

accepted (spec — jj-ergonomics trio, wayfinder map #132; amends ADR 0006;
implementation is a follow-on build map)

## Context

ADR 0006 adopted "the working tree *is* the change" and a visibility-aware
snapshot reconcile, but left snapshotting **explicit**: `loot status -m`
snapshots, `loot new` finalizes. jj's actual ergonomic win is that snapshot is
**implicit** — every command first records the working copy, so you cannot lose
work and there is no "did I stage that?" question. This ADR makes loot's snapshot
implicit and reconciles the resulting verb surface, consuming the durable change
id from ADR 0029. It also folds the seams the prototype (#137) surfaced when the
three trio decisions were exercised end-to-end.

The design must respect loot's non-jj constraints: it is **process-per-command**
(no daemon/watcher), the working tree is an **identity-filtered** view (ADR 0006's
whole reason for a careful reconcile), the shared DAG must stay quiet under
parallel agents (ADR 0022), and finalization is the **signing** boundary (ADR
0018) — snapshots must never sign.

## Decision

### Implicit snapshot on mutating verbs only; read-only verbs never snapshot

Every **mutating** verb first runs the ADR 0006 visibility-aware snapshot of the
working tree into the working change (carrying the change id per ADR 0029), then
does its job. **Read-only** verbs (`log`, `show`, `status`, `docks`, `manifest`,
`conflicts`, `whoami`, `grants`) never persist a snapshot. Two guards keep this
cheap and safe:

- **Tree-hash short-circuit** — the existing snapshot tree-hash (ADR 0017) no-ops
  a snapshot whose tree is unchanged, so a run of read-then-mutate commands does
  not churn the working change.
- **No daemon** — because loot is process-per-command, "snapshot on every command"
  means "at the start of each mutating invocation," not a background watcher. This
  is the whole of the mechanism.

The win: work cannot be lost between commands, and the mandatory `status -m`
ceremony is gone.

> **Amended 2026-07-12 (#219): capture-first extends to `pull`/`apply`, behind
> one tree-write chokepoint.** `pull`/`apply` are mutating verbs, so they
> capture uncaptured disk edits into the working change like every other one —
> the earlier "`pull`/`apply` have none" assumption in `converge_heads` was an
> accident of this ADR not yet reaching them, not a guarantee. A dirty pull
> becomes: **ingest always** (graph append is always safe), **converge only when
> clean**. The existing working-change guard makes convergence a **no-op for
> that pass** — you cannot fold heads under an in-progress working change
> without orphaning it — so the pull emits a loud note ("captured working change
> `<id>`; heads left unconverged — finalize (`loot new`) then re-run pull/apply
> to converge") and leaves the flat-heads state #203 made legal. Refuse-on-dirt
> was rejected for pull/apply (it nags the mid-work-sync case); `loot edit`'s
> refuse-on-dirt exception class is untouched. Underpinning both is **one
> internal tree-write chokepoint**: every path that overwrites the working tree
> from a change's content (the `converge`/adopt materializes) is gated by a
> single invariant — *never write the tree over uncaptured dirt* — evaluated
> before any head is dropped, so a caller that skipped capture is **refused**
> rather than silently clobbered. `undo`/`abandon` resurface is exempt **by
> intent** (rewriting the tree is what the operator asked for); a dock switch
> already captures. This graduates map #169's fog item *"pull materializes over
> uncaptured disk edits"* into a guarantee.
>
> **Amended 2026-07-16 (#280): `reconcile_onto` captures unconditionally — the
> chokepoint protected the wrong thing.** The tree-write chokepoint refuses a
> materialize over *uncaptured* dirt, but the bridge gated the **capture itself**
> on `had_new = !new_shas.is_empty()` — "did git bring new commits to ingest?".
> When git `main` moved because **another lane landed through loot**, its commit
> is already marked, so `had_new` was `false`, `reconcile_capture` never ran, and
> a *captured, un-finalized* working change (disk == working change, so the
> chokepoint's `tree_is_dirty_over` was `false` and it waved the write through)
> was materialized straight over — data loss (a described, 2h working change
> destroyed on an ordinary two-agent day, recovered only from an orphaned GitHub
> commit). `had_new` answers "is there something to ingest?"; the question a
> reconcile must ask is "is the tree about to be overwritten?", and every
> `reconcile_onto` arm except the no-ops may materialize `target`. So the
> `capture` parameter is **gone**: `reconcile_onto` always captures first. This
> is close to free — `reconcile_capture` already drops a capture that is empty or
> duplicates `pinned`/`target` (the co-located checkout after a `git pull`), so
> the common nothing-new pass still mints nothing — and it is what makes the
> fast-forward path recognize a disk that already holds the landed tree. The
> regression fixture moves `main` **the way a land does** (a marked, loot-projected
> commit), not via `git_native_commit` — the exact path every prior reconcile
> test missed. `converge_heads` already had this working-change guard (it defers
> rather than orphan); `reconcile_adopt` gets the same protection here by never
> being reached with a live working change on the disk.

### `status` becomes a pure read-only report (the `-m` flag is dropped)

`status` recomputes the pending working-tree delta **live** and prints it, and
**never persists**. Consequently the version id it shows for the working change is
a **live-computed, non-durable** value (another file save moves it with no loot
command in between). This is correct for a hash meaning "content right now," but
the durable handle a caller holds is the **change id** (ADR 0029), which `status`
shows alongside — the version id in read-only output is explicitly not something
to cache. `-m` is removed from `status`; naming moves to `describe`.

### `new` is the finalize/sign boundary and mints + prints the next change id

`loot new` finalizes the working change (signs it once, ADR 0018, over `version_id
‖ change_id`), then **eagerly mints the next change's change id and prints it**,
so the fresh change has a durable handle from birth rather than only after the
first edit. Convenience `new -m <msg>` finalizes-and-names in one step. Output
names the **new** change id, e.g. `finalized <version> <change>; started fresh
change <next-change>`.

### `describe` names the working change anytime (describe-after)

`describe -m <msg>` sets the working change's message at any point (it is a
mutating verb, so it snapshots first, then sets the message). No up-front message
requirement anywhere; naming is always after-the-fact.

> **Amended 2026-07-15 (#174): describe-after, but `new` refuses to *sign* an
> un-described change.** Naming stays after-the-fact — nothing demands a message
> up front, and every capture still runs nameless. But `new` is capture-**then**-
> finalize, so on a dirty tree "no up-front requirement" quietly meant *the
> placeholder is a valid subject for signed history*: the second loot-first day
> signed a dirty tree in one stroke (`0729287d`, subject `(working change)`),
> which rode to git `main` beneath the reviewed lane, unreviewed. Finalize is the
> signing boundary and a signed message is **permanent** — it becomes the subject
> of the commit projected onto `main` — so that is where the requirement lands:
> `finalize_capturing` refuses an un-described change (no message, or the
> `(working change)` placeholder a carry-along capture stored), naming
> `describe -m` first and `new -m` second. The refusal sits **after** the capture,
> so the edits are held safely in the working change and only the signature is
> withheld; and **below** the empty/duplicate drop, so a bare `new` on a clean
> tree stays the no-op it was rather than becoming a refusal. Deriving a subject
> from the changed paths was rejected: it would mint plausible-looking history
> nobody wrote, and loot has no changed-path concept to derive one from — `status`
> lists the whole tree. The two verbs that finalize on the operator's say-so —
> `loot new` and `loot-first land` — are the two callers of `finalize_capturing`,
> so both inherit the refusal: the "run `loot describe -m` before landing" ritual
> is now enforced rather than remembered.
>
> **The residual, and its closure.** #174's refusal was on the *deliberate*
> finalize only. `fold_line_in` (`loot dock merge`, the `loot adopt` catch-up)
> and the bridge's `reconcile_capture` (`loot ferry` over a git `main` that
> moved) capture-and-`finalize_working` **in passing**, to make a signed merge
> parent — and what they sign is the operator's own authored working change; only
> the *trigger* is mechanical. So they could still mint a signed
> `(working change)` subject and project it onto `main` — #174's exact harm, on a
> rarer path. Reproduced against the pre-fix binary: a `ferry` over unnamed disk
> work landed the literal subject `(working change)` on git `main` in one silent
> pass.
>
> **Amended 2026-07-15 (#275): the same refusal extends to those merges.** Both
> paths now refuse an un-described merge parent
> ([`REFUSE_UNDESCRIBED_PARENT`]) after capturing. Two arguments this ADR made
> for *not* doing that were checked and dropped:
>
> - *"A ferry that refuses is a ferry that blocks a land"* — **false**.
>   `loot-first land` finalizes (and thus names) **before** it ferries, so a land
>   never reaches these paths dirty. Nothing about landing changes.
> - *"#219 rejected refuse-on-dirt for the sync verbs"* — that rejection was
>   about being forced to **capture/finalize** to sync, which costs a decision.
>   Being asked for a **name** is not the same ask, and it only arises when the
>   sync must seal your work into permanent history anyway. Capture stays
>   implicit; only *signing* asks.
>
> The prompt and auto-subject-at-projection options were dropped with it: loot is
> process-per-command and agent-driven (ADR 0023), so a prompt is hostile to the
> callers it would fire on, and a mechanical subject over *authored* content is
> the same "history nobody wrote" this ADR rejected for `new`.
>
> The cost is honest and small: **uncaptured** dirt cannot be named in advance —
> naming *is* capturing — so a `ferry`/`adopt` over never-captured edits now takes
> two passes (refuse+capture, then `describe -m` and re-run). The refusal is
> safe to abandon mid-pass: the capture persists (it is what saves the edits),
> the materialize never runs so nothing is clobbered, and the pass's ingest is
> simply redone on the re-run — graph append is idempotent.
>
> **`loot-first review` is in scope, and that is deliberate.** Review projects
> through the same ferry, so a review taken while git `main` has moved under it
> must reconcile — which signs our side as a merge parent — and therefore asks
> for a name. This does *not* make review a post-`describe` verb: with `main`
> where you left it (the ordinary case) nothing is signed, nothing is asked, and
> `resolve_title`'s un-described fallback still names the PR. Only the merge asks.
>
> The merge **nodes** these paths mint (`merge_tips` in `fold_line_in`,
> `converge_heads`, `reconcile_merge`) are untouched: they are machine-authored
> and already carry an honest mechanical subject (`merge dock 'x' into 'main'`,
> `ferry: reconcile git main`). That is the line — *mechanical content* may be
> named mechanically; *authored content* may not.

### `log` and `status` go columnar

Two ids per change cannot ride the flat `{short} {message}` line legibly (the
prototype showed this concretely). `log`/`status` become **columnar**:

```
change     version   message                      vis        author
qsouzmpr   3f9a1c02  drafting the intro section              connor
wnhpktlr   —         (working change, empty)
```

Column order: **change · version · message · vis · author**. The porcelain/JSON
forms (ADR 0023) gain a `change_id` field beside the existing `id`; the
frozen-contract status chars are unchanged. This is the biggest surface change the
trio forces and is decided here rather than left to the implementer.

### Divergent changes: a marker plus a dedicated collapse verb

A **divergent change** (ADR 0029: one change id, two non-abandoned version ids) is
rendered with a trailing **`!`** on the change id, both versions listed:

```
change      version   message
qsouzmpr!   3f9a1c02  drafting the intro section
qsouzmpr!   9b2e017c  drafting the intro (reworded)
```

It is **not** a tree conflict, so `resolve`/`dock merge` (which merge trees, ADR
0001) do not apply — the two versions may have identical trees yet both persist as
distinct versions under one change id. Collapsing is *picking which version
survives*: **`loot abandon <version-id>`** drops a version from a divergent change
(jj-parity `jj abandon`), leaving a single version under the change id. Abandon is
recorded as an undoable operation (ADR 0031); nothing is deleted from the object
store, the version simply stops being a live head. (Where the user genuinely wants
to *merge* two divergent versions' trees, they use the existing converge/merge
path, which produces a new version — a different intent from picking one.)

### The demotion guard travels on the implicit snapshot

Because snapshot is now implicit, the visibility-demotion guard (#62) must ride
with it: an auto-snapshot that would **demote** a path's visibility (e.g. sealed →
public) **aborts by default** with a machine-readable verdict (ADR 0023) rather
than silently widening exposure. Override with **`--allow-demote <path>`**, a
**global flag on any snapshotting verb**, so an agent fixes the classification
inline without a verb detour. Escape hatches: global **`--ignore-working-copy`**
/ `--no-snapshot` skip the implicit snapshot entirely for one invocation.

> **Amended 2026-07-15 (#67): "a global flag on any snapshotting verb" is now
> enforced, not merely documented.** Both binaries scanned for the flags they
> knew and **ignored the rest**, so a global read as accepted wherever you typed
> it: `--allow-demote` on read-only `status`, or `--no-snapshot` on `describe`
> (which always records the tree — recording it is the verb's whole job), did
> nothing at all and said so. Each verb now **declares the flags it reads**, and
> the dispatcher rejects the rest *before the verb runs*. So a global rides
> exactly the verbs that honour it — `--allow-demote` the five snapshotting
> verbs, the capture skip all but `describe`; `status` takes neither. See "An
> unknown flag is an error" below.

### An unknown flag is an error, never noise

> **Amended 2026-07-15 (#67).** The rest of this ADR reconciles which verbs
> exist and what they do; this settles what happens to an argument that names
> none of them.

An unknown flag is **refused**, on every verb of both binaries, before the verb
runs. Ignoring it is not neutral — it *teaches a feature that isn't there*:
`loot log --path README.md` printed the whole unfiltered log, which reads as a
filter that ran and matched everything (#67, pilot finding 11). The refusal
names the flag and lists what the verb does accept.

The rule follows the grain of ADR 0005's dependency-light hand parsing (no
clap): one gate, two dispatch tables. Two consequences worth stating:

- **`-h`/`--help` rides every verb** and prints usage *instead of* running it.
  Otherwise it would be the one flag still silently ignored — and it was the
  dangerous one: `loot new --help` **finalized (signed) the working change**.
- **Flags are declared per verb, and re-checked per subcommand** — the dispatch
  table's `loot lane` entry is the union over `new`/`gc`/…, which catches every
  flag that exists nowhere in the CLI (the reported class) before dispatch and
  keeps `--help` riding the verb. A verb that branches on a subcommand then
  narrows the gate itself: it re-checks the resolved subcommand's own spec, so
  a flag real only on a *sibling* subcommand (`loot lane new --stale-hours`,
  `loot dock rm --at x`) refuses too (#278). The union and the subcommand specs
  are kept in step by a test, not by hand.

### Parallel-agent safety: snapshot never finalizes or signs

Auto-snapshot **only ever rewrites the working change** — it never adds a graph
node and never signs (signing stays at `new`, ADR 0018). So the shared DAG stays
quiet: graph nodes appear only on a deliberate `new`. Snapshotting is per-dock,
content-addressed, and lock-free (distinct docks never serialize, ADR 0022), so
concurrent agents each snapshot their own working change without contention.

## Considered alternatives

- **A filesystem watcher / daemon (true jj-style continuous snapshot).** Rejected:
  loot is process-per-command; a daemon is a large new surface and a lifecycle
  problem for a marginal gain over snapshot-at-invocation.
- **Keep `status -m` and only add a convenience.** Rejected: it retains the
  ceremony this milestone exists to remove.
- **Snapshot on read-only verbs too (uniform "every command").** Rejected: a
  `log` should never move the working change's version id or trip the demotion
  guard; read-only must stay read-only for scripting and for parallel agents.
- **Auto-finalize/sign on some heuristic.** Rejected: signing is a deliberate
  authorship act (ADR 0018) and auto-signing would spam the shared DAG and break
  parallel-agent quiet. `new` stays the one boundary.
- **Reuse `resolve` for divergent changes.** Rejected: a divergent change is not a
  tree conflict; conflating them would mis-model identical-tree divergence and
  overload the conflict path.

## Consequences

- Daily loot loses its remaining ceremony: edit → (implicit) record → `describe`
  to name → `new` to finalize. Work cannot be lost between commands.
- `status` is read-only and `-m` is gone; `log`/`status` are columnar with a
  `change_id` column (and porcelain/JSON field). Agents parsing machine output
  gain a stable `change_id` key.
- `new` mints-and-prints the next change id; `describe` is the only namer.
- A new `loot abandon <version-id>` verb and a `!` divergence marker enter the
  surface; both lean on ADR 0029's data model and ADR 0031's operation log.
- The demotion guard and `--allow-demote` / `--ignore-working-copy` flags become
  part of every snapshotting verb, preserving ADR 0006's no-silent-exposure
  invariant under implicit capture.
- ADR 0006's reconcile policy is unchanged — only its *trigger* moves from explicit
  to implicit; the visibility-aware diff and collision refusal are reused verbatim.
