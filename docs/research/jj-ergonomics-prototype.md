# Prototype — a day of loot *after* the jj-ergonomics trio

> Wayfinder prototype for [#137](https://github.com/Connor-Miller/loot/issues/137)
> on map [#132](https://github.com/Connor-Miller/loot/issues/132). A rough,
> throwaway artifact: a scripted transcript of the reconciled verb surface once
> **auto-snapshot** (#135), **stable change-ids** (#134), and **oplog/undo**
> (#136) are all in. The point is to catch a design **seam** while it is still
> cheap to move — before the spec (#138) is written. Nothing here is built; the
> output is hand-composed to be *faithful to loot's real formats* (`short()` =
> 8 hex chars, `status`/`log`/`docks` shapes from `loot-cli/src/main.rs`).

## Display convention this prototype pins down

Two ids per change (#134), and the prototype's first job is to answer the
ticket's question — *does a stable id read well next to the content hash?*

- **version id** — content+author hash, 8 hex chars, e.g. `3f9a1c02`. Digits
  `0-9a-f`. Rewrites on every snapshot.
- **change id** — the durable handle. Rendered as **reverse-hex letters**
  (jj's trick: map nibbles to `k l m n o p q r s t u v w x y z`), e.g.
  `qsouzmpr`. Never a digit.

**Finding: the two alphabets do the disambiguation for free.** A reader never
has to ask "which id is this?" — `3f9a1c02` is obviously the version, `qsouzmpr`
is obviously the handle, at a glance, with no prefix or label. This is why jj
picked reverse-hex, and it transfers to loot cleanly. **Recommendation for the
spec: adopt the letter alphabet for change ids; do not render both as hex.**

---

## Act 1 — the common flow: edit, auto-record, name, new

```console
$ vim notes.md                       # edit the working tree
$ loot log
3f9a1c02  qsouzmpr  add project skeleton  [logged by connor]
1a77e4b0  (working change)  qsouzmpr
```

**Seam #1 (surfaced, resolvable).** `log` is read-only (#135) so it did **not**
snapshot — yet it shows a working change whose version id `1a77e4b0` already
reflects the just-saved `notes.md`. That id is **computed live**, not persisted:
the persisted snapshot only advances on the next *mutating* verb. So the
version id shown for `(working change)` is a *live* value that can change with no
loot command in between (another file save moves it). That is fine for a hash
that means "content right now," but the spec must say plainly: **the working
change's version id in read-only output is live-computed and non-durable; only
its change id (`qob…`) is stable.** Otherwise a scripter will cache `1a77e4b0`
and be surprised. (This is also *why* we needed the change id — it is the only
part of the working row a caller can hold onto.)

```console
$ loot describe -m "drafting the intro section"
described working change 1b40c7aa as "drafting the intro section"
```

`describe` is a mutating verb, so it auto-snapshotted first (capturing
`notes.md`), *then* set the message — note the version id moved `1a77e4b0 →
1b40c7aa` but the change id is untouched. No `status -m` ceremony; the message
is set describe-after (#135).

```console
$ loot new
finalized working change 1b40c7aa; started fresh change wnhpktlr
```

**Seam #2 (surfaced, a real wording change).** Today `new` prints *"finalized
the working change; the next `status` starts a fresh one."* Post-trio there is no
`status`-starts-it step — `new` mints the next change id **eagerly** so the
fresh change has a durable handle from birth (#134 mints "at creation"). The
message must name the **new** change id (`wnhpktlr`) or the user has no handle
until they first edit. **Spec action: `new` mints-and-prints the next change id.**

```console
$ loot log
3f9a1c02  qsouzmpr  drafting the intro section  [logged by connor]
                    ^ note: change id qsouzmpr is unchanged across the amend;
                      only the finalized version id is shown now.
1c02aa41  w 3b…      add project skeleton  [logged by connor]
wnhpktlr  (working change)   <- empty, freshly minted handle, no version yet
```

**Seam #3 (surfaced — the `log` format genuinely needs a column).** The real
`log` line is `{short}  {message}{seal}{author}`. Wedging a second id in makes
the line ambiguous (see the ugly `w 3b…` I had to fake above). A stable id is
not free real estate — it wants its **own column**:

```console
$ loot log
change     version   message                      vis        author
qsouzmpr   3f9a1c02  drafting the intro section              connor
wnhpktlr   —         (working change, empty)
```

**Spec action: `log` becomes columnar** (change · version · message · vis ·
author). The flat `{short} {message}` line cannot carry two ids legibly. This is
the biggest surface change the trio forces and it should be decided in the ADR,
not left to the implementer.

---

## Act 2 — undo a mistake (the oplog safety net, #136)

```console
$ rm notes.md                        # oops, meant to rm scratch.md
$ loot new                           # ... and finalized the deletion
finalized working change 8c1de440; started fresh change ptmvkszn
$ loot op log
op 7  (just now)   new        finalize 8c1de440 · heads {8c1de440}
op 6  (just now)   snapshot   auto · notes.md removed
op 5  (2m ago)     new        finalize 1b40c7aa
op 4  (2m ago)     describe   "drafting the intro section"
op 3  (3m ago)     snapshot   auto · notes.md
...
$ loot undo
undid op 7 (new) — working change is ptmvkszn again, head back to 1c02aa41
$ loot undo
undid op 6 (snapshot) — notes.md restored in the working change
$ loot log
change     version   message                      vis        author
qsouzmpr   3f9a1c02  drafting the intro section              connor
ptmvkszn   1a77e4b0  (working change)             notes.md restored
```

Nothing was deleted from the object store (#136): the finalized `8c1de440`
survives in the graph, undo just moved the head pointer off it. `qsouzmpr`'s
finalized change is untouched — undo never crossed it.

**Seam #4 (surfaced, minor).** After two undos the `op log` should show the two
*compensating* ops (undo is a new op, not a pop). The transcript above hid them;
the spec should confirm `op log` grows on undo (jj-parity) rather than
shrinking — otherwise "undo the undo" (redo) has nothing to land on.

### The barrier (#136)

```console
$ loot push origin
pushed 2 changes to origin (relay clock 40871)
$ loot undo
loot: refusing to undo across a push barrier (op 8, push→origin).
      a push discloses; it cannot be retracted by undo. to reverse a
      published change, record a new change or `loot maroon` the path.
```

**Finding: the barrier message reads well and teaches the model.** It names the
op, states *why* (disclosure is one-way), and points at the real remedy. Keep
this shape in the spec. `grant` / `maroon` / `pull-grants` produce the same
refusal.

---

## Act 3 — a divergent change (the honest answer from #134)

Two docks (or two peers) each amend the *same* change id `qsouzmpr`, producing
two version ids under one handle. This is the display case #134 created that the
**existing** diverged-graph view does not express.

```console
$ loot log
change     version   message                      vis        author
qsouzmpr!  3f9a1c02  drafting the intro section              connor
qsouzmpr!  9b2e017c  drafting the intro (reworded)           connor
           ^ trailing ! = divergent: one change id, two live versions
ptmvkszn   1a77e4b0  (working change)
```

**Seam #5 (surfaced — this is the important one).** loot's current `log` only
branches into a multi-head view when `heads().len() > 1` ("N heads — diverged").
A **divergent change** is different: the graph may have a *single* head, yet one
change id points at two versions. The existing "diverged graph" machinery
**does not cover this** — divergence is per-change-id, not per-head.

The spec must decide two things the other three tickets left open:
1. **How `log`/`status` mark it** — the `!` suffix above is one cheap option;
   jj prints `?? (divergent)`.
2. **Which verb collapses it** — jj has `jj new` over both / `jj abandon`. loot
   has `dock merge` and `resolve` for *tree* conflicts, but a divergent change is
   not a tree conflict (the trees may be identical). **This needs its own verb or
   an explicit "pick a version" resolution** — it cannot ride the existing
   conflict path. Flagging it here, before the spec, is exactly what this
   prototype was for.

---

## Seams found (the payoff)

| # | Seam | Severity | Spec action |
|---|------|----------|-------------|
| 1 | Working change's **version id is live-computed** in read-only output, non-durable | doc | State it; the change id is the only holdable handle |
| 2 | `new` must **mint + print** the next change id eagerly | small | Change the `new` output line |
| 3 | Flat `log` line **cannot carry two ids** — needs a column | **medium** | `log`/`status` go **columnar** (decide in ADR) |
| 4 | `op log` must **grow on undo** (undo is an op), to enable redo | small | Confirm append-only oplog semantics |
| 5 | **Divergent change ≠ diverged graph** — existing multi-head view doesn't cover it; no verb collapses it | **medium** | New marker (`!`) + a dedicated "pick a version" verb; cannot reuse `resolve` |

**Net:** the reconciled surface holds together — auto-snapshot + describe-after +
`new` flow reads clean, the two-alphabet id display is a genuine win, and undo +
barriers behave. The two medium seams (columnar `log`, divergent-change verb)
are **display/verb decisions the three design tickets legitimately left to
integration** — they are cheap to settle in the spec (#138) and would have been
expensive to discover mid-build. That is the prototype earning its keep.
