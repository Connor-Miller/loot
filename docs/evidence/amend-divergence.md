# Evidence: divergence arises from ordinary work

The concrete, checkable proof for the amend model (wayfinder map
[#169](https://github.com/Connor-Miller/loot/issues/169), ADR 0032). The claim:

> **A divergent change can arise from ordinary concurrent work, not just a test
> fixture.** Two peers each `loot edit` the *same* durable change over the relay,
> finalize different amends, and sync — one graph then holds two live versions of
> one handle. `loot log`/`status` render the `!` marker, `loot abandon` collapses
> it, and `loot undo` restores it. And the control holds: a *solo* amend travels
> as a clean supersession (no `!`, no content-merge), which is exactly what the
> signed `predecessors` claim (ADR 0032) buys.

Like the rest of `docs/evidence/`, the proof is a **re-runnable script** whose
captured output is committed beside it: script
[`scripts/amend-divergence-demo.ps1`](scripts/amend-divergence-demo.ps1),
output [`runs/amend-divergence-demo.txt`](runs/amend-divergence-demo.txt)
(run 2026-07-12, **all checks passed**). It runs in two acts over a hermetic,
local `loot serve` relay — Act 2 mutates history (push), so it stays off the
shared VPS DAG.

This is the last slice of map #169: the keystone (ADR 0032, `fa0cdc2`) and the
build (`loot edit`, PR #196, `ac92bc1c`) already landed — this run is the
**proof** that the shipped verb produces divergence from real concurrent writers,
**no white-box construction** (no `record_carrying` test fixture).

## Why two identities, not two docks

Divergence is **cross-store** (build finding
[#171](https://github.com/Connor-Miller/loot/issues/171)). Two docks over one
shared store *cannot* self-diverge: the first dock's reopen is visible through
the shared blob, so the second `edit` refuses or chains onto the finalized amend.
Two live versions of one `change_id` arise only when two independent *stores*
each amend it and then sync. So the proof uses two keyring-separated identities
(`dev`, `agent`) over the relay (ADR 0026), not two docks.

## Act 1 — control: a solo amend is a clean supersession (ADR 0032)

`dev` finalizes a base change and pushes; `agent` clones it. `dev` then
`loot edit`s that same change, amends the file, finalizes, pushes — and `agent`'s
pull sees the amended version **replace** the original.

- [x] **`agent` clones `dev`'s base change** — `doc.txt = v1` on clone (run
      lines 36–39).
- [x] **`dev` reopens the landed change with `loot edit`** — the durable handle
      `knvkmrlm` is carried; the working change supersedes version `7de50c42`
      (lines 41–43), finalized + pushed (45–48).
- [x] **`agent`'s pull is a clean supersession — no `!`, no content-merge** —
      after pull + surface, `loot log` shows the single change `knvkmrlm` at the
      amended version `cbadfe5c`, no divergence marker, no "diverged" fork, and
      `doc.txt` is `dev`'s amended line (not a merge of old + new): converge
      dropped the superseded head (lines 50–66). This is ADR 0032's
      supersession-travels property — a solo amend is invisible as divergence.

## Act 2 — divergence: two identities amend the same change (`!` / abandon / undo)

Both peers share a base change `mzlxpytq`. Each `loot edit`s it and finalizes a
**different** amend on its own store — two live versions of one handle — then
pushes. `agent` pulls `dev`'s amend, so one graph holds both.

- [x] **Both peers share the base change** — `agent` pulls it, `feat.txt`
      present, single version (lines 78–86).
- [x] **Concurrent amends → two versions of one handle** — `dev` amends
      `feat.txt` to *dev's take* and pushes (relay tip 1, lines 88–96); `agent`,
      from the same base and *before* pulling `dev`'s amend, amends to *agent's
      take* and pushes (relay tip 2, lines 98–104).
- [x] **One pull puts both live versions in one graph → the `!` marker, FLAT**
      — `agent`'s pull ingests `dev`'s amend; `loot log` renders the durable
      handle `mzlxpytq!` twice, once per live version (`57a84e20`, `2f370248`),
      as a **flat listing** — not a "run `loot apply` to converge" fork — and
      `loot status` agrees the handle is divergent (lines 106–127). Converge
      minted **no merge** ([#203](https://github.com/Connor-Miller/loot/issues/203)):
      `loot conflicts` reports nothing (lines 121–122) and the working tree is
      clean on `agent`'s own side (line 126).
- [x] **`loot abandon <version-id>` is the whole settle** — abandoning `dev`'s
      version leaves the handle with `agent`'s single live version; the `!` is
      gone, the `change_id` survives, `loot conflicts` is still empty, and the
      survivor's tree stands clean (lines 129–144). Nothing is deleted.
- [x] **`loot undo` restores it — nothing was destroyed** — one undo walks the
      abandon back and the `!` returns with both versions (lines 146–155).

## What the run surfaced

The first run of this proof (2026-07-12, pre-#203) surfaced one behaviour worth
recording — since **resolved**:

- **`abandon` collapsed the handle-level divergence, but not the tree-level
  conflict `converge` created.** Because both amends edited the *same line*,
  the pull's `converge_heads` folded the two divergent versions under one
  signed merge head *and* raised a per-**path** content conflict on `feat.txt`
  that survived `abandon` — the one two-writer event represented twice, by two
  orthogonal mechanisms (per-`change_id` divergence, ADR 0032; per-path
  conflict, ADR 0001), settled by two separate steps. That was the "converge
  content-combination wart" flagged in map #169's Fog. **Resolved by
  [#198](https://github.com/Connor-Miller/loot/issues/198) →
  [#203](https://github.com/Connor-Miller/loot/issues/203)** (amending ADR
  0032): converge merges only genuinely independent heads — two live versions
  of one `change_id` stay flat as live heads, no merge is minted, no per-path
  conflict exists, and `loot abandon` is the whole settle. The committed run
  above is the post-#203 rerun proving it. The signed, travelling resolution
  (one amend naming *both* live versions as predecessors) remains the deferred
  [multi-predecessor path](https://github.com/Connor-Miller/loot/issues/169).

## Done

- [x] Both acts pass in a committed, re-runnable script
      ([run](runs/amend-divergence-demo.txt), rerun 2026-07-12 post-#203) —
      divergence arises from ordinary concurrent work (control + real
      two-identity amend), renders with `!` **flat** (no converge merge, no
      per-path conflict), collapses via `abandon` (the whole settle), restores
      via `undo`, with no white-box construction. Resolves map #169's proof
      ticket [#172](https://github.com/Connor-Miller/loot/issues/172); the
      divergence act doubles as the live proof for
      [#203](https://github.com/Connor-Miller/loot/issues/203).
