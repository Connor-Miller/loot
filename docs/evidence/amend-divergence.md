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
      `pxpzumlw` is carried; the working change supersedes version `ab8182ed`
      (lines 41–43), finalized + pushed (45–48).
- [x] **`agent`'s pull is a clean supersession — no `!`, no content-merge** —
      after pull + surface, `loot log` shows the single change `pxpzumlw` at the
      amended version `2bdc944e`, no divergence marker, no "diverged" fork, and
      `doc.txt` is `dev`'s amended line (not a merge of old + new): converge
      dropped the superseded head (lines 50–66). This is ADR 0032's
      supersession-travels property — a solo amend is invisible as divergence.

## Act 2 — divergence: two identities amend the same change (`!` / abandon / undo)

Both peers share a base change `xvnvrkul`. Each `loot edit`s it and finalizes a
**different** amend on its own store — two live versions of one handle — then
pushes. `agent` pulls `dev`'s amend, so one graph holds both.

- [x] **Both peers share the base change** — `agent` pulls it, `feat.txt`
      present, single version (lines 72–86).
- [x] **Concurrent amends → two versions of one handle** — `dev` amends
      `feat.txt` to *dev's take* and pushes (relay tip 1, lines 88–95); `agent`,
      from the same base and *before* pulling `dev`'s amend, amends to *agent's
      take* and pushes (relay tip 2, lines 97–104).
- [x] **One pull puts both live versions in one graph → the `!` marker** —
      `agent`'s pull ingests `dev`'s amend; `loot log` renders the durable handle
      `xvnvrkul!` twice, once per live version (`b38f4b62`, `2fffd634`), as a
      **flat listing** — not a "run `loot apply` to converge" fork — and
      `loot status` agrees the handle is divergent (lines 106–129).
- [x] **`loot abandon <version-id>` collapses the divergence** — abandoning
      `dev`'s version leaves the handle with `agent`'s single live version; the
      `!` is gone, the `change_id` survives (lines 131–142). Nothing is deleted.
- [x] **`loot undo` restores it — nothing was destroyed** — one undo walks the
      abandon back and the `!` returns with both versions (lines 150–160).

## What the run surfaced

Running the proof (not the read-only spec) surfaced one behaviour worth
recording:

- **`abandon` collapses the handle-level divergence, but not the tree-level
  conflict `converge` created.** Because both amends edited the *same line*,
  `agent`'s pull ran `converge_heads`, which folded the two divergent versions
  under one merge head *and* raised a per-**path** content conflict on `feat.txt`
  (lines 106–110, 123–126). The `!` divergence (per-`change_id`, ADR 0032) and
  the content conflict (per-path, ADR 0001) are **orthogonal** representations of
  the one two-writer event. `loot abandon` settles the *handle* — the `!`
  collapses — but the graph head is still the conflicted converge merge, so
  `loot conflicts` still reports `feat.txt` afterward (lines 144–148): settling
  the *tree* is a separate step. This is the "converge content-combination wart"
  already flagged in map #169's Fog; the signed, travelling resolution (one amend
  naming *both* live versions as predecessors) is the deferred
  [multi-predecessor path](https://github.com/Connor-Miller/loot/issues/169).
  Filed as a follow-up. The ticket's claim — the `!` divergence marker collapses
  under `abandon` and restores under `undo` — holds regardless.

## Done

- [x] Both acts pass in a committed, re-runnable script
      ([run](runs/amend-divergence-demo.txt), 2026-07-12) — divergence arises
      from ordinary concurrent work (control + real two-identity amend), renders
      with `!`, collapses via `abandon`, restores via `undo`, with no white-box
      construction. Resolves map #169's proof ticket
      [#172](https://github.com/Connor-Miller/loot/issues/172).
