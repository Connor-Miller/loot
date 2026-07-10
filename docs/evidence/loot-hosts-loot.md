# Evidence: loot hosts loot

The concrete, checkable definition of done for the thesis-proof milestone
(wayfinder map #54, resolved by ticket #60 on 2026-07-09). The thesis —
*visibility and permissions are properties of content and changes, not of the
repository* — is proven when every box below is checked. Demo claims are
**re-runnable scripts** whose captured output is committed beside this doc
(`docs/evidence/scripts/`, outputs in `docs/evidence/runs/`); the daily-driving
leg is a dated log (section A). This doc itself rides the relay: the proof is
content in the repo the thesis is about.

## Prerequisites (must land before evidence counts)

- [x] #61 — `.lootattributes` forward-slash globs fail open to Public on Windows
- [ ] #62 — attributes edit silently demotes restricted content to Public
- [ ] #64 — `.lootignore` (pilot: one stray `status` sealed 38 MB of `target/`)
- [ ] #65 — spurious conflict on content neither side edited
- [ ] #66 — `loot gc` regression (merged in #17, gone from the CLI)

#61/#62 gate every sealed-path claim (a fail-open seal is theater); the rest
gate daily driving (per the #56 pilot, a day fighting these is not a day of
evidence).

## A. Daily driving — 5 consecutive working days

A day counts iff **every change to this repo that day is finalized in loot and
pushed to the relay the same day**; git dual-runs as backup only (commits may
batch, but loot is the primary record). Divergence pain is logged per day —
that log is dogfood data, not failure.

| Day | Date | Changes pushed | Divergence / friction notes |
|-----|------|----------------|------------------------------|
| 1   |      |                |                              |
| 2   |      |                |                              |
| 3   |      |                |                              |
| 4   |      |                |                              |
| 5   |      |                |                              |

- [ ] 5 consecutive working days completed and logged above

## B. Agents as distinct identities (ADR 0026)

- [ ] First agent identity minted and registered — #86 (`new-agent.ps1`,
      peer add, relay allowlist)
- [ ] **Sealed-path script**: the agent's clone surfaces the repo with
      `docs/pitch/` absent; the dev's surfaces it present. Captured output
      committed.
- [ ] **Grant/maroon script**: grant a restricted path to the agent → agent
      reads it → maroon the agent → agent's next pull carries the new seal it
      cannot open. The Manifest audit trail (grant + re-seal events, as
      pubkeys) printed in the output.
- [ ] Honesty statement in the captured output: on one machine under one OS
      user, "agents cannot read" = key custody **plus the agent harness's file
      sandbox** (honest-participant posture, per ADR 0026).

## C. Hard embargo (ADR 0027)

- [ ] #14 — engine/wire: timed SealedGrant deposit, relay withholding,
      `FORMAT_MAJOR` bump
- [ ] #88 — CLI: push deposits timed grants; `pull-grants` files revealed keys
- [ ] **Attack-demo script (#89)**: a holder with an advanced clock, direct
      `.loot/escrow` inspection, and a patched binary **fails** to read the
      embargoed change before `reveal_at`, then reads it after the relay
      releases. Captured output committed.
- [ ] Honesty statement in the captured output: the claim is
      **holder**-adversary-proof; residual trust is the relay operator
      releasing on time, and in this demo operator = dev (ADR 0027).

## Done

- [ ] All boxes above checked; map #54 Destination satisfied; milestone
      "loot hosts loot" closed with a link to this doc.
