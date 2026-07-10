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
- [x] #62 — attributes edit silently demotes restricted content to Public
- [x] #64 — `.lootignore` (pilot: one stray `status` sealed 38 MB of `target/`)
- [x] #65 — spurious conflict on content neither side edited
- [x] #66 — `loot gc` regression (merged in #17, gone from the CLI)

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

- [x] First agent identity minted and registered — #86 (`crew` @
      `..\loot-crew\crew` via `tools/new-agent.ps1`; peer registry + relay
      allowlist; clone verified: full public tree present, `docs/pitch/`
      absent)
- [x] **Sealed-path script**: the agent's clone surfaces the repo with
      `docs/pitch/` absent; the dev's surfaces it present. Script
      `scripts/sealed-path-demo.ps1`, output `runs/sealed-path-demo.txt` (run
      2026-07-10 against the live relay: a fresh non-dev clone materializes 90
      public paths and skips the sealed path; the dev repo (connor) reads
      `docs/pitch/zk-host.md`). Read-only — no push, no relay pollution.
- [x] **Grant/maroon script**: grant a restricted path to the agent → agent
      reads it → maroon the agent → agent's next pull carries the new seal it
      cannot open. Script `scripts/grant-maroon-demo.ps1`, output
      `runs/grant-maroon-demo.txt`. Hermetic against a local `loot serve` (the
      cycle mutates history, so it stays off the shared VPS DAG). The Manifest
      audit trail (grantor/grantee as pubkeys) is printed. NB: fixed a real bug
      en route — `loot maroon` recorded the re-seal change unsigned, so it never
      propagated (ADR 0018: only signed history travels); the CLI now finalizes
      it.
- [x] Honesty statement in the captured output: on one machine under one OS
      user, "agents cannot read" = key custody **plus the agent harness's file
      sandbox** (honest-participant posture, per ADR 0026). Both demos print it;
      grant/maroon also flags that already-decrypted bytes are not forward-secret
      (ADR 0009).

## C. Hard embargo (ADR 0027)

- [x] #14 — engine/wire: timed SealedGrant deposit, relay withholding,
      `FORMAT_MAJOR` bump
- [x] #88 — CLI: push deposits timed grants; `pull-grants` files revealed keys
- [x] **Attack-demo script (#89)**: a holder with an advanced clock, direct
      `.loot/escrow` inspection, and a patched binary **fails** to read the
      embargoed change before `reveal_at`, then reads it after the relay
      releases. Script `scripts/attack-demo.ps1`, captured output
      `runs/attack-demo.txt` (run 2026-07-10 against the live VPS relay; all
      three pre-reveal attacks failed, post-reveal read succeeded). The demo is
      **mailbox-only** — the timed SealedGrant is deposited to the holder's
      pubkey-addressed mailbox (self-draining) and the ciphertext travels as an
      out-of-band bundle file, so nothing is stowed into the relay's shared DAG.
- [x] Honesty statement in the captured output: the claim is
      **holder**-adversary-proof; residual trust is the relay operator
      releasing on time, and in this demo operator = dev (ADR 0027).

## Done

- [ ] All boxes above checked; map #54 Destination satisfied; milestone
      "loot hosts loot" closed with a link to this doc.
