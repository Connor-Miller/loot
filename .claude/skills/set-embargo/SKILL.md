---
name: set-embargo
description: Set a path to embargoed with a reveal time — encrypted to everyone until a scheduled unix timestamp. Triggers on "embargo this path", "embargo until", "delayed reveal", "seal until <date>".
---

# set-embargo — seal a path until a reveal time

> ## ⚠️ HUMAN-IN-THE-LOOP — CONFIRM THE TIMESTAMP
> The reveal timestamp **is the whole point** of an embargo. Get it wrong and the
> content either unlocks early or stays sealed forever. **Never guess the reveal
> time or the path** — read them back to the human in human-readable form, confirm
> the unix conversion, and only then run the mutating verb. `loot push` deposits
> the timed grants and is a **disclosure barrier** (non-undoable, the
> `push`/`grant`/`maroon` class) — do not push until the human has signed off on
> the exact reveal time.

## Purpose

Embargo makes a path **encrypted to everyone, with the decryption key withheld
until a reveal time** (`CONTEXT.md`, Visibility → *Embargoed*). It models a
security fix or a delayed-reveal merge that is committed now but must stay
unreadable — even to peers who hold every other key — until a scheduled moment.

The mechanism the operator must understand: an embargoed key has **no bundle lane
at all**. Peers never receive it in a sync. Instead `loot push` deposits **one
timed SealedGrant per registered peer** into the relay's grant mailbox, and the
**relay withholds each grant until its own clock passes `reveal_at`**
(`CONTEXT.md`, Threat model / Escrow). The `reveal_at` rides inside the
grantor-signed envelope, so it cannot be altered without breaking the signature,
and the relay never takes a caller's clock. **The key does not travel until the
relay releases it** — a holder-adversary-proof embargo (a lying local clock, a
patched binary, or `.loot` inspection all fail, because the bytes are simply not
on any peer's machine before the reveal). Residual trust is only the relay
operator releasing on time.

## Triggers

Invoke when the human says any of: "embargo this path", "embargo `<path>`",
"embargo until `<date>`", "seal `<path>` until `<time>`", "delayed reveal", or
otherwise asks to hide a committed path until a scheduled moment.

## Type: HITL

The human owns two facts you must confirm before acting: the **exact path** and
the **exact reveal time**. Everything before `loot migrate` is read-only
conversation; `loot migrate`, the finalize, and especially `loot push` mutate and
disclose. Confirm, then act.

## The binary

Use the repo's release build, **not** the `loot` on `PATH` (that copy is a stale
pre-fix engine): `C:\Users\conno\source\repos\loot\target\release\loot.exe`.
Confirm the verb before you rely on it — `loot migrate --help` and
`loot embargo-status --help` explain rather than run. Run every command from the
**working directory / lane the human is in**; never reach into another checkout.

## Step 1 — Confirm the path and the reveal time (HITL)

Do not proceed until you and the human agree on both:

- **The exact path.** Confirm it exists and is committed —
  `loot log --path <path>` or `loot status`. Embargo re-seals content already in
  the tree; there is nothing to withhold from a path that was never captured.
- **The exact reveal moment**, stated in human terms *with a timezone* (e.g.
  "2026-08-01 09:00 America/New_York"). Read it back and get an explicit "yes".

## Step 2 — Convert the reveal time to a unix timestamp

The visibility spec takes **unix seconds**, not a date string. Convert
unambiguously (PowerShell, include the offset so there is no timezone guessing):

```powershell
[DateTimeOffset]::Parse("2026-08-01T09:00:00-04:00").ToUnixTimeSeconds()
```

Read the resulting integer back to the human alongside the human-readable date
and confirm they match. `loot embargo-status` will later echo the timestamp with
its human date — that is your cross-check.

## Step 3 — Migrate the path to embargoed

> **GROUNDING — do NOT hand-edit `.lootattributes`.** An earlier note said to
> edit the attributes file by hand; the real, signed path is the `migrate` verb,
> which records the visibility change into the working tree for you.

Run, from the human's working directory:

```
loot migrate <path> embargoed=<reveal-unix-ts>
```

`migrate` is a mutating verb — it auto-snapshots the working tree first (ADR 0030),
so no manual `loot status` is needed. Public → Embargoed is a **narrowing**, not a
demotion, so it needs **no `--allow-demote`** (that flag guards only *widening* a
path). If migrate refuses, read the typed error and stop — do not paper over it
with a flag.

## Step 4 — Finalize the change

`migrate` records the new visibility into the **working** change; it is not yet
signed. Finalize it the normal way for this position:

- Describe, then finalize: `loot describe -m "<why + reveal date>"` then `loot new`.
- Or, if this lane is landing to main, run it through the normal land flow (see
  the `land-change` skill) — the embargo rides the finalized change like any other.

Do not skip the finalize: an unsigned working change has no timed grants to deposit.

## Step 5 — Push to deposit the timed SealedGrants

```
loot push
```

This stows the change **and** runs the deposit pass: one timed SealedGrant per
registered peer for the embargoed path, deduped against the Manifest so an
interrupted push is resumable (`CONTEXT.md`, Threat model). **Until this push, no
peer can ever read the path** — not now, not after the reveal. This step is a
disclosure barrier: confirm the reveal time one last time before running it.

A recipient added *later* (`loot grant --relay <name> <path> <identity>` on an
embargoed path) inherits the same `reveal_at` — they get a timed grant, never an
early key.

## Step 6 — Verify

```
loot embargo-status <path>
```

Expect **embargoed until `<unix ts>` (`<human date>`)**. Confirm the timestamp and
human date are exactly what the human approved in Step 1. `embargo-status` checks
history, not just the working tree, so it is the authoritative read-back. Before
the reveal, `loot surface` will (correctly) not show the path's plaintext.

## Do / Don't

- **Do** confirm the path *and* the reveal timestamp with the human before any
  mutating verb — the timestamp is the whole point.
- **Do** convert the reveal time with an explicit timezone offset and read the
  unix integer back for confirmation.
- **Don't** hand-edit `.lootattributes` — use `loot migrate <path> embargoed=<ts>`.
- **Don't** expect `--allow-demote`; embargo narrows, it does not widen.
- **Don't** claim the embargo protects anyone until `loot push` has deposited the
  timed grants — before that the key never leaves this machine.
- **Don't** tell the human the key is "on peers but locked." It is **not on any
  peer** until the relay releases the timed grant at `reveal_at`.

## See also

- `CONTEXT.md` — Visibility (*Embargoed*), Sealed content, Escrow, Threat model,
  SealedGrant.
- `diagnose-visibility` skill — the read-only counterpart when a path is *missing*
  and embargo is one suspected cause.
