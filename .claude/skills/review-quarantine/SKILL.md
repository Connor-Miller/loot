---
name: review-quarantine
description: Review grants quarantined from unregistered senders and decide, per sender, to trust or discard. Trusting registers a peer and re-applies their grants — an identity-verification call only the human makes. Triggers on "quarantined grants", "trust this key", "review quarantine", "loot grants --quarantined".
---

# review-quarantine — trust or discard quarantined grants

> ## ⚠️ HUMAN-IN-THE-LOOP — NEVER AUTO-TRUST
> `loot grants --trust <pubkey>` **registers a new peer** — it writes the sender
> into `.loot/peers`, loot's `known_hosts`, and re-applies every grant they sent.
> Trusting a pubkey is an **identity-verification decision**: it asserts "this key
> really is who I think it is," which can only be confirmed **out-of-band** (a
> call, a signal message, a business card — not the relay that delivered the
> grant). **The agent must NEVER trust a pubkey on its own judgment.** You list,
> you present, you explain the choice — the human names the key to trust. When in
> doubt, the safe action is to do nothing: an untrusted grant simply stays in
> quarantine, harming nothing.

## Purpose

`loot pull-grants` applies grants from **registered peers** and files everything
else in **quarantine** (`.loot/quarantine/<sender-pubkey-hex>/<oid-hex>`) rather
than dropping it — a grant from a pubkey the [[Peer registry]] doesn't recognize
is held, not trusted (ADR 0015; `CONTEXT.md`, Quarantine). This skill walks that
holding pen: it surfaces each quarantined sender so a human can decide, per
sender, whether the key is genuinely theirs (→ **trust**, which registers the
peer and re-applies their grants) or unknown/unwanted (→ **discard**, which is
simply leaving it in quarantine). Nothing here needs the sender to be reachable
again — the whole sealed grant already arrived; trust just unlocks applying it.

## Triggers

Invoke when the human says any of: "review quarantine", "quarantined grants",
"what's in quarantine", "trust this key", "who sent these grants", or asks to run
`loot grants --quarantined`.

## Type: HITL

The **listing step is read-only and safe** (`loot grants --quarantined`,
`loot peer list` — purely local, no network). The **decision is the human's**:
`loot grants --trust <pubkey>` crosses a trust barrier (it registers a peer and
applies grants) and must never run on agent judgment. This skill lists, presents,
and explains — then **stops and waits for the human to name the key**. Discard
needs no command at all.

## The binary

Use the repo's release build, **not** the `loot` on `PATH` (that copy is a stale
pre-fix engine): `C:\Users\conno\source\repos\loot\target\release\loot.exe`.
Confirm the verb with `<binary> grants --help` (look for `--quarantined` and
`--trust`). Run every command from the **working directory the human is in** —
never reach into another checkout or lane. Quarantine is shared-store-rooted (one
identity's mailbox, not a lane concern), so any position of this repo sees it.

## Step 1 — List what is quarantined

```
<binary> grants --quarantined
```

Lists every pending entry: **sender pubkey (hex)**, **oid**, and **received
time**. This is local only — no relay call. (If nothing has been fetched yet,
`loot grants` peeks the relay mailbox count and `loot pull-grants` drains it; any
grant from an unregistered sender quarantines on the way in.)

- **Empty** → there is nothing to review. Say so and stop.
- **One or more entries** → group them **by sender pubkey** (a single sender may
  have several quarantined oids) and go to step 2.

## Step 2 — Present each sender to the human

For each distinct sender pubkey, present a compact block the human can act on —
do **not** decide for them:

- **Sender pubkey (hex)** — the full key, verbatim. This is the only globally
  stable identity a bare quarantined grant carries (no nickname), and the exact
  string `--trust` expects.
- **Received at** — when each grant landed.
- **What arrived** — the oid(s) held for this sender, and the on-disk paths
  `.loot/quarantine/<sender-pubkey-hex>/<oid-hex>` so the human can inspect the
  raw entries if they wish.
- **Is this sender already known?** — cross-check the pubkey against
  `loot peer list`. If it is somehow present there, note it (the grant likely
  quarantined before the peer was added — trusting is then a no-op re-apply).

State plainly, for each sender: *to accept, verify this pubkey out-of-band, then
trust it; to reject, leave it — quarantine holds it harmlessly.*

## Step 3 — Human decides, per sender

**Stop here and hand the decision to the human.** Do not proceed without an
explicit, per-sender instruction. For each sender:

- **TRUST** (human has verified the key is really theirs, out-of-band) — the
  human runs, or explicitly directs you to run:
  ```
  <binary> grants --trust <sender-pubkey-hex>
  ```
  This registers the sender as a peer (named by its own pubkey hex, since a bare
  key carries no nickname) **and** re-applies every still-held grant of theirs,
  moving each out of quarantine as it succeeds. A grant that fails to re-apply
  (e.g. an expired grant — expiry is re-checked on trust, no free pass for
  having waited) **stays** quarantined rather than being dropped.
- **DISCARD** (unknown, unwanted, or unverifiable) — **do nothing.** Leave the
  entry in `.loot/quarantine/`. It is inert: it is never applied, never counted
  as visible, and can be reviewed or trusted later. There is no "delete" verb and
  none is needed.

## Step 4 — Confirm the outcome

After a trust the human authorized, re-run `<binary> grants --quarantined` to
confirm that sender's entries have cleared (any that remain failed to re-apply —
report which and why, e.g. expired). Then `<binary> surface` shows the
newly-readable paths the applied grants unlocked.

## Guardrail

The one rule that cannot be relaxed: **the agent never chooses to trust a
pubkey.** Presenting a sender is not a recommendation to trust them; only the
human, having verified the key out-of-band, may name a key for `--trust`. If the
human is unsure, the correct answer is to leave it in quarantine — an untrusted
grant costs nothing.

## See also

- `CONTEXT.md` — Quarantine (#12), Peer registry, Grant, Grant expiry, Grant
  discovery (`grants` / `pull-grants`).
- `diagnose-visibility` — the sibling skill for "why can't I see a path?"; its
  quarantine branch lands here.
