---
name: rotate-key
description: Rotate the current identity's keypair — mint a new key, let `loot id rotate` run the expiry-preserving re-grant wave, then propagate the new pubkey to peers and the relay allowlist. Triggers on "rotate my key", "new keypair", "key rotation".
---

# rotate-key — rotate this identity's keypair and re-grant wave

> ## ⚠️ HUMAN-IN-THE-LOOP — NOT AUTOPILOT
> Rotation is a **distributed-trust** operation, not a local file swap (ADR
> 0016). It mints a new keypair, re-issues **every still-live grant** this
> identity holds, and archives the old key — but every peer's registry still
> binds you to your **old** pubkey, and the relay allowlist still admits the old
> key. Until each peer re-runs `loot peer add` and the operator updates the
> relay allowlist, your rotated identity is a **stranger** to them: grants you
> issue quarantine, and pushes under the new key can be refused. **Drive this
> with the human at every cascade step — never fire rotation and walk away.**

## Purpose

A loot identity is an ed25519 keypair at `.loot/id` (ADR 0014). Rotation
replaces that keypair while you stay **the same identity** to peers who knew
your old pubkey — the leaked-key or hygiene case. loot models this **not** as
cryptographic key-succession but as **"new identity + a re-grant wave"** (ADR
0016): the fresh key re-receives everything the old key could read, reusing the
existing [[Grant]] primitive.

The single command `loot id rotate` does the hard part **for you**:

- mints a new keypair (the new `.loot/id`),
- runs the **expiry-preserving re-grant wave** — re-issues every still-live
  grant this identity holds as a targeted bundle carrying its **original**
  `expires_at` exactly (an already-expired grant is never revived; a lapsing one
  is never silently extended, #20),
- **archives the old key** at `.loot/id.rotated-<ts>` — never deleted, it is the
  emergency-rollback artifact.

The re-grant wave is the part agents get wrong by hand. **Do not re-issue grants
yourself** — `loot id rotate` already did the whole wave. Your job is to run the
one verb, verify the new key took, and then shepherd the **out-of-band** trust
cascade to peers and the relay, which loot cannot do for you.

## Triggers

Invoke when the human says any of: "rotate my key", "rotate my keypair", "new
keypair", "key rotation", "my key leaked", or asks to run `loot id rotate`.

## Type: HITL

High-stakes and cascading. `loot id rotate` mints + re-grants (a grant is a
disclosure barrier — non-undoable, `CONTEXT.md`, Operation log & undo), and the
peer/relay propagation that follows is manual out-of-band re-trust that only the
human and operator can perform. Confirm before rotating; hand off the propagation
commands; do not assume the cascade is done.

## The binary

Use the repo's release build, **not** the `loot` on `PATH` (that copy is a stale
pre-fix engine): `C:\Users\conno\source\repos\loot\target\release\loot.exe`.
Confirm the verb before running it — `<binary> help` lists
`loot id rotate [dir]  new keypair + expiry-preserving re-grant wave into [dir]
(old key archived, ADR 0016)`. Run every command from the **repo / lane working
directory the human is in** — never reach into another checkout.

## Step 1 — Confirm intent and capture the old pubkey

- Record the identity you are about to retire: `loot whoami --pubkey` (bare
  OpenSSH line). Save this — peers still know you by it, and you will need to say
  "the key that *was* `<old-pubkey>` is now `<new-pubkey>`" when you re-trust.
- Confirm out loud with the human **why** they are rotating (leak vs. hygiene)
  and that they accept the cascade below. Do not proceed without a go-ahead.

## Step 2 — Rotate — `loot id rotate`

Run `loot id rotate` in the repo the human is in (the optional `[dir]` targets a
different repo; omit it to rotate here). One invocation:

1. mints the new keypair (installs it as `.loot/id`),
2. runs the **expiry-preserving re-grant wave** for all still-live grants,
3. archives the old key at `.loot/id.rotated-<ts>`.

**Do not** follow this with any `loot grant` — the wave already re-issued every
grant. Re-running grants by hand duplicates the manifest trail and is exactly the
mistake this skill exists to prevent. If a specific peer needs the re-issued
grants delivered, that is a normal `loot pull-grants` on **their** side once they
have re-trusted you (Step 4) — not a re-grant on yours.

## Step 3 — Verify the new key took

- `loot whoami --pubkey` — must now print the **new** pubkey, different from the
  old one you captured in Step 1. If it still shows the old key, rotation did not
  apply; stop and investigate (the old key remains at `.loot/id.rotated-<ts>`,
  so nothing is lost).
- Confirm the archive exists: `.loot/id.rotated-<ts>` should be present — the
  rollback artifact if anything downstream goes wrong.

## Step 4 — Propagate the new pubkey to peers (out-of-band)

The re-grant wave sealed grants to the new key, **but no peer trusts that key
yet** — their [[Peer registry]] still maps your name to the old pubkey, so a
grant from the new key **quarantines** on their side (`CONTEXT.md`, Quarantine).
loot has no automatic succession signal; re-trust is manual and out-of-band
(ADR 0016). For **each** peer repo that had this identity registered:

1. Deliver the new pubkey to that peer over a channel they can verify (the same
   care as an initial `peer add` — a rotation announcement is only as trustworthy
   as the channel).
2. On **their** machine they run:
   `loot peer add <your-name> <new-pubkey>`
   (re-adding under the same name rebinds it to the new key; `<pubkey>` of `-`
   reads the key from stdin). This clears the way for your re-granted bundles to
   apply instead of quarantine.
3. They then `loot pull-grants` and `loot surface` to pick up the re-issued
   grants under the new key.

Do not run `peer add` yourself against another checkout — hand each peer the
exact command and the new pubkey.

## Step 5 — Update the relay allowlist (operator-side)

The relay verifies every push envelope's signature and checks its **allowlist**
before stowing (`CONTEXT.md`, Push envelope). That allowlist still admits your
**old** key, so pushes signed by the new key can be refused. The allowlist is set
when the relay is served — `loot serve … --allow <pubkey> …` — so updating it is
an **operator** action, not something this repo can do remotely:

- Give the operator the new pubkey and ask them to add it to the relay's
  allowlist (per this project's deploy path — VPS relay work runs through the
  idempotent `scripts` repo, `npm run setup:loot`, never ad-hoc SSH).
- Once the new key is allowlisted, verify end-to-end with a real `loot push`
  (a 200/accepted stow proves the new identity is admitted).

## Step 6 — Report

Summarize for the human:

- old pubkey → new pubkey, and that the old key is archived at
  `.loot/id.rotated-<ts>` (rollback artifact — keep it).
- that `loot id rotate` already ran the re-grant wave (no manual grants issued).
- the propagation checklist and its state: which peers still owe a
  `loot peer add <name> <new-pubkey>`, and whether the relay allowlist has been
  updated. Rotation is not "done" until every peer has re-trusted the new key and
  the relay admits it.

## Do / Don't

- **Do** confirm intent and capture the old pubkey **before** rotating.
- **Do** verify `loot whoami --pubkey` shows the **new** key afterward.
- **Do** treat peer re-trust and the relay allowlist as required follow-through,
  not optional.
- **Don't** re-issue grants by hand — `loot id rotate` runs the whole
  expiry-preserving re-grant wave (that's the trap this skill guards against).
- **Don't** delete `.loot/id.rotated-<ts>` — it is the emergency-rollback key.
- **Don't** run `loot peer add` or touch the relay allowlist from this repo on a
  peer's/operator's behalf — hand them the command and the new pubkey; trust is
  re-established out-of-band.

## See also

- `CONTEXT.md` — Identity keypair, Identity portability, Peer registry, Grant,
  Grant expiry, Quarantine, Push envelope.
- `docs/adr/0016-identity-portability-and-rotation.md` — the rotation model
  (new identity + re-grant wave, archived old key, manual peer re-trust).
