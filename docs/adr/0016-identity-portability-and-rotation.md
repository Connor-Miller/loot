# Identity portability and rotation

## Status

accepted

## Context

A loot identity is an ed25519 keypair at `.loot/id` (ADR 0014). Two machine-level
needs surfaced that ADR 0014 did not address:

1. **Portability** — running as the *same* identity on a second machine (laptop +
   desktop). Peers know you by pubkey; to be "the same you" elsewhere, that
   machine needs the same keypair.

2. **Rotation** — replacing a keypair (leaked key, or hygiene) while *remaining
   the same identity* to peers who know your old pubkey.

These look similar but differ enormously in difficulty. Portability is a file
copy. Rotation is a distributed-trust problem: every peer's registry binds you
to your old pubkey, every grant is sealed to your old key, and there is no signal
connecting old-you to new-you.

## Decision

### Portability: `loot id export` / `loot id import`, passphrase-wrapped

Rather than instruct users to copy a mode-0600 file by hand, provide:

- `loot id export <file>` — writes the identity keypair to `<file>`, wrapped with
  a passphrase (OpenSSH native encryption via the `ssh-key` crate).
- `loot id import <file>` — prompts for the passphrase, installs the keypair as
  this repo's identity.

Passphrase-wrapping the *exported* file is required: an exported key is the
highest-risk artifact (it travels, it can be copied, it may sit in a backup). A
dedicated command is also the natural home for a future "encrypt `.loot/id` at
rest" upgrade.

**Deliberate asymmetry:** the in-repo `.loot/id` stays *unencrypted at rest*
(protected by filesystem perms 0600, per ADR 0014), while the *exported* file is
always passphrase-wrapped. This is not an inconsistency — the threat models
differ. The in-repo key is guarded by the OS; the exported key is guarded by
nothing but the passphrase once it leaves the repo. At-rest encryption of
`.loot/id` remains a future upgrade (ADR 0014 left this open); export-with-
passphrase exercises that crypto path first and de-risks it.

### Rotation: deferred, shape sketched

*Amendment (2026-07-19, #16): rotation shipped as `loot id rotate`, following
exactly the shape sketched below — a new identity keypair plus a re-grant wave
reusing the existing [[Grant]] primitive, not key-succession. Each re-grant
preserves the original grant's `expires_at` (#20; expired grants are never
revived), the old key is archived alongside the keyring
(`.loot/id.rotated-<ts>`, never deleted — the emergency-rollback artifact),
and peers re-trust the new pubkey manually via `loot peer add`, as
anticipated. The signed-succession-statement variant remains unbuilt.*

Rotation was initially NOT implemented. We recorded its likely shape so a
future implementation does not start from scratch and so reviewers stop
re-suggesting a naive version:

- Rotation is probably best modeled **not** as cryptographic key-succession but
  as **"new identity + a re-grant wave"**: the rotated-in key is a fresh
  participant, and the holder re-grants it everything the old key could read,
  reusing the existing [[Grant]] and [[Maroon]] primitives rather than inventing
  a key-succession protocol.
- If true continuity is needed (peers automatically following the rotation
  without manual re-trust), it would require a signed succession statement
  ("key CD.. succeeds key AB.., signed by AB..") that peers consume into their
  [[Peer registry]]. This entangles with revocation (ADR 0009) and the trust
  model (ADR 0015) and must be designed deliberately.
- The leaked-key case is genuinely hard: if AB.. leaked, a succession signed by
  AB.. is itself suspect. This likely needs the same out-of-band re-verification
  that initial peer-add requires — which again favors the "new identity +
  re-grant" model over automatic succession.

## Consequences

### Positive

- Portability ships now with almost no new code and a safer surface than `cp`.
- The passphrase path is established early, smoothing both at-rest encryption and
  any future key-handling features.
- Rotation's shape is on record, so the deferral is informed, not an oversight.

### Negative / accepted

- No rotation today. A compromised key has no clean recovery beyond "become a new
  identity and get re-granted" — which is exactly the deferred model, just done
  manually. Acceptable until there is a real user with a real rotation need to
  design against.
