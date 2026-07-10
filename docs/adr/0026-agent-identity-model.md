# Agent identity model: agents are clones

## Status

accepted

## Context

The thesis-proof milestone ("loot hosts loot", wayfinder map #54) requires the
dev and AI agents to exist as **distinct identities in one repo**: at least one
restricted path agents cannot read, and a grant/maroon cycle exercised for
real. Ticket #58 asked how agents exist as loot identities — granularity,
provisioning, bootstrap grants, and which content is genuinely sealed from
them — under one hard constraint: agents are ephemeral sessions, so the
identity lifecycle must not require per-session ceremony.

The physical dock model (ADR 0022 as reworked by PR #69) put `identity`,
`keyring`, the keypair, and `peers` in the **shared store's** `.loot/`. Every
dock over one store therefore shares one identity and one keyring: an agent
docking into the dev's store *is* the dev — it can open every restricted path.
Distinct identities over one store is an architectural fork, not a config
choice. Two honest shapes:

- **Agents work in their own clone.** Each agent identity is its own repo
  directory with its own `.loot`, keypair, and keyring, cloned from the live
  relay. Keyring separation is real by construction: the clone simply never
  receives restricted keys. Works today with zero engine work, and exercises
  the thesis surface — relay, remote grants, maroon over the wire.
- **Per-dock identity split.** Move identity/keyring/keypair/peers from the
  store into each dock; the store keeps only ciphertext + graph + manifest and
  becomes "a relay on your own disk". Thematically strong (the harbor becomes
  the cross-identity merge point) but a real layout-migration slice, and the
  milestone's standing preference is thesis-proof over feature-building.

## Decision

### Clones now, per-dock split later

For the milestone, **an agent identity is a persistent clone directory plus
its keypair**, synced through the relay. The per-dock identity split is
recorded as a post-milestone enhancement (its own issue), not built now.
Docks/harbor remain the *same-identity* parallelism tool; cross-identity
convergence goes through sync (`push`/`pull`, or local `bundle`/`apply`).

### One identity now, mint freely

The fleet starts with **one** agent identity. Minting another is deliberately
cheap — clone + `peer add` + allowlist line — so roles are added when
concurrent agents or per-role marooning actually shows up, not speculatively.
The ceremony constraint holds by construction: ceremony happens **once at
minting**; a session just starts in the clone directory and inherits its
identity. Session ≠ identity.

### Provisioning: script + docs

Minting is one command: a `new-agent.ps1` helper (pattern:
`test-repos/new-test-repo.ps1`) that clones from the relay, prints the new
pubkey, registers it in the dev repo's peer registry, and prints the
`LOOT_ALLOW_PUBKEYS` line for `scripts/.setup.env` (+ `npm run setup:loot`
re-run reminder, ADR 0014). A short docs page explains the model for future
sessions. Tracked as an execution issue.

### Bootstrap grants: none

A fresh agent clone receives public content automatically and is withheld
restricted keys by construction. Nothing is granted at bootstrap; grants
happen on demand — which is exactly the grant/maroon cycle the milestone
exercises as evidence.

### The genuinely sealed path is `docs/pitch/`

The zero-knowledge-host product/pitch notes are the restricted-from-agents
content: real private thinking that will actually be written this milestone
(not staged demo files), sealed `restricted=<dev identity>` via
`.lootattributes`. On-the-nose by design: the private content in the repo is
the pitch for private content.

## Consequences

- **#61 and #62 are hard prerequisites for the evidence.** The sealing surface
  is `.lootattributes`; forward-slash globs failing open to Public on Windows
  (#61) and silent visibility demotion (#62) would make the sealed path
  theater. Fix before claiming the milestone evidence.
- **Honesty note for the evidence checklist (#60):** on one machine under one
  OS user, "agents cannot read" is enforced by key custody *plus the agent
  harness's file sandbox* — an unsandboxed local process could read the dev
  keyring bytes off disk. Same honest-participant posture as the embargo
  threat model; state it, don't hide it.
- The agent's clone is loot-synced but not a git checkout; git dual-run stays
  in the dev repo. Divergence pain there is dogfood data per the map.
- Relay allowlist grows one line per agent identity; the allowlist lives in
  `scripts/.setup.env` (gitignored) and redeploys idempotently.
