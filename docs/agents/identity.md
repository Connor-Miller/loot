# Agent identities: agents are clones

How AI agents exist as loot identities (ADR 0026, wayfinder #58). Read this
before starting a session that should act as a distinct identity in this repo.

## The model

An agent identity is a **persistent clone directory plus its keypair**, synced
with the dev repo through the relay (`https://relay.millerbyte.com`).
Identity is *not* per session: ceremony happens **once at minting**, and an
ephemeral session simply starts in the clone directory and inherits it.
Session ≠ identity.

Why clones and not docks: every dock over one store shares that store's
identity and keyring — an agent docking into the dev's store *is* the dev.
Keyring separation must be structural, and a clone provides it by
construction: the clone never receives restricted keys. (A per-dock
identity/keyring split — "the store as a relay on your own disk" — is the
recorded post-milestone alternative, #87.)

## Minting (once per identity)

```powershell
./tools/new-agent.ps1 <name>            # e.g. crew
```

The script clones the relay into `..\loot-crew\<name>` (fresh keypair minted
by `loot init`), registers the pubkey in this repo's peer registry
(`loot peer add`), and prints the one manual step: append the pubkey to
`LOOT_ALLOW_PUBKEYS` in `scripts/.setup.env`, then `npm run setup:loot`
(PowerShell, scripts repo) so the relay accepts the agent's pushes
(ADR 0014 allowlist).

Start with one identity; mint more only when concurrent agents or per-role
marooning actually shows up.

## What an agent can and cannot see

- **No bootstrap grants.** Public content arrives with the clone. Restricted
  keys are withheld by construction — the demo path genuinely sealed from
  agents is **`docs/pitch/`** (restricted to the dev via `.lootattributes`).
  An agent's `surface` simply skips it.
- Grants happen on demand (`loot grant <path> <name>`), and revocation via
  `loot maroon` — the on-demand cycle is itself milestone evidence, with the
  Manifest as audit trail.

## Session ritual

A session acting as an agent identity works in the clone dir like any repo:
`loot status` / `describe` / `new`, then `loot push`; `loot pull` to catch up
with the dev's pushes. Cross-identity convergence goes through sync — docks
and the harbor remain *same-identity* parallelism tools.

## Honesty note (threat model)

On one machine under one OS user, "the agent cannot read `docs/pitch/`" is
enforced by key custody **plus the agent harness's file sandbox** — an
unsandboxed local process could read the dev's keyring bytes off disk. This
is the same honest-participant posture as the embargo threat model, and the
milestone evidence states it rather than hiding it (ADR 0026).
