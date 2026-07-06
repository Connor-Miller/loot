# CA4 — Buoys: navigational-role resolver over the attestation lane

**Type:** AFK · **Priority:** near · **Source:** docs/adr/0022-concurrent-agent-model-docks.md; grill-with-docs 2026-07-06

## What to build

A way to mark a historical change as a landmark to build from — without a tag or
a mutable ref. Reuse the **attestation lane already shipped** (ADR 0018 / S4:
`loot attest <change> [role]`, `.loot/attestations`). A **buoy** is the derived,
read-side concept: "the newest change attested with a navigational role by a
trusted peer." Because attestations are append-only and signed, each buoy pins
one change immutably and "current" is *computed*, never a mutable ref — so it
carries none of the concurrent-writer race a tag or branch pointer would.

Establish a role convention (`reviewed`, `base`) and add `loot buoy [role]` that
resolves the newest change carrying that role from an identity in the peer
registry (untrusted attesters are ignored, mirroring the grant/attestation trust
model). Optionally add `loot dock <name> --from-buoy [role]` to base a new dock
at the resolved landmark.

`attest` stays the only write-verb — a buoy adds no new writing primitive.

## Acceptance criteria

- [ ] `loot buoy [role]` returns the newest change attested with that role by a registered peer; defaults to a documented role (e.g. `reviewed`).
- [ ] Attestations from identities not in the peer registry are ignored by the resolver.
- [ ] With no matching attestation, the command reports "no buoy" cleanly rather than erroring.
- [ ] (If included) `loot dock <name> --from-buoy [role]` bases a new dock at the resolved change.
- [ ] No new write-side primitive — buoys are derived from the existing attestation lane.

## Blocked by

- None — can start immediately (attestation lane ships today). The `--from-buoy` convenience soft-depends on CA1.
