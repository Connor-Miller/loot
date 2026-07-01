# S4 — Attestation metadata lane

**Type:** AFK · **Priority:** mid · **Source:** docs/adr/0018-signed-changes-authored-history.md

## What to build

Add the review/sign-off half of ADR 0018: allow extra, detachable signatures over
an existing change id — co-authors, reviewer sign-offs, countersignatures —
carried as metadata, not folded into the change id. `apply` verifies and stores
them; `loot log` and `loot manifest` display who attested what. Advisory only (no
enforcement), and they never affect the change id or convergence.

## Acceptance criteria

- [ ] A second identity can attest an existing change; an attestation is a signature over the change id plus the attester pubkey and a role/type tag.
- [ ] Attestations travel in bundles and are verified on `apply`; an invalid attestation is dropped, not fatal.
- [ ] `loot log` / `loot manifest` show attestations, reverse-resolved to peer names.
- [ ] Attestations do not change the change id and do not affect convergence.
- [ ] The attestation record is versioned under S1.

## Blocked by

- S3 — Signed changes: author in id + validity enforcement
