# S3 — Signed changes: author in id + validity enforcement

**Type:** AFK (design decided in ADR 0018) · **Priority:** near-term · **Source:** docs/adr/0018-signed-changes-authored-history.md

## What to build

Give history authorship. Today a change has no author and no durable signature;
the push-envelope signature only proves who *pushed* and is stripped at the first
relay hop. Per ADR 0018: fold the author's ed25519 pubkey into the change id, sign
the change id at `loot new`, carry author pubkey + signature in the sync bundle so
they survive relay hops, reject any change whose signature does not verify against
its claimed author on `apply` and `stow`, and show the author in `loot log`.
Author *trust* (must-be-a-registered-peer) is NOT enforced here — it stays
advisory (display), reusing the peer registry, with enforcement deferred.

## Acceptance criteria

- [ ] `compute_change_id` includes the author pubkey; the same edit by two identities yields different change ids.
- [ ] `loot new` signs the finalized change id; the working change (rewritten on `status`, ADR 0006) is not signed until finalized.
- [ ] Author pubkey + signature travel in the bundle and are preserved across a relay `stow` (verified end-to-end after A → relay → C).
- [ ] `apply` and `stow` reject a change with a missing or invalid signature for its claimed author (tests: tampered change, forged author).
- [ ] `loot log` shows the author, reverse-resolved to a peer name (short hex fallback).
- [ ] Change format version bumped under S1.

## Blocked by

- S1 — Format versioning + compatibility gate
