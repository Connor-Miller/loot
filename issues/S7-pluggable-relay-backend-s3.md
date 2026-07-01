# S7 — Pluggable relay backend + S3 driver

**Type:** AFK · **Priority:** mid · **Source:** docs/lore-comparison.md (lore: replaceable backends, lore-aws)

## What to build

Let a relay store its ciphertext objects in an object store, not just the local
filesystem — the step that turns "a host that never sleeps" into a real hosted
service. Extract a storage-backend seam (a `RelayStore` trait) behind loot-net's
loose-object storage and the grant mailbox, then add an S3-backed implementation.
`loot serve` can be pointed at object storage and still stores/forwards only
ciphertext, reading no plaintext. Loose ciphertext objects (ADR 0012) map cleanly
onto object stores.

## Acceptance criteria

- [ ] A `RelayStore` trait abstracts object put/get/exists and mailbox operations; the existing filesystem relay is one implementation behind it, with no behavior change.
- [ ] An S3-backed implementation passes the same relay integration tests (against a local S3-compatible server such as MinIO in CI).
- [ ] `loot serve` selects the backend via config/flag.
- [ ] The S3 relay never receives or stores plaintext or restricted keys — asserted by a test (zero-knowledge invariant).

## Blocked by

- None — can start immediately.
