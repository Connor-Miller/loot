# Sealed content is a deep module; keys live in a separate Keyring

## Status

accepted

## Context

loot's thesis — "permissioning is key management" — had no module. Encryption,
visibility, and embargo were implemented as loose functions on `DagRepo`
(`seal`, `resolve_key`, `decrypt`, `grant_ids`, `can_decrypt`) and were
re-implemented independently in the non-canonical `spike-crdt`. Two adapters
duplicating the same policy is the signal that a shared deep module is missing.

Worse, content keys lived *inside* each stored object's grant map, and the sync
wire format serialized that map verbatim. So `bundle()` shipped decryption keys
to peers who, per ADR 0001, should only ever relay ciphertext. The key-leak was
structural, avoidable only by careful serialization.

## Decision

Introduce a **Sealed content** module in `loot-core` (the graduation ADR 0002
calls for) with a deliberately small interface:

- `seal(bytes, visibility) -> (Oid, SealedObject, ContentKey)`
- `open(sealed, oid, reader, keyring, now) -> Result<Vec<u8>>`

And these shapes:

- A **SealedObject** carries ciphertext, nonce, visibility, and **grant ids**
  (identity *names*, never keys).
- A **Keyring** is an identity's separate custody of content keys (`oid ->
  key`). `open` reads keys from it.

Key custody rules:

1. **Keys live only in the Keyring**, never in a SealedObject. Storing or
   syncing a SealedObject therefore cannot leak a key — the leak is closed *by
   construction*, not by serialization discipline.
2. **`open` is the single authorization chokepoint.** It enforces embargo (via
   `now >= reveal_at`) first, then visibility, then decrypts. Embargo is a rule
   the Sealed interface owns, not a property of key custody — keeping the
   Keyring a dumb custody map.
3. **`seal` returns the freshly-minted key; the caller files it.** The backend
   (which already owns its keyring) grants the key to authorized identities.
   Sealed itself never mutates a keyring, keeping its interface to `seal`+`open`.

## Considered alternatives

- **Keep plaintext keys in-object, strip them in `bundle`.** Rejected: the leak
  is one careless wire-format edit away from returning; it is avoided by
  discipline, not structure.
- **Wrap keys in-object (encrypt each content key to each identity).** Viable
  and closer to real PKI, but keeps keys travelling with objects and is more
  machinery than the spike needs. The Keyring split is simpler and makes the
  leak impossible rather than merely hard.
- **Embargo enforced by a time-locked Keyring.** Rejected for now: it pushes
  time-awareness into key custody and complicates the Keyring interface. `open`
  time-gating is honest for a spike and testable as pure logic.
- **A SealStore facade owning seal+keyring+store together.** Rejected: it
  re-couples sealing with storage, fighting the planned object-store / change-
  graph split (candidate 3 of the architecture review).

## Consequences

- Encryption/visibility/embargo concentrate in one module with one test
  surface; embargo and grant logic become testable without a backend or disk.
- `spike-dag` becomes a caller of `loot-core::sealed`; the duplicated policy in
  `spike-crdt` is now redundant (it stays non-canonical regardless).
- The `bundle()` key-leak is closed: bundles ship SealedObjects, which contain
  no keys.
- Spike-honest limit: `open` time-gating means a determined keyholder could in
  principle bypass embargo locally. Real embargo (key escrow / time-lock) is a
  later decision, deferred deliberately.
- The plaintext identity-hash dedup oracle (ADR 0002's open question) is
  untouched here and remains open.
