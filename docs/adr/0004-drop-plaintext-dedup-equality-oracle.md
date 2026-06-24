# Drop plaintext dedup to close the equality oracle

## Status

accepted

## Context

ADR 0002 left one open question: the DAG stored a plaintext identity hash
(`blake3(plaintext)`) alongside each object so that equal plaintext sealed under
different keys could be deduplicated. This leaked a **same-plaintext equality
oracle**: anyone who could see the hash learned "these two objects hold the same
plaintext," without holding any key.

Two facts sharpen this against loot's thesis:

1. The identity hash was not only an in-memory index — `wire::encode` wrote it
   into the **sync bundle**. So a **relay** (the party who holds ciphertext but
   no key — loot's defining novel actor, ADR 0001) could read the wire and infer
   plaintext equality across content it cannot decrypt. That relay is precisely
   the adversary the privacy thesis exists to protect against.

2. ADR 0002's alternative fix — a **keyed identity hash**
   (`blake3(secret, plaintext)`) — does not help here. A relay is a repo reader,
   so it would hold any repo-level secret. To withhold the secret from a relay
   you would have to gate it behind content-key possession, which collapses back
   to per-content keying and eliminates dedup anyway. The keyed hash closes the
   oracle only against total outsiders, not against the actor that matters.

## Decision

**Remove plaintext dedup entirely.** Delete `identity_hash` from `SealedObject`
and from `seal()`; stop shipping it on the wire; drop the `by_identity` index
from the object store. Address content **only** by the hash of its ciphertext.

Identical-ciphertext dedup (`by_addr`) is **kept**: two objects with the same
content address are byte-identical ciphertext, which reveals nothing a relay
didn't already have. This is what makes re-applying a sync bundle idempotent.

## Consequences

- The equality oracle is gone from both the store and the wire. A relay can no
  longer infer plaintext equality. The thesis is served.
- Re-sealing identical plaintext now stores a distinct object (fresh random key
  and nonce per `seal`, so distinct ciphertext and address). In practice loot
  could never dedup these anyway — per-object random keying already prevented
  cross-key ciphertext dedup — so the plaintext hash was the *only* mechanism
  that dedup'd them, and it was the leak. The storage cost is real but small and
  is the honest price of the thesis.
- Considered and rejected: **convergent encryption** (derive the key
  deterministically from the plaintext) would restore cross-key dedup, but it
  *is* an equality oracle by construction — identical plaintext yields identical
  ciphertext. That trades the thesis for storage, the opposite of this decision.
- `spike-crdt` (non-canonical) still derives a deterministic OID from plaintext;
  it is the benchmark record, not the product, and is left untouched.
