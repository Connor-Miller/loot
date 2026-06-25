# Forward maroon: re-seal, re-grant, commit

## Status

accepted

## Context

ADR 0009 decided that revocation has two levels: forward maroon (cuts future
access without touching past keys) and hard maroon (adds a purge event for
managed machines). This ADR records the design decisions behind implementing
forward maroon.

The core constraint is immutability: content-addressed objects never change.
"Revoking" access to a sealed object cannot mean deleting or modifying the
ciphertext — it would break the content-addressed guarantee and corrupt history.
Forward maroon must instead produce a *new* object sealed under a new key,
committed as the new current version. The old object stays in the store; a peer
who already holds its key retains past access. That is explicitly the forward
maroon contract.

## Decision

**`DagRepo::maroon(path, marooned, now) -> Result<MaroonResult>`**

1. Resolve the current OID and visibility for `path` from the current tree.
   Return `NotFound` if absent.
2. Decrypt the current content using this identity's keyring. Return
   `Unauthorized` if the caller doesn't hold the key (you can't re-seal what
   you can't read — same invariant as `grant`).
3. Build the remaining grantee list: the current `Restricted` ids minus the
   marooned identity. If the content was `Public` or `Embargoed`, the caller is
   the only remaining grantee (narrowing from ANYONE-granted to Restricted).
4. `put()` the plaintext under the new `Restricted(remaining)` visibility,
   minting a fresh content key.
5. `commit()` a new Change with the updated path→new_oid mapping and an
   auto-generated message.
6. For every remaining non-self grantee, call `grant(new_oid, grantee, now)`
   to produce a targeted key-handoff bundle. The caller delivers these bundles
   to the remaining grantees out-of-band (same pattern as `loot grant`).

Return a `MaroonResult { new_oid, grants }` so the CLI can write the grant
bundles to files and print delivery instructions.

## Considered alternatives

**Mutating `grant_ids` on the existing SealedObject.** Tempting because the
OID would stay the same, but the OID is `blake3(nonce || ciphertext)` — it
does not cover `grant_ids`. So grant_ids could be mutated without changing the
OID, and the marooned identity would still be able to decrypt using the old key
they hold. Re-sealing under a new key is the only mechanism that actually cuts
access.

**Deleting the old object from the store.** Would break immutability and
corrupt any peer who already holds the old bundle. The old object stays; the
change graph simply stops pointing to it as the current version.

**Shipping the new key to all peers in a regular bundle.** A regular bundle
only ships keys for ANYONE-granted content. Re-sealing under `Restricted`
means the key is never in a regular bundle — only in targeted grant bundles.
This is correct: the key must not travel to untargeted peers, including the
marooned identity.

## Consequences

- `MaroonResult` is a new public type exported from `loot_core`.
- `loot maroon <path> <identity> [dir]` writes grant bundles for remaining
  grantees and instructs the operator to also run `loot bundle` to distribute
  the re-sealed object.
- Forward maroon on Public/Embargoed content always narrows to Restricted; the
  operator should explicitly re-grant other identities if that is not the intent.
- Hard maroon (ADR 0009) extends this with a purge event in the bundle wire
  format, and is the next build step.
