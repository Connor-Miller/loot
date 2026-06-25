# Marooning has two levels: forward and hard

## Status

accepted

## Context

When access to a restricted file needs to be removed — someone leaves a team,
credentials rotate, a contractor's engagement ends — the system needs to answer
two distinct questions:

1. Can the marooned identity access *future versions*?
2. Can the marooned identity access *past versions they already have a key for*?

Content addressing means objects are immutable: once an OID exists in the
object store, its ciphertext is permanent. A peer who already holds the content
key can always decrypt past versions locally. Marooning cannot be purely
cryptographic against a party who already holds the plaintext key.

The question is whether loot should promise anything about past versions, and
if so, what operational mechanism backs that promise.

## Decision

**Two levels of marooning, both in scope, sequenced:**

**Forward maroon** (`loot maroon <path> <identity>`):

- Re-seals the content under a freshly-minted key
- Re-grants all currently authorized identities *except* the marooned identity
- Publishes a new Change with the new OID
- Makes no promise about past versions — the marooned identity retains any key
  they already hold

Natural for: "you may read the old code but not future updates" (contractor
off-boarded, OSS contributor lost commit access).

**Hard maroon** (`loot maroon --hard <path> <identity>`):

- Performs forward maroon (re-seal, re-grant minus the marooned identity)
- Additionally publishes a **purge event** in the bundle wire format
- Peers who receive and honor the event remove the marooned identity's Keyring
  entry for the affected OID
- Best-effort operational guarantee: cooperating machines purge; a peer that
  is offline, has the old bundle but not the new one, or runs a modified binary
  cannot be forced. If the marooned identity already copied the plaintext, loot
  cannot help.

Natural for: "person left the org, managed machines should terminate access
to past versions as well."

**Honest scope of the guarantee:**
Hard maroon is not a cryptographic guarantee — it is an operational one.
Its value is that it handles the common case (cooperating machines, standard
binary) cleanly and signals intent clearly in the audit trail. It does not
promise to erase plaintext the marooned identity already extracted.

## Considered alternatives

- **Only forward maroon.** Rejected: insufficient for the "left the org"
  case where teams expect that past secrets are also terminated on managed
  machines, not just future ones.

- **Cryptographic hard maroon (key-wrapping, re-encryption of all past
  objects).** Would require re-encrypting every historical version under the
  new key set and distributing those re-encrypted objects to all peers — a
  large operation that still can't help if the marooned identity cached the
  plaintext. The operational guarantee of the purge event achieves the
  practical goal at far lower complexity.

## Consequences

- Forward maroon is built first; hard maroon extends it with a purge event
  added to the bundle wire format.
- Visibility migration (Restricted → Public or Public → Restricted) is
  implemented using grant + forward maroon over the affected identity set.
  It is not a separate primitive.
- The honest limit (past plaintext is not erasable) must be surfaced in user-
  facing documentation to avoid false promises.
