# Revocation has two levels: forward and hard

## Status

accepted

## Context

When access to a restricted file needs to be removed — someone leaves a team,
credentials rotate, a contractor's engagement ends — the system needs to answer
two distinct questions:

1. Can the revokee access *future versions*?
2. Can the revokee access *past versions they already have a key for*?

Content addressing means objects are immutable: once an OID exists in the
object store, its ciphertext is permanent. A peer who already holds the content
key can always decrypt past versions locally. Revocation cannot be purely
cryptographic against a party who already holds the plaintext key.

The question is whether loot should promise anything about past versions, and
if so, what operational mechanism backs that promise.

## Decision

**Two revocation levels, both in scope, sequenced:**

**Forward revocation** (`loot revoke --forward <path>`):
- Re-seals the content under a freshly-minted key
- Re-grants all currently authorized identities *except* the revokee
- Publishes a new Change with the new OID
- Makes no promise about past versions — the revokee retains any key they
  already hold

Natural for: "you may read the old code but not future updates" (contractor
off-boarded, OSS contributor lost commit access).

**Hard revocation** (`loot revoke --hard <path>`):
- Performs forward revocation (re-seal, re-grant minus revokee)
- Additionally publishes a **purge event** in the bundle wire format
- Peers who receive and honor the event remove the revokee's Keyring entry
  for the affected OID
- Best-effort operational guarantee: cooperating machines purge; a peer that
  is offline, has the old bundle but not the new one, or runs a modified binary
  cannot be forced. If the revokee already copied the plaintext, loot cannot
  help.

Natural for: "person left the org, managed machines should terminate access
to past versions as well."

**Honest scope of the guarantee:**
Hard revocation is not a cryptographic guarantee — it is an operational one.
Its value is that it handles the common case (cooperating machines, standard
binary) cleanly and signals intent clearly in the audit trail. It does not
promise to erase plaintext the revokee already extracted.

## Considered alternatives

- **Only forward revocation.** Rejected: insufficient for the "left the org"
  case where teams expect that past secrets are also terminated on managed
  machines, not just future ones.

- **Cryptographic hard revocation (key-wrapping, re-encryption of all past
  objects).** Would require re-encrypting every historical version under the
  new key set and distributing those re-encrypted objects to all peers — a
  large operation that still can't help if the revokee cached the plaintext.
  The operational guarantee of the purge event achieves the practical goal
  at far lower complexity.

## Consequences

- Forward revocation is built first; hard revocation extends it with a purge
  event added to the bundle wire format.
- Visibility migration (Restricted → Public or Public → Restricted) is
  implemented using grant + forward revocation over the affected identity set.
  It is not a separate primitive.
- The honest limit (past plaintext is not erasable) must be surfaced in user-
  facing documentation to avoid false promises.
