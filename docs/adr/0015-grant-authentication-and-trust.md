# Grant authentication and trust model

## Status

accepted

## Context

Sealed grant relay delivery (ADR 0014) lets a grantor seal a content key to a
recipient's pubkey and deposit it in a relay mailbox. As first shipped, the
receiving side (`apply_sealed_grant`) performed no authentication: any party
could deposit a blob sealed to bob's pubkey, and bob would unseal it, file the
content key, and gain access — with no record of who sent it. Worse, the
Manifest (loot's audit trail, ADR 0008) recorded only `(oid, grantee, granted_at)`
with no grantor field, so grant history was forgeable: a peer could fabricate
"who granted what to whom."

This undermines loot's thesis. "Permissioning is key management" only holds if
the record of key handoffs is trustworthy. Three distinct questions were tangled
together:

1. **Authenticity** — is this grant really from the key it claims to be from?
2. **Identity** — what is the stable identifier for grantor and grantee?
3. **Authorization to accept** — should I trust grants from this party at all?

A fourth question lurks beneath: **key provenance** — did the grantor legitimately
hold the key they are granting, traced back to the content's originator? This is
deliberately out of scope (see Consequences).

## Decision

### Grants are signed by the grantor (authenticity)

A sealed grant bundle is wrapped in the same push envelope used for `push`
(ADR 0014): `[0x01][grantor_pubkey 32][signature 64][tag-3 bundle...]`. One
signing primitive, one verification path, reused. `apply_sealed_grant` unwraps
and verifies the envelope first, yielding a cryptographically-bound
`grantor_pubkey`, before unsealing the wrapped content key.

### Grantor and grantee are pubkeys, not names (identity)

Local names ("alice", "bob") are nicknames from the [[Peer registry]] and carry
no global meaning — two repos can disagree on who "bob" is. The pubkey is the
only globally-stable identity (the SSH model: the key is the identity,
`~/.ssh/config` names are sugar).

- The Manifest `GrantEntry` becomes `(oid, grantee_pubkey, grantor_pubkey, granted_at)`.
- A grant is sealed to the grantee's **pubkey**; the CLI resolves a name argument
  to a pubkey via the peer registry before the engine is ever called.
- The mailbox is addressed by **grantee pubkey**, not name. As a bonus this
  stops the relay from learning recipient names in cleartext (tighter
  zero-knowledge posture).
- Names are reattached only at display time (`loot manifest` reverse-resolves
  pubkeys to peer names, falling back to short hex).

### The cryptographic unseal is the authorization gate (no name compare)

`apply_sealed_grant` previously checked `grantee_name != self.identity` and
rejected on mismatch. This is deleted. The real, unforgeable gate is: *if my own
x25519 key unseals the wrapped content key, the grant was for me.* A failed
unseal means it was not. The name compare was a weaker restatement of what the
ECIES already proves.

### Peer-registry membership gates acceptance (authorization to accept)

A valid signature proves authenticity, not trust. `pull-grants` accepts only
grants whose `grantor_pubkey` is a registered peer. A grant from an unknown
pubkey is fetched but **quarantined**: printed as "grant from unknown key
ab12… — run `loot peer add` to trust" and not applied. This is the
`known_hosts` model: you verify a key out-of-band once, then trust grants from
it.

## Consequences

### Positive

- The audit trail is forge-evident: the grantor pubkey is bound by the
  signature, so fabricated grant history is detectable.
- One identity primitive (the pubkey) end-to-end; local names are pure UX.
- The relay learns less (mailbox keyed by pubkey, not name).
- The trust decision is explicit and familiar (peer-add = verify fingerprint).

### Negative / accepted costs

- A first grant from a not-yet-registered party requires an out-of-band
  `loot peer add` before it will apply. This is *correct* friction — silently
  accepting keys from strangers is a supply-chain hazard — but it is friction.
- `pull-grants` now sends the caller's pubkey (not name) to address the mailbox;
  one more call site that speaks pubkeys.

### Explicitly deferred: key provenance chains

We do **not** prove that a grantor legitimately held the key they granted,
traced back to the content's originator. A signed grant from Eve for content Eve
does not "own" still verifies and (if Eve is a trusted peer) applies. We accept
this because:

- Eve can only grant access to a key she actually possesses, which is just Eve
  sharing her own access — the normal, intended use of grants.
- Proving originator-rooted provenance requires a chain-of-custody on keys and a
  defined originator-authority model, neither of which exists yet. Building it
  now would be speculative.

If an originator-authority model is later defined, provenance chains become a
natural extension: each grant could carry a back-reference to the grant that
authorized the grantor, verifiable to the originator. The signature and Manifest
structure decided here are the foundation that addition would build on.
