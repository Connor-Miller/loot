# Hard embargo is a timed SealedGrant withheld by the relay

## Status

accepted

## Context

ADR 0007's Escrow module raised the bar for embargo but, as CONTEXT.md's threat
model records, it enforces **cooperatively**: the key bytes sit on every
holder's machine (in `.loot/escrow`), gated only by a local-clock comparison. A
holder with a modified binary reads the bytes directly; a holder with an
advanced clock triggers `flush` early. Worse, the bundle wire format ships
embargoed keys **in plaintext** (the `escrow_entries` section, ADR 0007), so
every peer and every relay that stows the bundle physically holds the key
before `reveal_at`.

The thesis-proof milestone ("loot hosts loot", map issue #54) requires one
hard-embargoed change whose key a modified client cannot read early. Wayfinder
ticket #59 grilled the mechanism. Candidates: an escrow service on the relay
holding recipient-wrapped keys; drand timelock encryption (tlock); threshold
release among peers.

## Decision

Four decisions, grilled 2026-07-09:

### 1. Trust model: relay as timed custodian of wrapped keys

The relay withholds embargoed content keys until `reveal_at`, enforced by the
**relay's** clock, server-side. Keys are ECIES-wrapped to each recipient's
pubkey before deposit, so the relay holds only wrapped blobs — it can read
neither the keys nor the content. The zero-knowledge-host property is
preserved: custody without knowledge.

Threshold release was rejected because every "peer" in this milestone is
operated by the same person (self-trust × n). drand timelock was rejected *for
now* — it is the stronger claim (no trusted party at all) but adds an external
network and crypto dependency to the milestone's critical path for a
distinction (operator colluding with himself) the demo doesn't need; it is
recorded as the future operator-trust-removal hardening.

### 2. Delivery: relay-only; the plaintext bundle escrow section is removed

The `escrow_entries` bundle section (plaintext `(ContentKey, reveal_at)`
pairs) is **removed** — a breaking wire change gated by `FORMAT_MAJOR`
(ADR 0019). Peers receive embargoed keys only from the relay, after
`reveal_at`. The local Escrow module survives solely as the **originator's**
staging between `seal` and push; that residual honest-clock custody is moot
because the originator already knows the plaintext they sealed.

Consequence stated honestly: with no relay configured, embargoed keys never
reach peers — ciphertext still syncs via bundles, keys don't. Issue #14's
"local-clock path still works when no relay is configured" acceptance
criterion is dropped deliberately: dual-mode would make one `Embargoed` label
mean two different guarantees.

### 3. Deposit shape: a SealedGrant with a `reveal_at`, not a parallel system

A hard-embargo deposit **is** the existing SealedGrant frame (ADR 0014/0015)
carrying a `reveal_at`: one per recipient pubkey, deposited at push time,
default recipients = all registered peers (matching Embargoed's "everyone
reads after reveal" semantics). Adding a recipient later = issuing another
timed grant, like any grant.

The relay's new logic is one rule: exclude a timed grant from mailbox
responses until `now >= reveal_at`. Retrieval is plain `loot pull-grants` —
signature verification and unknown-grantor quarantine (ADR 0015) come free.
Issue #14's dedicated `PUT/GET /escrow/<oid>` endpoints are superseded: they
would duplicate the mailbox's delivery and verification machinery, and their
payload converges on SealedGrant anyway.

Integrity notes: `reveal_at` rides inside the grantor-signed envelope, so a
recipient cannot tamper with it; a recipient cannot forge an earlier-revealing
deposit because they cannot wrap a key they do not hold; a malicious
*depositor* shortening their own embargo is not a threat (the originator may
reveal their own content whenever they like).

### 4. The honest claim: holder-adversary-proof

Hard embargo is adversary-proof **against the holder**: a modified client
cannot read early because the key bytes are not on its machine until the relay
releases them. Trust moves to the relay operator — a distinct protocol role
that in production is a different party, and that holds only wrapped blobs. In
the milestone demo, operator = dev; the demo states this rather than hiding
it, and demonstrates the holder claim adversarially: an identity with an
advanced clock, direct `.loot/escrow` inspection, and a patched binary fails
to obtain the key before `reveal_at`, then succeeds after. The map
Destination's "adversary-proof" is amended to "holder-adversary-proof".

## Considered alternatives

- **drand timelock (tlock).** Encrypt the key to a future drand round; the
  published round signature is the decryption key. Zero self-trust — strictly
  the stronger claim. Deferred as post-milestone hardening (see Context above);
  composable with this design (timelock the SealedGrant payload).
- **Threshold release among peers.** Rejected for this milestone: all peers
  are one operator until a second human keyholder exists (map fog).
- **Dedicated `/escrow` endpoints (issue #14 as written).** Superseded — see
  Decision 3. Also, #14's original wire protocol deposited plaintext keys at
  the relay, which would have broken the zero-knowledge-host story outright.
- **Wrapped keys in bundles, local clock gate.** Closes the casual read, not
  the modified-binary one (wrapped blob + recipient privkey are both local).
  All the format churn, none of the guarantee.

## Consequences

- The D-threat closes against holders for real; the residual trust (relay
  releases on time) is an operator property, stated in the demo.
- Breaking bundle format change (escrow section removed) under the
  `FORMAT_MAJOR` gate.
- `Escrow::flush`'s network swap (the ADR 0007 seam) lands as "pull-grants
  surfaces timed grants when due", not a bespoke endpoint.
- Execution: issue #14 rewritten to the engine/wire slice (frame `reveal_at`,
  relay withholding, format bump); two sibling issues for the CLI/workspace
  slice and the attack-demo script.
- CONTEXT.md: threat-model paragraph and **Escrow** entry updated; the
  *External-service escrow* item leaves "Open / undecided".
