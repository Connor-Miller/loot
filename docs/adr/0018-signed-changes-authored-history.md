# Signed changes: authored, tamper-evident history

## Status

accepted

## Context

A `ChangeNode` today is `{ id, parents, message, tree }`, and
`compute_change_id` is `blake3(message, parents, tree)`. There is no author and
no signature. History is *tamper-evident* — the parent hash chain means a
revision cannot be silently rewritten — but it is not *attributed*: loot has no
notion of who authored a Change.

The push envelope (ADR 0014) signs the push **in transit** and gives the relay
accountability for "who pushed," but that signature is verified and stripped
before `DagRepo::stow`; it does not travel with the Change. A Change relayed
A→C carries zero proof of authorship — the re-pusher wraps it in their own
envelope. So authorship dies at the first hop.

This is a gap in the thesis. "Permissioning is key management," and grants are
already forge-evident (ADR 0015), yet the Change — the reviewable,
permission-bearing unit of history — is anonymous. loot already has ed25519
identities, one signing primitive, and a `known_hosts`-style peer registry, so
*authored history* is a natural extension of machinery already built. It is also
a genuine leapfrog: hash-chain-only systems (git by default, and Epic's lore,
which is tamper-evident but not attributed) do not seal *who* wrote history.

## Decision

### Author is part of change identity

Fold the author's ed25519 pubkey into the change id:
`blake3(author_pubkey, message, parents, tree)`. Authorship is **intrinsic** —
a Change cannot be relabelled from Alice to Bob without becoming a different
Change. Because descendants hash-chain over parent ids, any descendant
cryptographically seals the authorship of its entire ancestry.

Consequence, accepted deliberately: the same edit made by two identities is two
distinct Changes (no cross-author change dedup). For code this is correct —
authorship is real, and nobody can silently adopt another's change id. Sealed
content **objects** still dedup by ciphertext address (ADR 0004) regardless; only
the tiny change-node metadata differs.

### Changes are signed at finalization

The author signs the change id with their ed25519 signing key at `loot new`
(finalization) — **not** on every working-change snapshot. `status` rewrites the
working change in place (ADR 0006); its identity is ephemeral until `new`, so
signing it on every snapshot would be churn with no durable meaning. The
signature covers the change id and is stored **beside** the node, not folded into
the id: identity stays a pure function of authored content, and re-signing never
forces more descendant rewriting than necessary. `author_pubkey` + `signature`
travel in the sync bundle (an additive wire field).

### Signature validity is always enforced; author trust is policy

- **Validity** — `apply` and `stow` reject any Change whose signature does not
  verify against its claimed `author_pubkey`. Because the author is *in the id*, a
  stripped signature cannot be silently tolerated: the id still names an author,
  and no valid signature for it means reject. This is not a toggle.
- **Trust** — whether you trust an author is a separate question. `loot log`
  shows the author, reverse-resolved to a peer name (ADR 0015 model). Enforcing
  that authors be registered peers (quarantining unknown-author Changes, mirroring
  `pull-grants`) is **opt-in policy** reusing the [[Peer registry]] and the
  `serve --allow` allowlist. Deferred, so open relays stay open by default.

### Attestation lane for extra signatures

Additional signatures — co-authors, reviewer sign-offs, countersignatures —
attach to a change id as **detachable metadata**, *not* folded into the id. They
are verified and displayed (`log` / `manifest`) but are advisory. This mirrors
how a grant already works (a primary fact plus a detachable signed attestation,
ADR 0015), and gives loot a code-review / sign-off story later without another
identity redesign. The record format reserves room for it now; the
implementation is a follow-on slice.

## Considered alternatives

**Author as detachable metadata, id stays content-only** (the git signed-commit
shape). Rejected as the *primary* model: it makes authorship a soft, strippable
claim — an author-agnostic id cannot distinguish "never signed" from "signature
removed," and nothing binds ancestry authorship. loot's spine is that identity is
first-class and cryptographically bound (ADRs 0014, 0015), so authorship should
be as intrinsic and tamper-evident as content. The metadata shape is kept only
for *extra* attestations layered on top.

**Sign every working-change snapshot.** Rejected: the working change is rewritten
in place on each `status` (ADR 0006); repeatedly signing an ephemeral tip is
churn with no durable meaning. Sign once, at `new`.

**Fold the signature (not just the author) into the change id.** Rejected:
identity should be a pure function of authored content. The stable author pubkey
belongs in the id; the signature — a proof *over* the id — sits beside it, so
re-signing does not gratuitously change identity.

## Consequences

### Positive

- History is authenticated and non-repudiable, not merely tamper-evident: any
  descendant seals the authorship of its whole ancestry. A leapfrog past
  hash-chain-only VCS (git default; Epic's lore).
- Reuses the existing ed25519 primitive, peer registry, and `known_hosts` trust
  model — no new crypto, grain-of-the-project.
- The attestation lane opens a review / sign-off workflow later with no further
  identity redesign.

### Negative / accepted costs

- `compute_change_id` changes, so change ids differ from pre-0018 ids. This is a
  format break, gated behind the format version (see the format-versioning slice)
  with a "newer reads older" story; existing repos re-id on migration or are read
  under the older format version.
- Same-content edits by different identities no longer share a change id (minor
  graph overhead; content objects still dedup).
- Rotation stays modelled as "new identity + re-grant wave" (ADR 0016);
  re-attributing history to a rotated key would change ids, which we accept rather
  than attempt cryptographic key-succession here.

### Explicitly deferred

- **Author-trust enforcement** (quarantine unknown-author Changes) — opt-in
  policy reusing the peer registry, later.
- **The attestation lane implementation** (co-sign / review sign-off) — a
  follow-on slice; the format reserves room now.
