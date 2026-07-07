# Object-level "wants" negotiation on push/pull

## Status

accepted

## Context

A sync bundle ships every SealedObject referenced by the changes it carries. So
whenever two peers' changes overlap on objects, a peer re-downloads ciphertext it
already holds — pure waste on the wire. CONTEXT.md earmarked "object-level sync
negotiation" as an open item, and Epic's *lore* negotiates transfer similarly.

We want transfer to be minimal — send only what the receiver lacks — without
changing correctness or weakening the zero-knowledge posture (a relay must not
learn anything new).

## Decision

Add a content-address negotiation round *before* object bytes move. The **sender
offers** the object addresses in the closure of the changes it would send; the
**receiver replies with the subset it is missing** ("wants"); the sender then
transfers a bundle whose object *bytes* are limited to those wants.

- **Pull** (relay → client): `client → /offer(have)` returns the offered
  addresses; the client computes `missing_objects`; `client → /fetch(have, wants)`
  returns `bundle_wanted(have, wants)`.
- **Push** (client → relay): the client offers its object addresses; `→ /wants`
  returns the subset the relay lacks; `client → /stow(bundle_wanted(&[], wants))`.
- loot-core owns the logic — `offered_objects`, `missing_objects`,
  `bundle_wanted` (a shared `bundle_impl` with the object set filtered) — so it is
  unit-testable; loot-net is thin transport; the CLI orchestrates the rounds.
- **Only object ciphertext is negotiated.** Change metadata, public keys, escrow
  entries, and attestations always ride (they are tiny, and a peer may hold an
  object's ciphertext but not its key).
- **Correctness is unchanged.** `apply`/`stow` already ignore addresses they
  hold; a "want" outside the offered closure is simply ignored by
  `bundle_wanted`. The negotiation only trims bytes.
- **Zero-knowledge preserved.** The negotiation exchanges *content addresses*
  only — already relay-visible — never keys or plaintext.

### Wire versioning — no global major bump

S5 changes **no artifact layout**: a negotiated bundle is byte-identical to a
normal one, just carrying fewer objects. A global `FORMAT_MAJOR` bump (4 → 5)
would therefore be wrong — it would make a v4 relay reject a v5 client's
*identically-formatted* bundle (a lockstep upgrade for a purely additive
feature) and churn every golden for no layout change.

Instead, the **new negotiation messages carry the S1 format marker**
(`[major][minor]`), so the wire protocol is version-gated: a peer on an
incompatible future major is rejected with `UnsupportedFormat`, not mis-parsed.
This satisfies "versioned under S1" without the global-bump coarseness that
ADR 0020 flagged.

## Consequences

- A re-pull or re-push with nothing new transfers **~0 object bytes**;
  overlapping-but-unequal peers transfer only the object delta.
- Change metadata and public keys still re-ship on every sync (tiny). A future
  change-level "have" refinement could trim that too, but S5 targets object
  bytes, which dominate transfer size.
- The old `/negotiate` (full-bundle pull) is retained for `loot clone` — a fresh
  clone holds nothing, so negotiation offers no benefit — and as a fallback.
- Mixed-version deployment: the negotiation messages' marker gates
  compatibility; a pre-S5 relay simply lacks `/offer`, `/fetch`, `/wants`
  (`clone` still works via `/negotiate`).
