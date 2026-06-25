# A relay stows bundles append-only and never merges

## Status

accepted

## Context

We are adding a network layer. The thesis reframes hosting: **a host is a relay
that never sleeps** — the same protocol role as any peer (ADR 0001's relay), but
always-on, well-connected, and holding no keys. A laptop, a `loot serve` box, and
a future hosted service are the same node type; they differ only in uptime and
whether they happen to hold keys. Getting the relay right means the host falls
out for free.

The problem: a relay must accept content pushed by many peers, but it holds no
keys, so it cannot read, merge, or resolve anything. The existing `apply`
operation classifies incoming changes against the local working tree and records
conflicts (ADR 0001). On a relay that path is meaningless: a relay has no working
tree, and two pushers' concurrent edits would manufacture "conflicts" the relay
can neither see nor resolve. A relay needs a fundamentally different ingest path
than a keyholder peer.

## Decision

A relay accepts a bundle via a new engine operation, **`DagRepo::stow(bundle)`**,
that is append-only and never merges:

1. Store every SealedObject in the bundle (content-addressed, idempotent — see
   ADR 0012), retaining any keys that rode along. Only ANYONE-granted (public)
   keys and embargoed escrow entries ever travel in a sync bundle; RESTRICTED
   keys never do (ADR 0003). So the relay's inability to read *restricted*
   content is automatic — it can never receive a restricted key — while public
   keys, which are non-secret by definition, are forwarded so a downstream peer
   receives readable public content. "Keyless" means **no restricted keys**, not
   zero keys.
2. Add every change-node as a new node in the change graph. Concurrent pushes
   produce multiple tips; the relay's graph is a forked DAG and that is correct.
3. Forward embargoed escrow entries and purge events so they keep propagating to
   downstream keyholders; the relay accumulates purges and re-emits them in its
   own outgoing bundles.
4. Never decrypt, never classify, never touch a working tree (it has none),
   never record a conflict.

Only sync bundles (tag 0) are stowable. A grant bundle (tag 1) is a targeted key
handoff with no meaning for a keyless relay, so `stow` rejects it rather than
silently dropping it.

Convergence is deferred entirely to keyholders: when a peer **pulls** from a
relay and `apply`s into its own working change, *that* node — which holds keys —
collapses the forks via the ADR 0001 classifier. The relay only ever accumulates
the union of every pushed DAG.

`stow` is a distinct named operation, not a flag on `apply` or an emergent effect
of an empty keyring. `apply` keeps its honest contract ("merge this into my
working change," for keyholders); `stow` means "store this cargo, never read it."
The two share a private object-storage helper but have separate entry points and
separate semantics. The name is nautical to match the domain (loot, Manifest,
Maroon, Escrow): you stow sealed cargo in the hold without opening it, and the
Manifest records what was stowed.

## Considered alternatives

**Relay maintains a merged authoritative graph (the GitHub model).** The server
holds "the converged truth." Rejected: merging requires reading plaintext, which
requires keys, which violates the thesis for any restricted or embargoed content.
A zero-knowledge relay structurally cannot be the merge authority.

**One `apply` that detects relay mode from an empty keyring.** Rejected: an empty
keyring is not the signal. A legitimate fresh keyholder peer also starts with an
empty keyring and *should* still merge into its working tree. Conflating "no keys
yet" with "I am a relay" is the trap. Making `stow` an explicit operation keeps
the relay role first-class and concentrates the store-and-forward behavior in one
place rather than scattering `if relaying { skip }` branches through `apply`.

**Symmetric `sync` that hides push and pull.** Rejected at the protocol level
(see CLI verbs): the mechanics are symmetric but the *intent* is not. A pull
receives ciphertext gated by the local keyring (safe by construction); a push
*publishes* sealed content to a node that persists it — a deliberate disclosure
event, exactly the moment the thesis cares most about. Push and pull stay
distinct verbs so the disclosure boundary is visible.

## Consequences

- `DagRepo::stow(bundle)` is a new engine operation. A pure relay only ever calls
  `stow` (on push) and `bundle` (on pull); it never calls `apply`.
- A relay's change graph legitimately holds multiple concurrent tips. Forks are
  collapsed only by keyholder peers on pull, never by the relay.
- The relay reuses the `.loot/` layout plus a `role` marker so `loot status` does
  not treat it as a working repo. Its keyring holds only forwarded public keys;
  it can never hold a restricted key, so it can never read restricted content.
- Concurrent pushes of disjoint objects need no lock (ADR 0012); only the small
  shared graph metadata is serialized.
- Push authentication is out of scope for the first slice (open relay). Content
  stays sealed so this is not a confidentiality hole; the exposure is storage
  abuse and lack of push accountability, deferred to a future identity-keypair
  foundation.
