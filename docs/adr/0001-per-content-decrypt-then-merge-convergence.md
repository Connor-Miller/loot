# Convergence is per-content, decrypt-then-merge

## Status

accepted

## Context

loot's thesis is that content can be encrypted to identities who lack the key
(private-in-public). We also decided sync must support concurrent offline edits
that **converge**, not just fast-forward. These collide: automatic content
merge requires reading plaintext, but a peer may hold only ciphertext. We had
to define the unit of convergence before writing either storage spike, because
both spikes implement the same `Repo` contract and must converge identically
for the bake-off to be fair.

## Decision

Convergence is **per-content, decrypt-then-merge**. Peers who both hold the key
for a unit of content perform a fine-grained merge of that content. A peer
without the key cannot merge it and may only **relay** its ciphertext. This
gives each peer one of two roles *per path*: **merger** (keyholder) or
**relay** (non-keyholder).

## Considered alternatives

- **Per-path, key-gated convergence.** Simpler (whole-file last-writer-wins or
  conflict), keeps the thesis intact, but throws away the fine-grained
  conflict-free merge that is the CRDT model's main reason to exist — which
  would bias the bake-off against CRDT before any code was written.
- **Leave it to the spikes.** Rejected: the contract could not freeze, so the
  spikes would diverge and stop being apples-to-apples.

## Consequences

- The `Repo` contract carries two peer roles per path (merger vs relay). Both
  the DAG and CRDT spikes must implement this, so it is shared complexity, not
  a CRDT-only concern.
- In the bake-off, the DAG competes on 3-way merge (conflicts possible) against
  the CRDT's conflict-free merge *among keyholders* — a fair, informative
  comparison.
- Sync is no longer "added later without changing the content model." It is now
  a foundational evaluation axis. CONTEXT.md updated accordingly.
