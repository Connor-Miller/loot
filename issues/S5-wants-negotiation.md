# S5 — Object-level "wants" negotiation

**Type:** AFK · **Priority:** near-term · **Source:** CONTEXT.md → Open / undecided ("Object-level sync negotiation"); docs/lore-comparison.md

## What to build

Stop re-shipping ciphertext a peer already holds. Add a content-address "wants"
round to push/pull: before object bytes move, the sender offers the object
addresses in the closure and the receiver replies with the subset it is missing;
only those transfer. Correctness is unchanged (`apply` already discards known
addresses) — this just makes transfer minimal. Realizes the object-level sync
negotiation already earmarked in CONTEXT.md.

## Acceptance criteria

- [ ] push/pull perform an address-level negotiation before transferring object bytes.
- [ ] A re-pull with nothing new transfers ~0 object bytes (asserted by a test).
- [ ] A peer missing only a subset receives only the missing objects (test with overlapping-but-unequal repos).
- [ ] Zero-knowledge posture preserved: negotiation exchanges content addresses (already relay-visible), never keys or plaintext.
- [ ] Wire protocol version bumped under S1.

## Blocked by

- S1 — Format versioning + compatibility gate
