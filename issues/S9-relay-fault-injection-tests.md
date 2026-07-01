# S9 — Relay fault-injection test harness

**Type:** AFK · **Priority:** optional · **Source:** docs/lore-comparison.md (lore: lore-chaos-client)

## What to build

A property / fault-injection test harness for the relay and sync path that
interrupts, reorders, and duplicates operations and asserts loot's core
invariants hold: keyholder peers converge, no torn objects, idempotency under
duplication, and — critically — the relay never obtains plaintext or restricted
keys. Earns trust in "sync v2" (S5 + S6).

## Acceptance criteria

- [ ] The harness can inject dropped/interrupted transfers, reordered concurrent pushes (forked tips), and duplicate deliveries.
- [ ] After fault injection, keyholder peers converge to the same materialized state on `apply`.
- [ ] No partial object is ever observed; idempotency holds under duplication.
- [ ] A zero-knowledge assertion: the relay's stored bytes contain no plaintext or restricted keys across all injected scenarios.

## Blocked by

- S5 — Object-level "wants" negotiation
- S6 — Resumable transfer
