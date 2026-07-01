# S6 — Resumable transfer

**Type:** AFK · **Priority:** mid (with S5, this is "sync v2") · **Source:** docs/lore-comparison.md (lore: resumable, out-of-order fragment transfer)

## What to build

Make push/pull resumable. A transfer interrupted partway resumes and sends only
the objects not yet delivered; because `stow` is append-only and idempotent,
re-sending is safe and re-running a completed sync is cheap. Builds directly on
the S5 negotiation (the "wants" set is what is left to send).

## Acceptance criteria

- [ ] An interrupted push, re-run, completes by transferring only the remaining objects (test kills mid-transfer, then resumes).
- [ ] An interrupted pull resumes equivalently.
- [ ] Re-running a completed push/pull is a no-op that transfers ~0 bytes (idempotent).
- [ ] No partial or torn object is ever surfaced or stowed (atomicity preserved).

## Blocked by

- S5 — Object-level "wants" negotiation
