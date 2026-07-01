# S1 — Format versioning + compatibility gate

**Type:** AFK · **Priority:** near-term (foundational) · **Source:** docs/lore-comparison.md; grill 2026-07-01

## What to build

Give loot's durable and on-wire artifacts an explicit, checked format version, so
later format changes stay safe and old content stays readable forever. Add a
version marker to the durable artifacts (repo state, sealed object, sync bundle)
and to the sync/push protocol, and check it on load and on receive: accept
anything a newer library knows how to read, and reject an incompatible-major
version with a clear, actionable error instead of a corrupt parse. Establish and
test the guarantee that a newer loot always reads what an older loot wrote.

This is the umbrella the other format-touching slices (S2, S3) extend, so it
goes first.

## Acceptance criteria

- [ ] Sealed object, repo state, and sync bundle each carry an explicit format-version marker (the push envelope already uses version byte `0x01` — bring the rest in line).
- [ ] Loading a repo or bundle written by an incompatible future major fails with a clear "unsupported format version — upgrade loot" message, not a panic or silent misparse.
- [ ] Loading an older but compatible format still succeeds (a golden-file fixture from a prior format round-trips).
- [ ] A short written compatibility policy ("newer reads older"; major = breaking) lands in docs.
- [ ] Tests cover newer-reads-older and incompatible-major rejection.

## Blocked by

- None — can start immediately.
