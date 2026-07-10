# 07 — Write the git interop bridge spec (the hand-off deliverable)
GitHub: #85

Type: task
Status: resolved
Blocked by: 04, 06

## Question

Synthesize the resolved decisions into a single implementation-ready spec — the
map's destination. Nothing left to decide; terminal synthesis.

Must cover:

- **Symmetry & visibility boundary** (01): git = surfaced readable tree of the
  syncing identity; sealed omitted; git→loot public-default via `.lootattributes`
  snapshot; trusted-remote constraint.
- **Change ↔ commit & DAG** (02): 1:1 + trailers; deterministic dates; refs per
  head + `main` at a designated dock; reverse via trailer short-circuit; mark map
  carries `origin`.
- **Identity & authorship** (03): identity map auto-seeded from git config; git-
  native → syncing-identity-or-legacy; SSH-signing + `Loot-Signature` trailer.
- **Divergence & reconciliation** (05): loot as authority (converge classifier);
  last-synced-pointer detection; conflicts resolved in loot; visibility invariant.
- **Mechanism & mark map** (06): plumbing, trigger verb, mark-map format, config.
- **ADR**: write a new ADR (git interop bridge — bidirectional mirror) recording
  the model + the trusted-remote and thesis (no-branches) notes.
- **Acceptance criteria + test plan** (run via the Rust/git handoff — see the
  ca4-buoys ticket 03 run-loop pattern).

## Notes

Where to write it: a fresh ADR under `docs/adr/` and an implementation ticket
under `issues/`. Verification runs in Connor's Rust/git environment.

## Answer

Spec written as two repo deliverables (not `.scratch/`):

- **`docs/adr/0028-git-interop-bridge.md`** — the decision record: symmetry &
  visibility boundary, change↔commit/DAG mapping + trailers + deterministic dates,
  identity map + SSH signing, loot-as-merge-authority reconciliation, and the
  `loot ferry` / git2 / mark-map mechanism, with considered alternatives and
  consequences (incl. the trusted-remote constraint).
- **`issues/GB1-git-interop-bridge.md`** — the implementation-ready, mostly-AFK
  ticket: what to build (projection, ingest, reconcile, mechanism), acceptance
  criteria, and a Rust+git test plan to run via the ticket-03-style handoff.

This is the map's destination. Nothing left to decide.
