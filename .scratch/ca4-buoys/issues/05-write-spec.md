# 05 — Write the CA4 buoys spec (the hand-off deliverable)
GitHub: #76

Type: task
Status: resolved
Blocked by: 01, 02, 04

## Question

Synthesize the resolved decisions (tickets 01, 02, 04) into a single
implementation-ready spec for CA4 buoys — the map's destination. Nothing left to
decide; this is terminal synthesis.

The spec must cover:

- **Resolver** (01): candidate set (signature-verified, role-matching, trusted
  attester incl. self, locally present); whole-graph scope; "newest" = maximal
  elements under the ancestor partial order; one → buoy, several → ambiguous, none
  → no buoy; missing changes skipped (`--verbose` reveals). Pure function of
  (change_graph, attestation_log, peer_registry, local_pubkey, role) — name the
  module/seam and its unit tests (fake registry + fake log, like the converge
  key-oracle).
- **Roles** (02): `reviewed` / `base` documented, free-form (no enum), bare
  default `reviewed`.
- **CLI** (04): `loot buoy [role] [--verbose] [--porcelain|--json]`; buoy's own
  frozen porcelain (`B`/`A` lines) + json shapes; exit codes 0/2/3/1; `cmd_buoy`
  returns its own `ExitCode`.
- **ADR**: amend/supersede ADR 0023's "no machine output on non-reconciliation
  verbs" note, since buoy is agent-facing by design. Note whether a new ADR (0025)
  or an amendment is preferred.
- **Acceptance criteria + test plan** aligned with the existing `CA4-buoy-resolver.md`
  acceptance list, refreshed for the resolved semantics.
- **Out of scope, recorded**: `--from-buoy` / `create_dock(base-at-change)` as the
  named follow-on chunk.

## Notes

Where to write it: the implementation-ready home is `issues/CA4-buoy-resolver.md`
(update it in place) and/or a fresh ADR under `docs/adr/`. Verification of the
built result belongs to ticket 03 (the Rust run/verify loop), which is
independent of writing this spec.

## Answer

Spec written as two deliverables, both in the repo (not `.scratch/`):

- **`docs/adr/0025-buoy-resolver.md`** — the decision record: resolver semantics
  (maximal-under-ancestor), free-form roles, CLI + own frozen porcelain/json, exit
  codes `0/2/3/1`, `--from-buoy` deferral, and an **amendment to ADR 0023** (machine
  output belongs on agent-driven verbs, not only reconciliation verbs).
- **`issues/CA4-buoy-resolver.md`** — rewritten as the implementation-ready,
  AFK ticket: what to build, resolver placement (`loot_core::buoy::resolve`, pure
  fn, needs an `is_ancestor`/reachable helper), refreshed acceptance criteria, and
  a Rust test plan to run via ticket 03.

This is the map's destination. Nothing left to decide; only 03 (run/verify loop)
remains, and it is verification, not a design decision.
