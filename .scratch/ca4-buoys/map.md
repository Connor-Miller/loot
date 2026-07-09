# Map: Chart CA4 buoys to a hand-off-ready spec
GitHub: #71

<!-- wayfinder:map -->

## Destination

A single, implementation-ready spec for **CA4 buoys** — the `loot buoy`
navigational-role resolver over the shipped attestation lane — with every design
decision pinned so an implementer (or an AFK agent) can build it with no open
questions. Planning map: it produces the spec, not the implementation.

## Notes

**Domain.** loot is an encrypted-DAG source-control system. A **buoy** is the
derived, read-side landmark "the newest change attested with role X by a trusted
peer" (ADR 0018 attestation lane / ADR 0022 concurrent-agent model). `attest`
stays the *only* write-verb — a buoy adds no new write primitive. Source of the
chunk: `issues/CA4-buoy-resolver.md`.

**Grounding fact that shapes the whole design.** An attestation record is
`{ change_id, attester_pubkey, role: String (free-form), signature }`, signed
over `change_id ‖ attester ‖ role` — **there is no timestamp** in the record
(`crates/loot-core/src/attestation.rs`). So "newest attested change" cannot mean
newest-by-attestation-time; it must be defined over the **change graph** itself.
Trust mirrors grants: only attesters in the peer registry count (ADR 0015).

**Execution constraint.** Claude cannot run `cargo`/`rustc` in this environment.
Any decision needing empirical input (a prototype, a test run, inspecting real
attestation-lane behaviour) is handed to **Connor** to run in his Rust
environment; results come back into the ticket. Prefer decisions makeable from
reading the code; flag explicitly when a run is required (see ticket 03).

**Skills each session should consult:** `/grilling`, `/domain-modeling`,
`/prototype` (for prototype tickets), `/research`. Refer to tickets by name.

## Decisions so far

<!-- one line per resolved ticket: gist + link -->

- [01 — Resolver semantics](issues/01-resolver-semantics.md) — `loot buoy [role]`
  = the **maximal elements under the ancestor partial order** of {changes with a
  signature-verified, role-matching attestation from a trusted attester (peer
  registry **or self**), present locally}; whole-graph scope; one maximal → the
  buoy, several → **report ambiguity** (no auto-pick), none → "no buoy"; missing
  attested changes skipped silently (`--verbose` reveals). Pure function of
  (graph, attestation log, peer registry, role).
- [02 — Role vocabulary](issues/02-role-vocabulary.md) — bless exactly two
  documented roles (`reviewed` = peer vouched, `base` = integration landmark);
  **free-form, not an enum** (symmetric with `attest`); bare `loot buoy` defaults
  to `reviewed` (matches `attest`'s default). Typo-at-attest footgun accepted; a
  future "attest warns on unknown role" noted but out of scope.
- [04 — CLI surface](issues/04-cli-surface.md) — `loot buoy [role] [--verbose]
  [--porcelain|--json]` (reuses CA3's `OutFmt`); buoy defines its **own** frozen
  porcelain (`B`/`A` lines, not the per-path merge table) + json; exit codes **0
  resolved / 2 no-buoy / 3 ambiguous / 1 error**; `--from-buoy` **deferred** (needs
  `create_dock` base-at-change — the follow-on chunk). Deliberately extends machine
  output to a non-reconciliation verb → amends ADR 0023's scope note (spec must say
  so).
- [05 — Write the CA4 buoys spec](issues/05-write-spec.md) — **destination
  reached.** Spec written as `docs/adr/0025-buoy-resolver.md` (decision record +
  ADR 0023 amendment) and a rewritten, implementation-ready
  `issues/CA4-buoy-resolver.md` (resolver placement, acceptance criteria, Rust test
  plan). Ready to hand off to implementation.
- [03 — Rust run/verify loop](issues/03-rust-run-loop.md) — runbook for the
  Rust-capable environment: baseline `cargo test`, inner loop on
  `cargo test -p loot-core buoy`, a CLI smoke exercising exit codes `0/2/3/1`, and
  a paste-back format so run results flow back without a Rust env here. No decision
  needed it (resolver is a pure fn); it's implementation prep.

---

**Map status: destination reached — all children resolved.** Every buoy design
decision is pinned, the hand-off spec exists (ADR 0025 +
`issues/CA4-buoy-resolver.md`), and the build/verify loop is defined. Nothing left
on the frontier. Next step is implementation, not wayfinding.

## Not yet specified

<!-- in-scope fog; graduates into tickets as the frontier advances -->

_All decision-fog has cleared._ 01, 02, and 04 resolved every open buoy design
question, so the spec-assembly fog graduated into
[05 — Write the CA4 buoys spec](issues/05-write-spec.md). A resolver prototype was
judged unnecessary: 01 settled on a pure function over (graph, attestation log,
peer registry, role), directly unit-testable, so no throwaway prototype is needed.

## Out of scope

<!-- ruled beyond this destination; never graduates -->

- Other next-chunk candidates the destination excludes — each a separate future
  effort, not this map: **External-service escrow**, **S7 pluggable relay + S3
  driver**, **Relay announcement**, **S8 sparse views**, **S9 fault-injection
  harness**. (Only CA4 was shortlisted.)
- **Soft advisory claims** (intent-to-edit signal) — deferred in ADR 0022; not a
  buoy concern.
- **Implementing / building / shipping CA4** — the hand-off target downstream of
  this map, not a decision on the route.
