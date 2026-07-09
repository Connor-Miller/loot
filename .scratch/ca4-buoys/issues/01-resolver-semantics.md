# 01 — Resolver semantics: define "newest change attested with role X by a trusted peer"
GitHub: #72

Type: grilling
Status: resolved
Blocked by: —

## Question

Define precisely what `loot buoy [role]` resolves to. Attestations carry **no
trustworthy timestamp** (signed payload is `change_id ‖ attester ‖ role` only,
`crates/loot-core/src/attestation.rs`), so "newest" must be defined over the
change graph, not attestation time. Pin every sub-decision:

- **(a) "Newest" ordering.** DAG topological order? Change authored-validity
  order (ADR 0018 signs author + validity into the change)? Something else? And
  the **tie-break** when the role is attested on two *incomparable* (concurrent)
  changes — deterministic (e.g. by change id) or reported as ambiguous?
- **(b) Whose attestations count.** Peer-registry members only (mirroring the
  grant/attestation trust model, ADR 0015). Does the **local identity's own**
  attestation count — is self-trust in or out?
- **(c) Scope of changes considered.** The whole change graph, or only the
  ancestry of the current dock's tip?
- **(d) Missing change.** Behaviour when a trusted attestation names a change not
  present in the local store.

## Notes

This is the heart of CA4; ticket 04 (CLI surface) is blocked on it because output
shape follows the resolved semantics.

## Answer

`loot buoy [role]` resolves as follows.

**Candidate set.** All changes `c` such that: (1) `c` is present in the local
store; (2) some attestation `a` exists with `a.change_id == c`, `a.role == role`,
`a.signature` verifies against `a.attester`; and (3) `a.attester` is trusted —
i.e. `a.attester` is in the peer registry **or** is the local identity's own
pubkey (**self-trust: yes**). Attestations naming a change not in the local store
are simply not candidates (**missing change: skip silently**; reveal them under a
`--verbose` flag for debugging).

**Picking "newest" (scope: whole change graph).** The candidate set is drawn from
the entire change graph, not just the current dock's ancestry — a buoy is a
landmark any dock can base off (`dock --from-buoy`). Since neither changes nor
attestations carry a trustworthy timestamp, "newest" is defined **topologically**,
precisely as the **maximal elements of the candidate set under the ancestor
partial order**:

- A candidate `c` is *maximal* iff no other candidate is a descendant of `c`
  (equivalently: drop any candidate that is an ancestor of another candidate).
  This is exact in a DAG with merges — it avoids miscounting "depth" along
  divergent merge paths; it is a pure function of the parent edges already in
  `change_graph`.
- **Exactly one maximal element** → that is the buoy.
- **More than one maximal element** → the role is attested on two or more
  *incomparable* (concurrent) changes → **report ambiguity**: list all maximal
  candidates, pick none. (Mirrors loot surfacing `Conflict` rather than silently
  guessing, ADR 0001. A hash tie-break was rejected: the pick would flip as
  history grows, defeating the point of a stable landmark.)
- **Zero candidates** → "no buoy" (clean report, not an error — see ticket 04).

**Purity / testability.** The resolver is a pure function of
`(change_graph, attestation_log, peer_registry, local_pubkey, role)`. No disk, no
keys, no clock — unit-testable with fakes, exactly like the converge classifier's
key-oracle seam.

**Feeds ticket 04:** the ambiguous-result shape (how to print N concurrent
candidates) and the "no buoy" exit code are CLI-surface decisions, deferred to 04.

