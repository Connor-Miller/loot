# Buoys: a navigational-role resolver over the attestation lane

## Status

accepted — implemented (CA4, `097cb25`, PR #70; exercised by the map #119 evidence, `docs/evidence/concurrent-agents.md`)

Amends ADR 0023 (see "Amendment to ADR 0023" below).

## Context

The concurrent-agent model (ADR 0022) calls for a way to "mark a historical
change to build from" — a landmark — **without** a tag or a mutable ref, both of
which reintroduce the concurrent-writer race that model exists to avoid. ADR 0022
named the answer in the abstract (a **buoy** is "the newest change attested with
role X by a trusted peer") but left the resolver's semantics and surface
unspecified. This ADR pins them.

Two facts about the shipped substrate constrain the design:

- **The attestation lane already exists** (ADR 0018 / S4). An `Attestation` is
  `{ change_id, attester: [u8;32], role: String, signature }`, signed over
  `change_id ‖ attester ‖ role`, stored in `.loot/attestations`, verified
  drop-not-fatal, carried in the sync bundle. `attest` is the only write-verb; a
  buoy adds none. Engine API: `all_attestations()`, `attestations_for(id)`.
- **Nothing carries a trustworthy timestamp.** Neither an attestation nor a
  `ChangeNode` records wall-clock time; a `ChangeNode` has only `parents`, and the
  change graph orders purely topologically (`change_graph::in_order`, DFS
  parents-before-children). So "newest" cannot mean newest-by-time — it must be
  defined over the DAG shape.

## Decision

### A buoy is the maximal role-attested change under the ancestor order

`loot buoy [role]` resolves to a change as follows.

**Candidate set** — every change `c` such that:

1. `c` is present in the local store; and
2. some attestation `a` has `a.change_id == c`, `a.role == role`, and
   `a.signature` verifies against `a.attester`; and
3. `a.attester` is **trusted** — it is registered in the peer registry
   (`.loot/peers`, ADR 0014/0015) **or** it is the local identity's own pubkey
   (self-trust is allowed; "needs an independent reviewer" is a per-role
   convention for an orchestrator to enforce, not the resolver's job).

Attestations naming a change absent from the local store are **not** candidates
(you cannot build from what you do not hold); `--verbose` reveals them for
debugging.

**Scope: the whole change graph**, not just the current dock's ancestry. A buoy
is a landmark any dock may base off, so restricting it to one line would hide a
`reviewed` change on a sibling fork.

**"Newest" = the maximal elements of the candidate set under the ancestor partial
order.** A candidate `c` is *maximal* iff no other candidate is a descendant of
`c` (equivalently: drop any candidate that is an ancestor of another candidate).
This is exact in a DAG with merges — unlike an ancestor-count "depth", it never
mis-ranks changes across divergent merge paths — and is a pure function of the
parent edges already in `change_graph`.

- exactly one maximal element → that change is the buoy;
- more than one → the role is attested on mutually **incomparable (concurrent)**
  changes → **report ambiguity**, listing all maximal candidates, picking none;
- zero candidates → **no buoy**.

A hash-based tie-break (always return one) was rejected: the pick would flip as
concurrent history grows, which is exactly the moving-target a buoy exists to
avoid. Surfacing ambiguity mirrors how the converge classifier surfaces
`Conflict` rather than silently choosing (ADR 0001).

### Roles are free-form; `reviewed` and `base` are the documented conventions

`role` stays the free-form `String` it already is on an attestation — no enum, no
resolver-side validation — so `attest` stays uncoupled and no format-gated role
migration is ever needed. Two roles are documented conventions:

- `reviewed` — a trusted peer vouched for the change (sign-off);
- `base` — a landmark to build / rebase a dock from (integration base).

Bare `loot buoy` (no role) defaults to `reviewed`, matching `attest`'s existing
default. Accepted footgun: a mistyped role at attest time is unfindable; the right
fix is a warning at *attest* time and is out of scope here.

### CLI surface

```
loot buoy [role] [--verbose] [--porcelain | --json]
```

Format is selected by the existing shared `out_fmt()` / `OutFmt {Human, Porcelain,
Json}` helper (`--json` > `--porcelain` > human), reused from CA3.

Because a buoy is a change id (not a per-path merge), it does **not** reuse
`verdict::porcelain` (a `status<TAB>path<TAB>base<TAB>incoming` merge table).
It defines its **own** frozen, `FORMAT_MAJOR`-versioned porcelain following the
same principles (one line, leading status char, tab-separated, no repeated keys):

```
B	<change-id-hex>	<role>      # resolved  (B = buoy)
A	<change-id-hex>	<role>      # one line per candidate when ambiguous (A)
                                # no buoy → no lines; the exit code carries it
```

`--json`:

```json
{"role":"reviewed","status":"resolved","buoy":"<hex>","attesters":["<hex>", "..."]}
{"role":"reviewed","status":"ambiguous","candidates":[{"change":"<hex>","attesters":["<hex>"]}]}
{"role":"reviewed","status":"none"}
```

Human default: resolved → the short id, role, and attester names (mirroring `loot
log`'s attestation display); ambiguous → the candidates with a "resolve by
attesting one" hint; none → `no buoy for role 'reviewed'`.

**Exit codes** make the three outcomes agent-distinguishable with no parsing:

| code | meaning |
| --- | --- |
| `0` | resolved (id on stdout) |
| `2` | no buoy for that role |
| `3` | ambiguous (>1 maximal candidate) |
| `1` | error (bad args, IO) — unchanged, consistent with every other verb |

`cmd_buoy` returns its own `ExitCode` rather than the generic `Result<(), String>`
→ 0/1 path in `main`; only the `"buoy"` dispatch arm changes, the other verbs are
untouched.

### `--from-buoy` is deferred

`loot dock <name> --from-buoy [role]` (base a new dock at the resolved landmark)
is **not** in this chunk. `create_dock` has no base-at-change parameter today
(`cmd_dock` → `ws.create_dock(name, at)`), so it needs a new engine capability to
base a dock at an arbitrary change — a clean additive follow-on. Consequence:
buoys are **inspection-only** until it lands (an orchestrator or human reads
`loot buoy` and acts manually).

### Amendment to ADR 0023

ADR 0023 scoped machine output to the reconciliation verbs and said to "avoid
adding machine output to the ~25 non-reconciliation verbs." `buoy` is a
non-reconciliation, read-only resolver, yet it is **agent-facing by design** — an
orchestrator calls it to decide what to build from — so `--porcelain`/`--json`
belong here. This ADR amends 0023's scope note: machine output is added to a verb
when agents drive it, not only to reconciliation verbs. Buoy's porcelain is its
own contract, versioned with `FORMAT_MAJOR` exactly like the reconciliation one.

## Considered alternatives

**A tag / bookmark / mutable "latest-reviewed" ref.** Rejected in ADR 0022 and
again here: a single ref N agents race to move is the contention buoys avoid.

**Hash tie-break so `buoy` always returns one change.** Rejected: silent, unstable
pick that flips as history grows.

**Ancestry-of-current-tip scope.** Always well-ordered, but cannot point at a
reviewed change on a sibling fork — too narrow for `--from-buoy`'s intended use.

**Constrain `role` to an enum.** Rejected: asymmetric with the free-form writer
(`attest`), and a typo is already written before `buoy` ever runs; better fixed at
attest time.

**Reuse `verdict::porcelain`.** Rejected: it is a per-path merge table; a buoy is
a single id. Forcing that shape would corrupt the frozen reconciliation contract.

## Consequences

- Landmarks become a derived, race-free, forge-evident read over primitives that
  already ship (attestations + the change graph) — no new write-verb, no new
  stored ref.
- The resolver is a pure function of `(change_graph, attestation_log,
  peer_registry, local_pubkey, role)` — no disk, no keys, no clock — so it is
  unit-testable with fakes, like the converge key-oracle. No prototype needed.
- Buoy's porcelain/json shape and its exit codes (`0/2/3/1`) become a **frozen
  contract** once agents depend on them; versioned with `FORMAT_MAJOR` (ADR 0019).
- Buoys are inspection-only until `--from-buoy` / `create_dock(base-at-change)`
  ships as the follow-on chunk.
- The whole-graph scan is O(attestations + reachable changes) per resolve;
  acceptable at current scale, revisit only if it shows up in benchmarks.
