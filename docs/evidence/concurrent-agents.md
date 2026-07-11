# Evidence: concurrent agents converge

The concrete, checkable proof for the concurrent-agents epic (wayfinder map
#119). The claim:

> **Two agents editing concurrently converge with no side silently dropped** —
> locally through docks + the harbor, and remotely through the relay's
> fork-collapse — and the whole reconciliation loop is **agent-drivable** via
> porcelain verdicts, with buoys marking integration landmarks and loot's
> per-path *merger vs. relay* split (ADR 0001) honored under concurrency.

Like the rest of `docs/evidence/`, the proof is a **re-runnable script** whose
captured output is committed beside it: script
[`scripts/concurrent-agents-demo.ps1`](scripts/concurrent-agents-demo.ps1),
output [`runs/concurrent-agents-demo.txt`](runs/concurrent-agents-demo.txt)
(run 2026-07-10, **all checks passed**). It runs in two acts.

This milestone was **proof + landing**, not construction: CA1–CA4 (docks,
`dock merge`+harbor, porcelain/JSON verdicts, `loot buoy`) were already on
`main`. Running the proof is what earned the last fixes — see *What the run
surfaced* below.

## Act 1 — local docks (same identity, one object store; ADR 0022)

Two docks fork off a base and edit concurrently, then integrate into a `harbor`
dock. Every reconciliation step is read back in **porcelain** — the agent's
driver.

- [x] **Two docks fork from a common base and edit concurrently** —
      `dock-a` and `dock-b` each add a disjoint file and both edit the same
      single-line `shared.txt` differently (run lines 22–39).
- [x] **`loot dock merge --porcelain` integrates into the harbor** —
      merging `dock-a` converges/merges cleanly (`=`/`M` rows, line 46–47).
- [x] **A genuine concurrent conflict surfaces — no side dropped** —
      merging `dock-b` yields `C shared.txt <base> <incoming>` alongside `=
      b-only.txt` (lines 51–52); `loot conflicts --porcelain` re-enumerates it
      for an agent to act on (line 57).
- [x] **`loot resolve` clears it and the integrated tree carries everything** —
      after resolve, `conflicts --porcelain` is empty and all three paths
      (`shared.txt`, `a-only.txt`, `b-only.txt`) are present (lines 61–66).
- [x] **A buoy landmarks the integration** — `loot attest <merge> base` then
      `loot buoy base` resolves the integration change, a *computed* landmark
      over the attestation lane, not a mutable ref (lines 88–93; ADR 0025).

## Act 2 — relay leg (two distinct identities; ADR 0001 / 0026)

A hermetic, local `loot serve` relay (mutating, so off the shared VPS DAG).
`dev` seals a restricted path and publishes; `agent` clones. Both then edit
**concurrently** and push — the relay's append-only DAG forks — and `agent`'s
pull collapses it.

- [x] **On clone, agent holds ciphertext but not the restricted path** —
      `secret.txt` is absent from its surface, no key (line 126).
- [x] **Two identities push concurrently → the relay DAG forks** —
      `dev` pushes `dev-feature.txt` (+ a `secret.txt` edit) and `agent` pushes
      `agent-feature.txt`, each a separate relay tip (lines 128–151).
- [x] **`loot pull --porcelain` collapses the fork — public work converges** —
      agent's pull reports `= dev-feature.txt` and merges dev's side in; after
      `surface`, agent's tree carries **both** concurrent features (lines
      154–168). No side dropped.
- [x] **The restricted path relays, not merges** — the path whose key agent
      does not hold surfaces as `R secret.txt` (RelayedUnmerged) and stays
      sealed: agent and the relay hold only ciphertext (lines 157, 169). This is
      the ADR 0001 per-path *merger vs. relay* split, under concurrency.
- [x] **Honesty statement in the captured output** — one machine, one OS user;
      "agent cannot read the restricted path" is key custody: the key never
      reached agent's keyring or the keyless relay (lines 182–185, ADR 0026).

## What the run surfaced (and fixed)

The read-only acceptance audit (#121) could not catch these; running the proof
did:

- **#128 — `pull`/`apply` never collapsed a concurrent two-writer fork.** Engine
  `apply_sync` ingested a peer's divergent tip as a *sibling head* and classified
  outcomes, but never merged tips — leaving the keyholder on `2 heads — diverged`
  with a working tree showing only its own side. Fixed with
  `Workspace::converge_heads` (the peer-side analogue of `merge_dock`), called by
  `pull` after ingest; `pull` also gained `--porcelain`/`--json`. Without this,
  Act 2 was not achievable at all. Regression test:
  `converge_heads_collapses_a_two_writer_fork_no_side_dropped`.
- **#126 — `loot dock merge` printed prose, not porcelain.** Routed through the
  CA3 verdict serializer so Act 1's central verb is agent-drivable.

## Done

- [x] Both acts pass in a committed, re-runnable script
      ([run](runs/concurrent-agents-demo.txt), 2026-07-10) — the epic's claim
      holds end to end (same-identity docks **and** cross-identity relay).
- [ ] Map #119 Destination satisfied; CONTEXT.md / ADRs reconciled to shipped
      reality (#124); CA2/CA3/CA4 (#50/#51/#52) and the buoys spec map (#71)
      closed under epic-landing (#125), linked to this doc.
