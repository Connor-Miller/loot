# Foundation is the encrypted content-addressed DAG

## Status

accepted

## Context

The foundational storage model had to be chosen between two candidates, built
as competing spikes against a shared `Repo` contract (ADR 0001) and an
identical, generic workload (`loot-bench`):

- **`spike-dag`** — encrypted content-addressed DAG, log-structured store.
- **`spike-crdt`** — Automerge CRDT document store, filesystem as a projection.

Both implemented the same trait, passed the same correctness scenarios, and
were measured by the same harness. The decision was deliberately held open
until the bake-off ran, and sync was put *into* the bake-off specifically so
the CRDT could demonstrate its one structural advantage (conflict-free
convergence of concurrent edits) rather than being judged only on local perf.

## Decision

Adopt the **encrypted content-addressed DAG** as loot's foundation.

## Evidence

Verified by running the spikes (release mode, repeated runs), not by argument:

- **The CRDT's best case — N keyholders editing the *same* file concurrently,
  then converging — produced silent data loss.** Result, stable across runs:
  `conflicts=0` but `surviving_peer_edits=0/4`. Because content is stored
  encrypted, Automerge cannot perform its character-level merge; it treats the
  ciphertext as an opaque register and resolves concurrently with
  last-writer-wins. Zero conflicts here means edits vanished, not that they
  merged.
- **The DAG surfaced the conflict instead.** Same scenario: `conflicts=3`,
  `surviving_peer_edits=1/4` — peer 0's edit auto-applied, the other three
  flagged for a human. For source control, a conflict a human resolves is
  strictly safer than an edit that disappears.
- **Local/scale perf favored the DAG.** 2000-file write+checkout was a tie
  (~220-300ms each). At 50k files the DAG was ~4.5x faster (375ms vs 1.68s)
  with a slightly smaller sync bundle (12.2MB vs 13.3MB).

## Why this is the real reason (not just perf)

Per-content encryption — loot's entire thesis — **structurally disables the
CRDT's only advantage.** A CRDT merges by reading content; encrypted content
cannot be read by a peer without the key, so the model collapses to
last-writer-wins exactly where it was supposed to win. The CRDT would shine in
a *non-encrypted* VCS; that is not the product. The DAG pays none of that tax
and fails safe (conflict, not loss).

## Considered alternatives

- **CRDT document store (`spike-crdt`).** Rejected on the evidence above:
  silent data loss under encryption, slower at scale, and it required a
  bolted-on synthetic "change record" to even represent a discrete reviewable
  commit (a CRDT converges state, not commits).

## Consequences

- `spike-dag`'s model graduates into `loot-core`. `spike-crdt` is **retained,
  not deleted**, as the benchmark record backing this decision; it is marked
  non-canonical in CONTEXT.md and is not part of the product.
- The benchmark harness (`loot-bench`) and both spikes stay in the tree so the
  decision is reproducible (`cargo test --release`).
- **Known follow-up (the DAG's own sharp edge):** dedup keyed on a plaintext
  identity hash leaked a same-plaintext equality oracle. **Resolved in ADR 0004:
  drop plaintext dedup entirely.**
- Methodology and results are written up for humans in
  `docs/bakeoff/index.html`.
