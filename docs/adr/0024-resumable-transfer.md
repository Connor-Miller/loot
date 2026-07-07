# Resumable transfer via batched, negotiated sync

## Status

accepted

## Context

A push or pull of a large object closure sends the ciphertext in one bundle. If
the transfer is interrupted — a dropped connection, a killed process — the relay
either received the whole bundle or none of it, so a re-run re-sends everything.
For big repos over flaky links that is the difference between "sync eventually
finishes" and "sync never finishes."

S5 already computes *what is left to send* (the negotiated "wants" set). S6 makes
that progress **durable** so a resume is cheap: send only the remainder.

## Decision

Transfer the wanted objects in **batches** rather than one monolithic bundle.

- `DagRepo::bundle_wanted_batched` computes the shared change delta, keys, and
  attestations **once**, then slices the object set into per-batch bundles. This
  keeps per-push/pull work O(graph\_size + N×batch\_payload) rather than
  O(N×graph\_size) that N separate `bundle_wanted` calls would cost.
- Each batch is stowed/applied and **persisted independently**: the relay saves
  after every `stow`; the client saves after every applied batch (via
  `Workspace::with_repo`). A completed batch is durable, so an interruption
  loses at most the single in-flight batch.
- **Resume is just re-running the command.** It re-negotiates (S5); because the
  delivered objects are now held by the receiver, the wants set shrinks to
  exactly the remainder, and only those objects transfer.
- **Idempotence.** `stow`/`apply` ignore objects and changes already present, and
  content addressing makes a re-sent object byte-identical, so re-running a
  *completed* sync is a no-op (~0 object bytes) and re-stowing a batch never
  duplicates.
- **Intra-batch atomicity.** Each loose object file is written temp-file-plus-rename
  (ADR 0012), so an interrupted write never surfaces or stows a torn object; a
  batch either fully lands or is re-negotiated and re-sent next run.
- **Cross-batch atomicity** is deliberately not provided. The change delta (change
  nodes, keys, attestations) rides every batch bundle and is persisted to the graph
  ahead of the object bytes it references. If a mid-pull failure leaves change
  nodes whose objects have not yet arrived, `loot surface` and `loot log` may error
  on those nodes until a re-pull completes. This is an acceptable trade-off:
  recovery is cheap (one re-pull), and providing cross-batch atomicity would
  require either buffering the entire transfer in memory before applying (defeating
  the per-batch persistence goal) or a two-phase protocol (significantly more
  complexity for a small benefit on typical connections).
- **Batch size: 32 objects.** Chosen to keep round-trips low on typical pushes
  (most repos transfer fewer than 32 objects per sync) while giving fine enough
  resume granularity on large initial syncs. Correctness is independent of this
  value; a completed batch is the unit of durable progress.
- **Merge outcomes.** `cmd_pull` merges per-path outcomes across batches with
  `converge::worst`, the same rule `apply_sync` uses within a single call, so a
  `Conflict` from an earlier batch cannot be overwritten by a later `Converged`.

At least one bundle is always sent even when no objects are outstanding, so the
change delta and attestations still propagate.

## Consequences

- An interrupted push or pull resumes and transfers only the remaining objects; a
  completed re-run moves ~0 object bytes.
- More round-trips than a single bundle (one per batch). `cmd_pull` refreshes
  `have` from the local heads after each batch, so the relay's change-delta
  computation stays proportional to actual remaining work rather than repeating
  the full delta on every request. A future streaming transport could collapse
  the round-trips entirely.
- **No format change.** S6 is pure client orchestration over the S5 negotiation
  and the append-only, idempotent `stow` (ADR 0011); `FORMAT_MAJOR` stays 4.
