# Per-object loose storage

## Status

accepted

## Context

The engine persisted the entire store as a single `repo` file: `save()` wrote
`persist_codec::encode_repo(&objects, &graph)` — the whole object store plus the
change graph — on every mutation. For a working repo that is fine. For a relay
(ADR 0011) accumulating many peers' worth of ciphertext, it is the real scaling
bottleneck: every `stow` rewrites O(store size) bytes to disk, regardless of how
few objects the push actually added.

This surfaced while designing the network layer. A relay takes pushes from many
peers, and the whole-repo-rewrite means push cost grows with total store size
rather than with the size of the delta. Bandaiding it with a write lock would
serialize correctly but leave the O(store) write cost in place. The bottleneck is
the rewrite, not the lock.

## Decision

Store each SealedObject as its own content-addressed file, written once and never
modified:

- An object lives at `objects/<hex-address>` where the address is its content
  address, `blake3(nonce || ciphertext)` (ADR 0004).
- Writes are atomic (write to a temp file, then rename). Writing an object the
  store already has is a no-op — the file already exists. Dedup is "does the file
  exist," and immutability is free because the filename *is* the content address.
- A push (`stow`) writes only the *new* object files: O(delta), not O(store).

The small metadata — change graph, Manifest, purges, keyring, escrow, conflicts —
stays as whole-file round-trips via `persist_codec`. These are tiny relative to
object content, so rewriting them per-mutation is negligible. Only the object
bytes, the thing that actually grows without bound, becomes incremental.

This is git's loose-object model, and the content-addressed design makes it
natural: an object's name is its address, so there is no rename-on-content-change
problem, no read-modify-write, and concurrent writers touching different objects
never collide (different filenames). Concurrent writers touching the *same* object
write byte-identical content to the same name — idempotent. This resolves most of
the relay concurrency concern for free: disjoint object writes are lock-free; only
the small shared graph metadata needs serialization, and that write is cheap.

## Considered alternatives

**Whole-repo single-file persistence (the status quo).** Simplest, and correct,
but O(store) write cost per mutation. Acceptable for a working repo, fatal for a
relay. Rejected as the relay's persistence layer; we are not bandaiding a known
bottleneck.

**Full incremental everything — objects, graph, and manifest as append-only logs
with packfiles and compaction.** What git eventually grows into. Rejected as
premature: the change graph and manifest are not the bottleneck, object bytes are.
Packing and compaction are months of work that target a cost we do not yet have.
We can add packing later behind the same object-store interface.

**Single-writer serialization without changing persistence.** Serializes pushes
correctly but leaves the O(store) rewrite in place — it addresses physical write
ordering, not the actual bottleneck. Rejected for the same reason as the status
quo.

## Consequences

- `object_store` persists each object as a loose content-addressed file; the
  write path is incremental (O(delta) per push).
- `save`/`load` split: objects are written incrementally as they are stored; only
  the metadata files round-trip whole.
- Concurrent `stow` of disjoint objects is lock-free; only graph-tip metadata is
  serialized.
- For the first slice, the in-memory model may eager-load objects on `load`; the
  write path (the bottleneck) is incremental regardless. Lazy object reads and
  packfiles are future refinements behind the same interface.
- Object-level sync negotiation (re-transmitting ciphertext the receiver already
  holds) remains a separate, still-open scaling question — this ADR fixes the
  *disk write* cost, not the *wire* cost.
