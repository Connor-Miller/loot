# Shared object-store N-writer audit (map #227, ticket #230)

**Question.** With model C (ADR 0034), N lanes write the *one* shared object
store concurrently. ADR 0012 says the loose-object store is lock-free for
disjoint objects, and #219 made materialize capture-first. What is left that is
not concurrency-safe — which shared-store writes can race under concurrent
`loot new` / `apply` / harbor drain, whether an advisory lock is needed and
where its boundary sits, and what the failure/retry surface should be?

Audited against ADR 0034's sharpened rule — **no mutable file has more than one
writer** — not the literal model-C phrasing. Source refs are `crate/file:line`
at the tree the audit ran on (`4f0a34b`).

---

## TL;DR

- **The seal did most of the work.** Because only *signed, immutable* changes
  cross into the shared graph (ADR 0034), and `heads` is now **lane-owned** and
  `git-mirror/` is **harbor-owned**, the cross-lane shared-write surface shrinks
  to *concurrent appends* of three whole-file classes at the store root.
- **The change `graph` has a lost-update + torn-read race.** `save_to` does a
  read-merge-write of the whole `graph` file with a **non-atomic** `fs::write`
  (`engine.rs:823-835`). Two lanes persisting concurrently: last writer wins, the
  other lane's just-appended node is silently dropped; a concurrent `load` can
  decode a half-written file.
- **The custody / advisory metadata is worse than the graph.** `keyring`,
  `escrow`, `manifest`, `purges`, `attestations`, `identity` are written
  **whole from in-memory state with no union-with-disk** (`engine.rs:854-859`) —
  last-writer-wins *clobber*, not append, plus the same torn-write exposure. The
  ADR files `keyring`/`manifest` under "shared, append-only", but the code
  overwrites.
- **Objects are lock-free for disjoint addresses, but not for the same
  address.** Two writers of the *same* new object race on a shared temp path
  `{addr}.tmp` (`persist_codec.rs:100`) → torn temp or a rename-source-missing
  error. Disjoint-object writes are genuinely safe (distinct filenames).
- **No locking exists** anywhere in the store path (grep confirms: the only
  `Mutex` is the unrelated tokio one in the net relay).
- **Recommendation:** one OS-advisory store lock (`fs4`: `flock`/`LockFileEx`,
  so a crash auto-releases) held **only** around `save_to`'s shared-metadata
  critical section, plus make those shared writes atomic (temp+rename). Blocking
  acquire with a timeout; surface `StoreBusy` only on timeout.

---

## What the seal already removed from the surface

The ticket names "heads file, change graph, marks". Two of those are no longer a
cross-lane concern after ADR 0034 landed (#228/#231):

| artifact | class (ADR 0034) | writer | cross-lane race? |
|---|---|---|---|
| `heads` | lane-owned | one lane (`store.rs:366` → lane root) | **No** — each lane's own frontier |
| `working-change` | lane-owned | one lane | **No** |
| `git-mirror/marks`, `state`, `pr-map`, `wip` | harbor-owned | the harbor (serialized) | **No cross-lane** — harbor-internal only (#229) |
| `graph` | shared, append-only | any lane, at finalize | **Yes** |
| `keyring` `escrow` `manifest` `purges` `attestations` `identity` | shared | any lane, every persist | **Yes** |
| `objects/<addr>` | shared, append-only | any lane | only for the *same* address |

The seal (ADR 0034: unsigned WIP never enters the shared graph — `is_working_change`
at `engine.rs:2089` gates it out of the finalized union) means the shared graph's
writers only ever **append signed, immutable nodes**. That is what shrinks the
audit to "concurrent appends", exactly as the ADR predicted. It does **not** by
itself make those appends safe — see below.

**Harbor drain does not contend on the shared graph.** A signed change is
appended to the shared graph at *finalize* (`loot new`), not at land; the harbor
projects already-landed changes into `git-mirror/` (harbor-owned, serialized).
So the shared-`graph` writers are exactly **`loot new` finalize** and
**`apply`/pull ingest**, never the harbor. One fewer contender than the ticket
supposed.

---

## Race 1 — the change graph (lost update + torn read)

`save_to` (`loot-core/src/engine.rs:809`), reached from every mutation via
`Workspace::persist` (`loot-cli/src/workspace.rs:2431`) and per-batch during a
pull (`apply_bundle`, `workspace.rs:2025`):

```rust
// engine.rs:822-835
let mut finalized = ChangeGraph::new();
if let Ok(bytes) = std::fs::read(store.graph()) {        // (1) READ whole graph
    for node in persist_codec::decode_nodes(&bytes)? {
        if !is_working_change(&node) { finalized.insert(node); }
    }
}
for node in self.graph.in_order() {                      // (2) MERGE our nodes
    if !is_working_change(node) { finalized.insert(node.clone()); }
}
std::fs::write(store.graph(), encode_graph(&finalized)); // (3) WRITE whole graph
```

Two failures:

1. **Lost update (read-modify-write window).** Lane A reads `{X}`, merges `a` →
   `{X,a}`. Lane B reads `{X}` before A writes, merges `b` → `{X,b}`. A writes
   `{X,a}`; B writes `{X,b}` — **node `a` is gone from the shared graph.** The
   union is order-independent and idempotent (`ChangeGraph::insert` dedups by id,
   `change_graph.rs:147`), which is why this is *only* a lost-update window and
   not corruption — but a finalized, signed change silently vanishing from the
   store is a correctness break. It survives in the author lane's `heads`, so it
   reappears the next time that lane persists; the damage is a window where the
   shared store is missing a node another lane may already have built a view on.

2. **Torn read.** `fs::write` truncates-then-writes in place; it is **not**
   atomic. A concurrent `load` (`decode_nodes` at `engine.rs:1685`) can read a
   truncated file mid-write → `decode_nodes` fails (short buffer) or, worse,
   decodes a prefix as a shorter-but-valid graph. Objects avoid this with
   temp+rename; the graph does not.

## Race 2 — custody / advisory metadata (clobber, not append)

```rust
// engine.rs:854-859 — whole-file, in-memory state, NO union-with-disk
std::fs::write(store.keyring(),  encode_keyring(&self.keyring));
std::fs::write(store.escrow(),   encode_escrow(&self.escrow));
std::fs::write(store.manifest(), encode_manifest(&self.manifest));
std::fs::write(store.purges(),   encode_purges(&self.purges));
std::fs::write(store.conflicts(),encode_conflicts(&self.conflicts)); // lane-owned (store.rs:140) — safe
std::fs::write(store.attestations(), encode_attestations(&self.attestations));
```

Unlike the graph, these get **no read-merge**: each lane writes its own
in-memory copy. If lane A files a content key (`keyring`) or records a grant
(`manifest`) and lane B — which never loaded A's entry — persists afterward, **B
overwrites A's addition.** Same torn-write exposure as the graph. `conflicts` is
correctly re-homed lane-side (`store.rs:140`), so it is *not* in this set;
`identity` is effectively constant so its clobber is benign, but `keyring`,
`escrow`, `manifest`, `purges`, `attestations` are live shared-append data being
written last-writer-wins. **This is the biggest surprise of the audit:** the ADR
classifies them "shared, append-only", but the persistence path treats them as
single-owner overwrite. Under a genuinely shared store with concurrent
`apply`/grant traffic, they lose data.

## Race 3 — object store (same-address temp collision)

ADR 0012's "disjoint objects are lock-free" holds — distinct addresses are
distinct filenames, written temp+rename, skip-if-exists (`persist_codec.rs:92-104`).
But the temp path is **not** unique per writer:

```rust
// persist_codec.rs:100 — SAME temp path for the SAME address, any writer
let tmp = obj_dir.join(format!("{}.tmp", crate::hex::encode(&addr.0)));
std::fs::write(&tmp, encode_object(obj))?;
std::fs::rename(&tmp, &dest)?;
```

Two lanes storing the *same* new object (same sealed bytes → same address; e.g.
the same bundle applied in two lanes, or overlapping pulls) write the same
`{addr}.tmp` concurrently: interleaved writes can tear the temp, and whichever
loses the `rename` gets a source-missing `Backend` error. Final bytes are
byte-identical so the *rename result* is fine, but the path is racy. **Fix:**
unique temp suffix (`{addr}.{pid}.{rand}.tmp`). Small, standalone, and closes the
one gap in ADR 0012's lock-free claim.

---

## Answers to the ticket's three questions

### Q1 — which shared-store writes can race?

Under concurrent `loot new` (finalize appends one signed node) and `apply`/pull
(per-batch ingest appends signed nodes, files keys, writes objects):

- **`graph`** — lost update + torn read (Race 1). *The* graph-metadata race.
- **`keyring` / `escrow` / `manifest` / `purges` / `attestations`** — clobber +
  torn write (Race 2).
- **`objects/<addr>`** — only when two writers store the *same* address (Race 3);
  disjoint addresses are safe.
- **`heads` / `marks`** — *not* racy across lanes (lane-owned / harbor-owned).
  The ticket's premise here is superseded by ADR 0034.
- Harbor drain does not touch the shared graph at all.

### Q2 — advisory lock, and where is its boundary?

**Yes, one is needed** — for Races 1 and 2. Recommended shape:

- **One OS-advisory lock per shared store**, a file at the store root
  (`.loot/store.lock`), taken via `fs4` (`flock` on unix, `LockFileEx` on
  Windows — the dev environment is Windows). OS-advisory, not a hand-rolled
  lockfile, so **a crashed holder's lock auto-releases** — no stale-lock reaping.
  Per-store (not per-repo-tree) so co-located multi-repo lanes (ADR 0034) each
  lock their own store.
- **Boundary = the shared-metadata critical section only**, *not* the whole
  command: acquire immediately before the graph read (`engine.rs:823`), release
  after the last shared write (`engine.rs:859`). Objects (`engine.rs:816`) stay
  **outside** the lock (already safe once Race 3's temp name is fixed — keeps the
  O(delta) incremental write off the critical path). Lane-owned writes
  (`write_working_change` `engine.rs:846`, `write_heads` `engine.rs:851`,
  `working`, `next-change`) stay **outside** (single writer by construction).
- **Also make the shared writes atomic** (temp+rename, as objects already are).
  The lock stops concurrent writers; atomic rename stops a *crash* mid-write from
  corrupting the shared graph for everyone. Both are needed — they cover
  different failures.
- **The graph write should union under the lock** (it already reads-merges; just
  needs to do so *inside* the critical section). The custody/advisory files
  (Race 2) need the same read-merge-under-lock treatment, or to be re-homed to a
  single writer — see the follow-ups.
- **Architecture / seam.** The lock belongs at the `RepoStore` seam (layout's
  one owner, ADR 0017): a `RepoStore::lock_shared() -> StoreGuard` that `save_to`
  holds across the shared section. This composes with the harbor (#229): the
  harbor serializes the `git-mirror/` integrator; this lock serializes the
  store-side shared append. **#229 should decide whether they are one mechanism
  or two** — a daemon that owns both, or two independent advisory locks.

### Q3 — failure / retry surface

- **Blocking acquire with a timeout.** The critical section is a few-KB
  whole-file write — single-digit milliseconds — so a blocking `flock` is
  invisible in the common case and needs **no user-facing error and no backoff
  loop.**
- On **timeout** (suggest 5–10 s — long enough that only a wedged/crashed holder
  trips it, though OS-advisory locks make a crashed holder self-heal), return a
  typed **retryable** error `RepoError::StoreBusy { held_ms }`, surfaced by the
  CLI as *"another lane is writing the shared store; retry."*
- No stale-lock cleanup path is required (OS auto-release on process death).
- If a non-blocking acquire is preferred for responsiveness, use bounded
  exponential backoff (e.g. 5 tries, 10→160 ms) before `StoreBusy`. Blocking is
  simpler and recommended.

---

## Graduated follow-ups (feeds #229 and the map's Fog)

1. **Store-side shared-append lock** — implement Q2. Owned by / co-decided with
   **#229** (harbor daemon-vs-lock): the harbor and this lock are the two halves
   of "serialize the shared writers".
2. **Object-store temp-path collision** (Race 3) — unique temp suffix. Small,
   standalone defect; the one hole in ADR 0012's lock-free claim.
3. **Custody/advisory metadata is clobbered, not appended** (Race 2) — decide
   read-merge-under-lock vs single-writer, and make the writes atomic. The
   audit's biggest surprise; arguably its own ticket, as it is a correctness gap
   independent of the lock mechanism.

All three are *append*-safety, not *materialize*-safety — #219 already fixed the
tree-write side; this audit is the store-write side it named as still-open.
