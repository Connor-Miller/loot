# Context: loot

A from-scratch source-control system. Working thesis: **visibility and
permissions are properties of content and changes, not of the repository.**
This is the one git complaint from the source material that nobody has solved;
it is loot's reason to exist.

## Glossary

**loot** — the project / the CLI binary.

**Change** — the reviewable, permission-bearing unit of history (loot's answer
to a git commit). A Change carries a set of paths, each with its own
visibility. Permissions attach here, not to the repo.

**Working change** — the always-present change at the tip that the working tree
*is* (JJ-style, ADR 0006). There is no separate "commit" step: `status`
snapshots the tree into the working change; `describe` names it; `new` finalizes
it and starts a fresh one on top. This kills git's add/commit ceremony.

**Snapshot (reconcile)** — turning the current working tree into the working
change, *visibility-aware* (ADR 0006). Against the last change's full tree, at
time `now`: paths the current identity can open are updated/deleted to match the
tree; paths it cannot open are carried forward unchanged (never seen, so never
changed); a write onto a non-visible path is refused (no silent clobber of
sealed content). Lives in the engine (`DagRepo::snapshot`); the Workspace only
supplies the tree.

**Workspace** — the CLI module owning the *process-bound ambient repo*: it
discovers `.loot/`, supplies the current identity and the clock, and persists on
mutation. Commands are thin verbs over it; the snapshot invariant and clock
injection live here. See ADR 0006.

**Visibility** — the access policy on a unit of content. One of:

- *Public* — readable by anyone who can read the repo.
- *Restricted* — readable only by named identities (key holders).
- *Embargoed* — encrypted to all; key withheld until a reveal time. Models
  embargoed security fixes and delayed-reveal merges.

**Identity** — a keyholder. Visibility is ultimately enforced by who holds the
decryption key for a unit of content. "Permissioning is key management."

**Sealed content** — the module that owns loot's thesis: encryption, visibility,
and embargo behind two operations. `seal(bytes, visibility)` produces a
*Sealed object* plus a freshly-minted content key; `open(sealed, reader, now)`
is the single authorization chokepoint — it enforces embargo (by `now`), then
visibility, then decrypts. Nothing else in the system decides who may read
content. See ADR 0003.

**Sealed object** — ciphertext + nonce + visibility + the *grant ids* (the
identities permitted to hold a key). It deliberately does **not** contain any
content key, so storing or syncing a Sealed object can never leak a key.

**Keyring** — an identity's private custody of content keys (`oid -> key`), held
separately from Sealed objects. `open` reads from the keyring; a relay simply
has no keyring entry and therefore cannot decrypt. Keys live here and only here.

**`.loot/`** — a repo's on-disk state (ADR 0005): `identity` (the ambient
keyholder), `repo` (sealed objects + change graph), and `keyring` (this
identity's keys, LOCAL-ONLY — never bundled). Written/read by the engine's
`save`/`load`; the CLI is process-per-command and round-trips through it.

**`.lootattributes`** — a gitattributes-style file mapping path globs to
visibility (`.env restricted=alice`, `*.md public`). The Workspace reads it on
snapshot to seal each path; unmatched paths default to Public. This is the
user-facing surface of the thesis — where you declare a file private.

**loot (the CLI)** — the first product crate (`loot-cli`, binary `loot`):
`init`, `status`, `describe`, `new`, `checkout`, `log`, `bundle`, `apply`. Thin
verbs over the [[Workspace]]; the JJ-style working change replaces git's
add/commit ceremony. Demonstrated end-to-end: a sealed `.env` checks out for its
keyholder and is silently skipped for anyone else, from the same repo and change
— and a non-keyholder's re-snapshot carries it forward rather than deleting it.

**Sync (`bundle`/`apply`)** — one-way transport via a bundle file (ADR 0001
realized in the CLI). `loot bundle <file>` writes ciphertext plus *only* the
keys for `ANYONE`-granted content (restricted keys never travel). `loot apply
<file>` merges idempotently and prints each path's outcome: *converged* (new or
identical), *merged*, *conflict*, or *relayed* — the last being the novel role,
where a non-keyholder carries ciphertext it cannot read. Demonstrated: Bob
applies Alice's bundle and stores her sealed `.env` as ciphertext he can't
decrypt.

**Object** — a content-addressed unit of stored bytes. In the encrypted-DAG
model, objects are encrypted independently (see *Sealed object*) and addressed
**solely** by the hash of their *ciphertext*. There is no plaintext-derived
identity; equal plaintext sealed under different keys is stored separately.

**Content address** — `blake3(nonce || ciphertext)`. The only identity an object
has. Two objects share an address only if their ciphertext is byte-identical,
which reveals nothing a relay didn't already hold — so address-equality dedup is
safe. Plaintext-equality dedup was removed because it leaked an equality oracle
to relays (ADR 0004).

**Sync** — bringing two repos into agreement. Now an *evaluation axis* of the
bake-off, not a deferred concern. The semantics under test: two machines edit
concurrently while offline, then reconcile and must **converge**.

**Convergence unit** — the granularity at which concurrent edits reconcile:
**per-content, decrypt-then-merge**. Peers who both hold the key for a unit of
content perform a fine-grained merge of it; a peer who lacks the key cannot
merge that content and may only **relay** its ciphertext. This splits peers
into two roles *per path*: *merger* (keyholder) and *relay* (non-keyholder).
See ADR 0001.

**Convergence classifier** — the module that decides, per path, what happens
when an incoming change meets the local tree: *Converged* (disjoint or
identical), *Merged*, *Conflict*, or *RelayedUnmerged*. It is a pure function
of (local tree, incoming change, a *Key oracle*) — it owns the ADR 0001 rule
and touches no storage or disk, so it is unit-testable with a fake oracle.

**Key oracle** — the narrow seam the classifier uses to ask the repo for
plaintext: `open(oid, now) -> Option<bytes>`. `None` *is* the relay role (this
identity can't open the content now); `Some(plaintext)` is what the merger uses
to tell a clean *Merged* from a *Conflict*. The classifier never sees keys or
ciphertext — only this oracle.

## Deliberately out of scope (for now)

- **jj-style ergonomics** (auto-snapshot working copy, stable change-ids,
  oplog). Desirable, but a UX layer added later — not the foundation.
- **git interop bridge.** Important eventually; not part of the first slice.

These are excluded from the *foundation* so the first slice ships fast and
nothing built on top forces a teardown.

## Foundation (decided — ADR 0002)

The foundation is the **encrypted content-addressed DAG**, now the canonical
engine at `loot_core::engine` (`DagRepo`, re-exported as `loot_core::DagRepo`).
Decided by running the bake-off, not by argument: under per-content encryption
the CRDT degrades to last-writer-wins and silently dropped concurrent edits
(0 of 4 survived), while the DAG surfaced conflicts (safe) and was ~4.5x faster
at 50k files. See ADR 0002 and `docs/bakeoff/index.html` for full methodology.

The engine is built from deep modules: `sealed` (encryption/visibility/embargo,
ADR 0003), `converge` (the merge classifier, ADR 0001), and the engine-private
`object_store` + `change_graph`. `crates/spike-dag` is now a thin shim that
re-exports the engine so the bake-off keeps its DAG-vs-CRDT symmetry.

`crates/spike-crdt` is **retained but non-canonical** — the benchmark record,
not part of the product. `crates/loot-bench` and both spike shims stay in the
tree so the decision is reproducible (`cargo test --release`).

## Open / undecided

- **Spike-honest embargo (ADR 0003).** `open()` time-gates on `now`, so a
  determined keyholder could bypass embargo locally. A real guarantee needs
  key-escrow / time-lock crypto and a threat model. Deferred.
