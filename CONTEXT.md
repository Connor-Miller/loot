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

The foundation is the **encrypted content-addressed DAG** (`crates/spike-dag`'s
model graduates into `loot-core`). Decided by running the bake-off, not by
argument: under per-content encryption the CRDT degrades to last-writer-wins
and silently dropped concurrent edits (0 of 4 survived), while the DAG surfaced
conflicts (safe) and was ~4.5x faster at 50k files. See ADR 0002 and
`docs/bakeoff/index.html` for full methodology and results.

`crates/spike-crdt` is **retained but non-canonical** — it is the benchmark
record backing the decision, not part of the product. `crates/loot-bench` and
both spikes stay in the tree so the decision is reproducible
(`cargo test --release`).

## Open / undecided

- **Spike-honest embargo (ADR 0003).** `open()` time-gates on `now`, so a
  determined keyholder could bypass embargo locally. A real guarantee needs
  key-escrow / time-lock crypto and a threat model. Deferred.
