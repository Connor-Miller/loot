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

**Object** — a content-addressed unit of stored bytes. In the encrypted-DAG
model, objects are encrypted independently and addressed by the hash of their
*ciphertext*, with a separate plaintext *identity hash* used only for dedup.

**Content address vs identity hash** — the address locates stored (encrypted)
bytes; the identity hash recognizes equal plaintext across keys for dedup.
They are deliberately different. (The known sharp edge of the encrypted model.)

**Sync** — bringing two repos into agreement. Now an *evaluation axis* of the
bake-off, not a deferred concern. The semantics under test: two machines edit
concurrently while offline, then reconcile and must **converge**.

**Convergence unit** — the granularity at which concurrent edits reconcile:
**per-content, decrypt-then-merge**. Peers who both hold the key for a unit of
content perform a fine-grained merge of it; a peer who lacks the key cannot
merge that content and may only **relay** its ciphertext. This splits peers
into two roles *per path*: *merger* (keyholder) and *relay* (non-keyholder).
See ADR 0001.

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

- **Dedup equality-oracle (the DAG's sharp edge).** Dedup keys on a plaintext
  identity hash, which lets the store recognize equal plaintext across keys —
  a leak that partially undercuts the privacy thesis. Options: drop cross-key
  dedup, or use a keyed identity hash. Tracked in ADR 0002, not yet decided.
