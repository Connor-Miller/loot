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

## Open / undecided

- **Foundation: encrypted content-addressed DAG vs CRDT document store.**
  Being decided by spiking both (`crates/spike-dag`, `crates/spike-crdt`)
  against a shared `Repo` trait and the `benches/` workload, then measuring
  speed and feel. The winner graduates into `loot-core`; the loser is deleted.
  The bake-off scores three axes: **thesis fit** (can it cleanly model a
  per-path-encrypted, reviewable, embargoable Change), **local perf** (write
  thousands of small objects, checkout a tree — the APFS small-file workload),
  and **sync** (concurrent offline edits converge per the rule above).
