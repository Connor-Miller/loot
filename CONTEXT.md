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

**Escrow** — the lifecycle stage between `seal` and `Keyring` for embargoed
content (ADR 0007). When a `seal` produces an `Embargoed` key, that key goes
into the Escrow — not the Keyring — for every identity including the originator.
`flush_escrow(now)` promotes eligible entries into the Keyring once
`now >= reveal_at`; until then the Keyring holds nothing for that object and
`open` returns `Embargoed`. The Workspace calls `flush_escrow` before every
content-reading operation (`checkout`, `snapshot`). Bundles ship embargoed keys
as a separate escrow section so peers receive them into their own Escrow. This
closes the D-threat: no identity holds a usable decryption key before reveal
time, not even the originator.

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

**Grant** — a key handoff event: the act of making an existing content key available to a new identity. Grants travel as targeted bundles (the grantor controls delivery by choosing who receives the bundle); the key itself rides in the bundle's keyring section. Grants are auditable via the Manifest. The primitive underlying marooning and visibility migration. CLI: `loot grant <path> <identity>`.

**Manifest** — an append-only record of grant events (`oid`, `grantee`, `granted_at`), separate from the change graph. Travels in bundles alongside objects and escrow entries so every peer has a complete audit trail of who was given access to what. Carries only the *fact* of a grant, never the key itself. Named for a ship's manifest recording what cargo was loaded and by whom.

**Maroon** — to cut off an identity's access to a path. Two levels:

- *Forward maroon* (`loot maroon <path> <identity>`) — re-seals content under a new key, re-grants remaining authorized identities (each receives a targeted grant bundle), publishes a new Change. The marooned identity retains the key for any past versions they already hold. Natural for "you may read the old code but not future updates." Implemented (ADR 0010).
- *Hard maroon* (`loot maroon --hard <path> <identity>`) — forward maroon plus a published purge event signaling all cooperating peers to remove the marooned identity's Keyring entry for the affected OID. Best-effort operational guarantee: cooperating machines purge; offline or modified-binary peers cannot be forced. Models the "person left the org" case. Implemented (ADR 0009, ADR 0010).

**Visibility migration** — promoting or demoting a path's Visibility as a first-class operation with history. Implemented as grant + maroon over the affected identity set: promoting `Restricted` → `Public` re-seals under a new ANYONE-granted key; demoting `Public` → `Restricted` re-seals under a new Restricted key and grants only the named identities. Falls out of grant and maroon working correctly — not a separate primitive.

**Relay** — a node that stores and forwards sealed content it cannot read (the non-keyholder role from ADR 0001). It holds **no restricted keys** — those never travel in a sync bundle (ADR 0003), so a relay can never read restricted content. It does forward public keys (non-secret by definition) so downstream peers receive readable public content. **A host is a relay that never sleeps** — a laptop, a `loot serve` box, and a future hosted service are the same protocol role, differing only in uptime. This makes a loot host a *zero-knowledge code host*: it physically cannot read private code, the thing a plaintext host like GitHub structurally cannot offer. Services that need plaintext (CI, server-side diff/search) are not ambient repo permissions but explicit, audited [[Grant]]s to a service Identity.

**Stow** — the relay's ingest operation (`DagRepo::stow`, ADR 0011): accept a bundle, store its sealed objects and add its change-nodes to the graph append-only, record grant facts in the Manifest, and *never* merge, decrypt, or touch a working tree. Nautical to the domain — you stow sealed cargo in the hold without opening it, and the Manifest records what was stowed. Distinct from `apply` ("merge into my working change"): a pure relay only ever calls `stow` (on push) and `bundle` (on pull). Concurrent pushes produce a forked DAG with multiple tips; forks are collapsed only by keyholder peers when they pull and `apply`.

**Remote** — a named relay URL stored in `.loot/config` as `name = url` (ADR 0013). Managed via `loot remote add/remove/list`. `loot push` and `loot pull` resolve their target as: explicit URL > `--remote <name>` > `origin` default. Analogous to git's remotes; the name `origin` is the conventional default but nothing is special about it in the engine.

**Network sync (`serve`/`push`/`pull`)** — the transport layer over `bundle`/`stow`/`apply` (ADR 0011). `loot serve` runs an open relay (HTTP, two endpoints: `POST /stow` for push, `POST /negotiate` for pull). `loot push [<url>]` is a deliberate *disclosure* act — it publishes the changes the relay lacks; `loot pull [<url>]` fetches the changes the local repo lacks and `apply`s them into the working change. Both resolve the target relay via the [[Remote]] config when no URL is given. Push and pull are distinct verbs because their security intent differs even though the mechanics are symmetric: a pull receives key-gated ciphertext (safe by construction); a push persists sealed content to another node. File-based `bundle`/`apply` are retained as the offline/sneakernet path.

**Loose object storage** — each SealedObject persists as its own content-addressed file at `objects/<hex-address>`, written once and immutably via atomic rename (ADR 0012). Dedup is "does the file exist"; a push writes only the new objects (O(delta), not O(store)), killing the whole-repo-rewrite bottleneck for relays. Concurrent writes to disjoint objects are lock-free (distinct filenames); only the small graph metadata is serialized. Git's loose-object model, made natural by content addressing.

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

- **External-service escrow.** The current Escrow module is local: a
  determined keyholder with access to the `.loot/` directory and a modified
  binary could still read the key bytes directly. A production guarantee requires
  a network escrow service that holds the key and only releases it at `reveal_at`.
  The seam is designed for this: replacing `Escrow::flush` with a network call
  leaves everything else unmodified. Deferred until the network layer exists.

- **Grant bundle relay delivery.** `loot grant` currently writes a bundle file for manual delivery. When identity keypairs land (see below), the grant bundle's keyring section switches from raw bytes to `encrypt(key, recipient_pubkey)` and `loot grant --relay <name>` becomes safe to add. The seam is designed; see ADR 0013.

- **Relay announcement.** A relay peer declaring its relay status so senders
  can discover who holds a key before bundling — enabling selective delivery
  rather than ship-everything. Independent of key management; deferred until
  grant/revocation are working.

- **Object-level sync negotiation.** Sync negotiates at the *change-id* level:
  the client sends its tips, the relay ships every change the client lacks plus
  the full object closure. This can re-transmit ciphertext the receiver already
  holds when object sharing crosses change boundaries (the receiver discards
  known addresses on `apply`, so it is correct, just not minimal). Acceptable
  for the first slice. **Revisit with scaling benchmarks**: if over-shipping
  shows up as a real cost, add a content-address "wants" round (client filters
  the relay's offered addresses down to the ones it is missing before bytes
  move). The wire format already carries everything, so this is additive.

- **Embargoed merges across repos.** Accepting a change from a peer but keeping
  the diff embargoed until a scheduled reveal. Requires a multi-remote model
  (not yet defined). Deferred until the network layer exists.

- **Identity keypairs and push authentication.** Today an Identity is just a
  string name; the Keyring holds *content* keys, not an identity signing key.
  The first relay slice is therefore an *open relay*: anyone reachable can
  push/pull. Content stays sealed (the relay holds no keys), so this is not a
  confidentiality hole — the exposure is storage abuse (junk-object spam) and
  no accountability for who pushed what. Closing this needs a real identity
  keypair foundation (per-identity public/private keys) so pushes can be signed
  and the relay can verify them against an allowed set. That keypair system is
  its own foundation, deferred until after transport works.
