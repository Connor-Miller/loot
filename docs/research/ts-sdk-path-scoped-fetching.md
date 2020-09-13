# Path-scoped object fetching — what the wire protocol actually requires

Research asset for [#380](https://github.com/Connor-Miller/loot/issues/380), child
of the TypeScript SDK map [#378](https://github.com/Connor-Miller/loot/issues/378).
Answers: does an in-memory agent that declares *"I need `src/auth/` and
`.lootattributes`"* need a new relay endpoint, and what would it leak?

## TL;DR recommendation

**The MVP needs zero new wire protocol.** Path-scoped *object* fetching already
falls out of the S5 object-level negotiation (ADR 0021), because loot already
separates the two things that matter here:

- **Tree structure** (`path → (oid, visibility)` for *every* path) is cleartext
  change metadata that always rides in a bundle.
- **Object content** (`SealedObject` ciphertext) is the expensive, key-gated part
  — and S5 already lets a peer fetch an arbitrary *subset* of it by address.

So an in-memory agent path-scopes **client-side**, in two existing round-trips:

1. `POST /fetch` with `have=[]`, `wants=[]` → a **metadata-only bundle**: every
   change node (hence every tree, hence every `path → oid` mapping) and *zero*
   object bytes. `bundle_wanted(&[], &{})` is exactly this — the empty-wants case
   is already a supported, tested path.
2. The agent walks the tip's tree locally, selects the oids whose paths match its
   declared prefixes, then `POST /fetch` again with `wants = those oids`. Only
   those object ciphertexts come down the wire.

That is the whole in-memory read path, on `main` today, with no Rust change.
A relay-side scoped endpoint (`/offer-scoped`) is a **later optimization**, not a
prerequisite — see Level 1 below.

## How sync works today

Two negotiation layers, both in `crates/loot-core/src/engine/negotiation.rs`,
fronted by thin HTTP in `crates/loot-net/src/lib.rs`:

- **Change-id level (S1, legacy).** `POST /negotiate` — caller sends the
  change-ids it `have`s; relay returns a full bundle of everything else. Retained
  for `loot clone` and as fallback.
- **Object level (S5, ADR 0021).** Pull: `POST /offer(have)` returns the object
  *addresses* in the closure of changes-not-`have`; caller diffs against what it
  holds; `POST /fetch(have, wants)` returns `bundle_wanted` — a bundle whose
  object **bytes** are limited to `wants`. Push is the mirror (`/wants` → `/stow`).

The invariant that makes path-scoping cheap (`negotiation.rs:196`, `bundle_impl`):
**change metadata always rides in full; only object ciphertext is negotiable.**
Every non-working change in the send set ships with its complete
`tree: BTreeMap<PathBuf, (Oid, Visibility)>`, its author pubkey, and its
signature. ADR 0021 states the metadata is "tiny" and re-ships on every sync.

## The structural fact everything hinges on

> In loot, **repository structure is public; only content is private.**

Evidence, not assertion:

- `ChangeNode.tree` is `BTreeMap<PathBuf, (Oid, Visibility)>`
  (`engine/change_graph.rs:23`) — a real path, an object address, a visibility
  tag.
- The bundle codec serializes each path as **plaintext**:
  `put_bytes(&mut out, path.to_string_lossy().as_bytes())`
  (`bundle_codec.rs:131`). No hashing, no obfuscation.
- The relay is **keyless but not blind**: `RelayStore::stow` decodes the bundle
  and stores the full `ChangeNode`s into a keyless `DagRepo`
  (`relay_net/relay_store.rs`). It cannot decrypt a `SealedObject`, but it holds —
  and can read — every path, every oid, every visibility tag, the whole DAG shape.
- `bundle_impl` ships trees for **every** change regardless of key custody; only
  *keys* are gated (public keyring section; restricted/embargoed keys withheld,
  ADR 0003/0027). A peer that pulls receives the full structure even for paths
  whose bytes it can never decrypt.

This is consistent with ADR 0021 ("the negotiation exchanges *content addresses*
only — already relay-visible") and with ADR 0028, which notes that the git-interop
**mirror** must *deliberately omit* revealed paths precisely because the change
graph would otherwise expose them.

**Consequence for #380's security question — "can the relay learn path names
without keys?"** It already does, today, for every path in the repo. Path-scoped
fetching adds **no new path-name leak**: a relay-side scoped offer would only
*use* path knowledge the relay already has. The confidentiality posture to be
honest about in SDK docs is the *existing* one: loot hides file **content**, not
file **names or tree shape**.

## What an in-memory agent actually needs (workflow analysis)

Map #378's agent loop: declare paths → fetch those objects → work in RAM with a
full identity → push a signed change. Tracing that against the model:

- **To read `src/auth/`**: the agent needs the tip's tree (to map paths → oids)
  plus the *content bytes* for the oids under `src/auth/`. Tree = cheap metadata;
  content = the scoped fetch. ✔ covered by the two-phase pull above.
- **To push a valid change**: this is the load-bearing constraint. A `ChangeNode`
  carries a **full-tree snapshot**, not a delta, and the version id folds the
  whole tree: `compute_change_id(author ‖ message ‖ parents ‖ tree ‖ predecessors)`
  (`change_graph.rs`). So to author a change on top of the tip, the agent must
  emit a **complete** `tree` — every path's `(oid, vis)`, reusing the parent's
  oids for the paths it did not touch. It therefore needs the parent's **full
  tree metadata** regardless of how few paths it fetched *content* for. It does
  **not** need the untouched paths' bytes — only their oids, which live in the
  (cheap) tree it already pulled.

This is why path-scoping is fundamentally a **content-bytes** optimization, never
a **structure** optimization: you cannot author on a truncated tree without
breaking id verifiability and materialization. The metadata-only first round is
not overhead to be engineered away — it is the exact thing the agent needs to
build a pushable change.

## Three levels of path-scoping

| Level | Wire change | What it trims | Verdict |
|------|-------------|---------------|---------|
| **0. Client-side (two-phase pull)** | none | object **bytes** to the declared paths | **MVP** |
| **1. Relay-side scoped offer** | one additive endpoint | the **offer round** + structure disclosure | first optimization |
| **2. Scoped shallow snapshot** | new frame + id-model change | change **metadata** and history depth | deferred / likely rejected |

### Level 0 — client-side, zero wire change (recommended MVP)

Exactly the two-phase pull above. Reuses `/fetch` with empty then scoped `wants`.
Cost: the agent downloads **all change metadata** (all trees, whole DAG) even to
read one directory. For loot-sized repos this is genuinely tiny; for a large repo
with deep history it is not, and it discloses the full structure to the agent
(usually fine — the agent is trusted with its own repo).

### Level 1 — relay-side scoped offer (first optimization)

Add one additive, version-marked endpoint, symmetric to `/offer`:

```
POST /offer-scoped   body: [S1 marker][have: change-ids][paths: prefix list]
                     → object addresses whose tree path matches a prefix
```

Backed by a new `DagRepo::offered_objects_scoped(have, paths)` that filters the
existing `offered_objects` walk by `c.tree` path prefix. The relay can compute
this with **no key access** (it holds cleartext trees). `/fetch` is reused
unchanged. This trims the *offer* to path-relevant oids and lets the agent skip
pulling the full change graph up front — but note it still cannot trim the change
metadata inside the returned `bundle_wanted` (bundles ship whole trees). So
Level 1's real win is a smaller **offer** and letting the relay, not the client,
enumerate the path→oid mapping; it does **not** shrink the bundle's metadata.

Gate Level 1 behind evidence: adopt it when a target repo's change-graph metadata
is measurably large, or when a deployment wants the relay to *enforce* that an
agent only sees its scoped paths' addresses. Follows ADR 0021's own versioning
rule — new negotiation message, S1 marker, no `FORMAT_MAJOR` bump.

### Level 2 — scoped shallow snapshot (deferred, probably rejected)

A projection where the relay serves a *path-pruned and/or history-pruned* view:
just the tip's scoped tree, no ancestry. This is what would truly shrink metadata
for a giant repo — and it **collides head-on with the id/signature model**: the
version id folds the *full* tree and the author's signature covers it
(ADR 0018/0029), so a truncated tree neither verifies nor lets the agent author a
successor. Realizing it means either (a) an unverified read-only projection type
that severs change identity (agent can read but the SDK must reconstruct a full
tree from somewhere to push), or (b) reworking change-ids to fold a Merkle tree
whose subtrees verify independently — a deep protocol change. Neither belongs in
an MVP. **Recommendation: leave in fog**, revisit only if a real large-repo agent
use case appears; even then, prefer keeping structure whole.

## Recommendation

1. **Build the SDK's in-memory read path on Level 0** — two `/fetch` calls, empty
   then path-scoped `wants`, resolving paths→oids from the metadata-only bundle
   client-side. No `loot-core`/`loot-net` change; the SDK ships against `main`.
2. **The push path is already object-negotiated** — the agent offers its new
   objects (`/wants`), stows only the missing bytes (`/stow`). No new work; the
   only requirement is that the agent hold the parent's full tree, which Level 0
   already delivers.
3. **Document the confidentiality posture honestly:** loot conceals content, not
   path names or tree shape. The relay already sees every path. This is not a
   regression the SDK introduces; it is the existing model, and it should be
   stated plainly in the SDK's security notes so agent authors don't assume path
   privacy.
4. **File Level 1 (`/offer-scoped`) as a deferred optimization**, gated on a
   measured metadata cost from a real large repo — not built speculatively.
5. **Keep Level 2 in the map's Fog** as "shallow scoped snapshot vs. the
   full-tree change-id invariant" — a protocol-depth question, not an SDK task.

## Impact on the map

- **Unblocks nothing new by edge** — #382 (SDK surface) was already only blocked
  on #380 + #381; this closes the #380 half. But it *reshapes* #382: the in-memory
  entry point does **not** need a bespoke "declare paths" protocol call; it needs
  a client-side path filter over a metadata-first pull. The grilling should design
  `LootClient.fromRelay(...)` around two-phase fetch, not around a hypothetical
  scoped endpoint.
- **Sharpens the map's "path-scoped fetching is a new protocol concept" note** —
  it isn't, for the MVP. It is a client-side use of existing S5 negotiation.
- **New fog patch:** *large-repo metadata cost* — when does shipping the whole
  change graph to a diskless agent stop being "tiny"? Graduates into the Level 1
  ticket if/when measured.

## Sources (all local, `main`)

- `crates/loot-core/src/engine/negotiation.rs` — `offered_objects`,
  `missing_objects`, `bundle_wanted`, `bundle_impl`, empty-wants metadata bundle.
- `crates/loot-core/src/engine/change_graph.rs:15-40` — `ChangeNode`, `tree`
  type, version-id composition.
- `crates/loot-core/src/bundle_codec.rs:128-137` — cleartext path serialization.
- `crates/loot-net/src/lib.rs:195-279` — `/offer` `/fetch` `/wants` `/stow`
  routes and handlers.
- `crates/loot-net/src/relay_store.rs` — keyless relay stows full change nodes.
- ADR 0021 (object-level wants negotiation), ADR 0018 (signed merge parents),
  ADR 0029 (stable change-ids), ADR 0027 (embargo/withheld keys), ADR 0028
  (git-interop bridge omits revealed paths), ADR 0011 (relay stow append-only).
