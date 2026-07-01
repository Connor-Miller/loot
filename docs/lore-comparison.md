# loot ↔ Epic's *lore*: comparison & improvement ideas

*Reference: [github.com/EpicGames/lore](https://github.com/EpicGames/lore) · docs at [epicgames.github.io/lore](https://epicgames.github.io/lore/) · v0.8.3 (Jun 2026), MIT, Rust.*

## TL;DR

loot and lore are near-mirror images built on the **same core** — a Rust,
CLI-first, BLAKE3 content-addressed DAG with an immutable object store and a
small mutable layer of pointers. They diverge on what they refuse to do:

- **lore's stated non-goals are loot's reason to exist.** lore is *centralized
  by design*, explicitly does **not** defend against an *adversarial server*,
  and says nothing about *encryption at rest or content secrecy* — the server
  reads your bytes. loot's whole thesis is the opposite: visibility and
  permissions belong to content, the relay is *zero-knowledge*, and private code
  is encrypted end-to-end.
- **loot's deferred concerns are lore's flagship strengths.** Chunking
  multi-terabyte binaries, fragment-level dedup, sparse/lazy workspaces, a
  published wire/on-disk format, a C ABI with six language SDKs, pluggable
  cloud backends, tiering/replication — loot has explicitly deferred all of it;
  lore has shipped or scheduled all of it.

**So the opportunity is unusually clean:** loot can borrow lore's *storage and
production engineering* almost wholesale without touching its confidentiality
thesis, because the two systems compete on orthogonal axes. The one place they
genuinely collide is **dedup vs. secrecy** (chunking + content-addressing leaks
an equality oracle — the exact reason loot's ADR 0004 dropped plaintext dedup).
That collision is the interesting design work, and it's solvable (§5).

---

## 1. What each system is

**lore** — Epic's "next-generation open source version control," aimed at
game/entertainment repos that mix code with huge binary assets. Centralized
server-of-record with offline capability, binary-first, obsessed with scale
(millions of files, terabyte files, thousands of concurrent users, multi-tenant
backends) and performance (zero-copy deserialization, fixed-width records). It's
a funded, multi-repo product: core library + server + CLI, a C API crate
(`lore-capi`), SDKs for JS/Python/C#/Go, an AWS backend (`lore-aws`), Vault
integration (`lore-hashicorp`), telemetry, chaos testing (`lore-chaos-client`),
and a QUIC transport (the repo vendors `quinn-proto`). ~130 commits, pre-1.0 but
with a formal format-stability guarantee.

**loot** — your from-scratch, **encryption-first** VCS. Thesis: *permissioning
is key management.* A Change is the permission-bearing unit; each path carries
its own visibility (public / restricted / embargoed); content is sealed under a
per-content symmetric key and addressed by `blake3(nonce || ciphertext)`. A
relay stores and forwards ciphertext it physically cannot read — a
*zero-knowledge code host*, which a plaintext host like GitHub structurally
cannot be. ~8.4k lines of Rust across `loot-core` (3.8k), `loot-cli`,
`loot-net`, `loot-identity`; JJ-style working change; grants (ECIES to a
recipient pubkey, signed by grantor, manifest audit trail); two-level revocation
(maroon); cooperative embargo escrow. Pre-alpha, solo, but the full loop
init→relay→grant→revoke works end-to-end.

---

## 2. Side-by-side

| Axis | **lore (Epic)** | **loot (you)** |
| --- | --- | --- |
| Core reason to exist | Scale + binary assets for game studios | Per-content confidentiality; zero-knowledge hosting |
| Language / interface | Rust, CLI + C ABI + 4 SDKs | Rust, CLI only |
| Maturity | v0.8.3, funded, multi-repo product | ~8.4k LOC, pre-alpha, solo |
| Hash / addressing | BLAKE3; address = hash of **plaintext** fragment | BLAKE3; address = hash of **ciphertext** (`nonce‖ct`) |
| Large-file storage | **FastCDC** chunking (64 KiB avg, 32 KiB–256 KiB), recursive fragment trees | **Whole-file** sealing — one object per file, no chunking |
| Dedup | Fragment-level, partition-scoped, structural (Merkle) | Ciphertext-address only; **no cross-key dedup** (by design) |
| Compression | Per-fragment **Zstd** (level 6), address of *uncompressed* bytes | **None** |
| On-disk layout | Local **packfiles** + mmappable index; loose on wire | **Loose objects** only (`objects/<addr>`, atomic rename) |
| Workspace | **Sparse** by default, **lazy** fetch, VFS on roadmap | Full **surface** of everything visible; no sparse/lazy |
| Branching | First-class branches: mutable pointer, UUIDv7 + name | **None** — a DAG of tips; forks collapsed by keyholders |
| "Latest" semantics | **Compare-and-swap** on mutable store (one serialization point) | Append-only **stow**; multiple tips, no atomic latest |
| Topology | Centralized; hot/warm/cold tiering, edge, read replicas | Relays = "a host that never sleeps"; single HTTP box today |
| Transport | Versioned protocol over 2 transports (QUIC via quinn) | HTTP (`POST /stow`, `/negotiate`), 97-byte signed envelope |
| Identity / auth | JWT sessions, partition-scoped authorization | **ed25519** identity, **x25519 ECIES** grants, peer registry |
| Content secrecy | **Not a goal** — server reads plaintext | **The point** — server never holds restricted keys |
| Access control unit | **Partition** (16-byte), coarse, multi-tenant isolation | **Per-content key**, fine-grained, per-path visibility |
| Revocation / lifecycle | **Obliteration** (drop payload, keep address) | **Maroon** = crypto-shred (forward + hard) + migration |
| Locking | Basic today; scalable locking on 2026 roadmap | None |
| Integrity / trust | Tamper-evident hash chain; client verifies fragments | Same chain **+ signed pushes/grants** (authenticated) |
| Multi-repo composition | **Links** (versioned) + **layers** (local) + forks | None |
| Format stability | Published wire/on-disk spec, semver, "newer reads older" | Internal, unversioned |
| Explicit non-goals | P2P, adversarial-server, (implicitly) secrecy | Ergonomics, git interop, hard adversarial embargo (for now) |

---

## 3. Shared DNA, and the philosophical fork

They agree on more than it first appears: content-addressed immutable store +
tiny mutable pointer layer; BLAKE3; DAG history; Rust; CLI-first; an ADR
culture; "immutable data makes atomicity and dedup tractable." loot is,
essentially, *lore's data model with encryption pushed down to the object* and
*decentralized trust pushed up to the client*.

The fork is a single decision: **who is trusted to read.** lore trusts the
server and spends its complexity budget on scale. loot trusts no one but
keyholders and spends its complexity budget on key management. Every difference
in the table descends from that one choice. That's why lore's engineering is
mostly *safe to borrow* — it lives below the trust boundary, in the parts that
move opaque bytes around.

---

## 4. lore's strengths worth borrowing — and how they land in loot

Ranked by leverage-to-effort. "Tension" = how much it fights the encryption thesis.

| # | Idea (from lore) | Leverage | Effort | Enc. tension | When |
| --- | --- | --- | --- | --- | --- |
| 1 | Chunking + fragment trees for large files | ★★★ | High | **High** (see §5) | Near |
| 2 | Sparse views + lazy on-demand fetch | ★★★ | Med | Low | Near |
| 3 | Signed Changes (authenticated history) | ★★★ | Low | None (leapfrog) | Near |
| 4 | Branches + CAS "latest" pointer at the relay | ★★☆ | Med | Low | Near |
| 5 | Compress-then-encrypt (Zstd per object/chunk) | ★★☆ | Low | Low | Near |
| 6 | Published, versioned wire/on-disk format | ★★☆ | Med | None | Near/Mid |
| 7 | Pluggable relay backends (S3/object store) | ★★☆ | Med | Low | Mid |
| 8 | C ABI + language SDKs (`loot-capi`) | ★★☆ | Med-Hi | Low | Mid |
| 9 | Resumable transfer + object-level "wants" | ★★☆ | Med | Low | Mid |
| 10 | Packfile compaction for cold storage | ★☆☆ | Med | Low | Mid |
| 11 | Locking for unmergeable/binary content | ★★☆ | Med | Low | Mid |
| 12 | Fixed-width, zero-copy DAG records | ★☆☆ | Med | Low | Later |
| 13 | Tiering / edge / replication for relays | ★★☆ | High | Low | Later |
| 14 | Chaos testing + code/doc standards | ★☆☆ | Low | None | Ongoing |

### Near-term (highest leverage)

**1 — Chunk large files into fragment trees.** Today loot seals each file as one
object addressed by its whole ciphertext, so a one-byte edit to a 2 GB asset
rewrites and re-transmits the entire object, and nothing is shared between
versions. lore's FastCDC + recursive fragment lists make storage and transfer
cost scale with *what changed*, not file size. This is loot's single biggest
scale gap — but it's also the one place encryption bites back (dedup leaks an
equality oracle). Do it via the encryption-aware design in §5, not naively.

**2 — Sparse views + lazy fetch.** lore treats "download only the part of the
tree you asked for, and hydrate fragments on access" as the *default*, not a
power feature. loot currently `surface`s everything visible. Adopt a
`.loot/view` inbound filter (lore's model) and fetch ciphertext fragments on
demand. **This has almost zero tension with encryption** — a relay serves opaque
blobs regardless of whether the client can decrypt them. High value for real
repos, moderate effort.

**3 — Signed Changes (leapfrog, don't just copy).** lore's history is
tamper-*evident* (hash chain) but not tamper-*attributable* — it doesn't sign
who authored a revision. loot already has ed25519 identities and signs push
envelopes and grants. Extending that signature to cover each **Change's state
hash** gives you an *authenticated, non-repudiable* history for near-zero extra
work — a property neither git-by-default nor lore advertises. This turns "trust
no one" from a storage property into a *history* property.

**4 — Branches + a CAS "latest" pointer.** loot has no branches; concurrent
pushes fork the DAG into multiple tips that only a keyholder collapses on
`apply`. lore's mutable store advances a branch with a single **compare-and-swap**
— its only serialization point. Crucially, **CAS is compatible with
zero-knowledge**: advancing an *opaque* branch pointer needs no plaintext, so a
relay can arbitrate "latest" without reading content. Add named branches
(stable ID + name, per lore) and a relay-side CAS to tame fork proliferation.

**5 — Compress-then-encrypt.** loot stores no compression; ciphertext is
incompressible, so compression *must* happen before sealing. Add Zstd (lore uses
level 6) at seal time, per object/chunk. Caveat to document: compressing
attacker-influenced data together with secrets enables CRIME/BREACH-style
leaks — keep each object's compression context isolated (which loot's
per-object model already does), and you're fine.

### Mid-term (productionization)

**6 — Publish a versioned format + "newer reads older" guarantee.** lore treats
its on-disk and on-wire formats as public, semver'd contracts. For a *security*
tool this matters more, not less: auditors and downstream implementers need a
frozen spec, and users need confidence that sealed content stays readable
forever. You already have the ADR discipline; formalize `SEALED-OBJECT`,
`PUSH-ENVELOPE` (already 97 bytes), and the bundle/stow wire format as versioned
specs.

**7 — Pluggable relay backends.** lore's storage backend is replaceable
(`lore-aws`, S3 tiers, Vault via `lore-hashicorp`). loot's loose ciphertext
objects are *ideal* for dumb object stores — a relay backed by S3 needs no
plaintext trust at all. This is how "a host that never sleeps" becomes a real
hosted service. Low tension, high strategic value.

**8 — C ABI + SDKs.** lore's C header is its canonical interface; six languages
wrap it. loot's "permissioning is key management" engine is exactly the kind of
primitive other tools would embed (CI systems, editors, secret managers). A
`loot-capi` + a Python/JS binding turns loot from a CLI into a platform.

**9 — Resumable transfer + object-level "wants."** lore transfers fragments
individually, out of order, in parallel, and resumes after failure; it queries
which fragments the peer is missing before sending bytes. loot's own open
questions already flag that sync over-ships ciphertext at change granularity —
lore's design is the blueprint: add a content-address "wants" round and make
`stow`/`pull` resumable.

**11 — Locking for unmergeable content.** lore is investing in *scalable*
locking because binary assets can't be merged. loot's convergence model already
splits paths into merger/relay roles; unmergeable binaries want an advisory lock
published as a Change. This pairs naturally with idea 1 (once you store big
binaries, you need to stop two people editing them).

### Later (scale-driven — defer until benchmarks demand it)

**12 — Fixed-width, zero-copy records** (lore's 96-byte nodes, 320-byte
revisions). **13 — Relay tiering/edge/replication.** **10 — Packfile compaction**
so cold relays don't hold millions of tiny loose files. Your own docs already
say "revisit with scaling benchmarks" — that's the right trigger for all three.

**14 — Adopt lore's process hygiene:** explicit code/doc standards
(comments, errors, logging, testing), and a `loot-chaos-client`-style
fault-injection harness for the relay. Cheap, compounding.

---

## 5. The one hard collision: dedup vs. confidentiality

This is the crux, so treat it as its own design decision (an ADR).

lore's dedup works because the address is `hash(plaintext_fragment)`, so
identical bytes anywhere collapse to one copy. loot deliberately rejected this
in **ADR 0004**: plaintext-derived identity hands a relay an *equality oracle*
("these two encrypted files have the same contents"), which leaks across users
and tenants. Hence ciphertext addressing, hence no cross-key dedup, hence
whole-file objects.

Chunking (idea 1) reopens exactly this wound: to get delta transfer you must
address sub-file pieces, and if those addresses derive from plaintext you're
back to convergent encryption and its oracle.

**Recommended reconciliation — chunk plaintext, encrypt each chunk under the
object's key, address the ciphertext, scope dedup to a key domain:**

1. Run FastCDC over the **plaintext** to pick content-defined boundaries (so
   boundaries are stable across small edits — the delta-transfer win).
2. Encrypt each chunk under the file's per-content key; address it by
   `blake3(nonce‖chunk_ciphertext)`, exactly as loot already addresses objects.
3. Build a fragment tree (lore's recursive scheme) whose leaves are these
   sealed chunks.

The result: **within one key domain** (a file's version history, or a
partition of files sharing a key), unchanged chunks reuse the same ciphertext
address → dedup + delta sync return. **Across key domains**, identical plaintext
yields different ciphertext → *no* equality oracle, ADR 0004 preserved. You've
recovered ~90% of lore's large-file win while keeping the confidentiality
property. The tradeoff to state plainly in the ADR: dedup is now
*partition/key-scoped*, not global — which is precisely the scope lore itself
enforces with partitions anyway, just reached from the opposite direction.

(If you ever want cross-user dedup on *public* content specifically, that
subset can safely use convergent encryption, since public content has no secret
to leak. Keep it opt-in and restricted to `public` visibility.)

---

## 6. What loot should **not** copy from lore

Borrowing engineering shouldn't erode the thesis:

- **Don't adopt the trusted-server model.** lore's simplicity comes from the
  server reading plaintext. That's the one thing loot must never do; keep the
  relay zero-knowledge even when it costs performance.
- **Don't replace per-content keys with partitions as the *primary* access
  unit.** Partitions are a fine *coarse* optimization (scope fetches, cheap
  isolation), but loot's fine-grained per-content visibility is the
  differentiator. Use partitions *under* the key model, not instead of it.
- **You already beat lore on lifecycle — don't regress.** lore's *obliteration*
  drops a payload but must be honored by the server. loot's *maroon* is
  crypto-shredding: throw away the key and the ciphertext is inert everywhere,
  including on hosts you don't control. Keep that framing; optionally *add*
  lore-style payload obliteration purely to reclaim relay disk (a storage
  optimization, not the security boundary).
- **Centralization is lore's default; for loot it's a deployment option.** Adopt
  lore's *server topology* (tiering, replicas) as an optional relay backbone —
  including as the trust anchor for the **network escrow / time-lock** service
  your embargo feature needs for a hard guarantee — but never as a *requirement*.

---

## 7. Suggested sequencing (mapped to loot's own open questions)

- **Now:** signed Changes (#3) and compress-then-encrypt (#5) — small, high
  return, no thesis tension. Start the sparse/lazy work (#2).
- **Next:** the chunking ADR (#1 + §5) and branches/CAS (#4) — the two big
  architectural moves; do the ADR first. Fold in object-level "wants" (#9),
  which your docs already earmarked.
- **Then productionize:** versioned format (#6), pluggable S3 relay backend
  (#7), and the `loot-capi` (#8) — the path from CLI to hostable platform. This
  is also where the **network-escrow service** (your #1 open question, "hard
  embargo") gets a home, built on a lore-style centralized-but-blind service.
- **Later, benchmark-driven:** zero-copy records (#12), tiering/replication
  (#13), packfile compaction (#10), scalable locking (#11).

---

## Sources

- Epic *lore* repo & README — https://github.com/EpicGames/lore
- *lore* system design doc — https://epicgames.github.io/lore/explanation/system-design/
- *lore* roadmap — https://epicgames.github.io/lore/roadmap/
- *lore* ADRs (FastCDC, Zstd-6, mutable-store branch tracking, S3 backends, JS bindings) — https://epicgames.github.io/lore/developing/decisions/
- loot `README.md`, `CONTEXT.md`, and ADRs 0001–0016 (this repo)
