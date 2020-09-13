# Research: Rust → TypeScript bridging for the loot SDK

Ticket #381 (child of map #378 — TS SDK, in-memory and physical loot). Companion
to [`ts-sdk-path-scoped-fetching.md`](ts-sdk-path-scoped-fetching.md) (#380).

> **Bottom line:** the boundary is much narrower than "bind loot-core." The relay
> wire protocol is plain HTTP with trivial length-prefixed binary bodies — TS
> speaks it natively with `fetch()`, no Rust in the loop. The *only* things that
> must not be reimplemented in ad-hoc JS are the **crypto protocol** and the
> **bundle/change codec**. Compile *those* — a narrow, pure-compute core — to
> **WASM** for in-memory mode. Offer physical mode as a thin **subprocess**
> wrapper over the existing `loot` binary. Reach for **napi-rs** only if a
> measured need for native physical-mode performance appears — it is the heaviest
> option (per-platform prebuild matrix) and buys nothing the other two don't.

---

## 1. Reframe: what actually has to cross the boundary?

The instinct is "the SDK calls loot-core, so bind loot-core." That is the wrong
unit. Splitting the engine along what an in-memory agent actually does shows three
very different layers, only one of which must be Rust:

| Layer | Examples | Can TS do it directly? |
|---|---|---|
| **Transport** | `/stow`, `/negotiate`, `/offer`, `/fetch`, `/wants`, `/grant`, `/pull-grants` | **Yes.** Plain HTTP POST with byte bodies. The wire encoders (`encode_have`, `encode_addrs`, `encode_have_wants`, the `[len][bytes]` grant framing) are ~10-line length-prefixed formats — a few dozen lines of TS. `loot-net`'s `push`/`pull`/`offer`/`fetch` are just `reqwest` wrappers around these; **none of that crate needs to cross the boundary.** |
| **Store orchestration** | build a `Change`, resolve paths→oids from a tree, decide public/restricted, assemble a bundle `Frame` | **Re-authored in TS**, calling down into the crypto layer. It must *not* reuse `DagRepo` — see §3. |
| **Crypto + canonical codec** | seal/open (AES-256-GCM+zstd), ed25519 sign / envelope, ECIES key seal/unseal, blake3 addressing + change-id, `bundle_codec::Frame` encode/decode | **No — must be Rust (WASM/napi).** Reimplementing the *protocol* in JS invites silent drift from the canonical engine (see §2). |

The transport layer being TS-native is the load-bearing simplification: it means
the WASM/native module never needs `tokio`, `reqwest`, sockets, or an async
runtime — exactly the dependencies that make Rust hard to run in a browser or
cheap to load in Node. The module is **pure `compute(bytes) -> bytes`**.

## 2. What MUST stay in Rust (key material + canonical framing)

Two categories, both correctness/security-critical:

**a) Private key material and the crypto protocol.** Never reimplement in
hand-rolled JS:

- **ed25519 signing** — `Identity::sign` / `wrap_envelope`
  (`loot-identity/src/lib.rs:234,253`). The 97-byte push envelope
  `[0x01][pubkey 32][sig 64][bundle…]` is what every relay verifies.
- **ECIES key seal/unseal** — `key_seal::{seal_key, unseal_key}`
  (`loot-identity/src/key_seal.rs`). This is a *specific* protocol, not just a
  primitive: ephemeral x25519 → ECDH → `blake3_derive_key("loot grant key wrap
  2024", shared‖eph_pub)` → ChaCha20-Poly1305 with **nonce = 0** (safe only
  because the ephemeral key is unique). Re-encode any of that label/nonce/order
  wrong in JS and grants silently stop interoperating.
- **ed25519 → x25519 derivation** — `to_scalar_bytes()` / `to_montgomery()`
  (`key_seal.rs:54,62`). Getting the Edwards→Montgomery map subtly wrong yields
  keys that verify in tests but fail against the Rust peer.
- **Content seal/open** — `sealed::{seal, open}` (`loot-core/src/sealed.rs`):
  AES-256-GCM, **compress-then-encrypt for `Public` only** (zstd level 6),
  embargo-then-visibility-then-key gate order. `open`'s three-step order is
  *part of the interface* (embargo → key custody → visibility error).

**b) Canonical content addressing and the change/bundle codec.** These define
identity, so any JS divergence produces objects the network rejects:

- **blake3 addressing** — `SealedObject::address = blake3(nonce‖ciphertext)`
  (`sealed.rs:56`).
- **The change-id folds the full tree** (ADR 0018/0029, confirmed by #380). A
  change's `Oid` is derived over a full-tree snapshot; a JS re-implementation
  that computes it even slightly differently authors changes no relay or peer
  will accept as successors.
- **`bundle_codec::Frame` encode/decode** — the on-wire bundle grammar
  (`loot-core/src/bundle_codec.rs`), version-gated by `format::{put,read}_version`.

The primitives themselves (ed25519, x25519, AES-GCM, ChaCha20-Poly1305, blake3)
all have audited pure-JS implementations (`@noble/*`). The hazard is **not** the
primitives — it is re-encoding loot's *composition* of them (labels, nonces,
framing byte-layouts, the full-tree fold) a second time and keeping two
implementations bug-for-bug identical forever. One canonical implementation,
compiled to WASM, removes that entire class of divergence.

## 3. The decisive constraint: there is no in-memory `DagRepo`

`DagRepo` and `RepoStore` are **not** a pure data structure with a pluggable
backend — they are hard-wired to `std::fs`. `DagRepo::load`, `record`, and
`surface` read and write `.loot/graph`, `.loot/keyring`, `.loot/objects/…`,
lane pointers, dock state, etc. directly (`engine.rs:944-1048, 2028-2255`;
`store.rs:78-768`). There is no `MemStore` and no filesystem-adapter trait to
swap.

Consequences:

- **In-memory mode cannot "just bind `DagRepo`."** Binding it as-is drags the
  whole `.loot/` filesystem contract into the agent's process — the exact thing
  in-memory mode exists to avoid.
- The store-orchestration layer (§1) is therefore **re-authored in TS** for
  in-memory mode: hold the working tree in JS objects, call the WASM crypto/codec
  for the sealed bytes and the bundle, POST via `fetch()`. This is a modest
  amount of logic precisely *because* #380 showed the agent path-scopes
  client-side over two existing `/fetch` calls — no new engine machinery.
- **Physical mode is the opposite:** it *wants* the `.loot/` fs contract and the
  full engine. The cheapest correct way to get all of it is to **not re-expose
  it at all** and shell out to the already-shipped `loot` binary (§4c).

This split — in-memory reuses only the crypto/codec core, physical reuses the
whole binary — is what makes the two SDK modes have genuinely different bridging
answers rather than one uniform binding.

## 4. The three strategies

### a) WASM — recommended for the in-memory crypto/codec core

Compile a **new, narrow `loot-sdk-wasm` crate** (facade over `loot-core::sealed`,
`loot-core::bundle_codec`, `loot-core::format`, and a *trimmed* slice of
`loot-identity`) to `wasm32-unknown-unknown` via `wasm-bindgen`.

- **Fit:** pure compute — no fs, no net, no time, no async needed inside the
  module (transport and clock live in the JS host). This sidesteps WASM's real
  limitations entirely.
- **Reach:** one `.wasm` artifact runs in **Node and the browser** and needs
  **no per-platform build matrix** and **no binary install** for the diskless
  agent — directly serving the destination's "no Rust binary in the loop."
- **Perf:** WASM crypto is ~1.5-3× native but *far* faster than the JS bridging
  overhead matters for — an agent seals/signs a handful of objects per change.
  Irrelevant at this workload.
- **Single source of truth:** the canonical Rust *is* the JS implementation. No
  drift (§2).

**Known friction to verify, not assume:**

- `getrandom = "0.2"` (`loot-core/Cargo.toml:15`) needs its **`js` feature** to
  reach `crypto.getRandomValues` under `wasm32-unknown-unknown`. Standard fix,
  but must be wired for the wasm target only.
- `zstd = "0.13"` binds C `libzstd` via `zstd-sys`. It compiles to
  `wasm32-unknown-unknown` but is the least certain dependency and inflates the
  module. **Mitigation / narrowing:** zstd is only touched for **`Public`**
  content (`sealed.rs:143`). An MVP in-memory agent working on restricted/private
  content never hits it; a public-content path can defer to a JS zstd (or handle
  compression host-side) if the C build proves painful. Flag for a spike.
- **Exclude `rpassword`** (terminal passphrase prompt,
  `loot-identity/Cargo.toml:20`) and the OpenSSH file serialization / passphrase
  export path from the wasm facade — none of it applies to a diskless identity.
  The wasm identity surface is intentionally *narrower* than the CLI's: generate
  / from-seed-bytes, `public_key_bytes`, `x25519_pubkey_bytes`, `sign`,
  `wrap_envelope`, `unseal_key`. (This narrowing is the concrete input #383
  needs — where the keypair lives and in what form.)

### b) napi-rs — defer; heaviest, buys nothing the MVP needs

A native Node addon binding the full stack, including a filesystem-backed
`DagRepo` and even `loot-net` transport.

- **Pro:** full native perf and real `std` (fs, time, tokio) — could host
  physical mode natively without the binary installed.
- **Con:** **Node-only** (no browser — abandons half the destination's reach),
  and a **per-platform/arch prebuild matrix** (win-x64, win-arm64, darwin
  x64/arm64, linux x64/arm64/musl…). That is exactly the release-engineering
  burden the loot-site effort already hit for the CLI binary (the Win-ARM64 gap,
  #270). `@napi-rs/cli` automates prebuilds, but it is real, ongoing CI ops.
- **Verdict:** justified *only* by a measured need for native physical-mode
  throughput that subprocess can't meet. No evidence of that need exists.
  Speculative — do not build it for the MVP (matches the repo's evidence-driven
  rule).

### c) subprocess — recommended for physical mode v1

Spawn the installed `loot` binary and parse `--porcelain` output (the CLI already
emits machine-readable rows — the lane table this session used is one).

- **Pro:** near-zero binding work; reuses the *entire* canonical engine including
  the `.loot/` fs contract §3 says physical mode wants; always in sync with the
  binary.
- **Con:** requires `loot` on `PATH` (already the loot-site distribution story);
  ~10-50 ms per spawn; **cannot do in-memory mode** (it *is* physical mode by
  definition — needs `.loot/` and the binary). So it is a *complement* to WASM,
  never a substitute.
- **Verdict:** the cheapest correct physical-mode MVP. Wrap, don't bind.

## 5. loot-core public API surface available for binding

For the WASM facade, the relevant already-`pub` surface (no new engine work):

- **Types** (`loot-core/src/lib.rs`): `Oid`, `Visibility`
  {`Public` | `Restricted(Vec<String>)` | `Embargoed{reveal_at}`}, `Change`
  {`id, parents, message, tree: BTreeMap<PathBuf,(Oid,Visibility)>`}, `RepoError`,
  `SyncBundle`, `MergeOutcome`.
- **Sealing** (`sealed.rs`): `seal(bytes, &Visibility) -> (Oid, SealedObject,
  ContentKey)`, `open(&SealedObject, &Oid, reader, &Keyring, now) -> Vec<u8>`,
  `SealedObject{nonce, ciphertext, vis, grant_ids, compressed}` + `.address()`,
  `Keyring`, `ContentKey = [u8;32]`, `grant_ids(&Visibility)`, `ANYONE`.
- **Codec / format** (`bundle_codec.rs`, `format.rs`): `Frame` encode/decode,
  `put_version` / `read_version` / `Cursor`.
- **Identity, trimmed** (`loot-identity/src/lib.rs`, `key_seal.rs`): `Identity`
  (`generate`, `public_key_bytes`, `x25519_pubkey_bytes`, `sign`, `wrap_envelope`,
  `unseal_key`), `unwrap_envelope`, `seal_key`/`unseal_key`,
  `x25519_pubkey_from_ed25519_bytes`, `ENVELOPE_*`, `WRAPPED_KEY_SIZE`.
  *Add* a from-raw-32-byte-seed constructor for the diskless case (today
  `Identity` only exposes `generate` + OpenSSH-file `load`) — small, feeds #383.
- **Transport — NOT bound.** `loot-net`'s `push`/`pull`/`offer`/`fetch`/`wants`/
  grant calls are `reqwest` wrappers; the SDK re-speaks the four+ endpoints in
  TS. Only the *wire encoders* (`encode_have`, `encode_addrs`,
  `encode_have_wants`, grant `[len][bytes]` framing) are worth porting — and they
  are trivial. Keep them byte-for-byte identical (ideally golden-tested against
  the Rust encoders' output).

## 6. Recommendation for the MVP SDK

1. **In-memory mode → WASM.** New narrow `loot-sdk-wasm` crate (wasm-bindgen)
   exposing seal/open, the trimmed identity (sign / envelope / ECIES /
   x25519 / from-seed), and `Frame`/format codec. TS re-authors the store
   orchestration and speaks the relay endpoints over `fetch()`. One `.wasm`, runs
   Node + browser, no binary, no platform matrix.
2. **Physical mode → subprocess.** Thin TS wrapper over the installed `loot`
   binary parsing `--porcelain`. Zero engine re-exposure.
3. **napi-rs → deferred** behind an explicit "native physical-mode perf is
   measured-insufficient" trigger. Not MVP.
4. **Golden-test the boundary.** Because §2's whole argument is "one canonical
   implementation," add cross-impl fixtures: Rust seals → WASM opens (and vice
   versa); WASM-authored change-id == Rust-authored for the same tree; TS wire
   encoders == Rust encoders. These tests are what *keep* the boundary narrow
   over time.

**Verification spikes before committing** (cheap, de-risk the WASM path):
`zstd-sys` under `wasm32-unknown-unknown` (bundle size + build), `getrandom/js`
wiring, and total `.wasm` size for the trimmed facade. If zstd proves hostile,
the public-content compression path is the only casualty and has host-side
fallbacks.

## 7. Feeds forward

- **#382 (SDK surface):** the entry points differ by mode by construction —
  `LootClient.fromRelay(url, identity)` drives WASM+fetch (in-memory);
  `LootRepo.open(path)` drives subprocess (physical). Design them as two
  backends behind a shared verb vocabulary, not one uniform binding.
- **#383 (in-memory identity):** the trimmed wasm identity surface (from-seed
  constructor, no OpenSSH file, no rpassword) *is* the shape of the diskless
  keypair — this doc hands #383 its concrete starting point.
