# loot-codec: a no-fs codec/crypto core that compiles to WASM

## Status

accepted (TS SDK map #378 — build slice #423, the tracer bullet). Realizes the
bridging decision from the #381 research ("WASM for the in-memory crypto/codec
core; TS speaks transport via `fetch()`; no in-memory `DagRepo`"). Prerequisite
for the in-memory TypeScript SDK (#421) and its slices #424–#427.

## Context

The in-memory SDK drives a loot repo from JS/TS with no `.loot/` on disk. Per
ADR-of-record #381, the crypto *protocol* and canonical codec must stay Rust —
reimplementing loot's composition of primitives in JS drifts — so they compile
to `wasm32-unknown-unknown` and TS calls them; only transport (plain HTTP) is
re-authored in TS via `fetch()`.

Two facts, verified by spike before building, shaped the design:

1. **`zstd-sys` will not build for `wasm32-unknown-unknown`.** It compiles C via
   `cc`/clang, which isn't available for the wasm target. `aes-gcm`, `blake3`,
   `ed25519-dalek`, and `getrandom` (with the `js` feature) all build cleanly.
2. **`loot-core` hard-depended on `zstd`** and mixed the pure codec/crypto with
   the `std::fs` engine (`DagRepo`, `store`). Compiling it whole to wasm was
   therefore impossible without surgery, and would drag the fs engine into the
   `.wasm` as dead weight (a #381-flagged size concern).

## Decision

**Extract `loot-codec`** — a new crate holding the no-fs, wasm-buildable core:
the byte format (`format`), the sync-bundle wire codec (`bundle_codec`), sealed
content (`sealed`: AES-GCM + blake3 addressing), detachable attestations
(`attestation`), and the leaf value types they share (`Oid`, `Visibility`,
`RepoError`, `ChangeNode`). `loot-core` depends on it and **re-exports every
item at its original path** (`loot_core::Oid`, `loot_core::bundle_codec::…`,
`loot_core::sealed::…`, …), so nothing downstream moved — the change is a pure
relocation, proven by the unchanged, still-green loot-core (296) and workspace
tests.

The change-DAG *algorithms* (`ChangeGraph`, `compute_change_id`, the tree
derivations) stay in `loot-core`'s engine; only the pure `ChangeNode` *shape*
the wire codec reads/writes moved. The read path (this slice) needs decode +
decrypt, not the change-id fold, so the fold's relocation is deferred to the
write slice (#424) if the wasm core needs it there.

**zstd moves host-side.** In `loot-codec` it is an optional feature (`default =
["zstd"]`): the native host enables it; the wasm wrapper builds with
`default-features = false`. `sealed::open` still couples decrypt + decompress
for native callers, but a new zstd-free `sealed::decrypt` primitive single-sources
the AES-GCM step so both native `open` and the wasm core use identical decrypt
code. Public content comes back still-compressed over the wasm boundary and JS
inflates it with a host zstd library.

**`loot-wasm`** is the `wasm-bindgen` wrapper crate: a thin ABI shell over a
pure, native-testable `core` module. It exports the decode / decrypt / address
primitives and a minimal diskless identity (`generate` / `fromSeed` /
`publicKey`) built directly on `ed25519-dalek` — **not** `loot-identity`, whose
OpenSSH-file and passphrase machinery (`ssh-key`, `rpassword`) do not belong on
the wasm boundary (#383).

## Consequences

- The codec/crypto is single-sourced: the wasm build and the binary compile the
  same `loot-codec`, so a change authored in JS is byte-identical to one the CLI
  authored. A golden-parity harness (`loot-wasm/tests/parity.rs`) runs the same
  assertions natively (against `core`) and under `wasm-pack test --node`
  (against the exported shell), freezing native-computed vectors so a
  wasm-specific miscompilation is caught.
- Building the wasm core requires the `wasm32-unknown-unknown` target and
  `wasm-pack`; zstd never enters that build.
- `loot-identity` remains native-only. A wasm-friendly identity that shares
  loot's signing/envelope *composition* (not just raw ed25519) is the write
  path's concern (#424), and may motivate extracting an identity core later.
- Deferred, per #381: `.wasm` size budgeting and confirming `getrandom-js`
  behavior in the real relay-connected agent (there is no randomness on the
  read path, so slice #423 does not exercise it).
