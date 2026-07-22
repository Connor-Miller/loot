# @millerbyte/loot-sdk

In-memory loot for JS/TS agents. Drive a loot repo entirely in RAM — no `.loot/`
on disk — over a WASM crypto/codec core.

> **Slices 1–2 (#423, #424):** connect to a relay, **read** public content, and
> **author + push** a signed public change with a pre-registered key. Private /
> grant reads and the physical (subprocess) backend arrive in later slices.

## What loot hides — and what it does not

loot encrypts **content**, not **structure**. Path names, the tree shape, and the
change graph travel to a relay **in cleartext**; only file *content* is sealed.
So the relay (and this SDK's path-scoping) can see *what paths exist and how they
relate* — it cannot read *what is in them* without the content key. **Do not put
secrets in path names.** (See [ADR 0040](../docs/adr/0040-loot-codec-and-the-wasm-core.md)
and the path-scoping research under `docs/research/`.)

## Usage

```ts
import { connectRelay, Identity } from "@millerbyte/loot-sdk";

const repo = await connectRelay("https://relay.example", Identity.generate());

for (const { path, visibility } of await repo.list()) {
  console.log(path, visibility); // "public" | "private"
}

const bytes = await repo.read("readme.md").bytes(); // Uint8Array
// or stream it:
for await (const chunk of repo.read("readme.md")) { /* … */ }
```

Reads are ungated, so any identity (a fresh `Identity.generate()`) can read public
content; a pre-registered key (`Identity.fromSeed`) matters for the write path.

### Authoring (capture-first)

```ts
// A pre-registered key: its public key must be in the relay's allow-list.
const repo = await connectRelay(url, Identity.fromSeed(seed));

await repo.edit("readme.md", new TextEncoder().encode("# hello\n"));
await repo.remove("stale.md");
await repo.describe("update the readme");
await repo.status(); // { message, changes: [{ path, kind: "added"|"modified"|"removed" }] }

const changeId = await repo.push(); // signs the full-tree change, stows it, returns the id
```

`edit`/`remove` mutate an in-RAM overlay that **is** the pending change (no
separate stage step). `push` folds the overlay into a signed full-tree change in
the WASM core — the change-id fold, both signatures, the bundle encode, and the
`/stow` envelope never leave Rust — and posts it to the relay. Slice 2 authors
**public** content, stored **uncompressed** (valid and readable; matching the
binary's zstd compression is a later efficiency follow-up, since zstd's C won't
build for wasm).

## How it works (in-memory mode)

- **Transport is plain HTTP via `fetch()`** — the SDK speaks the relay wire
  directly; `loot-net` never crosses into JS. The request framing and the bundle
  codec come from the WASM core (`loot-wasm`), so they can't drift from the binary.
- **Path-scoping (#380) is client-side.** A metadata fetch (no object bytes)
  resolves a path to its object address; a second, scoped fetch pulls just that
  object's bytes. Structure is public metadata; only content bytes are scoped.
- **zstd is host-side.** The WASM core decrypts; public content is inflated in JS
  (`fzstd`), because zstd's C library will not build for `wasm32`.

## Build

The WASM core is generated from `crates/loot-wasm` (not checked in):

```
npm run build:wasm   # needs wasm-pack + the wasm32-unknown-unknown target
npm run typecheck
npm test             # Seam-1 behavior suite: drives a real `loot serve` relay
```
