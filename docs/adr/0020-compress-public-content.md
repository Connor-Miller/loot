# Compress public content before sealing

## Status

accepted

## Context

Public content — source, docs, config — is highly compressible, and loot stores
and syncs it as ciphertext that a relay forwards verbatim. Compressing it before
sealing cuts both on-disk size and transfer bytes. Epic's *lore* compresses with
Zstd (level 6); we want the same win.

But compression and encryption interact dangerously on secrets. If an attacker
can influence part of a plaintext and observe the compressed-then-encrypted
length, the compression ratio leaks whether their guess collides with the rest
of the secret — the CRIME/BREACH family of attacks. loot deliberately mixes
public and sensitive content in one repo, per-content, so a naive "compress
everything" would open exactly this side-channel on `restricted` and `embargoed`
data.

We want the storage/transfer win on public content **without** exposing any
length or compressibility signal on sensitive content.

## Decision

At `seal` time, Zstd-compress (level 6) **only** content whose visibility is
`Public`, then encrypt the compressed bytes. `Restricted` and `Embargoed`
content is never compressed. `open` transparently decompresses when the flag is
set.

- **A per-object `compressed` flag** is recorded on the `SealedObject` and
  serialized in both the durable object file and the sync bundle. `open`
  decompresses iff it is set; the flag is the single source of truth, decoupled
  from any future change to which content we choose to compress.
- **Compress-then-encrypt, one context per object.** Each object is compressed
  in its own Zstd frame with no shared dictionary, so there is no cross-object
  compression context for a CRIME/BREACH-style oracle to exploit.
- **Keying off visibility is safe.** Visibility already travels in the clear on
  the sealed object (a relay must see it to route and forward). A relay learning
  "this object is public, and compressed" learns nothing it did not already
  know. Sensitive content's length and compressibility are never exposed,
  because sensitive content is never compressed.
- **The content address is unchanged:** it stays `blake3(nonce || ciphertext)`.
  The flag is metadata about how to interpret the decrypted payload, not part of
  content identity; the random nonce already makes addresses unique.

### Format impact (ADR 0019)

The `compressed` flag is a new byte in the sealed-object layout — a change an
older reader cannot parse: a v1 reader would read the flag byte as the start of
the ciphertext length and mis-parse, or (worse) read a compressed payload as
plaintext and surface Zstd bytes. By ADR 0019's definition that is a **breaking**
change, so this **bumps `FORMAT_MAJOR` from 1 to 2**.

- A v2 reader still reads v1 artifacts: a v1 object predates the flag and is
  treated as uncompressed (newer reads older).
- A v1 reader cleanly **rejects** a v2 artifact with "unsupported format
  version — upgrade loot", instead of silently surfacing corrupt content. This
  is the sync-path guarantee that matters: a stale peer never mis-reads a
  compressed public object.
- The sync bundle threads the frame's format major into body decoding, so inline
  objects are parsed against the right layout across versions.

## Consequences

- Public objects shrink materially on text/code corpora; restricted and
  embargoed payloads are byte-for-byte what they were before (never compressed),
  so no side-channel appears on sensitive data.
- The major bump is **global**: every artifact now carries marker `[2,0]`, so a
  v1 reader rejects even artifacts whose layout did not change (graph, keyring,
  escrow, empty bundles). This is safe — it refuses data rather than mis-reading
  it — but coarse. A later refinement could version artifacts independently so an
  unrelated reader need not reject them; that is a bigger change to ADR 0019's
  single global version and is out of scope here.
- New dependency: the `zstd` crate (bundled libzstd). Level 6 matches lore.
- Very small inputs may not shrink (Zstd frame overhead exceeds the savings);
  correctness (round-trip) still holds, and the win shows on real content.
- **Relay upgrade ordering**: the global major bump means a v2 client's bundles
  (marker `[2,0]`) are rejected by a v1 relay with `UnsupportedFormat`. Relays
  must be upgraded before v2 clients push to them. The failure is fast and
  explicit — a v1 relay returns `UnsupportedFormat` rather than silently
  mis-parsing — so deployment ordering is easy to verify.
