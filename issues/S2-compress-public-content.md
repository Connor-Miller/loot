# S2 — Compress public content (Zstd)

**Type:** AFK · **Priority:** near-term · **Source:** docs/lore-comparison.md (lore uses Zstd level 6)

## What to build

Cut storage and transfer for public content by compressing it before sealing. At
seal time, Zstd-compress content whose visibility is `public`, record a
`compressed` flag on the sealed object, and decompress after decrypt on `open`.
Leave `restricted` and `embargoed` content uncompressed so no new
compressibility/length side-channel appears on sensitive data — visibility
already travels in the clear on the sealed object, so keying compression off it
reveals nothing new. Compress-then-encrypt only; each object is its own
compression context (so CRIME/BREACH-style cross-context leaks don't apply).

## Acceptance criteria

- [ ] Public content is Zstd-compressed before sealing; the sealed object records whether its payload is compressed.
- [ ] `open` transparently decompresses; a public file round-trips byte-identical through seal → bundle → apply → surface.
- [ ] Restricted/embargoed objects are stored uncompressed and are byte-unchanged from today.
- [ ] A bench or test shows public objects shrink on a text/code corpus.
- [ ] The `compressed` flag is versioned under S1's format marker.

## Blocked by

- S1 — Format versioning + compatibility gate
