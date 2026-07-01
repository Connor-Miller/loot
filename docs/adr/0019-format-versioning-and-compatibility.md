# Durable and on-wire artifacts carry a checked format version

## Status

accepted

## Context

loot persists several durable artifacts — loose sealed objects, the change
graph, the keyring, the escrow, the manifest, purges, and conflicts — and moves
one artifact on the wire: the sync bundle (`bundle_codec::Frame`). Every one of
these is a hand-rolled positional codec: a sequence of little-endian counts and
length-prefixed fields with no self-description.

Only the push envelope (ADR 0014) carried a version: a leading `0x01` byte,
checked on receive. Everything else was unversioned. That is a latent trap. The
day any layout changes, an old reader handed new bytes does not fail — it
*mis-parses*, reading a length field out of the wrong offset and either erroring
deep in the stream with a nonsense message or, worse, silently decoding
garbage. And a new reader handed old bytes cannot tell "old format" from
"corrupt." A source-control system whose thesis is long-lived, embargoed, and
shared-over-untrusted-relays content cannot rest on "the format never changes."

We want one guarantee, stated plainly: **a newer loot always reads what an older
loot wrote**, and an artifact a build cannot understand is refused with a clear,
actionable error rather than a misparse or a panic.

## Decision

Every durable and on-wire artifact begins with a **two-byte version marker
`[major][minor]`**, checked on load and on receive.

- `major` is the **breaking** version. A change an older reader could not
  correctly parse bumps `major`.
- `minor` is a **backward-compatible** revision — a purely additive change that
  an older reader of the same major can still parse (it reads the prefix it
  understands).

The compatibility rule is "newer reads older": a reader accepts any `major` up
to and including its own `FORMAT_MAJOR`; a higher (unknown) major — or the
invalid major `0` — is rejected with `RepoError::UnsupportedFormat`, whose
message tells the user to upgrade loot. Any `minor` is accepted within a known
major. Rejecting `0` means a zeroed or truncated header cannot masquerade as a
valid artifact.

The marker and the gate live in one place, `loot-core::format`
(`put_version` / `read_version`), and are applied at each artifact's single
codec chokepoint:

- the **sealed object** loose file (`persist_codec::encode_object`);
- the **repo-state** files — graph, keyring, escrow, manifest, purges,
  conflicts;
- the **sync bundle** (`Frame::encode` / `Frame::decode`), so both `apply`
  (keyholder) and `stow` (relay) enforce it, and `loot apply` on an
  incompatible file surfaces the clear error at the CLI.

The push envelope keeps its own `0x01` byte (ADR 0014); this ADR brings the rest
in line rather than re-wrapping it.

A sealed object's content address is `blake3(nonce || ciphertext)`
(ADR 0012) — a function of the object's fields, not of its file encoding. The
marker rides in the file bytes only, so it does **not** change object addressing
or the loose-storage filename. This is what lets us version the durable object
format without rewriting every content address.

Bumping is mechanical: a breaking change to any layout bumps `FORMAT_MAJOR`; an
additive one bumps `FORMAT_MINOR`. Golden-byte fixtures lock the v1 layout of the
bundle, the graph, and the sealed object, so an accidental drift fails a test
instead of silently shipping an unversioned breaking change.

## Consequences

- **v1 is the baseline.** Artifacts written before this ADR are unversioned and
  are treated as unreadable "v0". loot is pre-release with no compatibility
  promise before v1, so this costs nothing; the guarantee starts here.
- **Cross-major reads require keeping old decoders.** The version check tells a
  reader *which* layout it is looking at; actually parsing an older major still
  needs that major's decoder retained in the code. Today only v1 exists, so this
  is a discipline for future majors, not present work.
- **Two bytes per artifact** of overhead — negligible next to ciphertext.
- **One error, one message.** `UnsupportedFormat { found, supported }` renders as
  "unsupported format version v{found} — upgrade loot", so a relay, a CLI user,
  and a library caller all see the same actionable failure.

This is the umbrella the other format-touching slices extend: compressing public
content (S2) and signed changes (S3) each change a layout under this marker, and
bump `minor` or `major` accordingly.
