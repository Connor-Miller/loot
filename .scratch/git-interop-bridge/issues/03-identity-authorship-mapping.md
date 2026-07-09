# 03 — Identity & authorship mapping

Type: grilling
Status: resolved
Blocked by: —

## Question

How do loot identities and git authorship correspond?

- **loot ed25519 identity → git author/committer.** How is a loot identity
  rendered as a git `Name <email>`? A convention (e.g. `alice
  <alice@loot.local>`), or a mapping file?
- **git author → loot identity.** On ingest, how is a git commit's author resolved
  to a loot identity (peer registry lookup? default to the syncing identity)?
- **Signing.** loot Changes are ed25519-signed (ADR 0018). Do we emit git signed
  commits (and how — the same key via SSH-signing, since loot uses OpenSSH
  ed25519)? Is loot's signature preserved as a commit trailer for round-trip
  verification?

## Notes

Independent of 01/02. loot already uses OpenSSH ed25519 keypairs (ADR 0014), which
git supports for SSH commit signing — worth checking that path in ticket 04.

## Answer

**Identity representation: a lightweight identity map, auto-seeded from git config,
peer-registry fallback.** A small `pubkey ↔ Name <email>` map:

- **Self is auto-seeded** from `git config user.name` / `user.email` so the syncing
  identity's loot pubkey renders as their *real* git identity — git history looks
  native, and their own git-native commits resolve back to them (satisfying Q2's
  "if it matches" path).
- **Unmapped peers fall back** to the peer-registry nickname + `<nickname>@loot.local`
  (`.loot/peers` already resolves pubkey bytes → nickname).
- The **authoritative** loot identity remains the `Loot-Author` pubkey trailer
  (ticket 02); the `Name <email>` is the human-friendly rendering. Representation
  bridge: change author is raw `[u8;32]`; the trailer is its hex; the peers file
  stores the OpenSSH line — all three encode the same key.

**git-native authorship (no `Loot-Author` trailer): syncing identity if it
matches, else unauthored legacy.** If the git author resolves (via the identity
map) to the syncing identity, author the change as that identity and sign it as
part of the sync. Otherwise ingest as a loot **unauthored/legacy** change
(`author: None` — already supported by the engine), preserving the original author
in a `Git-Author: Name <email>` trailer so provenance isn't lost. Never forge
another identity's loot signature (loot can't hold their key).

**Signing: SSH-sign mirrored commits with the loot key + keep the Loot-Signature
trailer.** loot→git commits are signed via git SSH signing (`gpg.format=ssh`) using
loot's OpenSSH ed25519 key, so the same key verifies in both worlds and the mirror
shows "verified". The `Loot-Signature` trailer is retained for loot-side round-trip
verification. Setup detail (allowed-signers file, config) feeds the mechanism fog.

**Feeds:** the identity-map file location + SSH allowed-signers config are
mechanism details for the sync-mechanism fog item; consumes ticket 02's trailers.

