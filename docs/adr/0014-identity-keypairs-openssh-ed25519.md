# Identity keypairs: ed25519 OpenSSH, signed push envelopes, peer registry

## Status

accepted

## Context

The relay (ADR 0011) was an open relay: anyone reachable could push. Content
stayed sealed, so this was not a confidentiality hole, but it meant no
accountability for who pushed what and no defense against storage-abuse spam.
Closing this gap requires real identity keypairs.

Two related problems: `loot grant` (ADR 0013) deferred relay delivery of grant
bundles because raw content key bytes traveling through a relay would give the
relay a restricted key, violating the thesis. An encryption keypair derived from
the signing keypair closes that gap: the grant bundle's content key can be sealed
to the recipient's public key before relay delivery.

## Decision

### Keypair structure

One ed25519 keypair per repo, generated at `loot init`. An x25519 key is derived
from the ed25519 seed for encrypted grant delivery (ADR 0013 upgrade path). The
derivation follows the standard Curve25519 field mapping used by Signal and
WireGuard.

Identity strings remain the primary identifier throughout the codebase (in
`.lootattributes`, the manifest, sealed object grant lists). The keypair is the
*credential* that backs an identity, not its name.

### On-disk format

OpenSSH format (`ssh-key` crate). Private key at `.loot/id` (mode 0600, never
leaves the machine); public key at `.loot/id.pub`. The OpenSSH pubkey line
(`ssh-ed25519 AAAA... name@loot`) is the canonical sharing format — familiar to
every developer, compatible with existing tooling.

### Keypair lifecycle

- `loot init --identity <name>` generates the keypair automatically.
- `loot keygen` backfills existing repos (fails if keypair already exists).
- `loot whoami` prints the identity name and public key line.

### Peer registry

`.loot/peers` stores `name = <openssh-pubkey-line>` pairs. Managed via:
```
loot peer add <name> <pubkey-line>
loot peer remove <name>
loot peer list
```
Used by the grant flow to look up a recipient's key for sealed delivery; used by
`loot serve --allow` to build the relay allowlist.

### Push envelope

Every push wraps the raw sync-bundle bytes in a 97-byte signed envelope:

```
[ 0x01 ][ ed25519 pubkey (32 bytes) ][ signature (64 bytes) ][ bundle ... ]
```

The relay's `handle_stow` verifies the signature before passing the inner bundle
to `DagRepo::stow`. Version byte `0x01` leaves room for future envelope formats.
The envelope is transport-agnostic (not HTTP-header-based) so it works over any
transport layer.

### Relay allowlist

`loot serve --allow <pubkey-hex>` (zero or more) locks the relay to specific
pushers. An empty allowlist means open relay — any valid signature is accepted.
The relay logs the pusher's public key regardless, providing accountability even
on an open relay.

`loot push` fails clearly with "no identity keypair found — run `loot keygen`"
if `.loot/id` is absent.

## Considered alternatives

**Two separate keypairs (ed25519 + x25519).** Rejected: doubles the key management
burden for users. Single seed → both keys is well-specified and widely deployed.

**Public key as primary identity.** Rejected: names are already baked into
`.lootattributes`, the manifest, sealed object grant lists, and every test.
Migrating to pubkey-as-identity is a large disruption with poor ergonomics.
`loot peer add` bridges the name→key mapping at the callsite that needs it.

**OpenSSH public key in HTTP headers.** Rejected: transport-agnostic body framing
works over any future transport without changes; headers are HTTP-only.

**Require keypair at init; no `loot keygen`.** Alternative rejected: `loot keygen`
is a one-command backfill for existing repos, costing essentially nothing.

## Consequences

- `loot-identity` is a new crate quarantined from `loot-core` (pure domain) and
  `loot-net` (async/HTTP). Both depend on it; no cycle.
- `loot init` is now slightly slower (keypair generation, ~microseconds).
- Existing relay deployments need to accept the new envelope format. The relay's
  `handle_stow` now requires a signed envelope; raw bundle pushes are rejected.
- Grant bundle relay delivery (ADR 0013 deferred gap) is now unblocked: the
  x25519 derivation seam is in place; sealed-to-recipient grant delivery is
  additive on top.
- The allowlist closes the storage-abuse door for relay operators who want it;
  open-relay deployments incur no new configuration.
