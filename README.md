# loot

A from-scratch source-control system.

**Thesis:** visibility and permissions belong to *content and changes*, not to
the *repository*. Commit your `.env`. Keep files private inside a shared repo.
Embargo a security fix: merge it, cut the release, reveal the source later.

This is the unsolved problem in modern version control. Ergonomics (jj already
nails them) are a layer for later.

## What works today

The full loop from first init to relay-based collaboration is functional:

```text
local:    init → status → describe → new → log → surface
file:     bundle → apply
relay:    serve → push → pull
grants:   grant → grant --relay → grants → pull-grants
identity: keygen → whoami → peer add → id export → id import
setup:    config → clone
```

### Try it: private `.env` in a shared repo

```bash
cargo build --release
export PATH="$PWD/target/release:$PATH"

cd $(mktemp -d)
printf 'TOKEN=supersecret\n' > .env
printf '# My Project\n'      > README.md
printf '.env restricted=alice\n*.md public\n' > .lootattributes

loot init --identity alice
loot status -m "initial work"
loot surface              # alice: restores both README.md and .env

# switch to a non-keyholder to prove it
printf mallory > .loot/identity
rm -f .env README.md
loot surface              # mallory: README.md appears; .env stays sealed
```

The `.env` ciphertext lives in `.loot/` the whole time. Mallory cannot decrypt
it, and if she snapshots and re-syncs, the sealed file is carried forward
untouched — snapshot is visibility-aware.

### Sync over a relay

A relay stores and forwards ciphertext it cannot read. Restricted keys never
travel in a sync bundle (ADR 0003), so the relay's zero-knowledge property is
enforced at the wire level, not by policy.

```bash
# Terminal 1: run a relay
loot serve --dir /tmp/relay --addr 127.0.0.1:4000

# Terminal 2: alice pushes
loot remote add origin http://127.0.0.1:4000
loot push

# Terminal 3: bob pulls (bob only sees public content)
loot clone http://127.0.0.1:4000 ./bob-repo --identity bob
```

### Grants: sharing a content key

```bash
# alice knows bob's public key (from `loot whoami` on bob's machine)
loot peer add bob "ssh-ed25519 AAAA..."

# deliver a sealed grant via the relay
loot grant --relay origin .env bob

# bob fetches and applies it
loot pull-grants           # verifies alice's signature, checks peer registry
loot surface               # now bob can read .env
```

### Embargo: timed reveals

```bash
# mark a file as embargoed until unix timestamp 1800000000
echo "VULN_DETAILS=CVE-2025-XXXX" > security-fix.txt
printf 'security-fix.txt embargoed=1800000000\n' >> .lootattributes

loot status -m "patch for CVE-2025-XXXX"
loot push                  # relay holds the ciphertext; key withheld until reveal_at
```

At `reveal_at`, `flush_escrow` promotes the key so anyone who pulls can read it.
The seam for a third-party key custodian (network escrow) is designed and ready.

## Architecture

```text
crates/
  loot-core       canonical engine: encrypted DAG, per-content visibility, convergence
  loot-identity   ed25519 keypairs, x25519 ECIES, signed push envelopes, peer registry
  loot-net        relay HTTP server + sync client (stow/negotiate/grant mailbox)
  loot-cli        the `loot` binary — commands are thin verbs over Workspace
  loot-bench      shared 50k-file benchmark workload
  spike-dag       thin shim re-exporting loot-core (bake-off compat)
  spike-crdt      non-canonical CRDT model (retained so the bake-off is reproducible)
```

### Key modules

| Module | What it owns |
| --- | --- |
| `loot-core::sealed` | Per-content encryption, key custody, embargo (ADR 0003, 0007) |
| `loot-core::converge` | Merger/relay convergence rule — decrypt-then-merge (ADR 0001) |
| `loot-core::engine` | Encrypted content-addressed DAG: put/get/record/surface/bundle/apply |
| `loot-core::manifest` | Grant audit trail: grantee, grantor pubkeys, timestamps |
| `loot-identity` | ed25519 sign/verify, x25519 derive, ECIES seal/unseal, push envelope |
| `loot-net::mailbox` | Relay grant mailbox: pubkey-addressed, content-addressed loose blobs |
| `loot-cli::workspace` | Ambient repo: identity, clock, persistence, idempotent snapshot |

### ADRs (docs/adr/)

| # | Decision |
| --- | --- |
| 0001 | Per-content decrypt-then-merge convergence |
| 0002 | Encrypted DAG as the canonical foundation (bake-off winner) |
| 0003 | Sealed content module + keyring custody (restricted keys never travel) |
| 0004 | Drop plaintext dedup equality oracle |
| 0005 | CLI slice, persistence, .lootattributes |
| 0006 | JJ-style workspace auto-snapshot |
| 0007 | Embargo escrow module |
| 0008 | Grant log and targeted key bundles |
| 0009 | Two-level revocation |
| 0010 | Forward-maroon implementation |
| 0011 | Relay stow append-only |
| 0012 | Per-object loose storage |
| 0013 | Named remotes and grant bundle delivery |
| 0014 | Identity keypairs: ed25519 OpenSSH, signed push envelopes |
| 0015 | Grant authentication and trust (grantor signs, peer-registry gate) |
| 0016 | Identity portability: export/import with passphrase wrapping |
| 0017 | RepoStore: one home for the `.loot/` layout |
| 0018 | Signed changes: author in id + validity enforcement |
| 0019 | Format versioning + compatibility gate (newer reads older) |

See [CONTEXT.md](CONTEXT.md) for the full domain glossary.

## Build & test

```bash
cargo build
cargo test          # ~25s — includes HTTP relay integration tests
cargo test -p loot-core   # fast, no I/O, 67 tests
```

## Command reference

```text
loot init [--identity <name>]             initialize a repo (identity from global config if omitted)
loot clone <url> <dir>                    clone a relay into <dir>; ends with a materialized working tree
loot config set <key> <val>              set a global config value (~/.config/loot/config)
loot status [-m <message>]               snapshot the working tree into the working change (idempotent)
loot describe -m <message>               name the working change
loot new                                 finalize the working change; start a fresh one
loot surface                             materialize what the current identity may see
loot log                                 show change history with visibility hints
loot bundle <file>                       write a sync bundle (ciphertext, no keys)
loot apply <file>                        merge a peer's bundle (idempotent)
loot grant <path> <identity> <file>      write a targeted grant bundle (file delivery)
loot grant --relay <remote> <path> <id>  seal and deliver a grant via relay mailbox
loot grants [<url>]                      peek pending grant count (no download)
loot pull-grants [<url>]                 fetch, verify, and apply sealed grants from relay
loot maroon [--hard] <path> <identity>   cut off <identity> from future access
loot migrate <path> <vis-spec>           change a path's visibility
loot manifest                            show the grant audit trail
loot conflicts                           list paths needing resolution
loot resolve <path> <file>               resolve a conflict
loot remote add <name> <url>             register a relay URL
loot push [<url>]                        publish changes to a relay
loot pull [<url>]                        fetch and merge changes from a relay
loot serve [--addr <host:port>]          run a relay
loot keygen                              generate an identity keypair
loot whoami                              show identity and public key
loot id export <file>                    export keypair, passphrase-encrypted
loot id import <file>                    import keypair from passphrase-encrypted file
loot peer add <name> <pubkey>            register a peer's public key
loot peer list                           list known peers
```
