# loot

A from-scratch source-control system.

**Thesis:** visibility and permissions belong to *content and changes*, not to
the *repository*. Commit your `.env`. Keep files private inside a shared repo.
Embargo a security fix: merge it, cut the release, reveal the source later.

This is the unsolved problem in modern version control. Ergonomics (jj already
nails them) are a layer for later.

## Status: working end-to-end slice

The thesis is demonstrable today: commit a private `.env`, and it checks out for
its keyholder while anyone else gets the same repo *without* it.

```bash
cargo build
cd $(mktemp -d)
printf 'TOKEN=supersecret\n' > .env
printf '# My Project\n'      > README.md
printf '.env restricted=alice\n*.md public\n' > .lootattributes

loot init --identity alice
loot commit -m "initial commit"
rm .env README.md
loot checkout            # alice: restores README.md AND .env

# a non-keyholder, same repo + commit:
printf mallory > .loot/identity
rm -f .env README.md
loot checkout            # mallory: restores README.md; .env stays sealed
```

The `.env` ciphertext is present in `.loot/` the whole time — mallory simply
can't decrypt it. Privacy is per-content, not per-repo.

### Sync carries ciphertext, not keys

```bash
# alice (keyholder) ships a bundle
loot bundle alice.loot

# bob, a different identity, applies it
loot apply alice.loot     # .env -> relayed (sealed, bob lacks the key)
loot checkout             # bob gets the public files; .env stays sealed
```

A non-keyholder can carry and forward your encrypted content without ever
reading it — the *relay* role. Restricted keys never travel in a bundle.

## Architecture

- [`crates/loot-core`](crates/loot-core) — the canonical engine and its deep
  policy modules: `engine` (encrypted content-addressed DAG, ADR 0002),
  `sealed` (encryption/visibility/embargo, ADR 0003), `converge` (the
  merger/relay convergence rule, ADR 0001).
- [`crates/loot-cli`](crates/loot-cli) — the `loot` binary: `init`, `commit`,
  `checkout`, `log`, `bundle`, `apply` (ADR 0005).
- [`crates/spike-crdt`](crates/spike-crdt) + [`crates/loot-bench`](crates/loot-bench)
  — the non-canonical CRDT model and shared workload, retained so the
  foundation bake-off stays reproducible (`docs/bakeoff/index.html`).

See [CONTEXT.md](CONTEXT.md) for the glossary and `docs/adr/` for decisions.

## Build & test

```bash
cargo build
cargo test
```
