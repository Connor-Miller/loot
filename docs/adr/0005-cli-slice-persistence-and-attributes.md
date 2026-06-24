# First product slice: a persistent CLI over the engine

## Status

accepted

## Context

The engine (`loot_core::engine`) was built and validated entirely in-memory; the
only thing that touched disk was `checkout`. To prove the thesis for a real user
— commit a private `.env`, check it out as an authorized vs. denied identity —
we need a CLI. A CLI is process-per-command, which forces three decisions the
in-memory engine never had to make: how state persists between invocations, how
the ambient identity and clock enter (the `Repo` trait takes `reader`/`now` per
call, which suited the bake-off's many-identity/fake-clock scenarios), and how a
user declares per-path visibility.

## Decision

Build a new `loot-cli` binary crate with four commands: `init`, `commit`,
`checkout`, `log`. No sync yet (bundle/apply is a later slice).

- **Persistence lives on the engine.** Add `DagRepo::save(dir)` /
  `DagRepo::load(dir)`, serializing repo state under `.loot/` using the engine's
  own (extended) wire encoding. The engine owns its on-disk format, just as it
  owns the sync wire format — the CLI only calls `load -> mutate -> save`. The
  alternative (a CLI-side persistence module) would require public accessors
  onto `object_store`/`change_graph`/`keyring`, leaking engine internals.
- **The keyring is a local-only file.** `.loot/keyring` holds this identity's
  content keys and is never part of a bundle (ADR 0003). On-disk it sits beside
  the objects, but it is conceptually private custody, not repo content.
- **Ambient identity from config, real clock.** `loot init --identity alice`
  writes `.loot/config`; every command reads `reader` from it and supplies
  `now = SystemTime::now()`. The `Repo` trait is unchanged — the CLI is a thin
  adapter that supplies the ambient values the trait already expects.
- **Visibility via `.lootattributes`.** A gitattributes-style file maps path
  globs to visibility (`.env restricted=alice`, `* public`). `commit` reads it
  and seals each path accordingly. Declarative and persistent, so a user can't
  silently leak `.env` by forgetting a per-commit flag.

## Considered alternatives

- **Per-command `--identity` / per-file visibility flags.** Simplest, but
  nothing persists; one forgotten flag commits `.env` as Public — a leak the
  declarative `.lootattributes` prevents.
- **CLI-owned persistence.** Rejected: leaks engine storage layout into the CLI.
- **Including embargo in this slice.** Deferred: embargo is still spike-honest
  (ADR 0003), so demoing it now would precede its hardening. The slice uses
  Public and Restricted only; the attributes format leaves room for embargo
  later.

## Consequences

- The engine gains a durable on-disk format. It is internal (written and read
  only by loot) and versioned implicitly by the engine; a real format-stability
  guarantee is out of scope for the slice.
- `now` from the system clock means embargo timing in the CLI is wall-clock
  based; the spike-honest caveat (a keyholder can bypass embargo) is unchanged.
- This is the first crate that is a *product*, not a spike or a benchmark.
