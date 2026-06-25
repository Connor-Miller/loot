# Named remotes in `.loot/config`; grant bundles are file-only until keypairs

## Status

accepted

## Context

Two independent but related decisions resolved while designing `loot grant`:

**Named remotes.** After transport landed (`loot push <url>` / `loot pull <url>`),
callers had to repeat the relay URL on every invocation. The natural fix — a
`name = url` config file and `loot remote add origin <url>` — was deferred to
the grant slice as the forcing function (grant's optional relay delivery required
the same infrastructure).

**Grant bundle delivery.** `loot grant` produces a targeted bundle carrying a
content key. The question: should it push the bundle to a relay automatically
(like `push` does for sync bundles), or write a local file for the user to
deliver out-of-band?

## Decision

### Named remotes

Store relay URLs in `.loot/config` as `name = url` pairs (blank lines and `#`
comments ignored). Three subcommands manage them:

```
loot remote add <name> <url>
loot remote remove <name>
loot remote list
```

`loot push` and `loot pull` resolve their target in priority order:
1. Explicit positional URL argument
2. `--remote <name>` flag
3. `origin` default

This upgrades the UX for all network commands at once; the seam is
`Workspace::remote_url(name) -> Option<String>`.

### Grant bundle delivery: file-only for the first slice

Grant bundles carry raw content key bytes (identity keypairs are a deferred
foundation — see ADR 0011 / CONTEXT.md). Routing a bundle with an unencrypted
restricted key through a relay would give the relay that key, directly
violating the thesis: **the relay holds no restricted keys**.

The seam is designed for the upgrade: when identity keypairs land, the grant
bundle's keyring section switches from raw bytes to `encrypt(key, recipient_pubkey)`,
and relay delivery becomes safe without changing the rest of the grant flow.

Until then, `loot grant <path> <identity> <file>` writes a `.bundle` file the
caller delivers directly (sneakernet, scp, a private channel). The `--relay`
flag is intentionally absent from `grant` to make the limitation visible.

## Considered alternatives

**Push grant bundles to the relay anyway.** Rejected: even temporarily punching
a hole in the "relay holds no restricted keys" invariant is the wrong tradeoff.
The fix (keypairs) is planned and the upgrade seam is designed; accepting the gap
would normalize the violation and risk it lingering.

**One universal `loot sync` command hiding push and pull.** Rejected at the
transport layer (ADR 0011): push is a deliberate disclosure act; pull is safe by
construction. Named remotes make the UX smoother without conflating the semantics.

## Consequences

- `.loot/config` is a new on-disk file. Workspace reads it lazily (missing =
  empty). The format is intentionally minimal — if loot ever needs richer config,
  this format is easy to extend.
- `loot remote add origin <url>` once; then bare `loot push` / `loot pull` work.
- `loot grant` writes a bundle file. The absence of `--relay` is a deliberate
  signal: this is a private key handoff, not a broadcast.
- When identity keypairs land, grant delivery to a relay is additive (no ADR
  needs revisiting — just implement the sealed-to-recipient key path and add
  `--relay` to `grant`).
