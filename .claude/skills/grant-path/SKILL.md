---
name: grant-path
description: Grant a restricted path's read key to a named peer — verify the peer is registered, pick file-bundle or relay delivery, issue the grant, and confirm it. Triggers on "grant X to Y", "give access to", "share path with", "let <peer> read <path>".
---

# grant-path — grant a restricted path to a named peer

> ## ⚠️ HUMAN-IN-THE-LOOP — NOT AUTOPILOT
> A grant hands a **content decryption key** to another identity and is an
> **operation barrier** (`grant` is in the non-undoable `push`/`grant`/`maroon`
> class, `CONTEXT.md` → Operation log & undo). Handing the key to the **wrong
> identity** cannot be taken back — `loot maroon` only re-seals *future* content,
> the peer keeps every byte it already read. So the human, not you, **confirms
> the exact recipient identity and picks the delivery method** before you issue
> anything. Never guess who "Y" is.

## Purpose

A path is sealed **Restricted** (readable only by named key holders,
`CONTEXT.md` → Visibility). Another person needs to read it. Granting is a small
ceremony with two failure modes agents keep hitting:

1. **Issuing a grant to an unregistered peer.** A grant is keyed by pubkey; if
   the recipient was never `peer add`ed the grant either can't be addressed or,
   on the receiving side, **quarantines** as coming from an unregistered sender.
   Verify registration **first**.
2. **Delivering the key but not the content.** The grant carries the *key*, not
   the sealed *bytes*. If the restricted content was never pushed to the relay
   (or the bundle never handed over), the recipient applies the grant and still
   sees nothing.

This skill runs the ceremony end-to-end and closes both gaps.

## Triggers

Invoke when the human says any of: "grant `<path>` to `<peer>`", "give
`<peer>` access to `<path>`", "share `<path>` with `<peer>`", "let `<peer>`
read `<path>`", or asks to run `loot grant`.

## Type: HITL

The human confirms the recipient identity and chooses delivery. You verify,
issue the grounded command, and confirm — you do **not** pick the recipient or
the method on your own.

### Setup (once, before the steps)

The real binary is
`C:\Users\conno\source\repos\loot\target\release\loot.exe` (the `loot` on PATH
is an older build). Run every command from the **repo / lane working directory
the human is in** — never reach into another checkout. Confirm verbs against
`loot help` (per-subcommand `--help` only prints global usage; `loot help` is
authoritative).

## Step 1 — Pin the path and the recipient (HITL)

Get the human to name, unambiguously:

- the **`<path>`** to share, and
- the **recipient identity `<identity>`** — the name it will be registered under.

Confirm the path is actually restricted before granting: `loot grant-status
<path>` (lists current grantees) or read the matching glob in `.lootattributes`.
If the path is Public there is nothing to grant; if it is Embargoed, a grant
can't open it early (`CONTEXT.md` → Embargo). Do not proceed until the human
confirms the recipient.

## Step 2 — Verify the peer is registered (do this FIRST)

- `loot peer list` — name → pubkey, loot's `known_hosts`. Look for the recipient.
- **Present** → good, go to step 3.
- **Absent** → register them. You need the recipient's public key, obtained
  **out of band** (they run `loot whoami --pubkey` and send you the bare
  OpenSSH line — verify it through a trusted channel, this is the trust
  decision). Then:
  ```
  loot peer add <identity> <pubkey>
  ```
  (`<pubkey>` of `-` reads the key from stdin.) Re-run `loot peer list` to
  confirm.

Never skip this step — an unregistered recipient means the grant can't be
addressed, and a grant *from* an unregistered grantor lands in the recipient's
quarantine instead of their keyring.

## Step 3 — Choose delivery (HITL): file bundle vs. relay

Ask the human which one. They are genuinely different:

| | **File bundle** | **Relay** |
|---|---|---|
| command | `loot grant <path> <identity> <file>` | `loot grant --relay <remote> <path> <identity> [--expires <ts>]` |
| how it travels | you hand `<file>` over out of band; recipient runs `loot apply <file>` | deposited straight into the relay's grant mailbox; recipient runs `loot pull-grants` |
| expiry | **none** — a tag-1 bundle carries no expiry | `--expires <unix-ts>`: recipient's `apply_sealed_grant` rejects it once `now >= ts` (#20, #352) |
| when | air-gapped / no shared relay, or one-off | there's a shared relay and you want auto-delivery and/or a time-boxed grant |

Note `<remote>` in the relay form is the **relay name or URL** (a registered
remote from `loot remote list`), *not* the recipient — the recipient is the
final `<identity>` positional.

## Step 4 — Issue the grant

### Delivery A — file bundle

```
loot grant <path> <identity> <file>
```

Writes a targeted, signed grant bundle to `<file>` (ciphertext + the wrapped
key; no private keys). **`--expires` is refused here** — if the human wants
expiry, use the relay form. Then **hand `<file>` to the recipient** (secure
channel); they apply it with `loot apply <file>`.

### Delivery B — relay

```
loot grant --relay <remote> <path> <identity>
# time-boxed:
loot grant --relay <remote> <path> <identity> --expires <unix-ts>
```

Seals and **deposits the grant into `<remote>`'s mailbox** — the command prints
`delivered sealed grant … recipient runs loot pull-grants to receive it`. On an
embargoed path the grant inherits the seal's `reveal_at` (a late recipient still
gets a timed, never an early, key).

## Step 5 — Make sure the CONTENT is on the relay too (the "forgot to push" trap)

The grant delivers the **key**, not the sealed **bytes**. If the restricted
content isn't already where the recipient will fetch it, they'll `pull-grants`,
file the key, and *still* surface nothing.

- **Relay delivery** → confirm the sealed content is published:
  `loot push` (publishes your sealed objects to the relay; the relay still can't
  read them). Grant delivers the key; `push` delivers the ciphertext — the
  recipient needs both, then `loot pull-grants` + `loot pull` / `loot surface`.
- **File delivery** → the `<file>` bundle already carries the ciphertext for that
  path, so `loot apply <file>` is enough on the recipient side — no push needed.

Do not report "granted" to the human until the recipient has a route to the
bytes, not just the key.

## Step 6 — Confirm

```
loot grant-status <path>
```

Lists current grantees for `<path>` — grantor, delivery method, granted_at. Check
the recipient now appears with the delivery method you used. (This is also the
pre-flight check before any later `loot maroon`, #5.) Report the one-line result:
who now holds the key, by which method, and — for relay — that the content was
pushed.

## Do / Don't

- **Do** run `loot peer list` and register the recipient **before** granting.
- **Do** let the human confirm the recipient identity and pick file vs. relay.
- **Do** push the sealed content (relay) or hand over the bundle (file) — the key
  alone is not access.
- **Do** use the `--relay` form when the human wants an expiry; it's the only
  path that enforces one (#352).
- **Don't** put `--expires` on the file-grant form — it's refused loudly.
- **Don't** confuse the relay form's `<remote>` (a relay name/URL) with the
  recipient `<identity>`.
- **Don't** treat a grant as reversible — it's a non-undoable barrier; `maroon`
  only re-seals the future.

## See also

- `CONTEXT.md` — Visibility, Identity, Peer registry, Quarantine, Sealed grant,
  Grant, Embargo, Operation log & undo.
- `docs/agents/identity.md`, `docs/agents/workflow.md` — identities, peers, and
  how grants travel between clones.
- Related skills: `diagnose-visibility` (recipient-side: why a path still won't
  surface), `burn-secret` (a path sealed Public by mistake).
