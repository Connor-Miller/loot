---
name: diagnose-visibility
description: Diagnose why a path is absent from `loot surface` by walking loot's four-way visibility decision tree (embargo / missing grant / unregistered-peer quarantine / expired grant). Use when the user asks "why can't I see X", "path not visible", "surface shows nothing", or "is this embargoed?".
---

# diagnose-visibility

Explain, in one line, **why a given path does not appear in `loot surface`** — and
print the exact command that fixes it.

loot's whole thesis is that visibility is a property of content, not the repo
(see `CONTEXT.md`). The cost of that power is that four *very* different failures
look identical from the outside — the file is simply not there:

- it is **embargoed** (encrypted to everyone until a reveal time),
- no **grant** has ever been issued to this identity,
- a grant *was* issued but the sender is an **unregistered peer**, so it sits in
  **quarantine**,
- a grant exists but has **expired**.

This skill disambiguates them.

## Triggers

Run this when the operator says any of:

- "why can't I see `<path>`"
- "`<path>` is not visible" / "surface shows nothing for `<path>`"
- "is `<path>` embargoed?"
- "I pulled but the file didn't show up"

## Type: AFK

Runs unattended. **Every diagnostic step below is read-only** (`surface`,
`embargo-status`, `grant-status`, `manifest`, `grants --quarantined`,
`peer list`, `whoami`, reading `.lootattributes`) — safe to run in a loop
without operator input. The **fixes are not**: `loot grants --trust`,
`loot pull-grants`, and any `loot grant` cross a trust/disclosure barrier and are
non-undoable (`CONTEXT.md`, Operation log & undo). So this skill **diagnoses and
prints the fix command; it does not run the mutating fix.** Stop after the
diagnosis line and hand the command to the operator.

### Setup (once, before the tree)

The real binary is
`C:\Users\conno\source\repos\loot\target\release\loot.exe` (the `loot` on PATH is
an older build). Run every command from the **repo / lane working directory**,
never edit or run verbs in another position's tree.

Two facts you need throughout:

- **This identity's pubkey** — `loot whoami --pubkey` (bare OpenSSH line). This is
  what you look for in the grantee list; a grant is keyed by pubkey, not name.
- **Known peers** — `loot peer list` (name → pubkey). This is loot's `known_hosts`
  and the registry that gates *accepting* grants.

Note: there is **no `loot checkout`** — the materialize verb is `loot surface`.
Prefer the `loot peer` command over poking `.loot/peers` by hand.

## Decision tree

Confirm the symptom first: `loot surface` — is `<path>` actually absent? If it is
present, there is nothing to diagnose. If absent, walk the branches **in order**
and stop at the first that matches.

### 1. Embargoed? — `loot embargo-status <path>`

Reports one of: *embargoed until `<unix ts>` (`<human date>`)*, *revealed*, or
*not embargoed*. It checks history, not just the working tree.

- **embargoed** → **STOP.** The content is encrypted to everyone until the reveal
  time; the key is not on any machine yet (`CONTEXT.md`, Threat model).
  - Diagnosis: `<path> is embargoed until <human date> — no key exists anywhere yet.`
  - Fix: **wait.** After `reveal_at` the relay releases the timed grant; run
    `loot pull-grants` then `loot surface`. If you are the *originator*, your local
    escrow flushes automatically on the next read — just `loot surface` past the
    reveal time. There is no way to open it early.
- **revealed** or **not embargoed** → embargo is not the cause. Go to step 2.

### 2. Are you even authorized? — read `.lootattributes` + `loot whoami --pubkey`

`.lootattributes` maps path globs to visibility
(`.env restricted=alice`, `*.md public`; unmatched → Public). Find the glob that
matches `<path>` and read its authorized identity set.

- **glob resolves the path `public`** → you should be able to see it; the block is
  not permission. Re-check step 1, or suspect a burn: `loot surface` labels a
  destroyed path *burned* (`CONTEXT.md`, Burn). If burned, the bytes are gone
  permanently — request a fresh copy from a holder.
- **glob is `restricted=<names>` / `embargoed=…` and your identity is NOT in the
  set** → you were never meant to hold this key.
  - Diagnosis: `<path> is restricted to <names>; your identity is not authorized.`
  - Fix (print, don't run): ask an authorized holder to grant you —
    `loot grant --relay <your-name> <path> <your-identity>` on their machine, then
    you run `loot pull-grants`.
- **your identity IS in the authorized set** → a grant is owed to you. Go to step 3.

### 3. Was a grant ever issued to you? — `loot grant-status <path>`

Lists current grantees for `<path>` (grantor, delivery method, granted_at).
Compare the grantee pubkeys against your own `loot whoami --pubkey`.

- **your pubkey is ABSENT from the grantee list** → no grant has been issued to
  you yet.
  - Diagnosis: `<path> has no grant to your identity — nobody has handed you the key.`
  - Fix (print, don't run): a holder issues
    `loot grant --relay <your-name> <path> <your-identity>`; then you run
    `loot pull-grants` and `loot surface`.
- **your pubkey IS listed** → the grant was issued; it just hasn't landed in your
  keyring. Go to step 4.

### 4. Did the grant get quarantined? — `loot grants --quarantined`

A grant from a pubkey your peer registry does not recognize is **quarantined**,
not applied (`CONTEXT.md`, Quarantine / Peer registry). Lists every pending entry:
sender pubkey hex, oid, received time. (If you have not fetched yet, `loot grants`
peeks the relay mailbox count and `loot pull-grants` drains it — a grant from an
unregistered sender quarantines on the way in.)

- **an entry's sender pubkey is NOT in `loot peer list`** → this is the failure.
  The key arrived but you never told loot to trust the sender.
  - Diagnosis: `A grant for <path> is quarantined from unregistered sender <pubkey-hex>.`
  - Fix (print, don't run): verify the pubkey out-of-band, then
    `loot grants --trust <sender-pubkey-hex>` — it registers the sender as a peer
    **and** re-applies every quarantined grant of theirs. Then `loot surface`.
- **nothing quarantined** → the grant applied cleanly but surface still skips it.
  Go to step 5.

### 5. Has the grant expired? — `loot manifest`

`loot manifest` is the grant audit trail; it records each grant's `expires_at`.
Past `expires_at`, `surface` skips the path **even though the key still sits in
your keyring** (defense-in-depth; `CONTEXT.md`, Grant expiry). This is the last
branch because it is the only one where you *hold* the key and still can't read.

- **the manifest entry for `<path>`/your pubkey has an `expires_at` in the past**
  (compare against now) →
  - Diagnosis: `Your grant for <path> expired at <human date>; the key is held but surface refuses it.`
  - Fix (print, don't run): the grantor re-issues with a future expiry —
    `loot grant --relay <your-name> <path> <your-identity> --expires <future-ts>` —
    then you `loot pull-grants` and `loot surface`. (Expiry only rides the
    `--relay` grant path; the tag-1 file grant carries none.)

### Fell through all five

The path is authorized, granted, un-quarantined, and unexpired but still absent —
that is not a visibility failure. Check that the path exists in the change at all
(`loot log --path <path>`, `loot status`) and that you are on the right position
(`loot lanes` / `loot status`). Report it as out of this skill's scope.

## Output contract

Emit exactly two lines per run:

```
diagnosis: <one-line reason, naming the branch that matched>
fix: <the exact command to run — or "wait until <date>" for embargo>
```

## See also

- `CONTEXT.md` — Visibility, Embargo, Escrow, Grant, Grant expiry, Peer registry,
  Quarantine, Burn.
- `docs/agents/workflow.md`, `docs/agents/identity.md` — positions, identities,
  and how grants travel between clones.
