---
name: maroon-identity
description: Revoke an identity's access to a path with `loot maroon` — walk the forward-vs-hard choice with the human, run the chosen mode, and confirm via `loot grant-status`. Triggers on "revoke access", "remove Y from X", "maroon".
---

# maroon-identity — revoke an identity's access to a path

> ## ⚠️ HUMAN-IN-THE-LOOP — NOT AUTOPILOT
> `loot maroon` cuts off an identity, and it comes in **two modes with very
> different blast radius**: a **forward** maroon (future access only) and a
> **hard** maroon (forward *plus* a purge event asking every peer to drop the
> content). Maroon is a **non-undoable operation barrier** (ADR 0031, the
> `push`/`grant`/`maroon` class — `loot undo` refuses to cross it). **Never pick
> forward vs. hard on your own judgment.** Present both modes, wait for the human
> to choose, then run only what they picked.

## Purpose

Someone should no longer be able to read a path — a teammate rotated off the
project, an identity was compromised, or a `restricted=` set is shrinking.
`loot maroon <path> <identity>` re-seals `<path>` under a **new key**, re-grants
the **remaining** authorized identities (each gets a fresh targeted grant), and
finalizes a signed re-seal change so it propagates via push/bundle
(`CONTEXT.md`, Maroon). This skill runs that revocation safely; its whole job is
getting the **forward vs. hard** branch right and never choosing it for the
human.

## Triggers

Invoke when the human says any of: "revoke access", "remove `<identity>` from
`<path>`", "maroon `<identity>`", "cut `<person>` off from `<path>`", "they left
the org — pull their access", or asks to run `loot maroon`.

## Type: HITL

The **diagnostic** step is read-only (`loot grant-status`) and safe to run. The
**maroon itself is a non-undoable disclosure barrier** and the **mode choice is
the human's** — stop and present both, do not run `loot maroon` until the human
picks forward or hard.

## The binary

Use the repo's release build, **not** the `loot` on `PATH` (that copy is a stale
pre-fix engine):
`C:\Users\conno\source\repos\loot\target\release\loot.exe`. Confirm the verb with
`loot maroon --help` before running. Run every command from the **working
directory the human is in** (this lane / their checkout) — never reach into
another position's tree.

## Step 1 — Confirm who currently holds the key

Establish the exact `<path>` and see who is granted before you revoke anything.

- `loot grant-status <path>` — lists current grantees for `<path>` (grantor,
  delivery method, granted_at). It is the sanity check before maroon (#5).
- Confirm the `<identity>` you are about to maroon actually appears, and note who
  will **remain** — those are the identities the maroon re-grants. Grantees are
  keyed by **pubkey**, not name; resolve names via `loot peer list` if unsure.

Do not proceed until you and the human agree on the exact `<path>` and
`<identity>`.

## Step 2 — Present the two modes and WAIT (do not choose)

Lay both modes out plainly and ask the human to pick. Do not run anything yet.

### Forward maroon — `loot maroon <path> <identity>`

- **Cuts off future access only.** Re-seals `<path>` under a new key and
  re-grants the remaining identities; the marooned identity **keeps the key for
  any past versions they already hold**, but gets nothing new.
- Natural for **"you may read the old code but not future updates."**
- No purge event; peers are not asked to delete anything.

### Hard maroon — `loot maroon --hard <path> <identity>`

- **Forward maroon plus a published purge event** telling every cooperating peer
  to remove the marooned identity's keyring entry for the affected OID.
- **Best-effort, not a guarantee:** cooperating machines purge; offline or
  modified-binary peers cannot be forced. It does **not** claw back content the
  identity already read and copied elsewhere.
- Models the **"person left the org"** case.

> The distinction is real and irreversible once run. **Wait for the human's
> explicit forward-or-hard decision.** If they are unsure, explain that hard adds
> a best-effort purge request but never guarantees deletion — then still let them
> choose.

## Step 3 — Run the chosen mode

Only after the human picks:

- **Forward:** `loot maroon <path> <identity>`
- **Hard:** `loot maroon --hard <path> <identity>`

(An optional trailing `[dir]` targets another repo dir; omit it to act on the
current one.) The verb snapshots the working tree first (ADR 0030) and finalizes
a signed re-seal change — no manual `loot status` needed. Remember this crosses a
barrier: **`loot undo` will refuse afterward.**

## Step 4 — Confirm the revocation

- `loot grant-status <path>` — re-run it. The marooned `<identity>`'s pubkey
  should now be **gone** from the grantee list, and the remaining identities
  should show fresh grants.
- If the change needs to reach peers, it propagates on the next `loot push`
  (forward re-seal) / and the purge travels with it (hard). Confirm with the
  human whether a push is expected here.

## Do / Don't

- **Do** run `loot grant-status <path>` before and after — it is the audit check.
- **Do** present forward vs. hard as the human's decision and wait.
- **Do** warn that maroon is non-undoable before running either mode.
- **Don't** choose the mode autonomously — the blast radius differs too much.
- **Don't** claim maroon un-shares already-disclosed content. **Forward is
  future-only** (the identity keeps keys for versions they already hold), and
  **hard's purge is best-effort** — neither retracts bytes already read or copied
  off-machine. For a mis-sealed *secret*, that is the `loot burn` lane, not
  maroon.

## See also

- `CONTEXT.md` — Maroon, Grant, Grant expiry, Manifest, Peer registry, Burn.
- ADR 0009 / ADR 0010 — hard maroon + purge, forward maroon re-seal.
