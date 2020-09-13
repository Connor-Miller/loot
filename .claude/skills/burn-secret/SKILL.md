---
name: burn-secret
description: Respond to a secret that got sealed Public by mistake — detect whether it was pushed, run `loot burn`, and print rotation guidance. Triggers on "burn secret", "mis-sealed", "accidental public", "leaked .env", "loot burn".
---

# burn-secret — respond to a mis-sealed secret

> ## ⚠️ HUMAN-IN-THE-LOOP — NOT AUTOPILOT
> This is the **highest-stakes error in loot**. `loot burn` is a **non-undoable
> operation barrier** (ADR 0031, the `push`/`grant`/`maroon` class): once the
> bytes are destroyed there is no `loot undo`. Whether the secret was **ever
> pushed** changes the entire response. **Never run `loot burn` on your own
> judgment when the answer is "already pushed" or "unknown" — stop and get an
> explicit human go-ahead first.** You are here to detect, warn, and guide, not
> to quietly execute a barrier.

## Purpose

A secret (`.env`, a `*.pem`, an `id_ed25519`, an API credential) was sealed
**Public** in finalized loot history — usually because a typo'd `.lootattributes`
rule (`.evn restricted=alice`) let it fall through to the public default, so the
mis-seal gate never named it. `migrate`/`maroon` only re-seal the *future*; the
old Public object stays readable to every peer, relay, and git mirror that holds
it. `loot burn <path>` is loot's cure: it **destroys the object's bytes and
records a signed tombstone** (the burn log) while the change graph — every node,
id, and signature — stays intact. This skill runs that cure safely, and its whole
job is getting the **never-pushed vs. already-pushed** branch right.

## Triggers

Invoke when the human says any of: "burn secret", "mis-sealed", "accidental
public", "a secret went public", "leaked `.env` / key / credential", or asks to
run `loot burn`.

## The binary

Use the repo's release build, **not** the `loot` on `PATH` (that copy is a stale
pre-fix engine): `./target/release/loot.exe` from the repo root. Build it first
(`cargo build --release`) if it is missing. Confirm the verb with
`./target/release/loot.exe burn --help`. Run every command from the working
directory the human is in — never reach into another checkout.

## Step 1 — Identify the path and confirm the exposure

Establish exactly which path is mis-sealed and that it really is Public.

- `loot surface` — materialize what the current identity may see; confirm the
  path is present in the tree (and, in old changes, that it is not already
  labelled `burned`).
- `loot status --porcelain` — read the per-path visibility column (the
  `~<TAB>path<TAB>visibility` rows). The path you are about to burn should show
  **Public**. If it already shows Restricted/Embargoed, stop: there is likely no
  leak, and burn is the wrong tool.

Do not proceed until you and the human agree on the exact `<path>`.

## Step 2 — Determine push status (HITL — read this carefully)

This is the branch that decides everything, and there is **no clean
programmatic check**.

> **KNOWN GAP — `loot push --dry-run` does not exist.** The original ticket
> assumed you could ask the relay whether it already holds the object via
> `loot push --dry-run`. That flag is **unbuilt** (issue #11). Do not run it —
> it will error. There is no push-status probe against the relay today.

So push status is a **human determination**, aided (never replaced) by local
signals:

- `loot op log` — the operation log **flags disclosure barriers**, and `push` is
  recorded as one. If you see a push barrier that could have carried this
  change's object, the secret **was pushed** → treat it as **already-pushed**.
- `loot log` — locate the change that sealed the path, to reason about whether it
  predates any push.

**A push op in the log proves "pushed." Its absence proves NOTHING.** The op log
only knows about pushes *this machine* made — it cannot see a peer that pulled,
the git mirror projected+pushed to a git remote, or a push from another clone.
So you must ask the human directly:

- Has this repo (or any clone) ever `loot push`ed since the secret was sealed?
- Was the change ferried to the git mirror and that mirror pushed to a git
  remote (GitHub etc.)?
- Could any peer have pulled it?

**If the human cannot say for certain, treat it as ALREADY-PUSHED.** When in
doubt, assume disclosure.

## Step 3 — Branch on push status

### Branch A — NEVER pushed (confirmed local-only)

The only copy was on this machine, so destruction is **complete** — the true
remedy.

1. Warn once, out loud, that `loot burn` is **non-undoable**. Confirm the human
   still wants to proceed.
2. Run `loot burn <path>`. It destroys every historical object of the path,
   records the signed tombstone, and prints the tier — expect
   **`never-pushed = complete`**. Sync will now permanently refuse to re-accept
   the burned oid, so no later pull can resurrect it.
3. Report **complete**: the bytes are gone everywhere they ever lived.
4. **Recommend a `.lootattributes` rule** so the accident cannot recur — an
   *explicit* rule is consent the mis-seal gate honors; falling through is not.
   Suggest, e.g.:
   ```
   .env restricted=<your-identity>
   ```
   (or the matching glob for the leaked path). This is the prevention companion
   to the cure.

### Branch B — ALREADY pushed, OR push status UNKNOWN

**STOP. Do not run `loot burn` yet.**

1. Report plainly to the human: the object was (or may have been) disclosed to a
   relay, a peer, or a git remote. Local destruction alone will **not** retract
   bytes on machines you do not control — this is best-effort, exactly like a
   hard maroon. The secret must be treated as **compromised and rotated**,
   regardless of what burn does.
2. **Fix the git mirror FIRST, before burning.** If the change was projected into
   the git mirror (and possibly pushed to a git remote), the secret's bytes are
   still in the git **tip**. Ordering matters: a `ferry` re-ingests tip content
   under a *fresh* oid the burn log cannot match, silently resurrecting the leak.
   So first remove/re-seal the path **at the git tip** (and rewrite git history on
   mirror + remote with filter-repo/BFG, or accept-and-rotate). loot never
   rewrites git history itself. Only then burn.
3. **Wait for explicit human confirmation** before running the destructive verb.
4. Only after that go-ahead, run `loot burn <path>` (still non-undoable). Expect
   the tier **`pushed = best-effort`**: local bytes destroyed plus a tombstone
   that travels as a **purge event** asking cooperating relays and peers to
   delete their copy — offline or modified peers cannot be forced.
5. Print / relay the **rotation guidance** burn itself emits, and reinforce it:
   - **Rotate the leaked credential now** — new key/token/password; revoke the
     old one at its source. Bytes already copied elsewhere are gone, same as git;
     rotation is the only real containment.
   - Apply the git-mirror remedy from step 2 if not already done.
   - Add the `.lootattributes` rule from Branch A so it never recurs.

## Do / Don't

- **Do** default to Branch B whenever push status is not provably local-only.
- **Do** warn about non-undoability *before* every `loot burn` invocation.
- **Do** fix the git tip before burning when a mirror is involved.
- **Don't** invent `loot push --dry-run` — it does not exist (#11).
- **Don't** run `loot burn` on an already-pushed or unknown secret without an
  explicit human go-ahead.
- **Don't** call burn a "purge," "delete," or "rewrite" — it destroys bytes and
  tombstones them; the graph is untouched.
