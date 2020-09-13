---
name: op-restore
description: Navigate loot's operation log to undo or restore a prior view. Use when the operator says "undo", "undo last", "step back", "restore op N", "go back to before X", or wants to reverse a view-changing command. Reads the op log for non-undoable barriers first, then steps back or jumps the view.
---

# op-restore

**Mode: AFK.** The diagnosis — reading the operation log and deciding whether the
target is reachable — is read-only and runs unattended. The `loot undo` /
`loot op restore` step is **local-view-only** (a pure pointer reset that never
touches the object store or the append-only graph; `CONTEXT.md`, Operation log &
undo), so it is safe to run once the barrier check passes. Stop and hand off only
where a barrier blocks the path (below).

## Purpose

Every **view-changing** command records one **operation** in loot's local-only
op log (`.loot/ops`). `loot undo` and `loot op restore <n>` are one-liners, but
they must not be fired blind: they **refuse across a non-undoable barrier**
(`push`, `grant`, `maroon`, `pull-grants`), and that refusal is *correct* — those
ops disclosed or published one-way state (a relay saw content, a keyring/manifest
changed) that a *view* reset cannot retract. This skill reads the log, checks for
a barrier between the current view and the target, and only then steps back.

## Triggers

- "undo", "undo last", "undo that"
- "step back", "go back one", "back to before `<command>`"
- "restore op `<n>`", "redo", "jump the view to `<n>`"
- any request to reverse a view-changing verb (`new`, `describe`, `abandon`,
  `adopt`, `lane merge`, `resolve`, `apply`/`pull`/`ferry`)

## Setup (once, before the steps)

The real binary is
`C:\Users\conno\source\repos\loot\target\release\loot.exe` (the `loot` on PATH is
an older build). Run every command from the **repo / lane working directory** you
want to move — the op log is per-machine and per-position; never run a verb in
another position's tree.

Two facts to keep straight (`CONTEXT.md`, Operation log & undo):

- The log is **newest-first** and **barriers are flagged** in `loot op log`.
- Restoring is itself a **new** operation, so the log only ever grows — redo
  always has a landing spot and **no change is ever deleted** (a signed change
  survives; undo just moves the head off it).

## Steps

### 1. Read the operation log — `loot op log`

Lists operations newest-first, each with its number `<n>` and a subject; the
**barrier ops (`push` / `grant` / `maroon` / `pull-grants`) are flagged**. The
top entry is the current view. Read it before touching anything.

### 2. Identify the target operation

- **"undo" / "step back" / "undo last"** → the target is one operation back: the
  second entry in the list (the view *before* the top op).
- **"restore op N" / "go back to before `<X>`"** → find the operation whose
  resulting view you want and record its number `<n>` from the log.
- **"redo"** (after an undo) → the target is the operation you undid *from*; it is
  still in the log (restore never deletes), so `loot op restore <n>` lands back on
  it.

If nothing needs reverting, or the log's top op is already the state you want —
**stop**; there is nothing to do.

### 3. Check for a barrier between the current view and the target

This is the whole reason the skill exists. Scan the entries **between the top of
the log and the target** for any op flagged as a barrier (`push`, `grant`,
`maroon`, `pull-grants`).

- **A barrier sits between them** → `undo` / `op restore` across it is **refused,
  and that is correct.** Do **not** try to force it. STOP and report: name the
  barrier op and its number, and give the real remedy — **reverse it forward**,
  not by view reset (`CONTEXT.md`, Operation log & undo):
  - a `push` disclosed content to a relay — you cannot un-disclose it; if the
    concern is a leaked secret, that is `loot burn` + rotate (see the
    `burn-secret` skill), not undo.
  - a `grant` / `maroon` / `pull-grants` changed one-way keyring/manifest state —
    reverse it with the opposing verb (`maroon` to cut off a mistaken grantee,
    a fresh `grant` to restore access), never by stepping the view back.
- **No barrier in between** → the target is reachable. Go to step 4.

### 4. Move the view — `loot undo` or `loot op restore <n>`

- **One step back** → `loot undo`. Steps the view back exactly one operation.
- **Jump to a specific operation** (further back, or redo forward) →
  `loot op restore <n>` with the number from step 2.

Both are local-view-only pointer resets. If the command still refuses at this
point, a barrier you missed sits in the path — re-read `loot op log` (step 3) and
respect the refusal.

### 5. Verify

Re-run `loot op log` — the restore you just did appears as a **new** top entry
(the log grew), confirming the view moved. Cross-check the actual state with
`loot status` / `loot log` to confirm the tree/heads are where you intended.

## Guardrail — barriers are a feature, not an obstacle

- **Never work around a barrier refusal.** `push`/`grant`/`maroon`/`pull-grants`
  are recorded non-undoable *by design*: they published or handed out one-way
  state a view reset cannot pull back. A refusal here means loot is protecting a
  disclosure boundary — treat it as correct and reverse the op **forward**
  instead.
- **`undo`/`op restore` are view-only.** They never delete a change, touch the
  object store, or rewrite the append-only graph — a signed change always
  survives. So an undo of a *non-barrier* op is cheap and reversible (restore
  forward again); confirm the barrier check in step 3 rather than fearing the
  step itself.
- **The log is local and per-position.** It is never bundled and is
  rebuildable-from-nothing (losing it loses undo history, not repo data). Run
  from the position you mean to move; do not expect one position's undo to affect
  another's.

## See also

- `CONTEXT.md` — Operation log & undo (barriers, view capture, restore-as-new-op),
  Push, Grant, Maroon, Burn.
- `burn-secret` skill — the forward remedy when the barrier you hit is a `push`
  that disclosed a secret.
