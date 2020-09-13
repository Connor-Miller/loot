---
name: land-change
description: Finalize, review, and land the current lane's change onto main — the finalize → review → pre-land gate → harbor land cycle. Triggers on "land this", "open PR", "finalize and land", or when a working session in a lane is done and needs to reach main.
---

# land-change

Drive one lane's in-flight change through the loot-first workflow to `main`:
describe → finalize → review PR → **human approval** → harbor land. loot is the
merge authority; the GitHub PR is a review view, not the merge target
(`docs/agents/workflow.md`).

## Triggers

- "land this" / "land the change" / "land it"
- "open PR" / "open the PR" / "put it up for review"
- "finalize and land"
- a working session in a lane is finished and the change needs to reach `main`

## Type: HITL (human-in-the-loop)

**Stop and wait for a human** at the review gate (step 5). Do not self-approve,
do not skip the wait, and do not proceed to land until the operator confirms the
PR is approved. The land command enforces this (`reviewDecision == APPROVED`, or
the self-authored fast path), but the human is the gate — surface the PR and hand
control back.

## Binaries

Run the **built release** binaries from the primary checkout — the `loot` on
PATH is an old build. From a lane, use the absolute paths (a lane is a sibling
directory, so `.\target\...` will not resolve):

- `loot` → `C:\Users\conno\source\repos\loot\target\release\loot.exe`
- `loot-first` → `C:\Users\conno\source\repos\loot\target\release\loot-first.exe`

Below, `loot` / `loot-first` mean those two binaries. Verify with `--help` if
unsure.

## Guard conditions — check before touching anything

- **Wrong directory (critical).** NEVER run a mutating loot verb from the
  primary checkout `C:\Users\conno\source\repos\loot` — a stray `loot new` /
  `loot undo` there finalizes or re-materializes shared work destructively (bug
  #436). Confirm you are in a **lane** first (step 1). Single-owner verbs
  (`lane gc`, `lane rm`, `remote add`) refuse from inside a lane by design; land,
  describe, new, review all run **from the lane**.
- **Undescribed change.** `loot new` and `loot-first land` both **refuse** an
  un-described working change (#174/#275): the message they sign becomes the
  permanent subject on `main`. Name it first with `loot describe -m` (step 2).
  The refusal keeps your captured edits — only the signature waits for a name.
- **Unsigned ≠ blessed.** A review PR shows GitHub **Verified** (SSHSIG) while
  deliberately unsigned in loot. Verified means "loot's key made this commit,"
  not "finalized." The loot land is what blesses.

## Steps

### 1. Confirm you are in a lane (not the primary)

```
cat .loot/lane-id          # a lane prints its id, e.g. t406; the primary has no such file
loot lanes                 # shows this lane with its tip, in-flight PR, dirty/clean
```

If `.loot/lane-id` is absent (or `.loot` is a plain directory that is the shared
store), you are in the **primary** — STOP. Open or move into a lane
(`loot lane new --ticket <n>` from the primary) and work there.

### 2. Describe the working change (if un-described)

`loot status` shows `(working change)` or no subject when it is un-described.
Name it — this is **required** before finalize/land:

```
loot describe -m "<subject>"
```

`describe` captures the tree *without* finalizing and names the change while you
still remember what it does.

### 3. Finalize — `loot new`

```
loot new
```

Signs the current change (ADR 0018) and starts a fresh one on top. This is
git-quiet (no mirror I/O). It refuses an un-described change — if it does, go
back to step 2.

### 4. Open / update the review PR — `loot-first review`

```
loot-first review
```

This mints the provisional commit for the change and does the **single-ref push**
of the `review/<lane-id>` branch, then opens (or updates) the PR. Note: a bare
`loot ferry --with-wip` alone does **not** push to GitHub — `loot-first review`
is the command that publishes and opens/updates the PR. On a review comment,
edit and re-run `loot-first review`; it appends a commit to the same branch
(same change id) so GitHub shows "changes since your last review."

Capture the PR number it prints — you need it for step 6.

### 5. Human review + approval — WAIT HERE

Hand the PR to the operator and **stop**. Do not proceed until a human has
reviewed and approved it on GitHub. This is the HITL gate.

### 6. Land — `loot-first land --pr <n>`

Once approved:

```
loot-first land --pr <n>
```

This runs the **pre-land gate** (`cargo test` — review approved the *projected
WIP*, so nothing has yet proven the commit about to land builds), finalizes the
lane (a no-op if step 3 already signed), projects the one **signed** commit onto
`main`, and collapses the PR head onto it. GitHub **auto-closes** the PR on the
zero-diff collapse — that close *is* the landing signal; a pointer comment
(change id → landed sha) is the audit trail. A
`landed: change_id=… main=<sha> pr=#<n> status=…` verdict is emitted.

- **`--skip-tests`** is the break-glass for **non-code** lands (docs, config)
  where the `cargo test` gate adds nothing. Do not use it to bypass a failing
  build.
- **`describe_contention` flake.** A known pre-land test flake fires under CPU
  load. It is not a regression — just **re-run `loot-first land --pr <n>`**.

### If the land BOUNCES

A same-path conflict with work that landed while this lane worked **bounces** the
land: nothing is pushed, `main` stays put, the signed change is safe, and the
conflict surfaces in `loot conflicts`. **Do not improvise the recovery** —
hand off to the **`diagnose-bounce`** skill, which owns the reconcile recipe
(`loot resolve …` → re-run `land`).

## After a successful land

- **Catch-up is manual.** From the **primary** checkout (not this lane):
  `git merge --ff-only origin/main` on the git side, and `loot adopt` on the
  loot side to settle the primary onto the landed tip.
- **Reap the lane.** `loot lane gc` reaps the now-landed lane (unnamed lanes,
  once landed or stale). Run it from the primary — `gc` refuses from inside a
  lane.

## See also

- `docs/agents/workflow.md` — the daily loop (steps 2→7) and the
  review-projection / harbor-land mechanics.
- `docs/agents/concurrent.md` — running several lanes at once; what serializes at
  the harbor.
- `diagnose-bounce` skill — bounce recovery.
