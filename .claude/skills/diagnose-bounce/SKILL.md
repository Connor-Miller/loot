---
name: diagnose-bounce
description: Resolve a bounced `loot-first land` — list the conflicted paths, surface both sides, resolve the true merge, and re-land. Triggers when a land bounces off the harbor: "land bounced", "conflict with harbor", "resolve and reland".
---

# diagnose-bounce

**Mode: AFK, with HITL escalation.** Run the recipe unattended; stop and ask a
human only at the two escalation points called out below (delete/edit conflicts,
and a merge you cannot decide from the two sides).

## Purpose

`loot-first land --pr <n>` serializes at the harbor (ADR 0036). When a sibling
lane lands while you worked, your land can **bounce**: the change conflicts with
what landed under you. The bounce is safe — nothing is pushed, your **signed
change is finalized and intact** — but the carry/adopt/resolve/re-land cycle is
not obvious from the error text alone. This skill drives it to a clean re-land.

The bounce message names the conflicted paths. That list plus `loot conflicts`
is your worklist.

## Triggers

- A `loot-first land` run reports a bounce / a same-path conflict with `main`.
- "land bounced", "conflict with harbor", "resolve and reland".

## Where you run

All verbs run **from the lane worktree**, never the primary checkout — a
mutating verb in the primary can clobber shared WIP (bug #436). Use the built
binary: `C:\Users\conno\source\repos\loot\target\release\loot.exe` (the `loot`
on PATH may be stale). Verify a subcommand with `loot <verb> --help`.

## Recipe

1. **List the conflicts.**

   ```
   loot conflicts --porcelain
   ```

   Each line is a path needing resolution (`C` rows carry the `ours`/`theirs`
   content addresses). This is your worklist.

2. **Carry your line onto landed `main` first — `loot adopt`.**

   If your resolution will need files a sibling *introduced* (e.g. your merged
   file references a module the sibling just added), run the no-arg catch-up
   **before** resolving:

   ```
   loot adopt
   ```

   This folds the harbor lineage in: it materializes the siblings' new files
   into your lane and cleanly merges every path that merges cleanly, shrinking
   the worklist to the genuinely-conflicted paths. Skipping this is the common
   trap — the pre-land `cargo test` gate compiles the lane **in isolation**, so
   a resolution that references a not-yet-present sibling file will not compile
   until this carry pulls it in. Re-run `loot conflicts` after adopting.

   (Un-described working change? `adopt` refuses, pointing at `describe -m` —
   name it first, the capture is not lost.)

3. **For each still-conflicted path, build the true merge.**

   ```
   loot diff --conflict <path>
   ```

   Shows both sides — `ours` and `theirs` — decrypted when you hold the key,
   otherwise the raw OIDs. Build the **real 3-way merge** against the sibling's
   version; this is usually *not* a naive pick-one. Write the resolved content
   to a temp file, then:

   ```
   loot resolve <path> <tempfile>
   ```

   Resolve **one path at a time** (`resolve` writes only that path). Repeat for
   every conflicted path.

4. **Verify, then re-land.**

   ```
   cargo test        # or cargo build — prove the resolved lane compiles
   loot-first land --pr <n>
   ```

   On re-land, each resolution folds into your carried commit, inheriting your
   subject as `<subject> (conflict resolution: <path>)` (#337). If `resolve`
   reported the bare `resolve conflict at …` placeholder instead, run
   `loot describe -m "<subject>"` before re-landing (#316 refuses otherwise).

## HITL escalation

**Escalate to a human — do not auto-resolve — when:**

- **A delete/edit conflict:** a path deleted on one side and edited on the
  other. Neither side auto-wins; resurrecting or dropping the file is a judgment
  call the agent must not make alone.
- **A content merge you cannot decide** from the two sides in
  `loot diff --conflict` (semantically incompatible edits, ambiguous intent).

Surface both sides and the paths involved, and ask before writing a resolution.

## Known flake

The pre-land gate occasionally trips a `describe_contention` test flake under
load. It is not a regression — just re-run `loot-first land --pr <n>`.

## STOP after landing

This skill ends at a clean re-land verdict. Do **not** run `loot lane gc` from
inside the lane (it refuses there); reaping the lane is a primary-side step.
