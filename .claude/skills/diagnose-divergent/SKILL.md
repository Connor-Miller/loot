---
name: diagnose-divergent
description: Explain and resolve the `!` divergent-change marker in loot. Use when `loot log` shows `!`, `loot status` shows `!`, output mentions a "divergent change", or one change id lists "two versions". Walks the abandon-or-converge decision with real loot commands.
---

# diagnose-divergent

**Mode: AFK.** Runs autonomously through diagnosis and the safe branch; escalates
to the human (HITL) at the one point where it cannot know intent.

## Purpose

The `!` after a change id in `loot log` / `loot status` is opaque without
context. Agents that meet it either ignore it (leaving history forked) or try to
"fix" it as if it were a merge conflict (it is not). This skill explains what `!`
means and drives the abandon-or-converge decision to a clean resolution.

## Triggers

- `loot log` or `loot status` shows a change id with a trailing `!`
- output/user says "divergent change", "two versions", "loot log shows !"
- a change id appears on more than one `version` row

## What `!` means

`!` marks a **divergent change**: one durable **change id** carrying **more than
one live version id**. Two writers independently *rewrote the same change id*
(e.g. concurrent amends across two lanes). It is the honest record of a
concurrent amend, **not an error**.

Critically, this is a divergence of *history*, **not a tree/content conflict**:

- A **tree conflict** is same-path bytes that disagree → `loot conflicts` /
  `loot resolve`. Divergence is untouched by those verbs.
- A **divergent change** is one change id with two version ids. The two versions
  may even have identical trees. `loot resolve` does nothing for it.

Do not reach for `loot resolve` here. The two remedies are **abandon** (drop the
stale version) or **converge** (tree-merge the two into a new superseding
version).

Read the two ids from `loot log` (map #132):

- **change id** — durable handle, reverse-hex letters (`qsouzmpr`), in the
  `change` column. The `!` hangs off this.
- **version id** — content+author hash, 8 hex digits (`3f9a1c02`), in the
  `version` column. Rewrites on every snapshot.

## Decision walk

### 1. Parse the marker

Run `loot log` and find the change id carrying the trailing `!`. That same change
id will appear on **two or more `version` rows** — one per live version. Record
the change id and **both version ids** (from the `version` column). If nothing
in `loot log` carries a `!`, there is no divergence — **stop** (see the
guardrail; do not run `loot abandon`).

### 2. Confirm it is divergence, not a tree conflict

The `!` is the confirmation. Cross-check `loot conflicts` — if it lists paths,
that is a *separate* tree conflict to resolve on its own; it is not what `!`
means and `loot abandon` will not touch it.

### 3. Compare the two versions

```
loot diff <version-id-A> <version-id-B>
```

`loot diff` takes an id prefix as a selector, so pass the two 8-hex version ids
(a unique prefix is enough). Also read each version's `message` column in
`loot log` for its subject. This tells you whether one version is a stale
leftover or both carry real, wanted work.

### 4. Decide

- **One version is stale** (superseded, a leftover snapshot, or the abandoned
  side of a rewrite) → drop it:

  ```
  loot abandon <stale-version-id>
  ```

  This drops that one version and leaves the other live under the change id. The
  node is never deleted (it joins the local-only `.loot/abandoned` set the live
  view filters out), and the op is **undoable** (`loot undo`). Selectors: `@`,
  `HEAD`, `HEAD~<n>`, or an id prefix — use the version id prefix.

- **Both versions are valid** (each carries real work you want to keep) →
  **converge** them into a new superseding version. This is a genuine tree-merge
  (a different intent from abandon — it *produces a new version*), so it is the
  ordinary converge path, run from the position that owns the other line:

  - the other version lives in a named lane → `loot lane merge <id-or-name>`
  - the other version arrived as a bundle → `loot apply <file>`

  There is **no** single verb that takes the two version ids and merges them.
  Converge means re-running the path that carries the *other* line into this
  position. If you cannot identify which lane or bundle carries the other
  version, treat it as uncertain (below).

- **Uncertain** — you cannot tell which version is stale, or cannot locate the
  source that carries the other line for converge → **stop and hand off to the
  human (HITL).** Report the change id, both version ids, and the `loot diff`
  summary. Do not guess.

### 5. Verify

Re-run `loot log`. The `!` should be gone (abandon) or replaced by a single new
superseding version under the change id (converge).

## Guardrail — `loot abandon`

- **Only run `loot abandon` when `!` is actually present.** It refuses a
  non-divergent change (that safety exists so it can never hide a change's sole
  version) — never run it speculatively or to "clean up" a change you have not
  confirmed is divergent.
- Use **plain `loot abandon <version-id>`**. Do **not** use `loot abandon --head
  <selector>` here — that drops a whole independent fork tip, a different
  operation, not the divergent-version drop.
- Abandon is **undoable** (`loot undo`) if you drop the wrong side — but confirm
  with `loot diff` (step 3) first rather than relying on undo.
