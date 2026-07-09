# Prompt: sync `.scratch/` wayfinder maps → GitHub issues (push-only)

Paste this whole file to an agent that has an authenticated `gh` CLI and this repo
checked out. It mirrors every wayfinder map under `.scratch/` up to GitHub issues,
idempotently. It never deletes anything and never pulls GitHub state back down.

---

## Your task

Push the wayfinder maps and tickets under `.scratch/` to GitHub issues in this
repo, so they are visible and actionable there. This is **one-way** (`.scratch` is
the source of truth) and **idempotent** (safe to re-run — update, don't
duplicate).

## Preconditions — verify first, stop if any fail

1. `gh auth status` succeeds.
2. `git rev-parse --show-toplevel` — run everything from the repo root; `gh`
   infers the repo from the remote.
3. There is at least one `.scratch/<effort>/map.md`.

Then confirm the target repo out loud: `gh repo view --json nameWithOwner -q .nameWithOwner`.

## Default to a dry run

Unless the user said "apply" / "for real", **do a dry run**: print exactly the
`gh` commands you *would* run (issue creates, label adds, dependency edges,
closes) and the backref lines you'd write — but execute nothing. Then ask the user
to confirm before applying.

## The model (how `.scratch` maps to GitHub)

Each `.scratch/<effort>/` is one **map** plus its **tickets**.

- **Map** `map.md` → one issue **labelled `wayfinder:map`**. Title = the map's H1.
  Body = the map's markdown (Destination / Notes / Decisions-so-far / Not-yet-
  specified / Out-of-scope), verbatim.
- **Ticket** `issues/NN-<slug>.md` → one issue, linked to the map as a **GitHub
  sub-issue**, labelled `wayfinder:<type>` where `<type>` is the ticket's
  `Type:` line (`research` / `prototype` / `grilling` / `task`). Title =
  the ticket's H1. Body = the ticket markdown.
- **Blocking**: the ticket's `Blocked by: NN, NN` line → GitHub **native issue
  dependencies** (see below). `—` / empty means none.
- **Status**: `Status: resolved` → the issue is **closed** (post the ticket's
  `## Answer` as a comment first). `Status: claimed` → assign the issue to the
  current user (`--add-assignee @me`). `Status: open` → open, unassigned.

## Backref contract (read this — it is what makes round-trips deterministic)

The link between a `.scratch` file and its GitHub issue is a single line:

```
GitHub: #<n>
```

written immediately under the file's H1 (in `map.md` and in every
`issues/NN-*.md`). Rules — both sync prompts obey these identically:

1. **The backref is file-local metadata, never part of the GitHub issue body.**
   On push you MUST strip the `GitHub:` line before sending the body to GitHub.
   On pull you MUST (re)write it locally and never read it from the body. This is
   what stops it duplicating or embedding on a pull → push → pull round-trip.
2. **`#<n>` is the sole identity anchor.** A file with a backref always maps to
   that exact issue — update it, never create. A file without one is new.
3. **Numbers are assigned by GitHub, recorded once, then reused forever.** Push
   writes the backref the first time it creates an issue; pull writes it the first
   time it materializes a file. After that the number is stable across any number
   of syncs in either direction.

So: pull-all-then-push-back reuses the same issue numbers and cannot duplicate,
because every pulled file already carries its `GitHub: #<n>`.

**Algorithm per file:**

1. If the file already has a `GitHub: #<n>` line → the issue exists. **Update** it:
   `gh issue edit <n> --title ... --body-file <tmp>` where `<tmp>` is the file body
   **with the `GitHub:` line stripped** (per the Backref contract), reconcile
   labels, then apply Status (assign/close/reopen) and blocking. Do **not** create
   a new issue.
2. If it has no backref → **create**: `gh issue create --title ... --body-file <tmp>`
   (again, body with no `GitHub:` line), capture the new number, and **write
   `GitHub: #<n>` back into the file** (commit that change too if the user wants the
   backrefs tracked).

Because backrefs live in the files, re-running only ever updates.

## Order of operations (per effort)

1. **Ensure labels exist** (idempotent):
   ```
   for L in wayfinder:map wayfinder:research wayfinder:prototype wayfinder:grilling wayfinder:task; do
     gh label create "$L" --color ededed 2>/dev/null || true
   done
   ```
2. **Map issue first** (children need its number for sub-issue linking).
3. **Ticket issues** in filename order (`01`, `02`, …) so blocker numbers exist
   before you wire edges. Create/update each; write backrefs.
4. **Link each ticket to the map as a sub-issue.** Preferred (native sub-issues):
   ```
   PARENT_ID=$(gh api repos/{owner}/{repo}/issues/<map-n> --jq .id)
   CHILD_ID=$(gh api repos/{owner}/{repo}/issues/<child-n> --jq .id)
   gh api --method POST repos/{owner}/{repo}/issues/<map-n>/sub_issues -F sub_issue_id=$CHILD_ID
   ```
   If the sub-issues endpoint isn't available, fall back to a task list in the map
   body (`- [ ] #<child-n>`) and prepend `Part of #<map-n>` to each child body.
   Skip the link if it already exists (check before adding).
5. **Wire blocking** with native dependencies. Resolve each local `NN` to its
   GitHub number via that ticket's backref, then use the blocker's **numeric
   database id** (not `#number`, not `node_id`):
   ```
   BLOCKER_DBID=$(gh api repos/{owner}/{repo}/issues/<blocker-n> --jq .id)
   gh api --method POST repos/{owner}/{repo}/issues/<child-n>/dependencies/blocked_by -F issue_id=$BLOCKER_DBID
   ```
   Check existing dependencies first and don't re-add. If native dependencies are
   unavailable, ensure a `Blocked by: #<n>, #<n>` line is present at the top of the
   child body instead.
6. **Apply status**, in this order so a resolved ticket ends closed:
   - `claimed` → `gh issue edit <n> --add-assignee @me`
   - `resolved` → extract the `## Answer` section, `gh issue comment <n> --body-file <answer.tmp>`, then `gh issue close <n>`. (If already closed, skip.)
   - `open` → if the issue is closed on GitHub but the file says `open`, `gh issue reopen <n>` (the file wins — push-only).

## Field reference (how to parse a ticket file)

Fields are simple `Key: value` lines near the top:

- `Type:` → one of research / prototype / grilling / task → label `wayfinder:<type>`
- `Status:` → open / claimed / resolved
- `Blocked by:` → comma-separated local ids (`01, 04`) or `—`
- `GitHub:` → `#<n>` backref (present iff already synced)

The map's `## Decisions so far` already links tickets by their local path; leave
that text as-is (it's human-readable and rides along in the map body).

## Report at the end

Print a table: effort · file · action (created #n / updated #n / skipped) ·
status applied · blockers wired. List any files that couldn't be parsed. If it was
a dry run, say so and how to apply for real.

## Guardrails

- Never `gh issue delete` or close anything not marked `resolved` in `.scratch`.
- One issue per `.scratch` file — the backref is the single source of the link.
- If a backref points to an issue that no longer exists (404), report it and ask;
  don't silently recreate.
- Don't touch issues that have no corresponding `.scratch` file.
