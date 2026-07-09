# Prompt: sync GitHub issues → `.scratch/` wayfinder maps (pull-only)

Paste this whole file to an agent that has an authenticated `gh` CLI and this repo
checked out. It materializes the wayfinder maps and tickets on GitHub down into
`.scratch/` files, idempotently. It is the mirror image of `sync-to-github.md`:
here **GitHub is the source of truth** and `.scratch` is regenerated to match.

> Do not run this in the same pass as the push prompt. Pick a direction: push
> (`.scratch` wins) or pull (GitHub wins). Running both interleaved can clobber
> edits. If in doubt, ask the user which side is authoritative right now.

---

## Your task

Pull every wayfinder map on GitHub (issues labelled `wayfinder:map`) and their
child tickets down into `.scratch/<effort>/`, reconciling status, answers, and
blocking. **One-way** (GitHub → `.scratch`) and **idempotent** (safe to re-run —
update files, don't duplicate).

## Preconditions — verify first, stop if any fail

1. `gh auth status` succeeds.
2. Run from the repo root (`git rev-parse --show-toplevel`); `gh` infers the repo.
3. Confirm the repo out loud: `gh repo view --json nameWithOwner -q .nameWithOwner`.

## Default to a dry run

Unless the user said "apply" / "for real", **do a dry run**: print the files you
*would* create or change and a unified-diff-style preview of each, but write
nothing. Then ask the user to confirm before applying.

## The model (how GitHub maps to `.scratch`)

- **Map issue** (label `wayfinder:map`) → `.scratch/<effort>/map.md`. Body becomes
  the file body; H1 = issue title.
- **Child ticket** (sub-issue of the map, label `wayfinder:<type>`) →
  `.scratch/<effort>/issues/NN-<slug>.md`. `<type>` from the `wayfinder:<type>`
  label sets the `Type:` line.
- **Blocking**: GitHub native issue dependencies → the ticket's `Blocked by: NN, NN`
  line (local ids, resolved via backrefs). None → `—`.
- **Status**: closed issue → `Status: resolved`; open + assignee → `Status: claimed`;
  open + unassigned → `Status: open`.
- **Answer**: the issue's resolution comment → the ticket's `## Answer` section.

## Backref contract (identical to the push prompt — this makes round-trips safe)

The link between an issue and a `.scratch` file is a single `GitHub: #<n>` line
written immediately under the file's H1. Rules:

1. **It is file-local metadata, never part of the issue body.** When you write a
   file from an issue body, first **strip any `GitHub:` / `Part of #…` line out of
   the body**, then add exactly one fresh `GitHub: #<n>` line under the H1. Never
   carry a backref in from the GitHub body.
2. **`#<n>` is the sole identity anchor.** An issue whose number already appears in
   some file → update that file. An issue with no matching file → new file.
3. **The number is assigned once by GitHub and reused forever**, so a
   pull → (edit) → push cycle reuses the same issue and cannot duplicate.

**Discovering the effort/file for an issue:**

1. Search existing `.scratch/**/*.md` for a `GitHub: #<n>` line matching the issue.
   If found → that is the file to **update in place** (keep its path/number).
2. If not found → new locally. **Create** the file (see naming below) and write
   its `GitHub: #<n>` backref.

Because the mapping lives in the files, re-running only updates.

## Naming new local files (no existing backref)

- **New map**: slugify the map title into `<effort>` (lowercase, spaces→`-`,
  strip punctuation). If that dir exists for a *different* map, disambiguate with
  the issue number: `<slug>-<n>`. Create `.scratch/<effort>/map.md` and
  `.scratch/<effort>/issues/`.
- **New ticket**: number `NN` by the child's position in the map's ordered
  sub-issue list (`01`, `02`, …); slug from the ticket title. `issues/NN-<slug>.md`.
- Preserve existing local numbering when updating; never renumber a ticket that
  already has a backref (it would break `Blocked by` references).

## Order of operations (per map)

1. **List wayfinder issues:**
   ```
   gh issue list --state all --label wayfinder:map \
     --json number,title,body,labels,state,assignees,comments
   ```
   For each map, get its children (native sub-issues if available, else the map
   body's task list / issues whose body has `Part of #<map>`):
   ```
   gh api repos/{owner}/{repo}/issues/<map-n>/sub_issues --jq '.[].number'
   ```
2. **Write the map file** first (`map.md`), with `GitHub: #<map-n>` under the H1.
3. **Write each ticket file** in child order. For each child issue, fetch full
   detail (`gh issue view <n> --json title,body,labels,state,assignees,comments`),
   then:
   - `Type:` ← the `wayfinder:<type>` label
   - `Status:` ← closed→resolved, open+assignee→claimed, else open
   - body ← the issue body (drop any duplicate backref/`Part of` lines you re-add)
   - `## Answer` ← the resolution comment (for closed issues, the last/longest
     `## Answer`-style comment; if unsure which comment is the answer, take the
     final maintainer comment and note the assumption)

   - write `GitHub: #<n>` backref
4. **Second pass — blocking.** Now every ticket has a backref, so translate each
   issue's native dependencies to local ids:
   ```
   gh api repos/{owner}/{repo}/issues/<n> --jq '.issue_dependencies_summary'
   ```
   Map each blocker issue number → the local `NN` via its file's backref, and write
   the `Blocked by:` line. (Two passes because ids must exist before edges resolve.)

## Reconciliation rules (GitHub wins)

- If a local file and its GitHub issue differ, **GitHub overwrites the local file**
  (this is pull). Show the diff in the dry run so the user sees what changes.
- If a local `.scratch` ticket has a backref to an issue that **no longer exists**
  (404) or is no longer labelled wayfinder, report it and ask — don't delete.
- Local `.scratch` files with **no backref and no matching GitHub issue** are left
  untouched (they're unpushed local work; pull never deletes them).
- Update the map's `## Decisions so far` only if the map issue body changed; keep it
  as the map body carries it (it rides along as text).

## Report at the end

Print a table: map · issue #n · file · action (created / updated / skipped) ·
status · children pulled · blockers wired. List issues skipped and why. If it was a
dry run, say so and how to apply.

## Optional: pull a plain backlog to wayfind over

If the user just wants the *non-wayfinder* open issues as raw material for a new
map (not full reconciliation), dump a snapshot instead:

```
gh issue list --state open --json number,title,labels,body \
  --jq '.[] | "- #\(.number) \(.title)"' > .scratch/backlog-snapshot.md
```

Then a `/wayfinder` session can chart a new effort over that list.

**Round-trip scope — important.** Only issues labelled `wayfinder:map` /
`wayfinder:<type>` are materialized as tracked `.scratch` files with backrefs, so
only those round-trip safely with the push prompt. The `backlog-snapshot.md` dump
above is **read-only raw material** — it has no backrefs and must never be fed to
the push prompt (doing so would try to create issues from a plain list). If you
want a plain issue to become a tracked wayfinder ticket, add it to a map as a
child (label it `wayfinder:<type>`) so it earns a backref on the next sync.

## Guardrails

- Never delete local files; never `gh issue` write (this direction is read-only on
  GitHub).
- One file per issue — the backref is the single source of the link.
- Don't run alongside the push prompt; pick one authoritative side per pass.
