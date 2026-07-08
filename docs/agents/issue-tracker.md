# Issue tracker

This repo tracks work as GitHub issues on `Connor-Miller/loot` via the `gh` CLI.
The `issues/` directory holds pre-publication drafts only (published by the
`create-*.sh` scripts); once published, GitHub is canonical.

## Wayfinding operations

Wayfinder (the planning skill) maps onto GitHub like this:

- **Map** — a GitHub issue labelled `wayfinder:map`. Current map:
  [#54 — thesis-proof milestone: loot hosts loot](https://github.com/Connor-Miller/loot/issues/54).
- **Tickets** — sub-issues of the map (native sub-issue relationship), each
  labelled `wayfinder:research` | `wayfinder:prototype` | `wayfinder:grilling` |
  `wayfinder:task`.
  - Attach: `gh api -X POST repos/Connor-Miller/loot/issues/<map>/sub_issues -F sub_issue_id=<issue id>`
    (the numeric `id` from `gh api repos/.../issues/<n> --jq .id`, not the number).
- **Claiming** — assign the ticket to yourself before any work
  (`gh issue edit <n> --add-assignee @me`). Open + unassigned = unclaimed.
- **Blocking** — GitHub native issue dependencies:
  `gh api -X POST repos/Connor-Miller/loot/issues/<n>/dependencies/blocked_by -F issue_id=<blocker id>`.
- **Frontier query** — open, unassigned sub-issues of the map whose blockers are
  all closed. List candidates with
  `gh issue list --label "wayfinder:grilling" --label "wayfinder:task" ...` or
  read the map issue's sub-issue panel; check each candidate's *Relationships*
  panel (or `gh api repos/.../issues/<n>/dependencies/blocked_by`) for open blockers.
- **Resolution** — post the answer as a comment, close the issue, append a
  one-line pointer to the map's *Decisions so far* section.

Execution work (feature slices like CA2–CA4) stays as ordinary issues; wayfinder
tickets are only the decisions/investigations charting the way.
