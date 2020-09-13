# Issue tracker: GitHub, via `gh`

This repo's tracker is GitHub Issues (`Connor-Miller/loot`), driven with the
`gh` CLI. This doc is the tracker-specific contract the wayfinder skill
consults; it sits beside [workflow.md](workflow.md) (how work lands) and
[identity.md](identity.md) (who agents are).

## Wayfinding operations

- **Map**: an issue labelled `wayfinder:map`. Tickets are issues labelled
  `wayfinder:<type>` (`research` / `prototype` / `grilling` / `task`).
- **Child**: a ticket's body carries `Child of map #<n>` (GitHub sub-issues
  are not used).
- **Blocking**: a body convention — `**Blocked by #<n>**` in the ticket body.
  A ticket is unblocked when every issue it names there is closed.
- **Frontier**: open, unassigned tickets of the map whose blockers are all
  closed. There is no native query; list the map's children and check their
  blockers: `gh issue list --label "wayfinder:grilling" ...` then
  `gh issue view <n>`.
- **Claim**: assign yourself — `gh issue edit <n> --add-assignee @me` — then
  run the claim ritual below. An open, unassigned ticket is unclaimed.

## Claim ritual: a claim spawns its lane (#232, ADR 0034/0035)

Work on a claimed ticket happens in a sealed lane, not in the primary
directory — that is what makes N concurrent agents in this repo safe. After
assigning:

```
loot lane new --ticket <n> --porcelain     # from the primary; row: L  id  name  path ...
cd <path from the row>                     # work here until the ticket lands
```

- The handle is ticket-derived (`t<n>`, suffixed until free), so
  `loot lanes` doubles as the claim board.
- Before acting on shared state (landing, `loot gc`, remotes), check
  `loot lanes --porcelain`: it reports each live lane's dir, tip, in-flight
  PR, dirty/clean, and heartbeat age, and is read-only (observing never
  refreshes another lane's heartbeat).
- Land through `loot-first review` / `land` as usual (workflow.md). Landing
  marks the lane; `loot lane gc` from the primary reaps it afterwards —
  don't delete the directory by hand.
- Caveats: spawn is primary-only and needs a keyed repo. Lands are serialized
  by the harbor lock (#229, ADR 0036): `loot-first land` takes a brief
  shared-store lock across the git-main projection, so concurrent lands queue
  rather than race — no manual one-at-a-time discipline needed.
