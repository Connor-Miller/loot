# ADR 0024 — Thesis-proof milestone: loot hosts loot

Date: 2026-07-07
Status: accepted

## Context

A drift check (wayfinder charting session) found the roadmap had shifted toward
feature-borrowing: the S-epic imported lore's feature set, and the DX tail grew
speculatively, while the most thesis-critical gaps (hard embargo enforcement,
#14) sat untouched. The project needed a fixed point to measure "on-path"
against.

## Decision

The next milestone is a **demonstrable proof of the thesis** ("visibility and
permissions are properties of content and changes, not of the repository"):

**loot hosts loot.** This repo's daily development runs on a loot relay on the
VPS, with the dev and AI agents as distinct identities in one repo — at least
one path genuinely restricted from agents, a grant/maroon cycle exercised in
real use, and one hard-embargoed change.

Scope decisions settled with it:

- **Hard embargo is in the milestone.** Cooperative (honest-clock) embargo does
  not prove the thesis; external-service escrow (#14) is on the path, not fog.
- **Dual-run with git.** `.loot/` and `.git/` coexist; GitHub keeps issues and
  backup. Divergence pain is dogfood data, not a failure.
- **The CA epic is on-path.** Docks/harbor/porcelain/buoys (CA2–CA4) are how
  agents participate as identities — retroactively justified by the milestone.
- **The DX tail is evidence-gated.** Daily-driver gaps get unparked by the
  dogfood pilot's findings, not speculation.

## Consequences

Planning runs through the wayfinder map
([#54](https://github.com/Connor-Miller/loot/issues/54)); every open issue is
triaged on-path / parked / dropped against this milestone (#55). Post-milestone
directions (zero-knowledge host as a product, multi-human collaboration) stay in
the map's Fog.
