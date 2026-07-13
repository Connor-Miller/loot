# Write the spec: loot.millerbyte.com
GitHub: #211 · wayfinder:grilling · blocked by #206 #208 #209 #210

## Question

**Assemble everything this map decided into the hand-off-ready spec + ADRs.**

The terminal ticket — runs when the install prototype, the `@millerbyte/ui`
contract, the site IA, and the deploy-chain verification are all closed.
Produce:

- **The buildable spec** — one document an execution session can build from:
  `site/` structure, page tree + content sources, the `@millerbyte/ui`
  dependency and its contract, the install pipeline (release CI, artifact
  contract, scripts), deploy configuration. Home: `docs/` in this repo (spec
  ticket picks the exact spot; precedent: research docs in `docs/research/`).
- **loot ADR** — the site + installer + subdomain decision (product front door
  at loot.millerbyte.com; site lives in-repo; one-liner install story; public
  visibility constraint on `site/`).
- **millerbyte ADR** — the `@millerbyte/ui` extraction: workspace package,
  presentational boundary, atomic extract-and-swap, sequencing vs the TanStack
  Start migration. (Authored in the millerbyte repo's `docs/adr/`.)
- **CONTEXT.md updates** — any new glossary terms the effort minted (in either
  repo), inline per repo convention.
- **Map closure** — resolve remaining fog into the spec, follow-on tickets, or
  explicit non-goals; the map closes when the spec is the single source of
  truth for execution.
