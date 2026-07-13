# Site IA and content plan
GitHub: #209 · wayfinder:grilling

## Question

**Page-by-page IA and content plan for the five surfaces: Landing, Install,
Docs, Why loot, Evidence.**

Pin, per page, what it says and where the material comes from:

- **Landing** — the thesis hook ("visibility and permissions belong to content
  and changes, not the repository") + the marquee one-liner + a "what works
  today" glimpse. How much sells vs shows?
- **Install** — platform-detected default command, all-platforms listing,
  `cargo install` footnote, manual-download fallback, troubleshooting.
- **Docs** — the collection structure: getting started, core concepts (the
  CONTEXT.md glossary is dev-facing — what's the *user-facing* concept set:
  visibility, grants, embargo, relay, identity, docks?), task guides, CLI
  reference (**hand-written v1**; generation from clap is fog). What's the v1
  page list?
- **Why loot** — the thesis deep-dive. **⚠ `docs/pitch/zk-host.md` is sealed
  content** (ADR 0028 guard rails: it never reaches GitHub). Mining it for
  public copy is a **deliberate reveal decision** — decide explicitly what
  reveals, what stays sealed, and whether the reveal uses `loot migrate` or
  copy is authored fresh with the pitch as private inspiration only.
- **Evidence** — `docs/evidence/*` (loot-hosts-loot, concurrent-agents,
  amend-divergence, loot-first) are dev-written proof docs. Present as-is,
  rewritten, or as a "proof log" index?

Also: the mining plan for public sources (README → quickstart, command table →
CLI reference), site nav/footer, and what "roadmap page" would even hold (fog —
confirm or park).

Output: the v1 page tree + per-page content sources, recorded here for the
spec ticket.
