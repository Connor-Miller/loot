# Deploy-chain constraints: Vercel, site/ subdir, script serving
GitHub: #210 · wayfinder:research

## Question

**Does the decided deploy chain actually hold? Verify the constraints before
the spec commits to it.**

Decided: Vercel project #2 rooted at `site/` in this repo, TanStack Start SSG,
`loot.millerbyte.com` CNAME, install scripts served by the site, binaries from
GitHub Releases. Verify each link:

- **Vercel × subdir root** — a second Vercel project on the same GitHub repo
  with root directory `site/`: confirmed supported? Build settings for TanStack
  Start SSG static output (millerbyte's own migration targets the same stack —
  ADR-0006 — so findings transfer both ways).
- **Loot-first wrinkle** — Vercel builds from GitHub `main`, which is the
  ferry's sealed-free projection. Confirm `site/` will be public visibility in
  `.lootattributes` and that ferry-driven pushes trigger deploys sanely (or
  that manual `vercel --prod` is the interim ritual — fog holds the long-term
  answer).
- **Serving `install.ps1` / `install.sh`** — static assets at stable URLs with
  headers that survive piping: correct content-type (`text/plain`-ish, not
  HTML-wrapped), no compression surprises for `iex`, UTF-8 (no BOM) for
  PowerShell, and Vercel not rewriting/redirecting the path (www-canonical
  redirects bit millerbyte before — confirm none apply on the subdomain).
- **DNS** — where millerbyte.com's DNS lives and the one CNAME needed;
  interaction with the VPS records (the relay), if any.

Output: pass/fail per link with evidence (a scratch Vercel deploy is fair
game), recorded here for the spec ticket.
