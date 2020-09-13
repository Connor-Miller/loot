# 36. loot's product front door: loot.millerbyte.com + the one-liner install

## Status

accepted (loot-site map [#204](https://github.com/Connor-Miller/loot/issues/204),
terminal ticket #211). Builds on ADR 0028 (git-interop bridge / sealed-free
projection — the visibility constraint on `site/`). The buildable detail lives in
`docs/specs/loot-site.md`; this ADR records the decision and its boundaries.

## Context

loot needs a public front door. The candidates were "a page under millerbyte.com's
Package/Docs area" versus "loot's own product subdomain." loot is its own product
with room to grow a pitch and roadmap later; it *borrows millerbyte's design
system*, not its information architecture. Separately, the install story had to be
first-class on Windows (this is a Windows dev shop) and not rest on `cargo install`
(a Rust-dev assumption). Four investigations settled the shape: release engineering
(#205), a real cross-platform install prototype (#206), the presentational-boundary
audit + `@millerbyte/ui` contract (#207/#208), the site IA (#209), deploy-chain
verification (#210), and Windows installer integrity (#221).

## Decision

- **A product subdomain: loot.millerbyte.com**, not a millerbyte Package page.
  Five surfaces: Landing · Install · Docs · Why loot · Evidence (IA in
  `docs/specs/loot-site.md`, from #209).
- **The site lives in-repo at `site/`** — TanStack Start in SSG mode, deployed as a
  **second Vercel project** rooted at `site/`. millerbyte.com is the live reference
  implementation; loot is the simpler all-static subset. DNS is a zero-registrar
  in-dashboard subdomain add (the zone is Vercel-managed). Install scripts are
  served through a Vercel external rewrite so `curl -sSf`/`irm` see a 200, not a
  redirect. The VPS relay is never a web or download host.
- **`site/**` is Public visibility** in `.lootattributes`. GitHub `main` is a
  sealed-free projection (ADR 0028) and Vercel builds from GitHub, so sealed
  content — notably `docs/pitch/` — structurally cannot be a build input. The site
  is authored fresh for users; sealed working-notes are private inspiration only.
- **The install story is a hosted one-liner** (`irm | iex` + `curl | sh`),
  cross-platform, binaries from **GitHub Releases via cargo-dist** (upstream, config
  in-tree). `cargo install` is a footnote. **Windows integrity is TLS-only for v1**,
  backed by GitHub Artifact Attestations + a published `sha256.sum` + documented
  manual verification — the generated PowerShell installer is shipped **unmodified**
  (the sh/ps1 checksum asymmetry is structural to dist, per #221).
- **The site borrows `@millerbyte/ui`** (published npm design system, born by atomic
  extract-and-swap in the millerbyte repo — millerbyte ADR 0010) for pixel-identity
  with millerbyte.com via shared plain-CSS tokens.

## Considered alternatives

- **A page under millerbyte.com** (no subdomain). Rejected: loot is a product with a
  pitch/roadmap ahead of it; it wants IA room, and only borrows the design system.
- **`cargo install` / crates.io as the headline.** Rejected: assumes a Rust dev and
  never exercises the real PATH-edit path; the general-audience one-liner is the
  story. `cargo install` stays a footnote (also gated on crate-name availability).
- **The VPS as a download/web host.** Rejected: it stays the zero-knowledge *relay*;
  GitHub Releases serves binaries (public repo → anonymous downloads), Vercel serves
  the site.
- **Hand-rolled PowerShell checksum verification.** Rejected (#221): forks dist's
  installer (re-patch every bump) and rides the same TLS anchor as script delivery;
  Artifact Attestations close the compromised-binary gap better.
- **Full SSR / on-demand rendering.** Rejected: the site is fully static content;
  SSG is the whole need, and it keeps the auth/CORS surface at zero.

## Consequences

- **A second Vercel project + a manual deploy ritual** (`vercel --prod`), inherited
  from millerbyte until the shared GitHub→Vercel auto-deploy is fixed (a fast-follow,
  not this decision's).
- **A real `v0.1.0` cut is gated** on machinery that does not exist yet: a tag-push
  **ferry verb** (#205) so `release.yml` reaches projected `main` on the tag, a
  **`loot --version`** (the binary can't report its version today — tracked as a
  standalone follow-on), and a **Linux `curl|sh` CI smoke leg**.
- **A cross-repo edge:** the loot site cannot pin a published `@millerbyte/ui`
  until millerbyte extracts and publishes it. The spec sequences millerbyte first.
- **The pitch stays sealed.** "Why loot" is authored fresh and sell-only; nothing
  from `docs/pitch/` is a build input, so ADR 0028's seal is preserved by
  construction, not by review vigilance.
