# Spec: loot.millerbyte.com — the loot product site + install pipeline

**Status:** hand-off-ready. Single source of truth for the *execution* session
that builds the site. Assembled by the terminal ticket of map
[Chart loot.millerbyte.com to a buildable spec (#204)](https://github.com/Connor-Miller/loot/issues/204);
every decision below is already resolved on a closed ticket — this document
collects them, it does not re-open them. Backed by
[ADR 0037](../adr/0037-loot-product-site-and-install.md) (loot side) and
millerbyte `docs/adr/0010-millerbyte-ui-design-system-package.md` (`@millerbyte/ui`).

## 0. What we are building

A fully static (SSG) product front door for loot at **loot.millerbyte.com** —
five surfaces (Landing · Install · Docs · Why loot · Evidence) — served as a
second Vercel project rooted at a new `site/` directory **in this repo**,
consuming the published **`@millerbyte/ui`** design system, and fronting a
cross-platform one-liner install (`irm | iex` + `curl | sh`) whose binaries come
from GitHub Releases via cargo-dist CI. The VPS stays loot's *relay*; it is never
a download or web host.

Non-destructive to loot's engine: the site is pure presentation + a release
pipeline. No gateway, no auth, no CORS surface.

## 1. Repository & directory layout

- **`site/` at the loot repo root** — TanStack Start in SSG mode (the millerbyte
  frontend is the live reference implementation of this exact stack; loot is the
  simpler all-static subset — no auth islands, no denylist). Deploy-chain
  verification: [#210](https://github.com/Connor-Miller/loot/issues/210), evidence
  `docs/research/deploy-chain-loot-site.md`.
- **`site/**` must be Public visibility** in `.lootattributes` — GitHub `main` is a
  sealed-free projection (loot-first, `docs/agents/workflow.md`); Vercel builds
  from GitHub, so sealed content structurally can never be a build input. The
  sealed `docs/pitch/` therefore cannot leak into a build even by accident.
- **Content authored fresh** for users as MDX content collections under `site/`,
  mining existing markdown (README, CONTEXT.md, evidence docs) for raw material.
  ADRs stay internal (not shipped).

## 2. Deploy configuration  (from #210)

- **Vercel project #2**, root directory = `site/` (proven pattern:
  millerbyte.com uses `rootDirectory: "frontend"`). Start/Vercel SSG preset,
  committed & in-flight on millerbyte per ADR-0006.
- **DNS is trivial** — the `millerbyte.com` zone is Vercel-managed (NS
  `ns*.vercel-dns.com`), so `loot.` is added in-dashboard: **zero registrar work,
  no CNAME**. No `redirects` block, so the apex→www 308 cannot leak onto the
  subdomain.
- **Install scripts served via a Vercel external rewrite / reverse proxy** so the
  hero command is on-brand and `curl -sSf` (no `-L`) sees a **200, not a 3xx**:
  - `/install.sh`  → `…/releases/latest/download/loot-cli-installer.sh`
  - `/install.ps1` → `…/releases/latest/download/loot-cli-installer.ps1`
  This is astral's exact production architecture for uv. The proxy fronts the
  **script only** — the binary archive is fetched GitHub-direct (see §5).
- **Interim deploy = manual `vercel --prod`** (inherits millerbyte's ritual; its
  GitHub→Vercel auto-deploy is broken — a shared fast-follow, not this spec's).
- **VPS relay (`api.→72.60.231.231`) is untouched** — never a download host.

## 3. `@millerbyte/ui` dependency  (from #208)

The site depends on the published **`@millerbyte/ui`** package (public npm,
`@millerbyte` scope) at `^0.1.0`. Full contract lives in millerbyte
`docs/adr/0010`. What the execution session needs to know:

- **Theming = plain CSS custom properties, no Tailwind preset.** Import the
  bundled stylesheet once at the site root: `import "@millerbyte/ui/theme.css"`.
  Pixel-identity with millerbyte.com is guaranteed because both sites import the
  identical CSS bytes; the package carries **zero `tailwindcss` dependency**.
- **Components** are named ESM exports from `.` (tree-shakeable). React/react-dom
  (+ framer-motion/lucide-react as used) are **peerDependencies** — the site
  supplies them.
- **ESM-only**, `.d.ts` floor TS 6.0 (resolves under the site's TanStack/TS
  toolchain).
- **Birth order:** `@millerbyte/ui` is extracted and published from the millerbyte
  repo (single atomic extract-and-swap PR) **before** the loot site can consume a
  published version. This is the one cross-repo sequencing edge — see §6.

## 4. Page tree + content sources  (from #209)

Nav = the five surfaces. Header: `loot` (home) · Install · Docs · Why loot ·
Evidence · [GitHub ↗]. Footer: install one-liner repeated · GitHub · license · a
"built with loot" badge → Evidence/loot-first.

| Route | Content | Source |
| --- | --- | --- |
| `/` Landing (**show-leaning**) | thesis hook + install one-liner + a "what works today" glimpse + three demo vignettes (private `.env` · embargo a fix · grant a key) → deep-link into Docs; CTA row Install / Why loot / Evidence | README §thesis, §"what works today", §three demos; CONTEXT.md thesis line |
| `/install` | platform-detected default command (§5), all-platforms listing, `cargo install` footnote, GitHub-Releases manual-download fallback, **verify-your-download** section (§5), troubleshooting | #205 target matrix, #206 install path, #210 proxy, #221 integrity |
| `/docs` | MDX collection: **Getting started** (quickstart from the README `.env` demo) · **Core concepts** (user-facing subset, *distilled* from CONTEXT.md — see below) · **Task guides** (1:1 from README demos) · **CLI reference** (hand-written v1, seeded verbatim from README §Command reference, grouped local/docks/sync/grants/identity/setup) | README (quickstart, command table, demos); CONTEXT.md (distilled) |
| `/why` Why loot (**fresh authored, SELL-ONLY**) | hook ("every host reads your code; loot's relay physically cannot") · the claim (a key that never leaves your machines vs a permission bit) · why now (AI agents make custody radioactive) · plaintext services = explicit audited grants · proof → Evidence. **No honest-limits section in v1.** | freshly authored; ideas-only from `docs/pitch/zk-host.md` (**stays sealed, no bytes**, ADR 0028 intact); CONTEXT.md Relay entry |
| `/evidence` | a **"proof log" index** — one card per proof, a "what this proves" line over the **verbatim** committed run output | `docs/evidence/*.md` + `docs/evidence/runs/*.txt` (loot-hosts-loot, concurrent-agents, amend-divergence, loot-first, hard-embargo attack demo) |

**User-facing core concepts** (dev→user distillation of the CONTEXT.md glossary,
*not* lifted): Changes · Visibility (public/restricted/embargoed) + `.lootattributes`
· Identity & keys ("permissioning is key management") · Grants · Relays & hosts
("a host is a relay that never sleeps") · Embargo · Docks (light, framed as the
concurrent/agent tool).

**Mining rule:** README → landing/quickstart/CLI-ref; CONTEXT.md → concepts;
evidence → proof log. The README §Architecture / ADR table is **not** shipped in
v1 (dev-facing). `docs/pitch/zk-host.md` is **private inspiration only**.

## 5. Install pipeline  (from #205, #206, #221)

- **Release engineering = cargo-dist, upstream** (`dist-workspace.toml` already
  in-tree, v0.32.0; shell + powershell installers; `hosting = "github"`;
  `install-path = ~/.loot/bin`, deliberately not CARGO_HOME). The generated
  `.github/workflows/release.yml` is checked in so an upstream stall can't strand
  us.
- **v1 target matrix — 5 native triples, as shipped in `v0.1.0`:** win x64 (MSVC)
  · mac arm64/x64 · linux x64/arm64 (**gnu**). Unified release tag **`v0.1.0`**
  (loot-cli bumped 0.0.0→0.1.0, `publish = false` + `[metadata.dist] dist = true`).
  **Win arm64 is served, not built:** the matrix originally chartered 6 triples,
  but `aarch64-pc-windows-msvc` was dropped at the v0.1.0 cut (#258) — dist 0.32
  cross-builds it on a Linux container via cargo-xwin, where ring's ARM assembly
  won't compile (an upstream cc-rs/xwin interaction, not a loot defect). dist maps
  that triple onto the x64 zip in the ps1 installer, so ARM64 Windows still
  installs and runs **under x64 emulation**. A *native* arm64 binary is #270.
  **The Install page must not claim a native win-arm64 download until #270 lands**
  — the all-platforms listing has 5 native entries, not 6.
- **Artifact contract:** `loot-cli-{triple}.{tar.xz|zip}` + `loot-cli-installer.{sh,ps1}`
  + unified `sha256.sum` + `dist-manifest.json`, from GitHub Releases (public repo
  → anonymous downloads work).
- **Ship the installers unmodified** — proven on a real Windows 11 box (#206):
  detect → download → unpack → `~/.loot/bin` → HKCU PATH prepend persisted, fresh
  shell resolves `loot`, idempotent re-run = one PATH entry. Evidence
  `docs/research/install-prototype-loot.md` + `docs/evidence/runs/install-prototype-windows.txt`.
- **Windows integrity story (from #221):** **accept TLS-only on the automated
  `irm | iex` path for v1.** The sh-verifies / ps1-doesn't asymmetry is structural
  to dist (uv's live installers show the identical split; no config knob exists),
  and the site proxy does **not** widen the trust boundary — the ps1 hard-bakes
  GitHub URLs, so the binary is always GitHub-direct over TLS; the proxy fronts the
  script only. Do **not** patch the ps1. Instead ship **defense in depth**:
  1. **enable GitHub Artifact Attestations** in `release.yml` (dist supports it;
     uv enables it) — stronger than an embedded sha256,
  2. publish the unified **`sha256.sum`** (dist default),
  3. **document manual verification** on the Install page (Windows
     `Get-FileHash … -Algorithm SHA256` vs `sha256.sum`, plus `gh attestation
     verify`).
  Evidence `docs/research/windows-installer-integrity.md`.

## 6. Prerequisites, follow-ons, non-goals

**Hard prerequisites** (must land before a real `v0.1.0` cut, i.e. before the
site's install page is truthful):

- **`@millerbyte/ui` published** — the single atomic extract-and-swap PR lands in
  the millerbyte repo (millerbyte ADR 0010), then `npm publish -w packages/ui`,
  before the loot site pins `^0.1.0`.
- **`loot --version` must exist** — the shipped binary currently cannot report its
  own version; a tool distributed via *versioned* Releases must. Small code fix,
  tracked as a standalone loot issue (filed at map closure).

**Execution steps after this spec** (not map tickets — the map ends here):

- Build `site/` and author its content; wire the Vercel project + subdomain +
  proxy rewrites; manual `vercel --prod`.
- Cut the real `v0.1.0`: needs a **tag-push ferry verb** (flagged missing by #205)
  so `release.yml` reaches projected `main` on the tag, a live GitHub Release to
  prove `releases/latest` + the proxy resolve, and a **Linux `curl | sh` CI smoke
  leg** (no WSL locally).

**Fast-follows** (deliberately deferred, not blockers):

- **CLI reference generation from `clap`** — hand-written for v1; generate once the
  docs collection exists and drift becomes real.
- **GitHub→Vercel auto-deploy** — interim is manual `vercel --prod` (shared with
  millerbyte, whose auto-deploy is broken); model is compatible, just unwired.
- **musl static Linux** builds; **Homebrew/Scoop/winget** taps; **per-release docs
  versioning**; **native ps1 checksum verification** if dist adds it upstream (free
  on a version bump — drop the manual-verify emphasis then); **drand-timelock**
  embargo hardening.

**Explicit non-goals:**

- **A `cargo install` story as the headline** — it stays a footnote (gated on
  crates.io name availability); the hosted one-liner is the story.
- **A roadmap page** — parked; the sell-only Why-loot posture defers any public
  forward-commitment. Nav stays the five surfaces.
- **Shipping the hosted zero-knowledge-host *service*** (pricing, signup, operated
  relay as a product) — the post-milestone bet (map #54), out of scope here.

## 7. Execution order (suggested)

1. millerbyte: extract-and-swap `@millerbyte/ui`, publish `0.1.0` (millerbyte ADR 0010).
2. loot: add `loot --version`.
3. loot: scaffold `site/` (TanStack Start SSG), depend on `@millerbyte/ui`, import
   `theme.css`; build the five surfaces from §4.
4. loot: wire Vercel project #2 + `loot.` subdomain + `/install.{sh,ps1}` rewrites.
5. loot: cut `v0.1.0` (tag-push ferry verb + Release + Linux smoke), turn on
   Artifact Attestations; verify the live install one-liner end-to-end.
6. Deploy (`vercel --prod`); confirm the hero command and the manual-verify docs.
