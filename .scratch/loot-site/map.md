> ✅ **MAP CLOSED COMPLETE — 2026-07-12.** Destination reached: the buildable spec
> is **`docs/specs/loot-site.md`**, backed by loot **ADR 0037** (renumbered from
> 0036, which the concurrent #229 harbor land took) and millerbyte **ADR** 0010.
> **Loot-side docs landed on git main `e09cb90`** (break-glass, docs-only; the
> primary loot state was mid-reconcile from #229 so the next ferry ingests it).
> All seven tickets resolved (#205, #206, #207, #208, #209, #210, #221) +
> the terminal spec (#211). Execution proceeds from the spec, not this map; the one
> live prerequisite is [#237 `loot --version`](https://github.com/Connor-Miller/loot/issues/237).

## Destination

A **hand-off-ready buildable spec + backing ADRs** for **loot.millerbyte.com** —
loot's own product front door (Landing · Install · Docs · Why loot · Evidence):
TanStack Start SSG in a new `site/` dir in this repo, consuming a published
**`@millerbyte/ui`** design-system package (born by atomic extract-and-swap as a
workspace package in the millerbyte repo), with the marquee **cross-platform
install one-liner** (`curl | sh` + `irm | iex`) served by the site and binaries
from GitHub Releases via CI. Deploys as a second Vercel project. **Building the
site is separate execution after the spec** — this map ends at the spec.

## Notes

- **Decided at charting (do not re-litigate):**
  - **Product subdomain, not a millerbyte Package page** — loot is its own
    product with room to grow (landing/pitch later); it borrows millerbyte's
    *design system*, not its information architecture.
  - **Destination = spec + ADRs**, not a shipped site.
  - **Shared component library** (not just theme tokens): a published
    **`@millerbyte/ui`** npm package (public, like `@millerbyte/react-logging`),
    living as a **workspace package in the millerbyte repo** next to `frontend/`.
  - **Atomic extract-and-swap**: the millerbyte frontend consumes the package
    immediately as part of extraction — no drift window, canonical in code from
    day one. Scoped to **presentational components + tokens only**, so the
    in-flight TanStack Start migration (millerbyte ADR-0006, a routing/SSG
    concern) doesn't churn it — the audit ticket verifies that boundary.
  - **Install story = hosted one-liner**, cross-platform (Windows `irm | iex` is
    first-class, this is a Windows dev shop). `cargo install` is a footnote, not
    the story. Binaries from **GitHub Releases** (repo is public — anonymous
    downloads work); scripts served by the site so the hero command is on-brand.
  - **Docs authored fresh for users** (MDX content collections in `site/`),
    mining existing markdown for raw material. ADRs stay internal.
  - **Site is fully static (SSG)** — no gateway, no auth, no CORS surface.
  - **Deploy**: Vercel project #2 rooted at `site/`, `loot.millerbyte.com`
    CNAME; the VPS stays the loot *relay*, never a download host.
- **Constraints the spec must respect:**
  - **`docs/pitch/` is sealed** (ADR 0028 guard rails). Mining `zk-host.md` for
    public landing copy is a **deliberate reveal decision** — the IA ticket must
    treat it as such, not as free raw material.
  - **`site/` must be public visibility** in `.lootattributes` — GitHub `main`
    is a sealed-free projection (loot-first, `docs/agents/workflow.md`), and
    Vercel builds from GitHub. Sealed content can never be a build input.
  - **Release tags + CI live git-side** on projected `main` — the release
    pipeline is downstream of the ferry, and must tolerate that.
  - Repo conventions: solo dev, Windows 11; VPS work only via idempotent
    scripts in the `scripts` repo (PowerShell).
- **Execution notes.** Tickets about the millerbyte frontend (audit, package
  contract) do their reading in `c:\Users\conno\source\repos\millerbyte`;
  resolutions land here. Refer to tickets by name. Skills per type:
  `/research` (research), `/grilling` + `/domain-modeling` (grilling),
  `/prototype` (prototype). Claude can run cargo here.

## Decisions so far

<!-- one line per closed ticket: gist + link -->

- [Release engineering for the install one-liner](https://github.com/Connor-Miller/loot/issues/205) — **cargo-dist, upstream** (tool survived axo's death: astral fork merged back v0.29.0, upstream at v0.32, uv pins 0.31; generated workflow is checked-in so a stall can't strand us); v1 targets = win x64/arm64 MSVC · mac arm64/x64 · linux x64/arm64 **gnu**; bump loot-cli to 0.1.0, unified tag **`v0.1.0`** (loot-first is a non-issue — tag-triggered CI only needs `release.yml` in the tagged commit); artifact contract `loot-cli-{triple}.{tar.xz|zip}` + `loot-cli-installer.{sh,ps1}` + `sha256.sum` + `dist-manifest.json`; ⚠ `curl -sSf` forbids redirects → site must **proxy** installer bytes (fed to deploy-chain ticket); evidence `docs/research/release-engineering-install-one-liner.md`
- [Presentational-boundary audit of the millerbyte frontend](https://github.com/Connor-Miller/loot/issues/207) — **boundary holds; collision map empty** (ADR-0006 Start migration already **landed** — extract-and-swap PR is free-standing); theme travels as **plain CSS** (`tailwind.config.js` is dead under Tailwind v4 — no preset needed; v4 `@theme` is the deliberate upgrade); v1 contents = 3 CSS files + ~12 pure components + `useFocusTrap`; highest-value near-miss = the `content/` chrome trio behind `ContentLinker`; evidence `docs/research/presentational-boundary-audit-millerbyte-frontend.md`
- [Deploy-chain constraints: Vercel, site/ subdir, script serving](https://github.com/Connor-Miller/loot/issues/210) — **all 4 links PASS** (millerbyte.com is the live reference chain: subdir-root proven via `rootDirectory:"frontend"`, ADR-0006 **Start/Vercel SSG preset** committed & in-flight, loot is the simpler *all-static* subset — no islands, no deny-list); `site/**` Public by default → ferries to `main`, sealed `docs/pitch` structurally can't be a build input; **DNS trivial** — `millerbyte.com` zone is Vercel-managed (NS `ns*.vercel-dns.com`) so add the subdomain in-dashboard, **zero registrar work**, VPS relay (`api.→72.60.231.231`) untouched; **scripts served via Vercel external rewrite / reverse proxy** `/install.{sh,ps1}` → `releases/latest/download/loot-cli-installer.{sh,ps1}` so `curl -sSf` (no `-L`) sees a 200 not a 3xx — honors #205; no `redirects` block → apex→www 308 can't leak to the subdomain; interim deploy = manual `vercel --prod`; ⚠ #206 live-fires that the proxy follows GitHub's `releases/latest` 302; evidence `docs/research/deploy-chain-loot-site.md`

- [Prototype a real cross-platform install of loot](https://github.com/Connor-Miller/loot/issues/206) — **cargo-dist installers ship unmodified** (proven on the real Windows 11 box: `irm|iex` → detect/download/unpack → `~/.loot/bin` → HKCU PATH prepend *persisted*, fresh shell resolves `loot`, idempotent re-run = one PATH entry, download-404 clear; host swapped to a local server via `LOOT_CLI_DOWNLOAD_URL`, everything downstream of the URL is shipped code); config landed in-tree (loot-cli→**0.1.0**, `repository` casing fixed, `publish=false`+`[metadata.dist] dist=true` — publish=false else *hides the bin from dist*, `dist-workspace.toml` 6 targets, pinned `release.yml`); decisions: **keep `loot-cli`** naming · **install-path `~/.loot/bin`** not dist's CARGO_HOME default; ⚠ 2 must-fix before a real v1 → **no `loot --version`** (fog) + **ps1 skips checksum verify while sh verifies** ([#221](https://github.com/Connor-Miller/loot/issues/221)); real GH release + `releases/latest` + Linux CI smoke + ferry tag-verb are post-spec execution; evidence `docs/research/install-prototype-loot.md`

- [The @millerbyte/ui package contract](https://github.com/Connor-Miller/loot/issues/208) — **theming = plain CSS custom properties, no Tailwind preset** (`tokens.css` is already framework-agnostic `:root` vars consumed by hand-authored classes; package carries **zero `tailwindcss` dep**; pixel-identity enforced by both sites importing the identical CSS bytes; v4 `@theme`/preset both rejected — keep tokens plain so a non-Tailwind consumer works; light-mode stays commented, out of v1); **exports** = `.` (named ESM component/hook barrel, tree-shakeable) + `./theme.css` (bundled stylesheet, `sideEffects:["**/*.css"]`); **build** = **ESM-only** (drops react-logging's CJS, per repo convention) via Vite lib + `tsc` types, React/react-dom/framer/lucide **externalized as peerDeps**, **`.d.ts` floor = TS 6.0** so types resolve under both frontend `bundler`/TS7 ([#137]) and gateway `nodenext`/TS6 ([#138]) — though only frontend + loot `site/` actually consume it, gateway is **not** a consumer; **publish** = public npm `@millerbyte` scope (react-logging precedent) + **root gains npm workspaces** (`["frontend","packages/*"]`), local consume via **workspace `*`** (atomic, no drift) / external via published `^0.1.0`, semver from **0.1.0**; **sequencing** = **single atomic PR** (collision map empty since ADR-0006 landed), publish decoupled as a later step so revert never strands npm; backing millerbyte ADR lands with spec #211. Handoff: extraction PR pins the exact peerDep set from the audit inventory
- [Site IA and content plan](https://github.com/Connor-Miller/loot/issues/209) — **v1 = five surfaces** (Landing `/` · Install · Docs · Why loot · Evidence; roadmap parked). **Landing show-leaning** (thesis hook + install one-liner + "what works today" loop + 3 demo vignettes → Docs). **Install** = platform-detected one-liner (site `/install.{ps1,sh}` proxy #210), all-platforms #205 matrix, `cargo install` footnote, GH-Releases fallback + checksums — ⚠ **integrity blocked on #221**, needs `loot --version` (fog #206). **Docs** (MDX) = getting-started + **user-facing** core-concepts (changes · visibility · identity/keys · grants · relays/hosts · embargo · docks — *distilled* from CONTEXT.md, not lifted) + task-guides (1:1 from README demos) + **hand-written CLI reference** (verbatim from README command table; clap-gen stays fog). **Why loot = fresh authored, SELL-ONLY** — `docs/pitch/zk-host.md` **stays sealed** (private inspiration only, no bytes, ADR 0028 intact), **no honest-limits section in v1** (reserved until >1-dev proof). **Evidence = "proof log" index** over verbatim `docs/evidence/runs/*` (one "what this proves" line per card; incl. hard-embargo attack demo). Mining: README→landing/quickstart/CLI-ref, CONTEXT.md→concepts, evidence→proof log, ADR table **not** v1. **Closing this unblocks terminal spec #211** (#208+#209 were its last blockers)
- [Windows installer skips checksum verification](https://github.com/Connor-Miller/loot/issues/221) — **accept TLS-only on the automated Windows `irm|iex` path for v1; back it with GitHub Artifact Attestations; document manual verify; do NOT patch the ps1.** The asymmetry is **structural to dist, not our misconfig**: on-disk (v0.32.0) `installer.sh` has `verify_checksum`+per-artifact sha256 (embedded at real CI build), `installer.ps1` has **no hash logic at all** (`WebClient.DownloadFile`→`Expand-Archive`) — confirmed identical in the **flagship deployment** (uv's live `uv-installer.sh` verifies, `uv-installer.ps1` doesn't); dist docs say the *shell* installer embeds+validates & point Windows at manual `Get-FileHash`; **no config knob exists** (else astral would use it). **Site proxy #210 does NOT widen the binary boundary** — ps1's `$ArtifactDownloadUrls` is hard-baked to GitHub (line 49), so the binary is always GitHub-direct over TLS; the Vercel rewrite fronts the *script only* (same site-trust we already extend). Rejected hand-rolling ps1 checksum (forks dist → re-patch every bump, honors #206 "ship unmodified"; and it rides the same TLS anchor as script delivery, so **attestations** close the compromised-binary gap better). v1 ships: attestations in `release.yml` (uv enables) + unified `sha256.sum` (dist default) + Install-page manual-verify (`Get-FileHash` vs `sha256.sum`, `gh attestation verify`). Feeds #211 install-pipeline; evidence `docs/research/windows-installer-integrity.md`
- [Write the spec: loot.millerbyte.com](https://github.com/Connor-Miller/loot/issues/211) — **TERMINAL. Map complete.** Assembled everything into the hand-off spec **`docs/specs/loot-site.md`** (site/ layout · Vercel/subdomain/proxy · `@millerbyte/ui` dep · five-surface page tree + sources · install pipeline w/ TLS-only+attestations integrity · prereqs/follow-ons/non-goals · execution order), **loot ADR 0037** (`docs/adr/0037-loot-product-site-and-install.md` — renumbered from 0036, taken by the concurrent #229 harbor land; product subdomain, site in-repo, hosted one-liner, TLS-only Windows integrity, borrows `@millerbyte/ui`), **millerbyte ADR 0010** (`docs/adr/0010-millerbyte-ui-design-system-package.md`, in the millerbyte repo — the extract-and-swap contract), **millerbyte CONTEXT.md** gains a *Design system (`@millerbyte/ui`)* term (loot CONTEXT untouched — the site isn't SCM-domain vocab). Follow-on [#237 `loot --version`](https://github.com/Connor-Miller/loot/issues/237) filed standalone. All fog resolved into the spec (see below).

## Fog

**All resolved into `docs/specs/loot-site.md` §6 at map closure (#211).** For the
record:
- **Fast-follows** (spec §6): CLI-reference-from-`clap` (hand-written v1) · GitHub→Vercel
  auto-deploy (interim manual `vercel --prod`) · musl static Linux · Homebrew/Scoop/winget ·
  per-release docs versioning · native ps1 checksums if dist adds them upstream · drand-timelock.
- **Non-goals** (spec §6): roadmap page (parked, sell-only posture) · `cargo install` as the
  headline (footnote, gated on crates.io name) · shipping the hosted zk-host *service*.
- **Prerequisite → ticket**: [#237 `loot --version`](https://github.com/Connor-Miller/loot/issues/237).
- **Post-spec execution** (spec §7): build `site/`, publish `@millerbyte/ui`, cut real `v0.1.0`
  (needs the tag-push ferry verb #205 flagged + a live Release + a Linux `curl|sh` CI smoke leg).

## Out of scope

- **Shipping the site** — execution after this map's spec.
- **The hosted zero-knowledge-host service** (pricing, signup, operated relay
  as a product) — the post-milestone bet, per map #54.










