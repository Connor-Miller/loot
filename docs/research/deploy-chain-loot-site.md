# Deploy-chain verification — loot.millerbyte.com

Wayfinder ticket [#210](https://github.com/Connor-Miller/loot/issues/210) (map [#204](https://github.com/Connor-Miller/loot/issues/204)).
Verdict: **all four links PASS** — the decided chain holds. One live-fire confirmation
(the proxy following GitHub's release redirect) is correctly deferred to the install
prototype [#206](https://github.com/Connor-Miller/loot/issues/206), which has a real
release to fire against.

The strongest evidence is that **millerbyte.com is already the working reference
implementation** of nearly this exact chain: a Vercel project rooted at a subdir,
migrating to TanStack Start SSG, on a Vercel-managed `millerbyte.com` zone. loot's
site is a strict *subset* — fully static, no auth, no gateway, no CORS surface.

---

## Link 1 — Vercel × subdir root + TanStack Start SSG output → **PASS**

- **Subdir root is proven in production.** The millerbyte project is rooted at a
  subdirectory today: `.vercel/project.json` → `"rootDirectory": "frontend"`,
  framework `vite`, node `22.x`, on Vercel org `team_MxdJz7…`. A second Vercel
  project on the **loot** GitHub repo with root directory `site/` is the identical
  pattern — two projects, one repo, distinct roots.
- **Start SSG on Vercel is a committed, in-flight local decision, not a gamble.**
  millerbyte ADR-0006 adopts TanStack Start scoped to **SSG/prerender**, explicitly:
  "the Vercel build moves from static-SPA output to the **Start/Vercel preset**."
  ADR-0007 documents the working prerender mechanism (Start's SSG crawler gated by a
  `NO_PRERENDER` deny-list in `vite.config.ts`).
- **loot is the simpler case.** The map fixes the loot site as *fully static, no auth
  islands* — so it needs no `ssr:false` routes and no deny-list at all; every route
  prerenders. Whatever Start/Vercel preset + build-output-dir millerbyte's migration
  lands on, loot mirrors it minus the island machinery. **Findings transfer both
  ways** (the ticket's ask): loot can adopt millerbyte's final preset config verbatim.
- **Residual (execution, not a blocker):** pin the exact Start/Vercel framework-preset
  name and output directory to whatever millerbyte's ADR-0006 cutover ships, since
  that migration is still in flight. No independent decision for loot to make.

## Link 2 — Loot-first / sealed-projection wrinkle → **PASS**

- **`site/` is Public by default.** loot's `.lootattributes` reads: *"Unmatched paths
  are Public"*; the only sealed rule is `docs/pitch/** restricted=connor`. `site/**`
  is unmatched → **Public** → it ferries to GitHub `main`, which is what Vercel builds
  from. No new attribute rule is strictly required; an explicit `site/** public` line
  is worth adding for locality/intent, not correctness.
- **Sealed content can never be a build input — structurally.** `docs/pitch/` never
  reaches GitHub, so a build on `main` cannot import it even by accident (the file
  isn't there; a build that referenced it would fail loudly). This is the belt to the
  IA ticket's suspenders: the "Why loot" reveal decision ([#209](https://github.com/Connor-Miller/loot/issues/209))
  is about *authoring* public copy, not about build-time access.
- **Deploy trigger = manual `vercel --prod` (interim), consistent with millerbyte.**
  millerbyte's `AGENTS.md`: GitHub→Vercel auto-deploy "is configured but currently
  broken — treat manual as the deploy." The loot site inherits the same ritual. The
  ferry-projection model is *compatible* with auto-deploy when it's fixed: `main` is
  the public projection, and ferry-driven pushes to it are legitimate deploy triggers
  (nothing sealed is on `main` to leak). The long-term auto-deploy fix stays in the
  map's Fog; the spec commits only to manual for v1.

## Link 3 — Serving the install scripts without a redirect → **PASS (via external rewrite / proxy)**

This is the load-bearing link, and #205 already framed the constraint: the hero
command `curl -sSf https://loot.millerbyte.com/install.sh | sh` uses **no `-L`**, so
**any 3xx breaks it**. The scripts are cargo-dist's generated installers living at
`github.com/…/releases/latest/download/loot-cli-installer.{sh,ps1}`, and
`releases/latest/download/…` itself 302s. So the site must return the *bytes*, not a
redirect.

- **Mechanism: Vercel rewrite to an external origin.** Primary source (Vercel docs,
  "Rewrites on Vercel", updated 2026-07-01): rewrites to external origins let Vercel
  "function as a **reverse proxy**… forward requests to these destinations" and route
  "**without changing the URL in the browser**." The client sees a 200 with proxied
  bytes — no 3xx — which is exactly what `curl -sSf` (and `irm`) require.

  ```jsonc
  // site/vercel.json
  {
    "rewrites": [
      { "source": "/install.sh",  "destination": "https://github.com/Connor-Miller/loot/releases/latest/download/loot-cli-installer.sh" },
      { "source": "/install.ps1", "destination": "https://github.com/Connor-Miller/loot/releases/latest/download/loot-cli-installer.ps1" }
    ]
  }
  ```

- **Why proxy beats baking the script into static output:** a build-time
  `curl -L … > public/install.sh` would go stale between releases and couple every
  release to a site redeploy. The proxy is always-latest and decouples the two
  pipelines. (This is what #205 meant by "the site must *proxy* the installer bytes.")
- **Content-type / BOM / compression concerns move upstream and are moot for piping.**
  Under the proxy model the site is a pass-through: content-type is whatever GitHub
  serves the release asset as (`application/octet-stream`), which piping ignores.
  cargo-dist emits UTF-8 installers (no BOM); GitHub does not gzip release-asset
  downloads, and even if an upstream gzipped, `curl` without `--compressed` receives
  raw bytes and `irm` decompresses transparently — **no compression surprise for
  `iex`/`sh`.** (These caveats would only bite if we ever hand-authored a *static*
  script instead of proxying — then serve it `text/plain; charset=utf-8`, UTF-8 no
  BOM. Not the chosen path.)
- **No apex→www redirect leaks onto the subdomain.** millerbyte.com apex returns
  `308 → https://www.millerbyte.com/` (observed live), but this is a **per-domain**
  setting: `frontend/vercel.json` has **no** `redirects` block, so the www-canonical
  rule lives in the millerbyte project's domain config and cannot apply to
  `loot.millerbyte.com`, which is a distinct domain on a different project. Static
  files with an extension serve at 200 with no redirect (verified live:
  `GET https://www.millerbyte.com/assets/index-*.css` → `200`, `Content-Type: text/css`,
  `cache-control: immutable`). Just don't enable "redirect to www" on the loot project.
- **One live-fire confirmation deferred to [#206](https://github.com/Connor-Miller/loot/issues/206):**
  that Vercel's external-rewrite proxy transparently *follows* GitHub's `releases/latest`
  302 (to `objects.githubusercontent.com`) server-side and returns a clean 200 to the
  client. Standard reverse-proxy behavior and consistent with Vercel honoring upstream
  cache headers, but it can only be proven once `v0.1.0` publishes real assets — which
  is precisely what the install prototype does. Correctly its test, not this ticket's.

## Link 4 — DNS → **PASS (trivial; zone is Vercel-managed)**

- **The `millerbyte.com` zone is hosted on Vercel.** `NS` records =
  `ns1.vercel-dns.com`, `ns2.vercel-dns.com` (observed live). So adding
  `loot.millerbyte.com` is **not** a registrar CNAME chore — you add the domain to
  Vercel project #2 and Vercel provisions the in-zone record + TLS automatically. The
  ticket's "one CNAME needed" is even simpler than assumed: zero manual DNS edits.
- `loot.millerbyte.com` already resolves to Vercel anycast (`216.198.79.x`, observed)
  because the zone is Vercel-managed; it will 404 until a project claims the domain.
- **The VPS relay is untouched.** `api.millerbyte.com` → `72.60.231.231` (the VPS,
  observed live) is an `A` record coexisting in the same Vercel-managed zone. Adding
  loot's record is orthogonal to it. The VPS stays the loot **relay**; binaries come
  from GitHub Releases, so the VPS is never a download host — consistent with the map.

---

## Evidence (all observed 2026-07-12)

| Probe | Result | Establishes |
|---|---|---|
| `nslookup -type=NS millerbyte.com` | `ns1/ns2.vercel-dns.com` | zone on Vercel → Link 4 trivial |
| `nslookup api.millerbyte.com` | `72.60.231.231` (VPS) | relay coexists, untouched |
| `nslookup loot.millerbyte.com` | `216.198.79.x` (Vercel anycast, unclaimed) | subdomain ready to claim |
| `curl -I https://millerbyte.com` | `308 → www` | apex redirect is per-domain… |
| `frontend/vercel.json` | no `redirects` block | …so it's a dashboard setting, won't leak to loot |
| `curl -I …/assets/index-*.css` | `200`, `text/css`, immutable | static files serve redirect-free |
| `.vercel/project.json` (millerbyte) | `rootDirectory: "frontend"` | subdir-root proven in prod |
| millerbyte ADR-0006 / 0007 | Start/Vercel preset + SSG crawler | Start SSG on Vercel is committed & in-flight |
| Vercel docs, "Rewrites" (2026-07-01) | external rewrite = reverse proxy, no URL change | no-redirect script serving |

## Hand-off to the spec ([#211](https://github.com/Connor-Miller/loot/issues/211))

- Vercel **project #2** on the loot GitHub repo, **root `site/`**, Start/Vercel SSG
  preset (mirror millerbyte's ADR-0006 final config; no islands, no deny-list).
- `site/vercel.json` carries **two external rewrites** (`/install.sh`, `/install.ps1`
  → `releases/latest/download/loot-cli-installer.{sh,ps1}`). No `redirects`. Do not
  enable redirect-to-www on this project.
- `.lootattributes`: add explicit `site/** public` (optional, for intent).
- **DNS:** add `loot.millerbyte.com` to project #2 in Vercel — zero registrar work.
- **Deploy:** manual `vercel --prod` for v1 (auto-deploy fix stays in map Fog).
- **Open live-fire item for #206:** confirm the external-rewrite proxy follows the
  GitHub `releases/latest` 302 and returns a clean 200 to `curl -sSf`.
