# Release engineering for the install one-liner

> Wayfinder research for [#205](https://github.com/Connor-Miller/loot/issues/205)
> on the loot.millerbyte.com map. Question: how do binaries get from this repo to
> `irm https://loot.millerbyte.com/install.ps1 | iex` /
> `curl -sSf https://loot.millerbyte.com/install.sh | sh`? loot has never cut a
> release or tag. Investigated 2026-07-11 against primary sources (repos, official
> docs, live release assets); every claim cites the source that owns it.

## Verdict

**Pipeline: adopt cargo-dist (`dist`), current upstream `axodotdev/cargo-dist`.**
The axo company is gone (axo.dev's DNS is dead and the domain is for sale), but the
tool outlived it: astral's temporary fork was merged back upstream in v0.29.0
(2025-07-31), the fork is archived with a pointer back to upstream, and upstream
has shipped four releases since — v0.32.0 on 2026-05-22. It generates a pinned,
checked-in GitHub Actions workflow plus tested shell/PowerShell installers,
per-release `sha256.sum` and `dist-manifest.json` — so even a future maintenance
stall leaves us with a working, vendored pipeline. The hand-rolled alternative
(taiki-e/upload-rust-binary-action) is the fallback, not the pick: it trades
dist's installer scripts (the hard 20% — platform detect, PATH/registry edits,
checksum verify) for naming control we don't need, because the site fronts the
naming anyway.

**Site contract:** loot.millerbyte.com serves `/install.sh` and `/install.ps1` as
**Vercel proxy rewrites** (not redirects — the marquee `curl -sSf` has no `-L`, so
a 3xx would break it) to GitHub's stable latest-asset URLs:
`https://github.com/Connor-Miller/loot/releases/latest/download/loot-cli-installer.{sh,ps1}`.
Each dist installer pins its own version's artifact URLs and embedded sha256
checksums, so "fetched via latest" always installs a self-consistent release.
This is astral's exact architecture for uv, minus their CDN.

**v1 target matrix (6):** `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`,
`aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-gnu`,
`aarch64-unknown-linux-gnu`. Linux ships **glibc** for v1 (loot's tree is
pure-Rust TLS/crypto but carries bundled libgit2 C via `git2`; musl works — gitui
proves it — but adds toolchain friction, so it's a fast-follow, not a blocker).

**Version + tag:** bump `loot-cli` to `0.1.0`, tag **`v0.1.0`** (unified
announcement — only `loot-cli` has a binary, so a unified tag announces exactly
one app). The tag is pushed to GitHub as a **single-ref push from the ferry**,
same guardrail as `main`/`review/*`. Tag-triggered CI does not care how `main`
got there.

**Artifact contract the install scripts code against:**

```
https://github.com/Connor-Miller/loot/releases/download/v{V}/
  loot-cli-{target-triple}.tar.xz      # unix archives (binary `loot` at root)
  loot-cli-{target-triple}.zip         # windows archives
  loot-cli-installer.sh                # dist shell installer (pins v{V} URLs + checksums)
  loot-cli-installer.ps1               # dist PowerShell installer
  sha256.sum                           # unified checksums, sha256sum-compatible
  dist-manifest.json                   # machine-readable release manifest
```

"Latest" resolves via GitHub's documented
`/releases/latest/download/{asset-name}` suffix (most recent non-prerelease,
non-draft release by `created_at`).

---

## 1. cargo-dist vs hand-rolled GitHub Actions

### Maintenance status (the critical check) — verified from primary sources

Timeline, each point from the artifact that owns it:

- **The company is gone.** `axo.dev` no longer resolves as a company site — a
  domain-for-sale page ([axo.dev](https://axo.dev/)), and the old docs host
  `opensource.axo.dev` fails DNS entirely (`getaddrinfo ENOTFOUND`, checked
  2026-07-11). Docs moved to GitHub Pages:
  [axodotdev.github.io/cargo-dist/book](https://axodotdev.github.io/cargo-dist/book/)
  (linked from the repo [README](https://github.com/axodotdev/cargo-dist)).
- **Astral bridged the gap, then folded back.**
  [astral-sh/cargo-dist](https://github.com/astral-sh/cargo-dist) describes
  itself as "an unofficial fork of axodotdev/cargo-dist 0.28.0 to apply minor
  updates and fixes for astral's projects" and says "The upstream project is
  active again and contains the changes from this fork, please refer to
  axodotdev/cargo-dist instead." The fork was **archived 2025-12-19** (read-only);
  its last release was 0.28.7 (2025-08-01).
- **Upstream is alive.** Per the
  [CHANGELOG](https://github.com/axodotdev/cargo-dist/blob/main/CHANGELOG.md):
  v0.29.0 (2025-07-31) "includes all of the new features from Astral's fork of
  dist" and "removes support for Axo Releases" (the dead company's hosting
  product); v0.30.0 (2025-09-07); v0.31.0 (2026-02-23, adds "mirrors" static-file
  hosting fallback); **v0.32.0 (2026-05-22)** —
  [releases](https://github.com/axodotdev/cargo-dist/releases). Repo is not
  archived; issues/PRs are open and moving.
- **Flagship users staked on it.** uv's live config
  ([dist-workspace.toml](https://github.com/astral-sh/uv/blob/main/dist-workspace.toml))
  pins `cargo-dist-version = "0.31.0"` for 19 targets with shell + powershell
  installers. Ecosystem projects track the same question (e.g.
  [posit-dev/air#297](https://github.com/posit-dev/air/issues/297) "Switch to
  astral-sh/cargo-dist?" — resolved by the fold-back).
- **UNVERIFIED:** who the named post-axo maintainers are. The v0.29.0 release
  notes credit the astral merge but name no maintainership handover; the README
  carries no governance notice. The release cadence is the evidence of life, not
  a stated commitment.

**Risk posture:** moderate-and-acceptable. Two structural mitigations: (a) the
generated `release.yml` and installers are **checked into our repo and pinned**
to a dist version — a future abandonment strands us on a working pipeline, not a
broken one; (b) astral demonstrated the escape hatch (fork, patch, merge back).

### What cargo-dist generates and imposes

From the [Rust quickstart](https://axodotdev.github.io/cargo-dist/book/quickstart/rust.html)
and [config reference](https://axodotdev.github.io/cargo-dist/book/reference/config.html):

- `dist init` writes dist config plus a "shippable build profile" and
  `.github/workflows/release.yml`; the workflow runs when you "push a properly
  formatted git tag like 'v0.1.0'" and creates the GitHub Release with all
  builds. Config lives in **`dist-workspace.toml`** (the current recommended
  home; `[workspace.metadata.dist]` in Cargo.toml is the legacy location —
  the docs note "We're currently in the middle of a major config migration").
- Per release it uploads: one archive per app×target, per-app
  `{app}-installer.sh` / `{app}-installer.ps1`, a unified `sha256.sum`, and
  `dist-manifest.json`. Existence proof — cargo-dist's own
  [v0.32.0 assets](https://api.github.com/repos/axodotdev/cargo-dist/releases/latest):
  `cargo-dist-{triple}.tar.xz`/`.zip`, `cargo-dist-installer.sh`/`.ps1`,
  `sha256.sum`, `dist-manifest.json`.
- [Archives](https://axodotdev.github.io/cargo-dist/book/artifacts/archives.html):
  defaults are "`.zip` on windows and `.tar.xz` elsewhere" (configurable via
  `windows-archive`/`unix-archive`); binaries sit at the archive root, README/
  LICENSE/CHANGELOG auto-included; tarballs nest contents in a directory named
  like the archive minus extension.
- [Checksums](https://axodotdev.github.io/cargo-dist/book/artifacts/checksums.html):
  sha256 default; per-artifact `.sha256` files plus the unified `sha256.sum`
  ("individual checksums will be deprecated in a future version in favor of that
  unified checksum file"). Installer-side verification: the docs page still says
  "work in progress," but the **shipped behavior verifies** — uv's live installer
  embeds per-platform sha256 values and calls `verify_checksum`
  ([releases.astral.sh/installers/uv/latest/uv-installer.sh](https://releases.astral.sh/installers/uv/latest/uv-installer.sh)).
- [PowerShell installer](https://axodotdev.github.io/cargo-dist/book/installers/powershell.html):
  documented usage is exactly our marquee shape (`powershell -c "irm {url} | iex"`);
  it edits `HKCU:\Environment` PATH with `REG_EXPAND_SZ` + `WM_SETTINGCHANGE`
  broadcast, rustup-style. Needs PowerShell ≥ 5.0 (Windows 10 fine).
- **Naming is imposed:** archives are named after the **cargo package**, not the
  `[[bin]]`. There is no override —
  [axodotdev/cargo-dist#832](https://github.com/axodotdev/cargo-dist/issues/832)
  (request to override package name) is open. So our assets are `loot-cli-*`
  unless we rename the package to `loot` (we don't publish to crates.io, so
  `publish = false` sidesteps any name squatting there). Users never type asset
  names — the scripts hide them — so v1 accepts `loot-cli-*`.

### Can dist installers be self-hosted from a custom domain?

- The installer's download base is the **Artifact URL**, computed for GitHub
  hosting as `{repo_url}/releases/download/{tag}` — "custom overrides are not
  currently supported"
  ([artifact-url reference](https://axodotdev.github.io/cargo-dist/book/reference/artifact-url.html)).
  So each installer script is version-pinned to its own release's assets.
- v0.31.0 added **mirrors**: `hosting = ["github", "simple"]` +
  `simple-download-url = "https://static.myapp.com/{tag}"` makes installers try
  hosts in order and fall back; but "dist won't _upload_ artifacts to static
  hosts; it expects you to handle that"
  ([v0.31.0 release notes](https://github.com/axodotdev/cargo-dist/releases/tag/v0.31.0)).
  Relevant only if we ever want binaries served from millerbyte.com — not needed
  for v1.
- **No conflict with site-served scripts** — this is precisely uv's production
  architecture: `https://astral.sh/uv/install.sh` is a **301 to**
  `https://releases.astral.sh/installers/uv/latest/uv-installer.sh` (observed
  live), a dist-generated script (it honors `CARGO_DIST_FORCE_INSTALL_DIR`) whose
  defaults pin a versioned release with GitHub fallback:
  `"https://releases.astral.sh/github/uv/releases/download/0.11.28 https://github.com/astral-sh/uv/releases/download/0.11.28"`,
  fetching `uv-{triple}.{tar.gz|zip}` with embedded sha256 verification.
  For loot, replace astral's CDN-copy step with a **Vercel rewrite (proxy)** of
  `releases/latest/download/loot-cli-installer.{sh,ps1}` — no per-release copy
  job, and no redirect for `curl` (sans `-L`) to trip over.

### The hand-rolled alternative

[taiki-e/upload-rust-binary-action](https://github.com/taiki-e/upload-rust-binary-action)
(v1.30.2, 2026-04-17, actively maintained): a matrix workflow where each leg
builds one target and the action archives + uploads to the tag's GitHub Release.
Inputs: `bin` (required), `target`, `archive` (default `$bin-$target`, with
`$tag` available), `checksum` ("sha256, sha512, b2, sha1, or md5"), `tar`/`zip`
per-OS defaults; cross-compilation via `cross` or `cargo-zigbuild`. This gives
`loot-{triple}.{ext}` naming for free — but we then own the install scripts:
platform/arch detection, archive unpack, PATH edits on three OSes including the
Windows registry dance, checksum verify, and every edge case dist has already
shipped fixes for (e.g. v0.32.0 "PowerShell installer now peeks inner exceptions
on download failures" —
[CHANGELOG](https://github.com/axodotdev/cargo-dist/blob/main/CHANGELOG.md)).
Starship's ~500-line hand-maintained
[install.sh](https://github.com/starship/starship/blob/master/install/install.sh)
is what that path costs at steady state.

### Comparison

| Axis | cargo-dist | hand-rolled (taiki-e) |
|---|---|---|
| Maintenance risk | Moderate: post-axo community cadence (4 releases since fork-merge); pinned generated workflow keeps working if the tool stalls | Minimal: taiki-e action is small and active; but *we* maintain the installers forever |
| Windows arm64 | Yes — uv ships `uv-aarch64-pc-windows-msvc.zip` from dist 0.31 ([latest release](https://github.com/astral-sh/uv/releases/latest)); note the config-reference docs' example target list lags and omits it | Yes — `target: aarch64-pc-windows-msvc` on a `windows-11-arm` runner (or cross from x64 MSVC) |
| Checksums / signing | `sha256.sum` + per-asset `.sha256` + installer-embedded verify; optional GitHub Artifact Attestations (uv enables them; attestation note visible on its release page) | `checksum: sha256` input; attestation/verify wiring is DIY |
| Installer quality | Tested `sh` + `ps1` with PATH handling, used by uv/ruff at enormous scale | Ours to write and debug |
| Naming control | Package-name-locked (`loot-cli-*`), #832 open | Full (`loot-{triple}`) |
| Effort to first release | `dist init` + answer prompts + push tag | Write matrix workflow + two installers + checksum plumbing |

---

## 2. Target matrix

### loot's native-dependency audit (local, `crates/*/Cargo.toml`)

- TLS is pure-Rust by design: `reqwest = { default-features = false, features
  = ["blocking", "rustls-tls"] }` with an in-repo comment "keeps loot's
  pure-Rust, no-system-TLS build" (`Cargo.toml` workspace deps). Crypto is
  blake3 / ed25519-dalek / x25519-dalek / chacha20poly1305 — all pure Rust.
  **No OpenSSL anywhere.**
- **The one C dependency: `git2 = { version = "0.19", default-features =
  false }`** for the ferry bridge (ADR 0028). With defaults off, the
  openssl-pulling `https` feature and `ssh` are excluded (feature wiring:
  [git2-rs Cargo.toml](https://github.com/rust-lang/git2-rs/blob/master/Cargo.toml)),
  but `libgit2-sys` still compiles bundled C: "The source for libgit2 is
  included in the libgit2-sys crate so there's no need to pre-install the
  libgit2 library" — vendored + statically linked when no compatible system lib
  is found ([git2-rs README](https://github.com/rust-lang/git2-rs#readme)).
  Consequence: every target needs a C toolchain (all GitHub runners have one),
  and cross-compiled legs need a C *cross* toolchain.
- Only `crates/loot-cli` defines a binary (`[[bin]] name = "loot"`); every other
  crate is lib-only (verified: sole `src/main.rs` in the workspace). One app to
  ship.

### musl vs glibc

Static musl is *feasible* despite the C dep — gitui (same shape: git2 + bundled
libgit2) ships its standard Linux x64 build as `x86_64-unknown-linux-musl` with
nothing more than `rustup target add` + `apt-get install musl-tools`
([gitui cd.yml](https://github.com/gitui-org/gitui/blob/master/.github/workflows/cd.yml)).
But gitui itself uses **gnu** for its arm64 leg — aarch64-musl needs a cross C
toolchain or `cargo-zigbuild` (dist grew cargo-zigbuild + cargo-auditable
support in v0.32.0, per the
[CHANGELOG](https://github.com/axodotdev/cargo-dist/blob/main/CHANGELOG.md)).
Recommendation: **gnu for v1** on both Linux legs — zero friction, and the glibc
floor is just the build runner's glibc (build the x64 leg on `ubuntu-22.04`,
glibc 2.35, if older-distro reach matters; native `ubuntu-24.04-arm` for arm64).
Add musl variants later as extra targets, not replacements — dist happily ships
gnu and musl side by side (its own release does).

### Runner availability (primary: [actions/runner-images](https://github.com/actions/runner-images) README, checked 2026-07-11)

| Target | Runner | Status |
|---|---|---|
| x86_64-unknown-linux-gnu | `ubuntu-24.04` / `ubuntu-22.04` (`ubuntu-latest`) | GA |
| aarch64-unknown-linux-gnu | `ubuntu-24.04-arm` (also 22.04-arm; 26.04-arm preview) | GA; free for public repos ([GA changelog 2025-08-07](https://github.blog/changelog/2025-08-07-arm64-hosted-runners-for-public-repositories-are-now-generally-available/), preview announced [2025-01-16](https://github.blog/changelog/2025-01-16-linux-arm64-hosted-runners-now-available-for-free-in-public-repositories-public-preview/)) |
| x86_64-pc-windows-msvc | `windows-latest` / `windows-2025` / `windows-2022` | GA |
| aarch64-pc-windows-msvc | `windows-11-arm` | GA for public repos ([preview changelog 2025-04-14](https://github.blog/changelog/2025-04-14-windows-arm64-hosted-runners-now-available-in-public-preview/), GA [2025-08-07](https://github.blog/changelog/2025-08-07-arm64-hosted-runners-for-public-repositories-are-now-generally-available/)); the label "will not work in private repositories" — irrelevant, loot is public. Alternatively cross-compile from x64 MSVC |
| aarch64-apple-darwin | `macos-latest` = `macos-15` (arm64); `macos-26` available | GA. `macos-14` is **deprecated**; macos-13 is gone from the images table |
| x86_64-apple-darwin | `macos-15-intel` / `macos-15-large` (or cross-compile on arm64 with `SDKROOT`) | GA (`-large` labels are paid; `macos-15-intel` is the standard Intel label) |

Universal2 (`lipo`) was considered and rejected for v1: two thin archives match
the ecosystem contract (uv, cargo-dist, starship all ship thin per-arch mac
builds) and keep the naming uniform.

### Recommended v1 matrix

The 6 targets in the verdict. Skipped for v1: `i686-*` (dying), `*-musl`
(fast-follow, see above), universal2, and everything uv ships beyond that
(ppc64/riscv/armv7 — no evidence of demand for a dev tool this young).

---

## 3. Versioning + tagging for a loot-first repo

### Does tag-triggered CI care how `main` got pushed? No.

- The projection invariant (`docs/agents/workflow.md`): git `main` is projected
  from loot via single-ref push; GitHub never merges. A release tag is just
  another ref.
- GitHub Actions `on: push: tags:` filters fire when a matching tag ref is
  pushed; for a pushed tag, `GITHUB_SHA` is the "tip commit pushed to the ref" —
  i.e. the tagged commit, with no dependence on branch history or how the branch
  ref moved
  ([events-that-trigger-workflows](https://docs.github.com/en/actions/writing-workflows/choosing-when-your-workflow-runs/events-that-trigger-workflows)).
  The workflow file is read from the tagged commit (push events carry no
  "must exist on default branch" requirement, unlike `delete`/`fork` — same
  doc), so **the release commit must already contain `release.yml`** — land the
  dist config through the normal dock → PR → land flow first, then tag that (or
  a later) landed commit. One footnote from the same doc: pushing more than
  three tags at once creates no events — never batch tags.
- **Guardrail compliance:** publishing the tag is `git push <inline-url>
  refs/tags/v0.1.0` from the ferry — a single-ref push of a ref pointing at an
  already-projected, sealed-free `main` commit. The mirror stays remote-less;
  no second path to GitHub is created. The natural home is a small ferry/land
  extension ("release" verb or flag) so tagging stays inside loot's projection
  machinery rather than an ad-hoc git command in the checkout.
- The dist workflow needs `contents: write` to create the Release; it creates
  Releases only, never touches branch refs, so it cannot fight the projection.

### Tag format

From the [dist CLI manual](https://axodotdev.github.io/cargo-dist/book/reference/cli.html),
`--tag` accepts two shapes: **unified** (`v1.0.0`, `0.1.0-prerelease.1`,
`releases/1.2.3`) — "Announcing/Releasing all packages in the workspace that
have that version" — and **singular** (`my-app-v1.0.0`, `my-app/1.0.0`) for one
package. Since `loot-cli` is the only distable package (only crate with
binaries; "distable" = defines binaries and not `dist = false`, per the
[workspaces guide](https://axodotdev.github.io/cargo-dist/book/workspaces/structure.html)),
a unified tag announces exactly one app, and we avoid the ugly singular form
`loot-cli-v0.1.0` on the marquee.

**Recommendation:** bump `crates/loot-cli` `version = "0.0.0"` → `"0.1.0"`,
tag **`v0.1.0`**, format `v{version}` forever. `0.x` signals pre-stability
honestly (loot's own store format is still moving); `1.0.0` should mean the
store/artifact contracts are frozen. Leave the lib crates at 0.0.0 — they're
not distable and not published. Cheap insurance for the future: set
`dist = false` on any crate that later grows a binary (e.g. a `loot-bench`
bin) so unified tags keep announcing only the product.

Pre-flight nit found during the audit: the workspace `repository` field says
`https://github.com/connormiller/loot` (lowercase, no hyphen) while the real
repo is `Connor-Miller/loot`. GitHub treats owner/repo case-insensitively, but
dist derives the Artifact URL from this field
([artifact-url reference](https://axodotdev.github.io/cargo-dist/book/reference/artifact-url.html))
— set it to the exact canonical URL before `dist init`.

## 4. The artifact-naming contract (pin this)

With cargo-dist and package `loot-cli`, every release at tag `v{V}` carries:

| Asset | Notes |
|---|---|
| `loot-cli-x86_64-pc-windows-msvc.zip` | binary `loot.exe` at archive root |
| `loot-cli-aarch64-pc-windows-msvc.zip` | |
| `loot-cli-aarch64-apple-darwin.tar.xz` | tarballs nest a `loot-cli-{triple}` dir ([archives doc](https://axodotdev.github.io/cargo-dist/book/artifacts/archives.html)) |
| `loot-cli-x86_64-apple-darwin.tar.xz` | |
| `loot-cli-x86_64-unknown-linux-gnu.tar.xz` | |
| `loot-cli-aarch64-unknown-linux-gnu.tar.xz` | |
| `loot-cli-installer.sh` / `loot-cli-installer.ps1` | pin `releases/download/v{V}` URLs + per-platform sha256 |
| `sha256.sum` | unified, `sha256sum -c`-compatible ([checksums doc](https://axodotdev.github.io/cargo-dist/book/artifacts/checksums.html)) |
| `dist-manifest.json` | releases/artifacts manifest; schema published as `dist-manifest-schema.json` on dist's releases, "basically every field… should be treated as optional" ([schema doc](https://axodotdev.github.io/cargo-dist/book/reference/schema.html)) |

Resolution rules:

- **Pinned:** `https://github.com/Connor-Miller/loot/releases/download/v{V}/{asset}`
  — the computed Artifact URL pattern
  ([artifact-url reference](https://axodotdev.github.io/cargo-dist/book/reference/artifact-url.html)).
- **Latest:** `https://github.com/Connor-Miller/loot/releases/latest/download/{asset}`
  — "To link directly to a download of your latest release asset… the suffix is
  `/releases/latest/download/asset-name.zip`"
  ([Linking to releases](https://docs.github.com/en/repositories/releasing-projects-on-github/linking-to-releases)).
  "Latest" = "the most recent non-prerelease, non-draft release, sorted by the
  `created_at` attribute"
  ([REST: Get the latest release](https://docs.github.com/en/rest/releases/releases?apiVersion=2022-11-28#get-the-latest-release))
  — so marking a release "pre-release" cleanly keeps it off the one-liner.
- **Site:** `loot.millerbyte.com/install.{sh,ps1}` → Vercel **rewrite/proxy** to
  the two `releases/latest/download/loot-cli-installer.*` URLs. Proxy, not
  redirect: `irm` follows redirects but the documented `curl -sSf` (no `-L`)
  does not — a redirect would pipe an empty 302 body into `sh`. (If the
  one-liner ever gains `-L`, a redirect works too; keep the proxy so the
  documented command is copy-paste safe.)

The names carry `loot-cli-` (package name; no override — open issue
[#832](https://github.com/axodotdev/cargo-dist/issues/832)). Acceptable: users
interact with the scripts, never the asset names. If release-page aesthetics
ever matter enough, the fix is renaming the package to `loot` with
`publish = false` — a repo-wide rename decision to take deliberately, not a
release-engineering requirement.

## Surprises + UNVERIFIED

- **Surprise:** `opensource.axo.dev` (the canonical docs URL cited across the
  ecosystem) is DNS-dead; docs quietly moved to
  `axodotdev.github.io/cargo-dist/book`. Cite the GitHub Pages URLs anywhere we
  write docs.
- **Surprise:** the marquee Unix one-liner in the map (`curl -sSf`, no `-L`)
  constrains the site: `/install.sh` must serve bytes (proxy), not redirect.
  uv dodges this with a 301 only because their docs one-liner uses `-LsSf`.
- **Surprise:** dist's config-reference target list omits
  `aarch64-pc-windows-msvc`, but uv ships it from dist 0.31 — the docs lag the
  tool. Trust the live releases over the reference page here.
- **UNVERIFIED:** named post-axo maintainers / a governance statement for
  cargo-dist (cadence and the astral merge-back are the evidence; no
  stewardship announcement found in the README, CHANGELOG, or release notes).
- **UNVERIFIED:** how dist's generated workflow builds `aarch64-pc-windows-msvc`
  by default (native `windows-11-arm` vs MSVC cross from x64) — uv's config
  routes builds through depot runners, so it isn't a clean reference; confirm
  with `dist init` + `dist plan` output at adoption time.
- **UNVERIFIED (deliberately untested):** exact glibc floor of
  `ubuntu-24.04`-built binaries and whether we care; decide when someone on an
  older distro actually shows up (dist also grew a `min-glibc-version` era of
  options and zigbuild support to fix this later).
