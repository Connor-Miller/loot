# Prototype: a real cross-platform install of loot

> Wayfinder prototype for [#206](https://github.com/Connor-Miller/loot/issues/206)
> on the loot.millerbyte.com map. Question: does the marquee install one-liner
> actually work end-to-end on a real machine — real binary, real installer,
> landing on PATH? Implements the release-engineering contract from
> [#205](https://github.com/Connor-Miller/loot/issues/205). Run 2026-07-12 on the
> dev's actual Windows 11 box (`x86_64-pc-windows-msvc`), dist v0.32.0.

## Verdict

**Ship cargo-dist's generated installers unmodified — don't wrap, don't
hand-roll.** The generated `loot-cli-installer.ps1` ran the full mechanism on a
real Windows 11 box with zero edits: platform/arch detect → download → unpack →
place `loot.exe` → prepend the install dir to the HKCU `Environment\Path` →
persist so a fresh shell resolves `loot`. Re-run is cleanly idempotent (no PATH
duplication). This confirms the #205 decision by *running* it, and answers the
"ship / wrap / hand-roll" question: **ship**.

The prototype swapped only the download host — from the not-yet-existent GitHub
Release to a local static server (`LOOT_CLI_DOWNLOAD_URL`, a first-class installer
override) — because no public release has been cut (deliberately out of scope this
session). Everything downstream of the URL is the real, shipped code path.

**Two must-fix items before a real v1 release, and one config change, below.**

## What was proven (real Windows 11 box)

Faithful marquee reproduction — `irm <installer> | iex`, host swapped to localhost:

```
===== BEFORE =====
loot on PATH? NOT FOUND (expected)
~/.loot/bin exists? False
User PATH contains .loot\bin? False

===== RUN: irm http://127.0.0.1:8799/loot-cli-installer.ps1 | iex =====
downloading loot-cli 0.1.0 (x86_64-pc-windows-msvc)
installing to C:\Users\conno\.loot\bin
  loot.exe
everything's installed!

===== AFTER =====
~/.loot/bin/loot.exe            8,263,680 bytes
User PATH (registry) now contains .loot\bin?   True   (prepended)
Fresh process (reads persisted registry PATH):
  (Get-Command loot).Source  ->  C:\Users\conno\.loot\bin\loot.exe
  loot status  ->  "not a loot repo at . (no .loot/)"   # ran from PATH ✓

===== IDEMPOTENT RE-RUN =====
everything's installed!
PATH entries containing .loot\bin: 1   (no duplication)
```

Verified, in order:

- **Platform detection** — resolved `x86_64-pc-windows-msvc`, fetched the matching
  `.zip`, unpacked with `Expand-Archive`.
- **Install location** — `install-path = "~/.loot/bin"` honored;
  `C:\Users\conno\.loot\bin\loot.exe` (8.26 MB, the dist-profile build).
- **PATH handling (the hard 20%)** — prepended to the **HKCU** `Environment\Path`
  registry value and persisted; a brand-new process reading the User+Machine
  registry PATH resolves `loot` and executes it. No admin, no elevation.
- **Idempotent upgrade** — a second `irm | iex` re-installs cleanly and leaves
  **exactly one** `.loot\bin` entry in PATH.
- **Failure mode (download 404)** — clear, nested output (the v0.32.0 "peek inner
  exceptions on download failures" behavior):
  ```
  downloading loot-cli 0.1.0 (x86_64-pc-windows-msvc)
  failed to download from http://127.0.0.1:8799/does-not-exist
    failed to download .../loot-cli-x86_64-pc-windows-msvc.zip to ...: The remote
    server returned an error: (404) Not Found.
  failed to download binaries
  ```

`dist plan` also reproduced the #205 artifact contract **exactly**: 6 targets,
`loot-cli-{triple}.{tar.xz|zip}` (bin at root), `loot-cli-installer.{sh,ps1}`,
`sha256.sum`, `dist-manifest.json`.

Raw transcript: [../evidence/runs/install-prototype-windows.txt](../evidence/runs/install-prototype-windows.txt).

## Config landed (in-tree, unlanded — for review)

- `Cargo.toml` — workspace `repository` casing fixed
  `connormiller` → `Connor-Miller` (dist derives the Artifact URL from it, #205
  pre-flight nit). dist also added `[profile.dist]`.
- `crates/loot-cli/Cargo.toml` — `version` `0.0.0` → **`0.1.0`**;
  `repository.workspace`/`authors.workspace` inherited (loot-cli didn't inherit
  `repository` before — dist needs it on the *distable* package); `publish = false`
  + `[package.metadata.dist] dist = true` (publish=false otherwise **hides the
  binary from dist** — the inverse of #205's `dist = false` note; found the hard
  way here); `description` added.
- `dist-workspace.toml` (new) — the dist config: 6 targets, `["shell","powershell"]`.
- `.github/workflows/release.yml` (new) — dist-generated, pinned to
  `cargo-dist-version = "0.32.0"`.

**Naming decision (the ticket's "decide here"): keep `loot-cli`.** Assets stay
`loot-cli-*`; users only touch the scripts, never asset names. Renaming the
package to `loot` stays a deliberate later call.

**`install-path` decision: `~/.loot/bin`, NOT dist's default `CARGO_HOME`.**
`CARGO_HOME` (`~/.cargo/bin`) silently assumes a Rust dev, is already on their
PATH, and so *never exercises the installer's PATH-edit path* — wrong for a
general-audience product one-liner. A dedicated namespaced dir installs the same
everywhere and forces the real PATH machinery (which is exactly what we proved).

## Must-fix before cutting a real v1

1. **`loot` has no `--version` (nor a `version` subcommand).** A binary
   distributed via *versioned* GitHub Releases that can't report its own version
   is a release blocker — users can't tell what the one-liner gave them, and
   upgrade/bug-report UX depends on it. `loot --version` → `loot 0.1.0`.
   → ticket.
2. **The PowerShell installer does NOT verify checksums; the shell installer
   does.** `loot-cli-installer.sh` carries `verify_checksum` + per-artifact
   values; `loot-cli-installer.ps1` (v0.32.0) has no checksum logic at all —
   integrity rests entirely on HTTPS/TLS. For a Windows-first shop marketing an
   `irm | iex` one-liner, that asymmetry deserves a deliberate decision (dist
   config? site-side integrity? accept TLS-only?). → ticket.

## Deferred — needs CI or a real public release

- **Linux `curl | sh`** — untestable on this box (no WSL). Exercise via a CI
  smoke-test leg (`ubuntu` runner installs its own freshly-built artifact).
- **Real GitHub Release + `releases/latest/download` resolution + the site
  proxy (#210)** — the prototype proved everything downstream of the download
  URL; the URL itself (latest-resolution, the Vercel proxy) is unproven until a
  real release exists.
- **The tag-push ferry verb** — #205 flagged that publishing `v0.1.0` should be a
  ferry/land extension (single-ref tag push of a sealed-free `main` commit); it
  **does not exist yet**. Cutting the real release needs it built (or a
  documented break-glass single-ref tag push).
