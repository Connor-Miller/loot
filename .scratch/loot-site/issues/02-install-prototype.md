# Prototype a real cross-platform install of loot
GitHub: #206 · wayfinder:prototype · blocked by #205

## Question

**Prove the marquee install command works end-to-end on real machines — a real
binary, from a real GitHub Release, landing on PATH.**

Prototype, not spec: cut a pre-release tag (per the release-engineering
ticket's pipeline + naming contract), let CI publish real artifacts, then write
and run the two scripts:

- **`install.ps1`** via `irm | iex` on the dev's actual Windows 11 box —
  platform/arch detection, fetch from Releases, install location, **PATH
  handling** (user PATH edit? shim dir?), execution-policy and no-admin
  realities.
- **`install.sh`** via `curl | sh` on Linux (WSL and/or CI) — same detection
  and PATH story, `~/.local/bin` vs `/usr/local/bin`.
- **Failure modes**: unsupported target, download failure mid-stream, re-run
  (idempotent upgrade?), what the error output looks like when piped.

If the release-engineering ticket lands on cargo-dist, the question sharpens
to: do we ship its generated installers, wrap them, or hand-roll to control
the UX? The prototype answers by *running* them.

Output: working scripts (wherever the pipeline wants them) + a transcript of
both installs succeeding, linked from the resolution.
