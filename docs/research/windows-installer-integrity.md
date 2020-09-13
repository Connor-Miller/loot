# Windows installer integrity — loot's install-pipeline decision

Wayfinder ticket [#221](https://github.com/Connor-Miller/loot/issues/221) (map [#204](https://github.com/Connor-Miller/loot/issues/204)),
type `research`. Investigated 2026-07-12 on the real Windows 11 box, against the
generated installers from the install prototype ([#206](https://github.com/Connor-Miller/loot/issues/206))
and the live flagship dist deployment (uv/astral).

**Decision:** for v1, **accept TLS-only on the automated Windows `irm | iex`
path**, back it with **GitHub Artifact Attestations**, and **document manual
verification**. Do **not** patch the generated PowerShell installer. This matches
the reference dist deployment exactly and honors #206's "ship cargo-dist
installers unmodified."

---

## The asymmetry is real, and it is structural to dist — not our config

Confirmed by reading both generated installers on disk (`target/distrib/`, dist
v0.32.0):

- **`loot-cli-installer.sh`** carries a full `verify_checksum` function
  (sha256/sha512/sha3/blake2) and calls it per artifact after download
  (`if [ -n "${_checksum_style:-}" ]; then verify_checksum …`). At a *real*
  release build, dist embeds per-artifact sha256 values into the case table; our
  local `dist generate` output has the function but empty values (so it prints
  "no checksums to verify" — an artifact of local generation, not the shipped
  behavior).
- **`loot-cli-installer.ps1`** has **no hash logic at all** — no `Get-FileHash`,
  no `verify_checksum`, nothing. It downloads via `Net.WebClient.DownloadFile`
  and immediately `Expand-Archive`s. Integrity rests entirely on HTTPS/TLS.

This is **not** a loot misconfiguration. The flagship dist deployment shows the
same split in production:

- uv's live **sh** installer (`releases.astral.sh/installers/uv/latest/uv-installer.sh`)
  embeds per-platform sha256 values (e.g. `_checksum_value="33540eb7…"`) and calls
  `verify_checksum`.
- uv's live **ps1** installer (`…/uv-installer.ps1`) has **no** checksum
  verification — `Net.Webclient … downloadFile($url,$dir_path)` then
  `Expand-Archive`, TLS-only.

dist's own docs corroborate: *"the **shell** installer now embeds checksum
information and validates the tarball before unpacking it"* — shell, not
powershell; the checksums page still lists installer-side verification as a
work-in-progress, and the PowerShell page points Windows users at manual
`Get-FileHash`. There is **no config knob** that turns on ps1 verification — if
there were, astral (who staked their entire distribution on dist and enable extra
hardening like Artifact Attestations) would use it. It is an upstream gap, not a
setting we left off.

## The trust boundary (with the site proxy) is narrower than it looks

The deploy-chain decision ([#210](https://github.com/Connor-Miller/loot/issues/210))
serves the *installer script* through a Vercel external rewrite
(`/install.ps1` → GitHub `releases/latest/download/loot-cli-installer.ps1`). It is
tempting to read "bytes now flow GitHub → Vercel → user" as widening the trust
boundary for the download. It does not, for the **binary**:

- The ps1's `$ArtifactDownloadUrls` is **hard-baked to GitHub**
  (`https://github.com/Connor-Miller/loot/releases/download/v0.1.0`, ps1 line 49).
  Wherever the *script* is served from, the **binary archive is fetched directly
  from GitHub over TLS**. The proxy is not in the binary's path.
- So the proxy adds Vercel to the trust base **for the script only**. And `irm | iex`
  *executes* that script, so script integrity is what matters most there — but the
  rewrite is a transparent pass-through (no re-hosted copy, no byte rewriting), and
  script delivery is TLS end-to-end on both hops. We already trust Vercel to serve
  the whole site; serving the script is the same trust, not a new one.

Net: TLS-only on the ps1 path means the residual risk is a **tampered binary
artifact on GitHub Releases** (compromised release/account) that TLS can't catch —
a real but narrow threat, identical to what every uv Windows user accepts today,
and unchanged by the proxy.

## Why not just add checksum verification to the ps1?

- It means **forking dist's generated ps1** and re-patching it on every version
  bump — the exact maintenance drag #206 rejected ("ship installers unmodified,"
  so an upstream stall can't strand us). The generated installer is a moving
  target with PATH/registry edge cases we don't want to own.
- The checksum a hand-rolled ps1 would compare against would itself have to be
  fetched/embedded and would ride the **same TLS anchor** the script delivery
  already rests on — so it defends only against a tampered *binary* given an
  *authentic* script. That specific gap is better closed by **attestations**
  (cryptographic, out-of-band, tool-verified) than by bespoke shell we maintain.

## What v1 ships instead (defense in depth, no fork)

1. **GitHub Artifact Attestations** — enable in the release workflow (dist
   supports it; uv enables it). Gives every artifact a signed, `gh attestation
   verify`-checkable provenance record — a stronger guarantee than an embedded
   sha256, and it covers the "compromised binary" threat TLS-only leaves open.
2. **Publish the unified `sha256.sum`** (dist does this by default) so anyone can
   verify manually.
3. **Document manual verification on the Install page** (feeds IA [#209](https://github.com/Connor-Miller/loot/issues/209)'s
   "verify your download" section): Windows `Get-FileHash <file> -Algorithm SHA256`
   compared against `sha256.sum`, plus the `gh attestation verify` path for the
   security-conscious.

## Hand-off to the spec (#211)

- Install-pipeline section records: **automated Windows path is TLS-only in v1
  (matches uv), backed by attestations + documented manual verify; ps1 stays
  unmodified.**
- **Fog / fast-follow:** if dist adds native ps1 checksum verification upstream, it
  arrives free on a version bump — track it and drop the manual-verify emphasis
  then. Same hardening tier as drand-timelock for embargo: real, but post-milestone.
