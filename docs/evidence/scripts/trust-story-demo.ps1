#requires -Version 5
<#
.SYNOPSIS
  Trust-story evidence run (#340, map #339) -- the trust remedies, end to end.

.DESCRIPTION
  Scripts the whole trust-hardening story against a LOCAL relay spawned from
  this build (loot serve), so nothing touches the production relay and the
  demo is self-contained. Five acts, every claim asserted from real output:

    1. Mis-seal -> burn (ADR 0038, #343/#344): `loot new` REFUSES a first-time
       public-by-fallthrough seal of a secret-shaped path (.env); the operator
       overrides deliberately (--allow-reveal, first-seal summary); `loot burn`
       destroys the bytes and records a signed tombstone; `loot verify` still
       passes (a burned absence is documented, not damage); re-applying a
       pre-burn bundle does NOT resurrect the bytes (the store ingest
       chokepoint refuses a burned oid); the forward fix (delete at tip)
       finalizes silently.
    2. Grant expiry (#20): a sealed grant deposited with --expires admits the
       holder while live; past expires_at the SAME grant is rejected outright
       at apply ("grant expired at"), and `loot surface` skips the lapsed
       path rather than re-materializing it.
    3. Quarantine (#12): a grant from an UNKNOWN sender is held in
       .loot/quarantine, listed by `loot grants --quarantined`, then trusted
       via `loot grants --trust <pubkey-hex>` and re-applied through the same
       expiry-checking gate.
    4. `loot embargo-status` (#15): reports "embargoed until" pre-reveal,
       "revealed" after (driven by LOOT_CLOCK, the documented cross-process
       clock override), and "not embargoed" for a plain path. Runs in
       MALLORY's repo: an embargoed seal is unreadable even to its author
       (ADR 0007), so the author's next capture would refuse to overwrite
       it -- mallory finalizes nothing afterwards, alice must keep capturing.
    5. Rotation (#16, ADR 0016): `loot id rotate` re-issues the still-live
       grants this identity holds as bundles (a lapsed grant is SKIPPED, never
       revived -- #20's property), archives the old key (never deletes it),
       and mints a fresh keypair. A grant aimed at the retired key's mailbox
       is never seen by the rotated identity; after the grantor re-registers
       the new key, the flow works end to end.

  Roles: CASEY = a standalone repo for the offline burn act. ALICE
  (originator), BOB (holder, the identity that rotates), MALLORY (a sender
  BOB has never registered) share the local relay.

  Clock trick: expiry, embargo-status, and the rotation skip are all decided
  against the CLIENT clock, so LOOT_CLOCK fast-forwards them without sleeps.
  (The relay's own clock only gates timed reveal_at delivery -- see the
  attack demo, docs/evidence/scripts/attack-demo.ps1, which proves that side.)

  Attributes trick: alice and mallory write BYTE-IDENTICAL .lootattributes
  files (the full rule set for the whole run), so when bob pulls both
  histories the shared path converges by content instead of conflicting.

  Known limitation, deliberately NOT asserted here: the applied side of a
  rotation re-grant bundle does not yet carry expiry (tag-1 bundle
  limitation) -- tracked as #368.

.EXAMPLE
  powershell -File docs\evidence\scripts\trust-story-demo.ps1
#>
param(
    [int]$RelayPort = 47340,
    [string]$WorkDir = ""
)

# Continue, not Stop: native tools write progress/errors to stderr, and under
# Stop the `2>&1` capture in Run() wraps each stderr line as a terminating
# NativeCommandError (a PowerShell 5.1 quirk). Correctness rides on explicit
# $LASTEXITCODE checks and the Check/Failures tally, not on $?.
$ErrorActionPreference = "Continue"
$Root    = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$Cargo   = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
$Loot    = Join-Path $Root "target\release\loot.exe"
$RunsDir = Join-Path $Root "docs\evidence\runs"
$LogPath = Join-Path $RunsDir "trust-story-demo.txt"
if ($WorkDir -eq "") {
    $WorkDir = Join-Path $env:TEMP ("loot-trust-story-" + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
}
$RelayUrl = "http://127.0.0.1:$RelayPort"
$script:Failures = 0

# Unique markers so every content check greps for THIS run's bytes.
$SECRET  = "DB_PASSWORD=" + [Guid]::NewGuid().ToString("N")
$PLAN    = "PLAN-"    + [Guid]::NewGuid().ToString("N").Substring(0, 12)
$TIP     = "TIP-"     + [Guid]::NewGuid().ToString("N").Substring(0, 12)
$HANDOFF = "HANDOFF-" + [Guid]::NewGuid().ToString("N").Substring(0, 12)

# Decode child-process (loot) stdout as UTF-8 so its em-dashes / arrows survive
# capture instead of mojibake-ing under the console's ANSI codepage.
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

if (-not (Test-Path $RunsDir)) { New-Item -ItemType Directory -Force $RunsDir | Out-Null }
[System.IO.File]::WriteAllText($LogPath, "", $Utf8NoBom)

function Log([string]$msg) {
    Write-Host $msg
    [System.IO.File]::AppendAllText($LogPath, $msg + "`r`n", $Utf8NoBom)
}

# Run a native command in $dir, echo + capture its output, remember its exit code.
function Run([string]$title, [string]$dir, [scriptblock]$cmd) {
    Log ""
    Log (">>> " + $title)
    Push-Location $dir
    try { $out = (& $cmd 2>&1 | Out-String) } finally { Pop-Location }
    $script:LastCode = $LASTEXITCODE
    foreach ($line in ($out -split "`r?`n")) {
        if ($line.Trim() -ne "") { Log ("    " + $line.TrimEnd()) }
    }
    return $out
}

function Check([bool]$ok, [string]$what) {
    if ($ok) { Log ("PASS: " + $what) }
    else     { Log ("FAIL: " + $what); $script:Failures++ }
}

function NowUnix { return [long][DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
function PubLine([string]$dir) { return ((Get-Content (Join-Path $dir ".loot\id.pub") -Raw).Trim()) }
function WriteFile([string]$path, [string]$text) {
    [System.IO.File]::WriteAllText($path, $text, $Utf8NoBom)
}

# Is any loose object whose address starts with $shortHex still present under
# $repoDir\.loot\objects? Robust to flat or sharded (ab\cdef...) layouts: test
# the bare name and the parent-dir + name concatenation.
function BurnedObjectPresent([string]$repoDir, [string]$shortHex) {
    $files = Get-ChildItem -Path (Join-Path $repoDir ".loot\objects") -Recurse -File -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        if ($f.Name.StartsWith($shortHex)) { return $true }
        if (($f.Directory.Name + $f.Name).StartsWith($shortHex)) { return $true }
    }
    return $false
}

Log "=== loot trust-story evidence run (#340, map #339) ==="
Log ("run started (utc): " + [DateTimeOffset]::UtcNow.ToString("u"))
Log ("relay:             " + $RelayUrl + " (local, spawned by this script)")
Log ("work dir:          " + $WorkDir)

# --- 0. build the binary, init the cast, start the local relay ---
# Built without Run()'s 2>&1 capture: cargo writes progress to stderr, which
# the capture would log as NativeCommandError noise.
Log ""
Log ">>> building loot (release)"
Push-Location $Root
& $Cargo build --release -p loot-cli | Out-Null
Pop-Location
if (-not (Test-Path $Loot)) { Log "FATAL: loot release binary did not build"; exit 1 }
Log ("    loot: " + $Loot)

New-Item -ItemType Directory -Force $WorkDir | Out-Null
$CaseyDir = Join-Path $WorkDir "casey"
$AliceDir = Join-Path $WorkDir "alice"
$BobDir   = Join-Path $WorkDir "bob"
$MalDir   = Join-Path $WorkDir "mallory"
foreach ($d in @($CaseyDir, $AliceDir, $BobDir, $MalDir)) {
    New-Item -ItemType Directory -Force $d | Out-Null
}

Run "casey:   loot init --identity casey"   $CaseyDir { & $Loot init --identity casey }   | Out-Null
Run "alice:   loot init --identity alice"   $AliceDir { & $Loot init --identity alice }   | Out-Null
Run "bob:     loot init --identity bob"     $BobDir   { & $Loot init --identity bob }     | Out-Null
Run "mallory: loot init --identity mallory" $MalDir   { & $Loot init --identity mallory } | Out-Null
$AlicePub = PubLine $AliceDir
$BobPub   = PubLine $BobDir

$RelayDir = Join-Path $WorkDir "relay"
$RelayProc = Start-Process -FilePath $Loot `
    -ArgumentList @("serve", "--dir", $RelayDir, "--addr", "127.0.0.1:$RelayPort") `
    -PassThru -WindowStyle Hidden
Log ""
Log (">>> local relay spawned (pid " + $RelayProc.Id + "), waiting for it to answer")
$relayReady = $false
foreach ($try in 1..20) {
    Push-Location $AliceDir
    & $Loot grants $RelayUrl 2>&1 | Out-Null
    $code = $LASTEXITCODE
    Pop-Location
    if ($code -eq 0) { $relayReady = $true; break }
    Start-Sleep -Seconds 1
}
if (-not $relayReady) {
    Log "FATAL: local relay never answered"
    if (-not $RelayProc.HasExited) { Stop-Process -Id $RelayProc.Id -Force }
    exit 1
}
Log "    relay is answering"

try {

Log ""
Log "================  ACT 1: MIS-SEAL -> BURN (ADR 0038)  ================"

WriteFile (Join-Path $CaseyDir ".env")      ($SECRET + "`n")
WriteFile (Join-Path $CaseyDir "readme.md") "casey's working notes`n"

$g = Run "casey: loot new (the mis-seal gate must refuse .env)" $CaseyDir {
    & $Loot new -m "initial"
}
Check (($script:LastCode -ne 0) -and ($g -match 'refusing to seal .*\.env.* publicly')) `
    "a secret-shaped path resolving Public by fallthrough is refused at the signing seam"

$g = Run "casey: loot new --allow-reveal .env (deliberate override)" $CaseyDir {
    & $Loot new --allow-reveal .env -m "deliberate reveal"
}
Check (($script:LastCode -eq 0) -and ($g -match 'first-seal summary')) `
    "the per-path override seals it, and the first-seal summary says so out loud"

# A pre-burn ciphertext bundle -- the resurrection vector we later prove dead.
# Written OUTSIDE the repo so no later capture sweeps it into history.
$BundlePath = Join-Path $WorkDir "casey-cipher.bundle"
Run "casey: loot bundle (pre-burn ciphertext, the resurrection vector)" $CaseyDir {
    & $Loot bundle $BundlePath
} | Out-Null
Check (Test-Path $BundlePath) "pre-burn bundle written"

$g = Run "casey: loot burn .env" $CaseyDir { & $Loot burn .env }
$m = [regex]::Match($g, 'destroyed ([0-9a-f]{8})')
$BurnOid = $m.Groups[1].Value
Check (($g -match 'burned 1 object') -and ($g -match 'destruction is complete on this machine') -and $m.Success) `
    "never-pushed tier: bytes destroyed on this machine, signed tombstone recorded"
Check (-not (BurnedObjectPresent $CaseyDir $BurnOid)) `
    "the burned object's bytes are gone from .loot/objects"

$g = Run "casey: loot surface (the burned path is labelled, never silent)" $CaseyDir {
    & $Loot surface
}
Check ($g -match 'burned \(bytes destroyed') `
    "surface labels the burned path instead of silently skipping it"

$g = Run "casey: loot verify (a burn is documented absence, not damage)" $CaseyDir {
    & $Loot verify
}
Check (($script:LastCode -eq 0) -and ($g -match 'all objects OK')) `
    "verify passes on a store with burned objects"

Run "casey: loot apply cipher.bundle (resurrection attempt)" $CaseyDir {
    & $Loot apply $BundlePath
} | Out-Null
Check (-not (BurnedObjectPresent $CaseyDir $BurnOid)) `
    "applying the pre-burn bundle does NOT resurrect the bytes (ingest refuses a burned oid)"

Remove-Item (Join-Path $CaseyDir ".env") -Force
$g = Run "casey: the forward fix -- delete .env at tip, finalize" $CaseyDir {
    & $Loot new -m "drop the mis-sealed path"
}
Check ($script:LastCode -eq 0) `
    "the forward fix finalizes without tripping the gate (first-seal scoped)"

Log ""
Log "================  ACT 2: GRANT EXPIRY (#20)  ================"

# One canonical rule set for the whole run, byte-identical in every repo that
# seals content, so the shared .lootattributes path converges when histories
# meet in bob's repo instead of conflicting.
$Reveal = (NowUnix) + 3600
$Attrs = "plan.md restricted=alice`n" +
         "tip.md restricted=mallory`n" +
         ("roadmap.md embargoed=" + $Reveal + "`n") +
         "handoff.md restricted=alice`n"

WriteFile (Join-Path $AliceDir ".lootattributes") $Attrs
WriteFile (Join-Path $AliceDir "plan.md")  ($PLAN + "`nthe sealed plan body`n")
WriteFile (Join-Path $AliceDir "notes.md") "public notes, nothing sealed`n"
Run "alice: seal plan.md restricted, notes.md public; push to the relay" $AliceDir {
    & $Loot new -m "sealed plan + public notes"
    & $Loot remote add origin $RelayUrl
    & $Loot push
} | Out-Null
Check ($script:LastCode -eq 0) "alice pushed her history to the local relay"

Run "bob: register alice, pull" $BobDir {
    & $Loot peer add alice "$AlicePub"
    & $Loot remote add origin $RelayUrl
    & $Loot pull
} | Out-Null
Check ((Test-Path (Join-Path $BobDir "notes.md")) -and (-not (Test-Path (Join-Path $BobDir "plan.md")))) `
    "pull materializes the public path; the sealed plan stays withheld (no key yet)"

$T1 = (NowUnix) + 3600
Log ""
Log ("expires_at (unix): " + $T1 + "   (one hour out; LOOT_CLOCK will lapse it without sleeping)")
$g = Run "alice: grant --relay plan.md bob --expires (sealed, expiring)" $AliceDir {
    & $Loot peer add bob "$BobPub"
    & $Loot grant --relay $RelayUrl plan.md bob --expires $T1
}
Check ($g -match 'expires at ') "sealed grant deposited carrying expires_at"

$g = Run "bob: pull-grants + surface (grant is live)" $BobDir {
    & $Loot pull-grants $RelayUrl
    & $Loot surface
}
$planPath = Join-Path $BobDir "plan.md"
$planLive = (Test-Path $planPath) -and (Select-String -Path $planPath -Pattern $PLAN -SimpleMatch -ErrorAction SilentlyContinue)
Check (($g -match 'applied 1/1') -and $planLive) `
    "before expires_at the grant admits bob: plan.md materializes with the sealed content"

# The same grant, re-deposited -- but bob's clock is now past expires_at.
Run "alice: deposit a second copy of the expiring grant" $AliceDir {
    & $Loot grant --relay $RelayUrl plan.md bob --expires $T1
} | Out-Null
$env:LOOT_CLOCK = ($T1 + 3600).ToString()
$g = Run "bob (clock past expires_at): pull-grants" $BobDir {
    & $Loot pull-grants $RelayUrl
}
Check ($g -match 'grant expired at') `
    "past expires_at the same grant is rejected outright at apply -- nothing installed"

Remove-Item $planPath -Force
$g = Run "bob (clock past expires_at): surface" $BobDir { & $Loot surface }
Check (-not (Test-Path $planPath)) `
    "surface skips the lapsed path -- an expired grant no longer materializes content"
Remove-Item Env:\LOOT_CLOCK

# Restore plan.md's exact bytes (the real clock is still before expires_at, so
# bob legitimately holds a live key for it): a clean tree over the tip lets the
# later pulls converge instead of capturing a dirty working head that would
# shadow the merged view.
WriteFile $planPath ($PLAN + "`nthe sealed plan body`n")

Log ""
Log "================  ACT 3: QUARANTINE (#12)  ================"

WriteFile (Join-Path $MalDir ".lootattributes") $Attrs
WriteFile (Join-Path $MalDir "tip.md") ($TIP + "`na tip from a sender bob never registered`n")
Run "mallory: seal tip.md, push, grant to bob (bob does NOT know mallory)" $MalDir {
    & $Loot new -m "tip"
    & $Loot remote add origin $RelayUrl
    & $Loot push
    & $Loot peer add bob "$BobPub"
    & $Loot grant --relay $RelayUrl tip.md bob
} | Out-Null

# Bob ingests mallory's history first: with a clean tree the pull converges the
# two lineages, and tip.md rides along sealed (no key yet).
Run "bob: pull (mallory's history arrives; tip.md stays sealed)" $BobDir {
    & $Loot pull
} | Out-Null

$g = Run "bob: pull-grants (unknown sender must be held, not applied)" $BobDir {
    & $Loot pull-grants $RelayUrl
}
Check ($g -match 'quarantined grant from unknown key') `
    "a grant from an unregistered sender is quarantined, not silently applied or dropped"

$m = [regex]::Match($g, '--trust ([0-9a-f]{64})')
$MalHex = $m.Groups[1].Value
if (-not $m.Success) {
    # Fallback: the quarantine directory is keyed by sender pubkey hex.
    $qdir = Get-ChildItem (Join-Path $BobDir ".loot\quarantine") -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($qdir) { $MalHex = $qdir.Name }
}

$g = Run "bob: loot grants --quarantined" $BobDir { & $Loot grants --quarantined }
Check ($g -match '1 quarantined grant') "the held grant is reviewable: sender pubkey, oid, received time"

$g = Run ("bob: loot grants --trust " + $MalHex.Substring(0, 12) + "...") $BobDir {
    & $Loot grants --trust $MalHex
}
Check ($g -match 're-applied 1/1') `
    "trusting the sender registers the peer and re-applies the held grant through the same gate"

Run "bob: surface (now holding mallory's key)" $BobDir {
    & $Loot surface
} | Out-Null
$tipPath = Join-Path $BobDir "tip.md"
$tipLive = (Test-Path $tipPath) -and (Select-String -Path $tipPath -Pattern $TIP -SimpleMatch -ErrorAction SilentlyContinue)
Check ([bool]$tipLive) "the trusted sender's content materializes for bob"

Log ""
Log "================  ACT 4: EMBARGO-STATUS (#15)  ================"

# In mallory's repo: an embargoed seal is unreadable even to its author until
# reveal_at (ADR 0007), so the author's NEXT capture would refuse to overwrite
# it. Mallory finalizes nothing after this act; alice still has captures ahead.
WriteFile (Join-Path $MalDir "roadmap.md") "the embargoed roadmap body`n"
Run "mallory: seal roadmap.md embargoed" $MalDir {
    & $Loot new -m "embargoed roadmap"
} | Out-Null

$g = Run "mallory: embargo-status roadmap.md (pre-reveal)" $MalDir {
    & $Loot embargo-status roadmap.md
}
Check ($g -match 'embargoed until') "pre-reveal: reported embargoed-until with the reveal timestamp"

$env:LOOT_CLOCK = ($Reveal + 3600).ToString()
$g = Run "mallory (clock past reveal_at): embargo-status roadmap.md" $MalDir {
    & $Loot embargo-status roadmap.md
}
Check ($g -match 'revealed') "post-reveal: the same path reports revealed"
Remove-Item Env:\LOOT_CLOCK

$g = Run "mallory: embargo-status tip.md (restricted, not embargoed)" $MalDir {
    & $Loot embargo-status tip.md
}
Check ($g -match 'not embargoed') "a non-embargoed path reports not-embargoed"

Log ""
Log "================  ACT 5: ROTATION (#16, ADR 0016)  ================"

# Bob holds two grants: plan.md (expires at T1) and tip.md (no expiry).
# Rotate with the clock past T1: the wave must re-issue tip.md ONLY --
# rotation never revives a lapsed grant (#20's property, at the wave).
$OldBobPub = PubLine $BobDir
$RegrantDir = Join-Path $WorkDir "bob-regrants"
$env:LOOT_CLOCK = ($T1 + 3600).ToString()
$g = Run "bob (clock past plan.md's expiry): loot id rotate" $BobDir {
    & $Loot id rotate $RegrantDir
}
Remove-Item Env:\LOOT_CLOCK
$NewBobPub = PubLine $BobDir
$bundles = @(Get-ChildItem $RegrantDir -Filter "regrant-*.bundle" -ErrorAction SilentlyContinue)
$archived = @(Get-ChildItem (Join-Path $BobDir ".loot") -Filter "id*rotated*" -ErrorAction SilentlyContinue)
Check ($NewBobPub -ne $OldBobPub) "rotation minted a fresh keypair (whoami changes)"
Check ($archived.Count -ge 1) "the old key is archived (.loot/id.rotated-<ts>), never deleted -- the rollback artifact"
Check (($bundles.Count -eq 1) -and ($g -match 'skipped 1 expired grant')) `
    "the re-grant wave re-issued the one live grant and SKIPPED the lapsed one -- rotation never revives"
Log "    (note: applied-side expiry carry of a re-grant bundle is tracked as #368 and deliberately not asserted here)"

# The retired key's mailbox is dead to the rotated identity: a grant aimed at
# the OLD pubkey (alice's registry is stale) is never seen by bob's new key.
# handoff.md's rule has been in the canonical .lootattributes all along.
WriteFile (Join-Path $AliceDir "handoff.md") ($HANDOFF + "`npost-rotation handoff body`n")
Run "alice: seal handoff.md, push" $AliceDir {
    & $Loot new -m "handoff"
    & $Loot push
} | Out-Null
Run "alice: grant handoff.md to bob's RETIRED key (stale registry)" $AliceDir {
    & $Loot grant --relay $RelayUrl handoff.md bob
} | Out-Null
$g = Run "bob: pull-grants (the old mailbox is dead to the new key)" $BobDir {
    & $Loot pull-grants $RelayUrl
}
Check ($g -match 'no pending grants') `
    "a grant aimed at the retired key never reaches the rotated identity"

Run "alice: re-verify bob out-of-band, register the NEW key, grant again" $AliceDir {
    & $Loot peer add bob "$NewBobPub"
    & $Loot grant --relay $RelayUrl handoff.md bob
} | Out-Null
# Pull BEFORE pull-grants: a sealed grant's tag-3 body carries the object
# ciphertext, and holding every offered object strands the next pull's
# negotiation with zero fetch round-trips -- the carrying change never
# ingests (#370). Ingest the change first, then apply the key.
$g = Run "bob: pull, pull-grants, surface (the new key receives)" $BobDir {
    & $Loot pull
    & $Loot pull-grants $RelayUrl
    & $Loot surface
}
$hoPath = Join-Path $BobDir "handoff.md"
$hoLive = (Test-Path $hoPath) -and (Select-String -Path $hoPath -Pattern $HANDOFF -SimpleMatch -ErrorAction SilentlyContinue)
Check (($g -match 'applied 1/1') -and $hoLive) `
    "after the grantor registers the new key, grants flow to it end to end"

Log ""
Log "================  TRUST CLAIM (map #339)  ================"
Log "A mis-sealed secret has a remedy: the gate refuses the accident, the"
Log "override is a deliberate per-path ceremony, and `loot burn` destroys the"
Log "bytes with a signed tombstone that sync refuses to resurrect -- while"
Log "verify keeps passing, because a documented absence is not damage."
Log "Grants lapse at expires_at on the recipient's own gate; grants from"
Log "unknown senders wait in a reviewable quarantine; embargo state is"
Log "inspectable at every step; and identities rotate with a wave that"
Log "re-issues only what is still live and archives what it retires."

Log ""
Log "================  RESULT  ================"
if ($script:Failures -eq 0) {
    Log "ALL CHECKS PASSED -- the trust story holds end to end against this build."
} else {
    Log ($script:Failures.ToString() + " CHECK(S) FAILED -- see above.")
}
Log ("run finished (utc): " + [DateTimeOffset]::UtcNow.ToString("u"))

} finally {
    if ($RelayProc -and -not $RelayProc.HasExited) { Stop-Process -Id $RelayProc.Id -Force }
}

try { Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue } catch {}
if ($script:Failures -ne 0) { exit 1 }
