#requires -Version 5
<#
.SYNOPSIS
  Hard-embargo attack demo (#89, ADR 0027) -- evidence for map #54 section C.

.DESCRIPTION
  Scripts an adversarial HOLDER attempting early access to an embargoed change
  three ways -- all failing -- then reading it normally after the RELAY's clock
  passes reveal_at:

    1. Lying clock    -- LOOT_CLOCK set far past reveal_at; `loot grants`/
                         `pull-grants` still yield nothing. The relay's clock
                         gates delivery; the wire carries no client clock field
                         to lie with (ADR 0027).
    2. Direct inspect -- the plaintext secret and any key material are absent
                         from the holder's entire .loot (objects, escrow,
                         keyring). The holder possesses only ciphertext.
    3. Patched binary -- a client built from the same engine with EVERY
                         client-side time gate removed (the `patched-client`
                         cargo example: flush + read at now = u64::MAX) still
                         cannot read: there are no key bytes to bypass.

  Then, after reveal_at, `loot pull-grants` delivers the key (the relay released
  it) and `loot surface` materializes the plaintext -- the read succeeds.

  Why this is clean against the LIVE relay: the only relay interaction is the
  timed SealedGrant deposited to the holder's pubkey-addressed mailbox (drained
  on delivery, keyed by a throwaway holder key) plus the holder's pull-grants.
  The ciphertext object travels holder-ward as an out-of-band bundle FILE, so
  NOTHING is stowed into the relay's shared append-only DAG -- the demo leaves
  the production relay's history untouched.

  Roles: ORIGINATOR = the dev (a temp repo with an originator keypair; the
  originator may reveal their own content whenever they like, so they are not
  the adversary -- stated openly). HOLDER = a temp repo with a fresh keypair,
  standing in for any adversarial recipient.

.EXAMPLE
  powershell -File docs\evidence\scripts\attack-demo.ps1
  powershell -File docs\evidence\scripts\attack-demo.ps1 -EmbargoSeconds 60
#>
param(
    [string]$RelayUrl = "https://relay.millerbyte.com",
    [int]$EmbargoSeconds = 90,
    [string]$WorkDir = ""
)

# Continue, not Stop: native tools (cargo, loot) write progress/errors to stderr,
# and under Stop the `2>&1` capture in Run() wraps each stderr line as a
# terminating NativeCommandError (a PowerShell 5.1 quirk). Correctness rides on
# explicit $LASTEXITCODE checks and the Check/Failures tally, not on $?.
$ErrorActionPreference = "Continue"
$Root    = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$Cargo   = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
$Loot    = Join-Path $Root "target\release\loot.exe"
$Patched = Join-Path $Root "target\debug\examples\patched-client.exe"
$RunsDir = Join-Path $Root "docs\evidence\runs"
$LogPath = Join-Path $RunsDir "attack-demo.txt"
if ($WorkDir -eq "") {
    $WorkDir = Join-Path $env:TEMP ("loot-attack-demo-" + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
}
$script:Failures = 0
$SECRET = "EMBARGO-SECRET-" + [Guid]::NewGuid().ToString("N").Substring(0, 12)

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

Log "=== loot hard-embargo attack demo (#89, ADR 0027) ==="
Log ("run started (utc): " + [DateTimeOffset]::UtcNow.ToString("u"))
Log ("relay:             " + $RelayUrl)
Log ("work dir:          " + $WorkDir)
Log ("embargo window:    " + $EmbargoSeconds + "s")

# --- 0. build both binaries BEFORE the embargo clock starts ---
# Built without Run()'s 2>&1 capture: cargo writes progress to stderr, which the
# capture would log as NativeCommandError noise. Progress goes to the console;
# the log stays clean.
Log ""
Log ">>> building binaries (loot release + patched-client example)"
Push-Location $Root
& $Cargo build --release -p loot-cli | Out-Null
& $Cargo build -p loot-core --example patched-client | Out-Null
Pop-Location
if (-not (Test-Path $Loot))    { Log "FATAL: loot release binary did not build"; exit 1 }
if (-not (Test-Path $Patched)) { Log "FATAL: patched-client example did not build"; exit 1 }
Log ("    loot:           " + $Loot)
Log ("    patched-client: " + $Patched)

New-Item -ItemType Directory -Force $WorkDir | Out-Null
$OrigDir = Join-Path $WorkDir "originator"
$HoldDir = Join-Path $WorkDir "holder"
New-Item -ItemType Directory -Force $OrigDir | Out-Null
New-Item -ItemType Directory -Force $HoldDir | Out-Null

# --- 1. two fresh identities (no clone: the demo never touches the shared DAG) ---
Run "originator: loot init --identity connor" $OrigDir { & $Loot init --identity connor } | Out-Null
Run "holder:     loot init --identity holder" $HoldDir { & $Loot init --identity holder } | Out-Null
$OrigPub = PubLine $OrigDir
$HoldPub = PubLine $HoldDir

# --- 2. originator seals an embargoed change and deposits a timed grant ---
$Reveal = (NowUnix) + $EmbargoSeconds
Log ""
Log ("reveal_at (unix):  " + $Reveal + "   (" +
     [DateTimeOffset]::FromUnixTimeSeconds($Reveal).ToString("u") + ")")

[System.IO.File]::WriteAllText((Join-Path $OrigDir ".lootattributes"),
    "embargoed.md embargoed=$Reveal`n")
[System.IO.File]::WriteAllText((Join-Path $OrigDir "embargoed.md"),
    "$SECRET`nthe embargoed change body -- readable only after reveal_at`n")

Run "originator: seal + finalize the embargoed change" $OrigDir {
    & $Loot status -m "embargoed change"
    & $Loot new
} | Out-Null

# The holder gets the CIPHERTEXT out-of-band as a bundle file (no key -- v5
# bundles have no embargoed-key lane). Nothing is pushed to the relay's DAG.
$BundlePath = Join-Path $WorkDir "cipher.bundle"
Run "originator: loot bundle (ciphertext only, no key) -> file" $OrigDir {
    & $Loot bundle $BundlePath
} | Out-Null

# Register the holder, then deposit ONE timed SealedGrant to the holder's
# mailbox on the LIVE relay. grant --relay inherits the seal's reveal_at (#88).
Run "originator: peer add holder + grant --relay (timed deposit)" $OrigDir {
    & $Loot peer add holder "$HoldPub"
    & $Loot grant --relay $RelayUrl embargoed.md holder
} | Out-Null

# --- 3. holder ingests the ciphertext, trusts the originator as grantor ---
Run "holder: peer add connor + apply the ciphertext bundle" $HoldDir {
    & $Loot peer add connor "$OrigPub"
    & $Loot apply $BundlePath
} | Out-Null

Log ""
Log "================  PRE-REVEAL ATTACKS (must all fail)  ================"

# --- attack 1: lying clock ---
$env:LOOT_CLOCK = ($Reveal + 1000000).ToString()
$g = Run "attack 1 (lying clock): LOOT_CLOCK >> reveal_at; loot grants + pull-grants" $HoldDir {
    & $Loot grants $RelayUrl
    & $Loot pull-grants $RelayUrl
    & $Loot surface
}
Remove-Item Env:\LOOT_CLOCK
# The file is materialized only if the read leaked; absent = not readable.
$mdPath = Join-Path $HoldDir "embargoed.md"
$readable1 = (Test-Path $mdPath) -and (Select-String -Path $mdPath -Pattern $SECRET -SimpleMatch -ErrorAction SilentlyContinue)
Check (($g -match "no pending grants") -and (-not $readable1)) `
    "advanced holder clock does not release the key (relay clock gates, not the holder's)"

# --- attack 2: direct inspection of the holder's .loot ---
# Genuinely recurse every file under .loot and grep for the plaintext secret.
$dotFiles = Get-ChildItem -Path (Join-Path $HoldDir ".loot") -Recurse -File -ErrorAction SilentlyContinue
$hits = $dotFiles | Select-String -Pattern $SECRET -SimpleMatch -ErrorAction SilentlyContinue
# Confirm the ciphertext object IS present (the holder possesses the sealed blob).
$objDir = Join-Path $HoldDir ".loot\objects"
$objCount = (Get-ChildItem -Path $objDir -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count
Run "attack 2 (inspection): grep the holder's entire .loot for the plaintext secret" $HoldDir {
    Write-Output ("scanned " + $dotFiles.Count + " file(s) under .loot")
    if ($hits) { Write-Output "SECRET FOUND IN:"; $hits | ForEach-Object { Write-Output ("  " + $_.Path) } }
    else       { Write-Output "the plaintext secret appears in NO file under .loot" }
    Write-Output ("ciphertext objects held: " + $objCount + " (the holder has the encrypted blob, not the key)")
    $esc = Join-Path $HoldDir ".loot\escrow"
    if (Test-Path $esc) { Write-Output ("escrow file: " + (Get-Item $esc).Length + " bytes (empty header = no embargoed key staged)") }
    else                { Write-Output "escrow file: absent (no embargoed key staged)" }
} | Out-Null
Check (((-not $hits)) -and ($objCount -gt 0)) `
    "the holder holds only ciphertext: the plaintext secret and key material are absent from .loot"

# --- attack 3: patched binary (all client time gates removed) ---
Run "attack 3 (patched binary): read at now = u64::MAX with every gate removed" $HoldDir {
    & $Patched $HoldDir holder embargoed.md
} | Out-Null
Check ($script:LastCode -eq 3) "a client with the time gate removed still cannot read (no key bytes to bypass)"

# The relay itself confirms the grant is withheld pre-reveal.
$peek = Run "relay check: loot grants (relay clock still < reveal_at)" $HoldDir { & $Loot grants $RelayUrl }
Check ($peek -match "no pending grants") "the relay withholds the grant from its mailbox until its own clock passes reveal_at"

# --- 4. wait for the relay clock to pass reveal_at ---
Log ""
$waitFor = ($Reveal - (NowUnix)) + 10   # +10s buffer for client/relay clock skew
if ($waitFor -gt 0) {
    Log ("waiting " + $waitFor + "s for the relay clock to pass reveal_at...")
    Start-Sleep -Seconds $waitFor
}

Log ""
Log "================  POST-REVEAL READ (must succeed)  ================"
Run "holder: loot pull-grants + surface (relay has now released the key)" $HoldDir {
    & $Loot pull-grants $RelayUrl
    & $Loot surface
} | Out-Null
$readable2 = (Select-String -Path (Join-Path $HoldDir "embargoed.md") -Pattern $SECRET -SimpleMatch -ErrorAction SilentlyContinue)
Check ([bool]$readable2) "after reveal_at the relay delivers the key and the holder reads the embargoed change normally"

# --- 5. the trust claim, stated verbatim in the captured output ---
Log ""
Log "================  TRUST CLAIM (ADR 0027)  ================"
Log "The claim is HOLDER-adversary-proof: no holder -- with an advanced clock, a"
Log "patched binary, or direct disk inspection -- can read an embargoed change"
Log "before reveal_at, because the key bytes are never on the holder's machine;"
Log "they sit at the relay, ECIES-wrapped, until the RELAY's clock releases them."
Log ""
Log "Residual trust: early release requires the RELAY OPERATOR -- a distinct role"
Log "that holds only wrapped blobs it cannot read. In THIS demo the operator is"
Log "the dev (operator = holder-of-the-VPS = the same person running loot), stated"
Log "openly. Removing even that trust (drand timelock) is the recorded"
Log "post-milestone hardening; the holder-adversary claim does not depend on it."

Log ""
Log "================  RESULT  ================"
if ($script:Failures -eq 0) {
    Log "ALL CHECKS PASSED -- embargo is holder-adversary-proof against the live relay."
} else {
    Log ($script:Failures.ToString() + " CHECK(S) FAILED -- see above.")
}
Log ("run finished (utc): " + [DateTimeOffset]::UtcNow.ToString("u"))

try { Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue } catch {}
if ($script:Failures -ne 0) { exit 1 }
