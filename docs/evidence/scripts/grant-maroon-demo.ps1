#requires -Version 5
<#
.SYNOPSIS
  Grant / maroon lifecycle demo (map #54 section B, ADR 0008/0009/0015) --
  evidence that access is granted and revoked per-content, with an auditable
  trail, over a keyless relay.

.DESCRIPTION
  A dev seals a restricted path, an agent joins as a distinct identity, and the
  full access lifecycle runs against a relay:

    1. Before any grant, the agent's clone holds the ciphertext but no key --
       the restricted path is absent from its surface.
    2. The dev issues a sealed grant via the relay mailbox; the agent
       pull-grants, files the key, and reads the content.
    3. The dev HARD-maroons the agent: the path is re-sealed under a fresh key
       the agent does not hold, and a purge event is emitted. On the agent's
       next pull the current content resolves to the new seal it cannot open --
       the path goes dark again.
    4. `loot manifest` prints the audit trail: the grant event (grantor and
       grantee as pubkeys) and the re-seal, so every key handoff is on record.

  Hermetic by design: this MUTATES history (grant, re-seal, push), so it runs
  against a LOCAL `loot serve` relay spun up for the run -- the same relay-clock
  / keyless-forwarding code as the VPS, with zero risk to the production relay's
  shared append-only DAG. The mechanism is identical; only the host differs.

  Honesty (ADR 0026): one machine, one OS user; identity-scoped visibility in a
  cooperating multi-identity repo (stated in the output).

.EXAMPLE
  powershell -File docs\evidence\scripts\grant-maroon-demo.ps1
#>
param(
    [int]$Port = 47452,
    [string]$WorkDir = ""
)

# Continue, not Stop: native tools write to stderr; under Stop the 2>&1 capture
# in Run() raises terminating NativeCommandError in PowerShell 5.1.
$ErrorActionPreference = "Continue"
$Root    = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$Cargo   = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
$Loot    = Join-Path $Root "target\release\loot.exe"
$RunsDir = Join-Path $Root "docs\evidence\runs"
$LogPath = Join-Path $RunsDir "grant-maroon-demo.txt"
$RelayUrl = "http://127.0.0.1:$Port"
$SECRET = "RESTRICTED-SECRET-" + [Guid]::NewGuid().ToString("N").Substring(0, 12)
if ($WorkDir -eq "") {
    $WorkDir = Join-Path $env:TEMP ("loot-grant-maroon-" + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
}
$script:Failures = 0
$script:Relay = $null

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
if (-not (Test-Path $RunsDir)) { New-Item -ItemType Directory -Force $RunsDir | Out-Null }
[System.IO.File]::WriteAllText($LogPath, "", $Utf8NoBom)

function Log([string]$msg) {
    Write-Host $msg
    [System.IO.File]::AppendAllText($LogPath, $msg + "`r`n", $Utf8NoBom)
}
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
function PubLine([string]$dir) { return ((Get-Content (Join-Path $dir ".loot\id.pub") -Raw).Trim()) }
function Cleanup {
    if ($script:Relay -and -not $script:Relay.HasExited) {
        try { $script:Relay | Stop-Process -Force -ErrorAction SilentlyContinue } catch {}
    }
    try { Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue } catch {}
}

Log "=== loot grant / maroon lifecycle demo (section B, ADR 0008/0009/0015) ==="
Log ("run started (utc): " + [DateTimeOffset]::UtcNow.ToString("u"))
Log ("relay:             " + $RelayUrl + "   (local `loot serve` -- hermetic; mutating demo)")
Log ("work dir:          " + $WorkDir)

# --- build (cached) ---
Log ""
Log ">>> building loot (release)"
Push-Location $Root
& $Cargo build --release -p loot-cli | Out-Null
Pop-Location
if (-not (Test-Path $Loot)) { Log "FATAL: loot release binary did not build"; exit 1 }

New-Item -ItemType Directory -Force $WorkDir | Out-Null
$RelayDir = Join-Path $WorkDir "relay"
$DevDir   = Join-Path $WorkDir "dev"
$AgentDir = Join-Path $WorkDir "agent"

try {
    # --- 0. start a local, keyless relay ---
    Log ""
    Log (">>> starting local relay: loot serve --dir <tmp> --addr 127.0.0.1:$Port")
    $script:Relay = Start-Process -FilePath $Loot `
        -ArgumentList @("serve", "--dir", $RelayDir, "--addr", "127.0.0.1:$Port") `
        -PassThru -WindowStyle Hidden
    # Readiness: a raw TCP connect to the listener (never opens a loot workspace,
    # so the real repo in $Root is never touched).
    $up = $false
    for ($i = 0; $i -lt 80; $i++) {
        Start-Sleep -Milliseconds 250
        try {
            $c = New-Object System.Net.Sockets.TcpClient
            $c.Connect("127.0.0.1", $Port); $c.Close(); $up = $true; break
        } catch {}
    }
    if (-not $up) { Log "FATAL: local relay did not come up"; Cleanup; exit 1 }
    Start-Sleep -Milliseconds 250
    Log "    relay is up."

    # --- 1. dev seals a restricted path and publishes the ciphertext ---
    New-Item -ItemType Directory -Force $DevDir | Out-Null
    Run "dev: loot init --identity dev" $DevDir { & $Loot init --identity dev } | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $DevDir ".lootattributes"), "secret.txt restricted=dev`n")
    [System.IO.File]::WriteAllText((Join-Path $DevDir "secret.txt"), "$SECRET`nthe restricted content only granted identities may read`n")
    Run "dev: seal + finalize + push the restricted change" $DevDir {
        & $Loot remote add origin $RelayUrl
        & $Loot status -m "add restricted secret"
        & $Loot new
        & $Loot push
    } | Out-Null
    $DevPub = PubLine $DevDir

    # --- 2. agent clones: ciphertext only, no key ---
    Run "agent: clone the relay as identity 'agent'" $WorkDir {
        & $Loot clone $RelayUrl $AgentDir --identity agent
    } | Out-Null
    $AgentPub = PubLine $AgentDir
    $readBefore = Test-Path (Join-Path $AgentDir "secret.txt")
    Check (-not $readBefore) "before any grant, the agent cannot read the restricted path (secret.txt absent)"

    # --- 3. dev grants the key to the agent via the relay mailbox ---
    Run "dev: peer add agent + grant --relay secret.txt agent" $DevDir {
        & $Loot peer add agent "$AgentPub"
        & $Loot grant --relay $RelayUrl secret.txt agent
    } | Out-Null

    Run "agent: peer add dev + pull-grants + surface" $AgentDir {
        & $Loot peer add dev "$DevPub"
        & $Loot pull-grants $RelayUrl
        & $Loot surface
    } | Out-Null
    $granted = Join-Path $AgentDir "secret.txt"
    $readAfterGrant = (Test-Path $granted) -and (Select-String -Path $granted -Pattern $SECRET -SimpleMatch -ErrorAction SilentlyContinue)
    Check ([bool]$readAfterGrant) "after the sealed grant, the agent files the key and reads the restricted content"

    # --- 4. dev hard-maroons the agent: re-seal under a new key + purge ---
    # cmd_maroon finalizes (signs) the re-seal change so it propagates via push.
    Run "dev: loot maroon --hard secret.txt agent (re-seal excluding the agent) + push" $DevDir {
        & $Loot maroon --hard secret.txt agent
        & $Loot push
    } | Out-Null

    # The agent already decrypted the old plaintext once; that copy on disk is
    # not forward-secret (ADR 0009 -- already-read bytes are out of scope). The
    # test of the maroon is whether the agent can read the CURRENT content, so
    # drop the local copy and see whether loot can restore it after the re-seal.
    Remove-Item $granted -Force -ErrorAction SilentlyContinue
    $pullOut = Run "agent: drop the old copy, then loot pull + surface (receives the re-seal + purge)" $AgentDir {
        & $Loot pull $RelayUrl
        & $Loot surface
    }
    $restored = (Test-Path $granted) -and (Select-String -Path $granted -Pattern $SECRET -SimpleMatch -ErrorAction SilentlyContinue)
    $sealedOnPull = ($pullOut -match "sealed" -and $pullOut -match "lack the key")
    Check ((-not $restored) -and $sealedOnPull) `
        "after the hard maroon, the agent's pull carries a seal it cannot open (loot cannot restore secret.txt -- no key)"

    # --- 5. the audit trail ---
    $manifest = Run "dev: loot manifest (grant audit trail, grantor/grantee as pubkeys)" $DevDir {
        & $Loot manifest
    }
    Check ($manifest -match "agent") "the Manifest records the grant to the agent (auditable key-handoff trail)"

    Log ""
    Log "================  RESULT  ================"
    Log "Access to secret.txt was granted to the agent, exercised, then revoked --"
    Log "each step per-content, propagated over a keyless relay, and recorded in the"
    Log "Manifest. Permissions are a property of the content and the grant graph,"
    Log "not of the repository."
    Log ""
    Log "Honesty (ADR 0026): one machine under one OS user. 'The agent cannot read"
    Log "after maroon' means key custody PLUS the agent harness's file sandbox --"
    Log "an honest-participant posture. The re-seal denies the NEW content to the"
    Log "marooned key; the hard-maroon purge additionally drops the old key on"
    Log "cooperating peers. Forward secrecy for already-read bytes is out of scope"
    Log "(the agent may have copied what it already decrypted -- ADR 0009)."
    Log ""
    if ($script:Failures -eq 0) {
        Log "ALL CHECKS PASSED -- grant, read, maroon, and audit all behaved."
    } else {
        Log ($script:Failures.ToString() + " CHECK(S) FAILED -- see above.")
    }
    Log ("run finished (utc): " + [DateTimeOffset]::UtcNow.ToString("u"))
}
finally {
    Cleanup
}
if ($script:Failures -ne 0) { exit 1 }
