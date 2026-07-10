#requires -Version 5
<#
.SYNOPSIS
  Sealed-from-agents path demo (map #54 section B, ADR 0026) -- evidence that
  visibility is a property of CONTENT, not the repository.

.DESCRIPTION
  The repo's `docs/pitch/**` is sealed `restricted=connor` (.lootattributes):
  the zero-knowledge-host product notes, readable by the dev and withheld from
  agent identities. This demo shows the SAME relay content surfacing two ways:

    - AGENT view: a fresh clone from the live relay with a NON-dev identity
      pulls the full history and every ciphertext object, but surfacing it
      leaves docs/pitch/ absent -- loot deliberately skips the sealed path
      (the clone has the object bytes, not the key). Public paths materialize
      normally.
    - DEV view: the real working repo (identity connor) holds the key in its
      keyring, so docs/pitch/zk-host.md is present and readable.

  Same bytes on the relay; the difference is key custody. The clone is
  READ-ONLY (a pull), so this touches neither the dev's working tree nor the
  relay's shared DAG.

  Honesty (ADR 0026): on one machine under one OS user, "agents cannot read"
  means key custody PLUS the agent harness's file sandbox -- an honest-
  participant posture, not a hostile-process guarantee. Stated in the output.

.EXAMPLE
  powershell -File docs\evidence\scripts\sealed-path-demo.ps1
#>
param(
    [string]$RelayUrl = "https://relay.millerbyte.com",
    [string]$WorkDir = ""
)

# Continue, not Stop: native tools write progress/errors to stderr, which the
# 2>&1 capture in Run() would otherwise raise as terminating NativeCommandError
# under PowerShell 5.1. Correctness rides on explicit checks, not on $?.
$ErrorActionPreference = "Continue"
$Root    = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$Cargo   = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
$Loot    = Join-Path $Root "target\release\loot.exe"
$RunsDir = Join-Path $Root "docs\evidence\runs"
$LogPath = Join-Path $RunsDir "sealed-path-demo.txt"
$SealedPath = "docs/pitch/zk-host.md"
$PublicPath = "CONTEXT.md"
if ($WorkDir -eq "") {
    $WorkDir = Join-Path $env:TEMP ("loot-sealed-path-" + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
}
$script:Failures = 0

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

Log "=== loot sealed-from-agents path demo (section B, ADR 0026) ==="
Log ("run started (utc): " + [DateTimeOffset]::UtcNow.ToString("u"))
Log ("relay:             " + $RelayUrl)
Log ("dev repo:          " + $Root)
Log ("sealed path:       " + $SealedPath + "   (.lootattributes: docs/pitch/** restricted=connor)")

# --- build (cached) ---
Log ""
Log ">>> building loot (release)"
Push-Location $Root
& $Cargo build --release -p loot-cli | Out-Null
Pop-Location
if (-not (Test-Path $Loot)) { Log "FATAL: loot release binary did not build"; exit 1 }

New-Item -ItemType Directory -Force $WorkDir | Out-Null
$AgentDir = Join-Path $WorkDir "agent"

# --- AGENT view: fresh clone from the live relay with a non-dev identity ---
# Clone is a pull: it fetches the full history + every ciphertext object, then
# auto-surfaces what THIS identity may read. Nothing is pushed.
Run "agent: clone the live relay as identity 'reviewer' (read-only)" $WorkDir {
    & $Loot clone $RelayUrl $AgentDir --identity reviewer
} | Out-Null
$agentSurface = Run "agent: loot surface (materialize what 'reviewer' may see)" $AgentDir {
    & $Loot surface
}

$agentSealed  = Test-Path (Join-Path $AgentDir $SealedPath)
$agentPublic  = Test-Path (Join-Path $AgentDir $PublicPath)
$skippedSeen  = ($agentSurface -match "sealed path")
Check (-not $agentSealed) "the agent's clone does NOT materialize the sealed path ($SealedPath absent)"
Check ($agentPublic)      "the agent's clone DOES materialize public content ($PublicPath present)"
Check ($skippedSeen)      "loot reports sealed path(s) skipped for the agent (it holds the ciphertext, not the key)"

# --- DEV view: the real working repo (identity connor holds the key) ---
# Read-only: we do NOT run status/surface here (surface would re-materialize and
# could clobber uncommitted work). We read connor's already-materialized view.
$devSealedFull = Join-Path $Root $SealedPath
$devSealed = Test-Path $devSealedFull
$devWhoami = Run "dev: loot whoami (the real repo's identity)" $Root { & $Loot whoami }
Check ($devWhoami -match "identity:\s*connor") "the dev repo's identity is connor (the grantee of docs/pitch/**)"
Check ($devSealed) "the dev's working tree HAS the sealed path present and readable ($SealedPath)"
if ($devSealed) {
    $firstLine = (Get-Content $devSealedFull -TotalCount 1)
    Log ""
    Log (">>> dev reads the sealed path (first line of $SealedPath):")
    Log ("    " + $firstLine)
}

Log ""
Log "================  RESULT  ================"
Log "Same ciphertext on the relay; docs/pitch/ is present for the dev (connor"
Log "holds the key) and absent for the agent clone (ciphertext only). Visibility"
Log "is a property of the content, not the repository."
Log ""
Log "Honesty (ADR 0026): this is one machine under one OS user. 'Agents cannot"
Log "read the sealed path' means key custody PLUS the agent harness's file"
Log "sandbox -- an honest-participant posture. A hostile process running as the"
Log "dev's OS user could read the dev's keyring off disk; the claim is about"
Log "identity-scoped visibility within a cooperating multi-identity repo, which"
Log "is exactly what the thesis is about."
Log ""
if ($script:Failures -eq 0) {
    Log "ALL CHECKS PASSED -- the sealed path is dev-visible, agent-invisible."
} else {
    Log ($script:Failures.ToString() + " CHECK(S) FAILED -- see above.")
}
Log ("run finished (utc): " + [DateTimeOffset]::UtcNow.ToString("u"))

try { Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue } catch {}
if ($script:Failures -ne 0) { exit 1 }
