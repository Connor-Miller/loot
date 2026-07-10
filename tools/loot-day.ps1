#requires -Version 5
<#
.SYNOPSIS
  One command for a loot-first working day: finalize the day's work in loot,
  push it to the relay, and log the day (evidence for map #54 section A).

.DESCRIPTION
  Runs the daily ritual and records it:
    1. `loot status -m <message>` - snapshot the working tree into loot.
    2. `loot new`                 - finalize (sign) the day's change.
    3. `loot push`                - publish to the relay (O(delta), resumable).
  Then appends a dated section to docs/dogfood/drive-log.md with the mechanical
  facts (loot change id, objects pushed, git backup head, loot-vs-git
  divergence) and a `friction:` line for you to complete, and prints the row to
  paste into the evidence table (section A).

  git is the backup: this does NOT commit to git. Commit/push git as usual.

.PARAMETER Day
  Which drive day this is (1..5).

.PARAMETER Message
  The loot change message for the day (what changed).

.PARAMETER DryRun
  Snapshot + finalize locally but skip the push (for a rehearsal).

.EXAMPLE
  pwsh tools/loot-day.ps1 -Day 1 -Message "embargo CLI + attack demo + section-B evidence"
#>
param(
    [Parameter(Mandatory = $true)][int]$Day,
    [Parameter(Mandatory = $true)][string]$Message,
    [switch]$DryRun
)

# NOTE: keep this file ASCII-only. PowerShell 5.1 parses a no-BOM script as ANSI,
# so a stray em-dash/arrow in the SOURCE mojibakes into a parse error. Runtime
# output (loot's own em-dashes) is fine; only the source must stay ASCII.
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $PSScriptRoot
$Loot = Join-Path $Root "target\release\loot.exe"
$LogPath = Join-Path $Root "docs\dogfood\drive-log.md"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

if (-not (Test-Path $Loot)) {
    Write-Host "loot binary not found - building release..." -ForegroundColor Cyan
    Push-Location $Root
    & "$env:USERPROFILE\.cargo\bin\cargo.exe" build --release -p loot-cli
    Pop-Location
}
if (-not (Test-Path $Loot)) { throw "loot release binary missing: $Loot" }
if (-not (Test-Path $LogPath)) { throw "drive log missing: $LogPath (create it first)" }

Push-Location $Root
try {
    $date = [DateTime]::Now.ToString("yyyy-MM-dd")

    # loot-vs-git divergence at the START of the day: loot head vs git HEAD.
    $lootHeadBefore = ((& $Loot log 2>&1 | Select-Object -First 1) | Out-String).Trim()
    $gitHead = (git rev-parse --short HEAD).Trim()
    $gitSubject = (git log -1 --pretty=%s).Trim()

    Write-Host "=== loot day $Day ($date) ===" -ForegroundColor Green
    Write-Host ">>> loot status -m ..."
    & $Loot status -m $Message
    Write-Host ">>> loot new"
    & $Loot new

    # The finalized day change is now loot's head.
    $lootHead = ((& $Loot log 2>&1 | Select-Object -First 1) | Out-String).Trim()
    $changeId = ($lootHead -split '\s+')[0]

    $pushed = "(dry run - not pushed)"
    if ($DryRun) {
        Write-Host ">>> (dry run) skipping loot push" -ForegroundColor Yellow
    } else {
        Write-Host ">>> loot push"
        $pushOut = (& $Loot push 2>&1 | Out-String)
        Write-Host $pushOut
        $m = [regex]::Match($pushOut, "pushed\s+(\d+)\s+new object")
        $pushed = if ($m.Success) { "$($m.Groups[1].Value) object(s)" } else { "see push output" }
    }

    # Append the day section to the drive log. (Kept ASCII; loot ids are hex.)
    $entry = @"

## Day $Day - $date

- loot change: ``$changeId`` "$Message"
- pushed: $pushed to the relay
- git backup HEAD: ``$gitHead`` "$gitSubject"
- loot head at start of day: $lootHeadBefore
- friction: <fill in - what diverged or hurt today, or ``none``>
"@
    [System.IO.File]::AppendAllText($LogPath, $entry, $Utf8NoBom)

    Write-Host ""
    Write-Host "logged to docs/dogfood/drive-log.md - now fill the 'friction:' line." -ForegroundColor Cyan
    Write-Host "paste this row into the evidence table (section A of docs/evidence/loot-hosts-loot.md):"
    Write-Host ""
    Write-Host "| $Day | $date | ``$changeId`` $Message | <friction one-liner> |"
}
finally {
    Pop-Location
}
