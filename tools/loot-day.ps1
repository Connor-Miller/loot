#requires -Version 5
<#
.SYNOPSIS
  One command for a loot-first working day: capture the day's work in loot,
  ferry the git side across the bridge, push to the relay, and log the day
  (evidence for map #54 section A).

  NOTE: this is the *git-first* ritual (git leads, loot ingests). Its
  loot-first successor is tools/loot-first.ps1 (map #148): loot leads, the PR
  reviews projected WIP, and git main is projected downstream. Prefer that
  for new work; see docs/agents/workflow.md.

.DESCRIPTION
  Runs the daily ritual and records it:
    1. If git sees uncommitted work (or -ForceSnapshot):
         `loot status -m <message>` + `loot new`  - capture the day's WIP.
       On a git-clean tree this is skipped: everything that reached git main
       arrives through the bridge instead, one loot change per commit.
    2. `git push <mirror> main` + `loot ferry`    - one bridge pass (ADR 0028):
       ingest merged git commits as loot changes, reconcile with loot's
       converge classifier, re-project loot heads into the private mirror.
    3. `loot push`                                - publish to the relay.
  Then appends a dated section to docs/dogfood/drive-log.md with the mechanical
  facts (loot change id, ferry summary, objects pushed, git backup head) and a
  `friction:` line for you to complete, and prints the row to paste into the
  evidence table (section A).

  The bridge mirror lives at .loot/git-mirror/mirror.git and holds this
  identity's FULL READABLE TREE in plaintext, including content sealed to
  others (docs/pitch). It is local-only by design: never add a remote to it
  and never push it anywhere (ADR 0028). git commits/pushes to GitHub happen
  from the normal checkout as usual and never include sealed content.

.PARAMETER Day
  Which drive day this is (1..5).

.PARAMETER Message
  The loot change message for the day (what changed).

.PARAMETER DryRun
  Capture + ferry locally but skip the relay push (for a rehearsal).

.PARAMETER ForceSnapshot
  Snapshot even when git reports a clean tree. Needed when the day's edits
  live only under git-ignored, loot-tracked paths (e.g. docs/pitch/), which
  the git-dirty check cannot see.

.EXAMPLE
  pwsh tools/loot-day.ps1 -Day 2 -Message "ferry binding + capture fix"
#>
param(
    [Parameter(Mandatory = $true)][int]$Day,
    [Parameter(Mandatory = $true)][string]$Message,
    [switch]$DryRun,
    [switch]$ForceSnapshot
)

# NOTE: keep this file ASCII-only. PowerShell 5.1 parses a no-BOM script as ANSI,
# so a stray em-dash/arrow in the SOURCE mojibakes into a parse error. Runtime
# output (loot's own em-dashes) is fine; only the source must stay ASCII.
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $PSScriptRoot
$Loot = Join-Path $Root "target\release\loot.exe"
$Mirror = Join-Path $Root ".loot\git-mirror\mirror.git"
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

    # 1. Capture the day's WIP when git can see uncommitted work. On a clean
    #    tree the bridge carries everything, one loot change per git commit,
    #    and an extra snapshot would only mint a redundant identical change.
    $gitDirty = @(git status --porcelain).Count -gt 0
    if ($gitDirty -or $ForceSnapshot) {
        Write-Host ">>> loot status -m ..."
        & $Loot status -m $Message
        Write-Host ">>> loot new"
        & $Loot new
    } else {
        Write-Host ">>> git-clean tree: skipping snapshot (the ferry ingests committed work; use -ForceSnapshot if today's edits are only under docs/pitch or other git-ignored loot paths)" -ForegroundColor Yellow
    }

    # 2. One bridge pass (ADR 0028). Sync the local-only mirror to this
    #    checkout's main first, then let loot ingest/reconcile/project.
    $ferryLine = '(mirror missing - ferry skipped; bind with: loot ferry --git-dir .loot/git-mirror/mirror.git)'
    if (Test-Path $Mirror) {
        # Forced on purpose: this checkout is authoritative for the mirror's
        # main (ferry re-points main at the loot dock tip after projecting, so
        # a plain push stops fast-forwarding as soon as loot is ever ahead).
        # Nothing is lost - every projected commit stays reachable under the
        # mirror's refs/loot/* namespace, and the mirror is local-only.
        Write-Host ">>> git push (private mirror) main"
        git push --quiet --force "$Mirror" main:refs/heads/main
        Write-Host ">>> loot ferry"
        $ferryOut = (& $Loot ferry --git-dir .loot/git-mirror/mirror.git 2>&1 | Out-String)
        Write-Host $ferryOut
        # loot's own line already starts "ferry:"; strip it so the log template's
        # "- ferry: $ferryLine" prefix is not doubled.
        $ferryLine = ((($ferryOut -split "`r?`n") | Where-Object { $_ -match "^ferry:" } | Select-Object -First 1) -replace '^ferry:\s*', '')
        if (-not $ferryLine) { $ferryLine = "see ferry output" }
    } else {
        Write-Host ">>> $ferryLine" -ForegroundColor Yellow
    }

    # The day's finalized/reconciled change is now loot's head.
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
- ferry: $ferryLine
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
