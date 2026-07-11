#requires -Version 5
<#
.SYNOPSIS
  The loot-first daily orchestrator (map #148): loot leads, git main is a
  downstream projection, the GitHub PR is a review view built from projected
  unfinalized loot WIP. Successor to the git-first tools/loot-day.ps1 ritual.

.DESCRIPTION
  Subcommands (see docs/agents/workflow.md for the full loop):

    review [-Title <t>]   Project the ambient dock's WIP for review:
                          `loot ferry --with-wip` -> review/<dock> in the
                          private mirror -> single-ref push to GitHub -> open
                          (or refresh) the PR. Records the PR in the pr-map
                          ledger keyed by the durable change id.

    land -Pr <n>          Land an approved PR the loot way: finalize
                          (`loot new`) on the PR's dock -> `loot ferry`
                          (projects the signed commit onto main + reaps the
                          provisional lane) -> fast-forward push main to
                          GitHub -> point the PR head at the landed sha so
                          GitHub marks it Merged by reachability (#150) ->
                          `loot push` to the relay. Falls back to
                          close-with-pointer when main cannot fast-forward.

    status                Show the in-flight review lanes and their PRs.

    init-hook             Install the warn-only pre-commit hook (#151):
                          committing directly to git main is break-glass,
                          warned but never blocked.

  loot itself never talks to GitHub; every gh/push call lives here. The
  private mirror (.loot/git-mirror/mirror.git) stays local-only: publishing is
  always a SINGLE-REF push with an inline URL - never `git remote add`, never
  --all/--mirror - and the pushed closures (main, review/*) are sealed-free by
  construction (#149).

.EXAMPLE
  pwsh tools/loot-first.ps1 review -Title "embargo CLI polish"
  pwsh tools/loot-first.ps1 land -Pr 201
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('review', 'land', 'status', 'init-hook')]
    [string]$Cmd,
    [int]$Pr = 0,
    [string]$Title = "",
    [switch]$DryRun
)

# NOTE: keep this file ASCII-only (PowerShell 5.1 parses a no-BOM script as
# ANSI; see loot-day.ps1). Machine lines it emits/parses: `review: ...` and
# `landed: ...` (ADR 0023-style key=value rows).
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $PSScriptRoot
$Loot = Join-Path $Root "target\release\loot.exe"
$Mirror = Join-Path $Root ".loot\git-mirror\mirror.git"
$PrMap = Join-Path $Root ".loot\git-mirror\pr-map"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Fail([string]$msg) { Write-Host "error: $msg" -ForegroundColor Red; exit 1 }

function Get-OriginUrl {
    $url = (git -C $Root remote get-url origin 2>$null | Out-String).Trim()
    if (-not $url) { Fail "no origin remote on the checkout - cannot publish to GitHub" }
    return $url
}

# pr-map ledger (#153 seam 2): one line per lane, `<change> <dock> <pr>`.
function Read-PrMap {
    $rows = @()
    if (Test-Path $PrMap) {
        foreach ($line in Get-Content $PrMap) {
            $f = $line.Trim() -split '\s+'
            if ($f.Count -eq 3) { $rows += [pscustomobject]@{ Change = $f[0]; Dock = $f[1]; Pr = [int]$f[2] } }
        }
    }
    return $rows
}
function Write-PrMap($rows) {
    $text = ($rows | ForEach-Object { "$($_.Change) $($_.Dock) $($_.Pr)" }) -join "`n"
    if ($text) { $text += "`n" }
    [System.IO.File]::WriteAllText($PrMap, $text, $Utf8NoBom)
}

function Ensure-Binary {
    if (-not (Test-Path $Loot)) {
        Write-Host "loot binary not found - building release..." -ForegroundColor Cyan
        Push-Location $Root
        & "$env:USERPROFILE\.cargo\bin\cargo.exe" build --release -p loot-cli
        Pop-Location
    }
    if (-not (Test-Path $Loot)) { Fail "loot release binary missing: $Loot" }
}

Push-Location $Root
try {
    switch ($Cmd) {

        'init-hook' {
            $hookDir = Join-Path $Root ".git\hooks"
            if (-not (Test-Path $hookDir)) { Fail "no .git/hooks here" }
            $hook = Join-Path $hookDir "pre-commit"
            $body = @'
#!/bin/sh
# loot-first guard (map #148, warn-only by design - break-glass stays open).
branch=$(git symbolic-ref --short HEAD 2>/dev/null)
if [ "$branch" = "main" ]; then
  echo "loot: warning - committing directly to git main is off the loot-first path." >&2
  echo "      git main is a projection of loot; the next 'loot ferry' ingests this." >&2
  echo "      prefer: loot dock <task> -> loot ferry --with-wip -> PR  (docs/agents/workflow.md)" >&2
fi
exit 0
'@ -replace "`r`n", "`n"
            [System.IO.File]::WriteAllText($hook, $body, $Utf8NoBom)
            Write-Host "installed warn-only pre-commit hook at .git/hooks/pre-commit"
        }

        'status' {
            $rows = Read-PrMap
            if (-not $rows) { Write-Host "no in-flight review lanes"; break }
            foreach ($r in $rows) {
                Write-Host ("lane change={0} dock={1} pr=#{2}" -f $r.Change.Substring(0, 8), $r.Dock, $r.Pr)
            }
        }

        'review' {
            Ensure-Binary
            Write-Host ">>> loot ferry --with-wip"
            $out = (& $Loot ferry --with-wip 2>&1 | Out-String)
            Write-Host $out
            $line = ($out -split "`r?`n") | Where-Object { $_ -match '^review: ' } | Select-Object -First 1
            if (-not $line) { Fail "ferry emitted no review line" }
            if ($line -match 'op=none') { Write-Host "nothing to review."; break }
            if ($line -notmatch 'dock=(\S+) branch=(\S+) sha=(\S+) change=(\S+) version=(\S+) round=(\d+) op=(\S+)') {
                Fail "unparseable review line: $line"
            }
            $dock = $Matches[1]; $branch = $Matches[2]; $chg = $Matches[4]; $op = $Matches[7]

            $url = Get-OriginUrl
            Write-Host ">>> git push (single-ref, inline URL) $branch"
            if (-not $DryRun) {
                git -C $Mirror push --force --quiet $url "refs/heads/${branch}:refs/heads/${branch}"
                if ($LASTEXITCODE -ne 0) { Fail "pushing $branch to GitHub failed" }
            }

            $rows = Read-PrMap
            $mine = $rows | Where-Object { $_.Change -eq $chg -and $_.Dock -eq $dock }
            if ($mine) {
                Write-Host ("review round updated on PR #{0} ({1})" -f $mine.Pr, $op)
            } elseif (-not $DryRun) {
                $t = $Title
                if (-not $t) {
                    $t = ((& $Loot log 2>&1 | Select-Object -First 1) | Out-String).Trim() -replace '^\S+\s+', ''
                    if (-not $t) { $t = "loot-first: $dock" }
                }
                Write-Host ">>> gh pr create --head $branch"
                $prUrl = (gh pr create --head $branch --base main --title $t --body "Review view of unfinalized loot WIP (change ``$chg``, dock ``$dock``) - see docs/agents/workflow.md. Lands via loot on approval; GitHub will mark it Merged by reachability." 2>&1 | Out-String).Trim()
                Write-Host $prUrl
                if ($prUrl -match '/pull/(\d+)') {
                    $rows += [pscustomobject]@{ Change = $chg; Dock = $dock; Pr = [int]$Matches[1] }
                    Write-PrMap $rows
                } else { Fail "could not parse PR number from: $prUrl" }
            }
        }

        'land' {
            if ($Pr -le 0) { Fail "usage: loot-first land -Pr <n>" }
            Ensure-Binary
            $rows = Read-PrMap
            $lane = $rows | Where-Object { $_.Pr -eq $Pr }
            if (-not $lane) { Fail "PR #$Pr is not in the pr-map ledger (was it opened by 'review'?)" }

            # The approval signal (#152): APPROVED - or, for a self-authored PR
            # (GitHub forbids approving your own), no CHANGES_REQUESTED. That
            # asymmetry is a live finding of the #155 run, logged as evidence.
            $info = (gh pr view $Pr --json reviewDecision,author,state 2>&1 | Out-String | ConvertFrom-Json)
            if ($info.state -ne 'OPEN') { Fail "PR #$Pr is $($info.state), not OPEN" }
            $viewer = (gh api user -q .login 2>&1 | Out-String).Trim()
            $decision = "$($info.reviewDecision)"
            $selfOk = ($info.author.login -eq $viewer) -and ($decision -ne 'CHANGES_REQUESTED')
            if ($decision -ne 'APPROVED' -and -not $selfOk) {
                Fail "PR #$Pr not approved (reviewDecision='$decision')"
            }
            Write-Host ("land: pr #{0} decision='{1}'{2}" -f $Pr, $decision, $(if ($selfOk -and $decision -ne 'APPROVED') { " (self-authored fast path)" } else { "" }))

            # Finalize must hit the PR's dock, not whatever is ambient (#153).
            $current = ((& $Loot docks 2>&1 | Out-String) -split "`r?`n" | Where-Object { $_ -match '^\*' } | Select-Object -First 1)
            if ($current -and $current -notmatch [regex]::Escape($lane.Dock)) {
                Fail "ambient dock is not '$($lane.Dock)' - run 'loot dock $($lane.Dock)' first (land refuses to finalize another lane)"
            }
            if ($DryRun) { Write-Host "(dry run) stopping before finalize"; break }

            Write-Host ">>> loot new  (finalize + sign; git-quiet)"
            & $Loot new
            Write-Host ">>> loot ferry  (project signed change -> main, reap the lane)"
            $fOut = (& $Loot ferry 2>&1 | Out-String)
            Write-Host $fOut

            $sha = (git -C $Mirror rev-parse refs/heads/main 2>$null | Out-String).Trim()
            if (-not $sha) { Fail "mirror main has no tip after ferry" }
            $url = Get-OriginUrl
            $branch = "review/$($lane.Dock)"

            Write-Host ">>> git push main (fast-forward) + collapse PR head -> $($sha.Substring(0,8))"
            git -C $Mirror push --quiet $url "refs/heads/main:refs/heads/main"
            $status = 'merged'
            if ($LASTEXITCODE -ne 0) {
                # Diverged main (#151 residual): close-with-pointer fallback.
                $status = 'closed-with-pointer'
                gh pr close $Pr --comment "Landed via loot as change ``$($lane.Change)`` -> mirror main ``$sha``. GitHub main had diverged; reconcile with 'loot ferry' then push." | Out-Null
            } else {
                git -C $Mirror push --force --quiet $url "${sha}:refs/heads/${branch}"
                # Reachability flip is async on GitHub's side; poll briefly.
                $merged = $false
                foreach ($i in 1..10) {
                    Start-Sleep -Seconds 2
                    $st = (gh pr view $Pr --json state -q .state 2>&1 | Out-String).Trim()
                    if ($st -eq 'MERGED') { $merged = $true; break }
                }
                if (-not $merged) {
                    $status = 'closed-with-pointer'
                    gh pr close $Pr --comment "Landed via loot as change ``$($lane.Change)`` -> main ``$sha`` (reachability flip did not register; closing with pointer)." | Out-Null
                }
                git -C $Mirror push --quiet $url ":refs/heads/${branch}" 2>$null
            }

            Write-Host ">>> loot push  (relay)"
            $pOut = (& $Loot push 2>&1 | Out-String)
            Write-Host $pOut

            Write-PrMap ($rows | Where-Object { $_.Pr -ne $Pr })
            Write-Host ("landed: change_id={0} main={1} pr=#{2} status={3}" -f $lane.Change, $sha, $Pr, $status) -ForegroundColor Green
        }
    }
}
finally {
    Pop-Location
}
