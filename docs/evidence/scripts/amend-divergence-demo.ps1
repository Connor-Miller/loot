#requires -Version 5
<#
.SYNOPSIS
  Amend-divergence demo (wayfinder map #169) -- evidence that a divergent change
  ARISES FROM ORDINARY WORK: two peers each `loot edit` the same change over the
  relay, and the fork renders (`!`), collapses (`loot abandon`), and restores
  (`loot undo`) -- with no white-box construction.

.DESCRIPTION
  Two acts over a hermetic, local `loot serve` relay, proving the amend model
  (ADR 0032) end to end on real concurrent writers -- never a test fixture:

  ACT 1 -- CONTROL: a solo amend travels as a CLEAN SUPERSESSION.
    `dev` finalizes a change and pushes; `agent` clones it. `dev` then
    `loot edit`s that change, amends the file, finalizes, and pushes. `agent`
    pulls -- and sees the amended version REPLACE the original: no `!` anywhere,
    no content-merge of old and new (converge drops the superseded head). ADR
    0032's supersession-travels property: a solo amend is invisible as divergence.

  ACT 2 -- DIVERGENCE: two identities amend the SAME change_id -> `!`.
    Both peers share a base change. Each `loot edit`s it and finalizes a
    DIFFERENT amend on its own line (dev on its store, agent on its clone) --
    two live versions of one durable handle, neither superseding the other.
    `agent` pulls dev's amend: one graph now holds both. `loot log`/`status`
    render the `!` marker on the divergent change (flat listing, not a
    "run apply" fork); converge minted NO merge (#203), so there is no per-path
    conflict and the tree stays clean on the agent's own side; `loot abandon
    <version-id>` collapses it to one live version -- the whole settle;
    `loot undo` brings the divergence back. Divergence is cross-STORE
    (build finding #171): two docks in one store cannot produce it, so the proof
    uses two identities over the relay.

  Hermetic by design: Act 2 MUTATES history (push), so it runs against a LOCAL
  relay spun up for the run -- the same keyless-forwarding code as the VPS, with
  zero risk to the production relay's shared DAG.

  Honesty (ADR 0026): one machine, one OS user; two distinct keyring-separated
  identities cooperating over the relay.

.EXAMPLE
  powershell -File docs\evidence\scripts\amend-divergence-demo.ps1
#>
param(
    [int]$Port = 47521,
    [string]$WorkDir = "",
    [string]$LootExe = "",
    [string]$LogFile = ""
)

# Continue, not Stop: native tools write to stderr; under Stop the 2>&1 capture
# in Run() raises a terminating NativeCommandError in PowerShell 5.1.
$ErrorActionPreference = "Continue"
$Root    = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$Loot    = if ($LootExe -ne "") { $LootExe } else { Join-Path $Root "target\release\loot.exe" }
$RunsDir = Join-Path $Root "docs\evidence\runs"
$LogPath = if ($LogFile -ne "") { $LogFile } else { Join-Path $RunsDir "amend-divergence-demo.txt" }
$RelayUrl = "http://127.0.0.1:$Port"
if ($WorkDir -eq "") {
    $WorkDir = Join-Path $env:TEMP ("loot-amend-" + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
}
$script:Failures = 0
$script:Relay = $null

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$LogDir = Split-Path $LogPath -Parent
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Force $LogDir | Out-Null }
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
function WriteFile([string]$path, [string]$content) {
    [System.IO.File]::WriteAllText($path, $content, $Utf8NoBom)
}
# The durable change_id is 8 reverse-hex LETTERS (a-z, never a digit); the
# version id is 8 hex digits. `loot status` prints "working change <cid> ...".
function ChangeIdFromStatus([string]$dir) {
    Push-Location $dir
    try { $out = (& $Loot status 2>&1 | Out-String) } finally { Pop-Location }
    $m = [regex]::Match($out, 'working change ([a-z]{8})')
    return $m.Groups[1].Value
}
function Cleanup {
    if ($script:Relay -and -not $script:Relay.HasExited) {
        try { $script:Relay | Stop-Process -Force -ErrorAction SilentlyContinue } catch {}
    }
    try { Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue } catch {}
}

Log "=== loot amend-divergence demo (wayfinder map #169) ==="
Log ("run started (utc): " + [DateTimeOffset]::UtcNow.ToString("u"))
Log ("work dir:          " + $WorkDir)

# --- build (cached) ---
Log ""
Log ">>> building loot (release)"
Push-Location $Root
& (Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe") build --release -p loot-cli | Out-Null
Pop-Location
if (-not (Test-Path $Loot)) { Log "FATAL: loot release binary did not build"; exit 1 }

New-Item -ItemType Directory -Force $WorkDir | Out-Null

try {
    # --- hermetic local relay (Act 1 + Act 2 both push) ---
    Log ""
    Log (">>> starting local relay: loot serve --dir <tmp> --addr 127.0.0.1:$Port")
    $RelayDir = Join-Path $WorkDir "relay"
    $script:Relay = Start-Process -FilePath $Loot `
        -ArgumentList @("serve", "--dir", $RelayDir, "--addr", "127.0.0.1:$Port") `
        -PassThru -WindowStyle Hidden
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

    $DevDir   = Join-Path $WorkDir "dev"
    $AgentDir = Join-Path $WorkDir "agent"

    # =====================================================================
    # ACT 1 -- CONTROL: a solo amend travels as a clean supersession.
    #          One writer edits a landed change; the peer sees a clean
    #          replacement -- no `!`, no content-merge.
    # =====================================================================
    Log ""
    Log "############################################################"
    Log "# ACT 1 -- CONTROL: solo amend => clean supersession (ADR 0032)"
    Log "############################################################"

    New-Item -ItemType Directory -Force $DevDir | Out-Null
    Run "dev: init, write doc.txt = v1, finalize + push" $DevDir {
        & $Loot init --identity dev
        & $Loot remote add origin $RelayUrl
    } | Out-Null
    WriteFile (Join-Path $DevDir "doc.txt") "doc: version one`n"
    $ctrlCid = ChangeIdFromStatus $DevDir
    Run "dev: loot new -m 'write doc' (finalize the base) + push" $DevDir {
        & $Loot new -m "write doc"
        & $Loot push
    } | Out-Null
    Log ("    [control change_id = " + $ctrlCid + "]")

    Run "agent: clone the relay as a DISTINCT identity 'agent'" $WorkDir {
        & $Loot clone $RelayUrl $AgentDir --identity agent
    } | Out-Null
    Run "agent: surface + read doc.txt (has dev's v1)" $AgentDir {
        & $Loot surface
    } | Out-Null
    $agentDocV1 = (Get-Content (Join-Path $AgentDir "doc.txt") -Raw)
    Check ($agentDocV1 -match "version one") "agent clones dev's base change (doc.txt = v1)"

    # dev amends the SAME change_id -- a solo edit, then pushes.
    Run "dev: loot edit $ctrlCid (reopen the landed change)" $DevDir {
        & $Loot edit $ctrlCid
    } | Out-Null
    WriteFile (Join-Path $DevDir "doc.txt") "doc: version one, amended by dev`n"
    $devAmend = Run "dev: finalize the amend (loot new) + push" $DevDir {
        & $Loot new
        & $Loot push
    }

    # agent pulls -- must see a CLEAN supersession: no `!`, no content-merge.
    $ctrlPull = Run "agent: loot pull (expect clean supersession, no divergence)" $AgentDir {
        & $Loot pull $RelayUrl
    }
    Run "agent: loot surface" $AgentDir { & $Loot surface } | Out-Null
    $ctrlLog = Run "agent: loot log (the control -- no bang marker on the change)" $AgentDir {
        & $Loot log
    }
    $agentDocV2 = (Get-Content (Join-Path $AgentDir "doc.txt") -Raw)

    Check ($ctrlLog -notmatch "!") "CONTROL: no divergence marker (!) after a solo amend (clean supersession)"
    Check ($ctrlLog -notmatch "diverged") "CONTROL: log does not report a diverged fork"
    Check ($agentDocV2 -match "amended by dev") "CONTROL: agent's doc.txt is dev's amended version (replacement)"
    Check ($agentDocV2 -notmatch "(?s)version one`n.*amended") "CONTROL: no content-merge of the old and new lines (converge dropped the superseded head)"

    # =====================================================================
    # ACT 2 -- DIVERGENCE: two identities amend the same change_id.
    #          The fork renders (`!`), collapses (abandon), restores (undo).
    # =====================================================================
    Log ""
    Log "############################################################"
    Log "# ACT 2 -- DIVERGENCE from concurrent amends (! / abandon / undo)"
    Log "############################################################"

    # A fresh base change both peers will fork their amends from.
    WriteFile (Join-Path $DevDir "feat.txt") "feat: base`n"
    $divCid = ChangeIdFromStatus $DevDir
    Run "dev: write feat.txt = base, finalize + push" $DevDir {
        & $Loot new -m "add feat"
        & $Loot push
    } | Out-Null
    Log ("    [divergent change_id = " + $divCid + "]")

    Run "agent: pull the base change (both peers now share it, single version)" $AgentDir {
        & $Loot pull $RelayUrl
        & $Loot surface
    } | Out-Null
    Check (Test-Path (Join-Path $AgentDir "feat.txt")) "agent shares the base change (feat.txt present, one version)"

    # CONCURRENT amends: dev edits + pushes; agent edits its OWN line from the
    # same base BEFORE pulling dev's amend -- two live versions of one handle.
    Run "dev: loot edit $divCid, feat.txt = dev's take, finalize + push" $DevDir {
        & $Loot edit $divCid
    } | Out-Null
    WriteFile (Join-Path $DevDir "feat.txt") "feat: dev's take`n"
    Run "dev: finalize dev's amend + push (relay tip 1)" $DevDir {
        & $Loot new
        & $Loot push
    } | Out-Null

    Run "agent: loot edit $divCid (its own line, from the shared base)" $AgentDir {
        & $Loot edit $divCid
    } | Out-Null
    WriteFile (Join-Path $AgentDir "feat.txt") "feat: agent's take`n"
    Run "agent: finalize agent's amend + push (relay tip 2 -> two versions of one handle)" $AgentDir {
        & $Loot new
        & $Loot push
    } | Out-Null

    # agent pulls dev's amend: one graph now holds BOTH live versions.
    $divPull = Run "agent: loot pull (dev's amend lands next to agent's -> DIVERGENCE)" $AgentDir {
        & $Loot pull $RelayUrl
    }
    $divLog = Run "agent: loot log (the ! divergence marker, flat listing)" $AgentDir {
        & $Loot log
    }
    $divStatus = Run "agent: loot status (agrees: the working change's handle is divergent)" $AgentDir {
        & $Loot status
    }
    # The two amends touched the same line -- but the divergence is ONE
    # two-writer event, already rendered by the ! marker. Converge leaves the
    # co-versions FLAT (#198/#203, amending ADR 0032): no `converge diverged
    # head` merge is minted, so no per-path conflict exists, the tip stays on
    # the agent's own side, and the tree is clean. `loot abandon` is the whole
    # settle.
    $divConflicts = Run "agent: loot conflicts (EMPTY -- converge minted no merge, so no per-path conflict)" $AgentDir {
        & $Loot conflicts
    }

    Check ($divLog -match ([regex]::Escape($divCid) + "!")) "DIVERGENCE: log renders the ! marker on the divergent change_id"
    Check ($divLog -notmatch "run .loot apply. to converge") "DIVERGENCE: it is a flat divergent listing, not a 'run apply' fork"
    Check ($divConflicts -notmatch "feat.txt") "DIVERGENCE STAYS FLAT (#203): no per-path conflict -- converge minted no merge of the co-versions"
    $agentFeat = [System.IO.File]::ReadAllText((Join-Path $AgentDir "feat.txt"))
    Check ($agentFeat -match "agent's take") "DIVERGENCE STAYS FLAT (#203): the working tree is clean on OURS (agent's own amend)"

    # Two live version ids under the divergent change id -- capture them to abandon one.
    $verIds = @()
    foreach ($m in [regex]::Matches($divLog, '(?m)^' + [regex]::Escape($divCid) + '!?\s+([0-9a-f]{8})')) {
        $verIds += $m.Groups[1].Value
    }
    $verIds = $verIds | Select-Object -Unique
    Check ($verIds.Count -ge 2) "DIVERGENCE: two live versions listed under one durable handle ($($verIds -join ', '))"

    if ($verIds.Count -ge 2) {
        # Abandon the FIRST-listed version (dev's side, per the log's author
        # column) -- agent keeps its own amend. Picking a side is the WHOLE
        # settle (#203): the survivor's tree stands, no per-path conflict
        # exists before or after, one undoable op.
        $abandonVer = $verIds[0]
        $abandonOut = Run "agent: loot abandon $abandonVer (collapse the divergence -- keep agent's side)" $AgentDir {
            & $Loot abandon $abandonVer
        }
        $afterAbandon = Run "agent: loot log (collapsed -- one live version, no bang)" $AgentDir {
            & $Loot log
        }
        Check ($afterAbandon -notmatch ([regex]::Escape($divCid) + "!")) "ABANDON: the ! marker is gone -- divergence collapsed to one live version"
        Check ($afterAbandon -match [regex]::Escape($divCid)) "ABANDON: the change_id survives with its remaining live version"

        # #203 closes the #172 finding: with no converge merge minted, abandon
        # settles the ONE two-writer event completely -- the tree is the clean
        # survivor, and there is no standing per-path conflict left behind.
        $afterConflicts = Run "agent: loot conflicts (still empty -- abandon left a clean tree, nothing to resolve)" $AgentDir {
            & $Loot conflicts
        }
        Check ($afterConflicts -notmatch "feat.txt") "ABANDON IS THE WHOLE SETTLE (#203): no standing per-path conflict after the collapse"
        $survivorFeat = [System.IO.File]::ReadAllText((Join-Path $AgentDir "feat.txt"))
        Check ($survivorFeat -match "agent's take") "ABANDON IS THE WHOLE SETTLE (#203): the survivor's tree stands (agent's take, clean)"

        $undoOut = Run "agent: loot undo (walk the abandon back)" $AgentDir {
            & $Loot undo
        }
        $afterUndo = Run "agent: loot log (divergence restored -- the bang is back)" $AgentDir {
            & $Loot log
        }
        Check ($afterUndo -match ([regex]::Escape($divCid) + "!")) "UNDO: the divergence is restored -- the ! marker returns (nothing was destroyed)"
    }

    Log ""
    Log "================  RESULT  ================"
    Log "Divergence arises from ORDINARY WORK, no white-box construction:"
    Log "  Act 1 (control): a solo 'loot edit' amend travels the relay as a clean"
    Log "         supersession -- the peer sees a replacement, no bang marker, no"
    Log "         content-merge (converge drops the superseded head). ADR 0032's"
    Log "         supersession-travels property."
    Log "  Act 2 (divergence): two identities each 'loot edit' the SAME change_id"
    Log "         and finalize different amends; one pull puts both live versions"
    Log "         in one graph -- FLAT (#203): no converge merge, no per-path"
    Log "         conflict, tree clean on ours; 'loot log'/'status' render the !"
    Log "         marker; 'loot abandon' is the whole settle; 'loot undo' restores"
    Log "         it. Divergence is cross-STORE (two docks in one store cannot"
    Log "         produce it, #171)."
    Log ""
    Log "Honesty (ADR 0026): one machine, one OS user; two keyring-separated"
    Log "identities cooperating over a hermetic local relay."
    Log ""
    if ($script:Failures -eq 0) {
        Log "ALL CHECKS PASSED -- divergence from ordinary work proven, both acts."
    } else {
        Log ($script:Failures.ToString() + " CHECK(S) FAILED -- see above.")
    }
    Log ("run finished (utc): " + [DateTimeOffset]::UtcNow.ToString("u"))
}
finally {
    Cleanup
}
if ($script:Failures -ne 0) { exit 1 }
