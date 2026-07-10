#requires -Version 5
<#
.SYNOPSIS
  Concurrent-agents demo (wayfinder map #119) -- evidence that two agents edit
  concurrently and CONVERGE WITH NO SIDE DROPPED, with the whole reconciliation
  loop agent-drivable through porcelain verdicts.

.DESCRIPTION
  Two acts, proving the concurrent-agents epic (docks + harbor + buoys +
  porcelain) end to end:

  ACT 1 -- LOCAL DOCKS (one identity, one shared object store; ADR 0022).
    Two docks fork off a base and edit concurrently: dock-a and dock-b each add
    a disjoint file, and both edit the SAME single-line file differently. They
    integrate into a `harbor` dock via `loot dock merge --porcelain`:
      - merging dock-a converges/merges cleanly;
      - merging dock-b surfaces a genuine Conflict (C) on the shared file --
        neither side dropped -- resolved via `loot conflicts` / `loot resolve`;
      - `loot attest <merge> base` + `loot buoy base` landmark the integration
        (a read-side landmark over the attestation lane; no mutable ref).
    Every reconciliation step is read back in porcelain, the agent's driver.

  ACT 2 -- RELAY LEG (two DISTINCT identities; ADR 0001 / 0026).
    A hermetic, local `loot serve` relay. `dev` seals a restricted path and
    publishes; `agent` clones (ciphertext only). Both then edit concurrently and
    push -- the relay's append-only DAG FORKS (two tips). `agent` pulls and
    `apply --porcelain` COLLAPSES the fork: dev's public work converges in
    (no side dropped), while the restricted path -- whose key agent does not
    hold -- surfaces as RelayedUnmerged (R): carried as ciphertext it cannot
    read. That per-path merger/relay split, under concurrency, is loot's
    convergence thesis.

  Hermetic by design: Act 2 MUTATES history (push), so it runs against a LOCAL
  relay spun up for the run -- the same keyless-forwarding code as the VPS, with
  zero risk to the production relay's shared DAG. Act 1 is purely local.

  Honesty (ADR 0026): one machine, one OS user; identity-scoped visibility in a
  cooperating multi-identity repo. "agent cannot read the restricted path" means
  key custody -- the key bytes are not on the relay or in agent's keyring.

.EXAMPLE
  powershell -File docs\evidence\scripts\concurrent-agents-demo.ps1
#>
param(
    [int]$Port = 47463,
    [string]$WorkDir = ""
)

# Continue, not Stop: native tools write to stderr; under Stop the 2>&1 capture
# in Run() raises a terminating NativeCommandError in PowerShell 5.1.
$ErrorActionPreference = "Continue"
$Root    = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$Cargo   = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
$Loot    = Join-Path $Root "target\release\loot.exe"
$RunsDir = Join-Path $Root "docs\evidence\runs"
$LogPath = Join-Path $RunsDir "concurrent-agents-demo.txt"
$RelayUrl = "http://127.0.0.1:$Port"
$SECRET = "RESTRICTED-SECRET-" + [Guid]::NewGuid().ToString("N").Substring(0, 12)
if ($WorkDir -eq "") {
    $WorkDir = Join-Path $env:TEMP ("loot-concurrent-" + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
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
function WriteFile([string]$path, [string]$content) {
    [System.IO.File]::WriteAllText($path, $content, $Utf8NoBom)
}
function PubLine([string]$dir) { return ((Get-Content (Join-Path $dir ".loot\id.pub") -Raw).Trim()) }
function Cleanup {
    if ($script:Relay -and -not $script:Relay.HasExited) {
        try { $script:Relay | Stop-Process -Force -ErrorAction SilentlyContinue } catch {}
    }
    try { Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue } catch {}
}

Log "=== loot concurrent-agents demo (wayfinder map #119) ==="
Log ("run started (utc): " + [DateTimeOffset]::UtcNow.ToString("u"))
Log ("work dir:          " + $WorkDir)

# --- build (cached) ---
Log ""
Log ">>> building loot (release)"
Push-Location $Root
& $Cargo build --release -p loot-cli | Out-Null
Pop-Location
if (-not (Test-Path $Loot)) { Log "FATAL: loot release binary did not build"; exit 1 }

New-Item -ItemType Directory -Force $WorkDir | Out-Null

try {
    # =====================================================================
    # ACT 1 -- LOCAL DOCKS: two docks fork, integrate into the harbor,
    #          a real conflict surfaces + resolves, a buoy landmarks it.
    # =====================================================================
    Log ""
    Log "############################################################"
    Log "# ACT 1 -- local docks + harbor + conflict + buoy (ADR 0022)"
    Log "############################################################"

    $A1 = Join-Path $WorkDir "act1"
    New-Item -ItemType Directory -Force $A1 | Out-Null
    Run "init the repo (identity dev) and lay down a base change" $A1 {
        & $Loot init --identity dev
    } | Out-Null
    WriteFile (Join-Path $A1 "shared.txt") "base line`n"
    Run "snapshot + finalize the base (both docks fork from here)" $A1 {
        & $Loot status -m "base"
        & $Loot new
    } | Out-Null

    # dock-a forks from the base, edits the shared line + adds a disjoint file.
    Run "dock-a: fork, edit shared.txt + add a-only.txt" $A1 {
        & $Loot dock dock-a
    } | Out-Null
    WriteFile (Join-Path $A1 "shared.txt") "alpha's take`n"
    WriteFile (Join-Path $A1 "a-only.txt") "from dock-a`n"
    Run "dock-a: snapshot + finalize" $A1 {
        & $Loot status -m "dock-a work"
        & $Loot new
    } | Out-Null

    # dock-b forks from the SAME base (switch back to main first), edits the
    # same shared line DIFFERENTLY + adds its own disjoint file.
    Run "dock-b: fork from base, edit shared.txt differently + add b-only.txt" $A1 {
        & $Loot dock main
        & $Loot dock dock-b
    } | Out-Null
    WriteFile (Join-Path $A1 "shared.txt") "bravo's take`n"
    WriteFile (Join-Path $A1 "b-only.txt") "from dock-b`n"
    Run "dock-b: snapshot + finalize" $A1 {
        & $Loot status -m "dock-b work"
        & $Loot new
    } | Out-Null

    # harbor is an ordinary dock by convention -- fork it from the base.
    Run "harbor: create the integrator dock (forks from base, no work yet)" $A1 {
        & $Loot dock main
        & $Loot dock harbor
    } | Out-Null

    $mergeA = Run "harbor <- dock-a: loot dock merge dock-a --porcelain" $A1 {
        & $Loot dock merge dock-a --porcelain
    }
    Check ($mergeA -match "(?m)^=\ta-only\.txt") "dock-a's disjoint file converges into the harbor (= row)"

    $mergeB = Run "harbor <- dock-b: loot dock merge dock-b --porcelain (CONCURRENT same-line edit)" $A1 {
        & $Loot dock merge dock-b --porcelain
    }
    Check ($mergeB -match "(?m)^C\tshared\.txt\t") "the concurrent same-line edit surfaces as a Conflict (C) -- not silently dropped"
    Check ($mergeB -match "(?m)^=\tb-only\.txt")   "dock-b's disjoint file still converges (= row) alongside the conflict"

    $confl = Run "loot conflicts --porcelain (the agent reads what needs resolving)" $A1 {
        & $Loot conflicts --porcelain
    }
    Check ($confl -match "(?m)^C\tshared\.txt\t") "the conflict is enumerable in porcelain for an agent to act on"

    WriteFile (Join-Path $WorkDir "resolution.txt") "reconciled: alpha + bravo`n"
    Run "loot resolve shared.txt <- reconciled content (keeps both sides' intent)" $A1 {
        & $Loot resolve shared.txt (Join-Path $WorkDir "resolution.txt")
    } | Out-Null
    $conflAfter = Run "loot conflicts --porcelain (expect empty -- resolved)" $A1 {
        & $Loot conflicts --porcelain
    }
    Check (($conflAfter.Trim()) -eq "") "after resolve, no conflicts remain (porcelain is empty)"

    $a1files = @("shared.txt", "a-only.txt", "b-only.txt")
    $allPresent = $true
    foreach ($f in $a1files) { if (-not (Test-Path (Join-Path $A1 $f))) { $allPresent = $false } }
    Check $allPresent "the integrated harbor tree carries BOTH docks' disjoint work + the resolved file (no side dropped)"

    # Landmark the integration with a buoy (over the attestation lane; ADR 0025).
    Run "finalize the integration as a change" $A1 { & $Loot new } | Out-Null
    $logOut = Run "loot log (find the finalized integration change)" $A1 { & $Loot log }
    $cid = [regex]::Match($logOut, '\b[0-9a-f]{8}\b').Value
    Run "loot attest $cid base   (mark it a navigational landmark)" $A1 {
        & $Loot attest $cid base
    } | Out-Null
    $buoy = Run "loot buoy base   (resolve the landmark -- computed, not a mutable ref)" $A1 {
        & $Loot buoy base
    }
    Check ($buoy -match "buoy \(base\):") "a buoy resolves the integration change as the 'base' landmark"

    # =====================================================================
    # ACT 2 -- RELAY LEG: two identities push concurrently -> the relay DAG
    #          forks -> a pull+apply collapses it; a sealed path relays (R).
    # =====================================================================
    Log ""
    Log "############################################################"
    Log "# ACT 2 -- concurrent convergence via the relay (ADR 0001/0026)"
    Log "############################################################"

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

    # dev: a public file + a restricted file, published to the relay.
    New-Item -ItemType Directory -Force $DevDir | Out-Null
    Run "dev: init + declare secret.txt restricted" $DevDir { & $Loot init --identity dev } | Out-Null
    WriteFile (Join-Path $DevDir ".lootattributes") "secret.txt restricted=dev`n"
    WriteFile (Join-Path $DevDir "notes.txt")  "shared project notes`n"
    WriteFile (Join-Path $DevDir "secret.txt") "$SECRET`nrestricted content only dev holds the key for`n"
    Run "dev: snapshot + finalize + push the initial changes" $DevDir {
        & $Loot remote add origin $RelayUrl
        & $Loot status -m "public notes + restricted secret"
        & $Loot new
        & $Loot push
    } | Out-Null
    $DevPub = PubLine $DevDir

    # agent: clone -> ciphertext only; the restricted path is absent.
    Run "agent: clone the relay as a DISTINCT identity 'agent'" $WorkDir {
        & $Loot clone $RelayUrl $AgentDir --identity agent
    } | Out-Null
    $AgentPub = PubLine $AgentDir
    Check (-not (Test-Path (Join-Path $AgentDir "secret.txt"))) "on clone, agent holds ciphertext but not the restricted path (no key)"

    # --- concurrent edits: dev and agent each add a disjoint public file and
    #     push. dev also re-touches the restricted secret. The relay's DAG forks.
    Run "dev (concurrent): add dev-feature.txt, touch secret.txt, push" $DevDir {
        & $Loot new
        ""
    } | Out-Null
    WriteFile (Join-Path $DevDir "dev-feature.txt") "dev's concurrent feature`n"
    WriteFile (Join-Path $DevDir "secret.txt") "$SECRET`nrestricted content only dev holds the key for`nplus a concurrent secret edit`n"
    Run "dev: snapshot + finalize + push (tip 1)" $DevDir {
        & $Loot status -m "dev feature + secret edit"
        & $Loot new
        & $Loot push
    } | Out-Null

    Run "agent (concurrent, before pulling dev): add agent-feature.txt, push" $AgentDir {
        & $Loot peer add dev "$DevPub"
        ""
    } | Out-Null
    WriteFile (Join-Path $AgentDir "agent-feature.txt") "agent's concurrent feature`n"
    $agentPush = Run "agent: snapshot + finalize + push (tip 2 -> relay DAG now forked)" $AgentDir {
        & $Loot status -m "agent feature"
        & $Loot new
        & $Loot push
    }

    # --- collapse: agent pulls dev's tip and applies -> the fork converges.
    $applyOut = Run "agent: loot pull + apply, read the collapse in porcelain" $AgentDir {
        & $Loot pull $RelayUrl --porcelain
    }
    Check ($applyOut -match "dev-feature\.txt") "agent's apply pulls in dev's concurrent file (fork collapses -- dev's side not dropped)"
    Check ($applyOut -match "(?m)^R\tsecret\.txt") "the restricted path agent can't open surfaces as RelayedUnmerged (R) -- carried, not merged"

    Run "agent: loot surface (materialize what agent may read)" $AgentDir {
        & $Loot surface
    } | Out-Null

    $hasDev   = Test-Path (Join-Path $AgentDir "dev-feature.txt")
    $hasAgent = Test-Path (Join-Path $AgentDir "agent-feature.txt")
    $secretReadable = (Test-Path (Join-Path $AgentDir "secret.txt")) -and `
        (Select-String -Path (Join-Path $AgentDir "secret.txt") -Pattern $SECRET -SimpleMatch -ErrorAction SilentlyContinue)
    Check ($hasDev -and $hasAgent) "after convergence agent's tree carries BOTH concurrent features -- no side dropped"
    Check (-not [bool]$secretReadable) "the restricted content stays sealed to agent (relay + agent hold only ciphertext)"

    Log ""
    Log "================  RESULT  ================"
    Log "Two acts, one thesis: concurrent edits CONVERGE with no side dropped."
    Log "  Act 1 (local docks): two docks integrate into the harbor; a genuine"
    Log "         same-line conflict surfaces (C), resolves, and a buoy landmarks"
    Log "         the integration -- every step driven by porcelain verdicts."
    Log "  Act 2 (relay leg): two DISTINCT identities push concurrently, the"
    Log "         relay DAG forks, and a pull+apply collapses it -- public work"
    Log "         converges while a restricted path relays (R) as ciphertext the"
    Log "         non-keyholder cannot read. The per-path merger/relay split,"
    Log "         under concurrency (ADR 0001)."
    Log ""
    Log "Honesty (ADR 0026): one machine, one OS user. 'agent cannot read the"
    Log "restricted path' is key custody -- the key never reached agent's keyring"
    Log "or the keyless relay. Docks are the same-identity concurrency unit; the"
    Log "relay leg is the cross-identity one."
    Log ""
    if ($script:Failures -eq 0) {
        Log "ALL CHECKS PASSED -- concurrent convergence proven, both acts."
    } else {
        Log ($script:Failures.ToString() + " CHECK(S) FAILED -- see above.")
    }
    Log ("run finished (utc): " + [DateTimeOffset]::UtcNow.ToString("u"))
}
finally {
    Cleanup
}
if ($script:Failures -ne 0) { exit 1 }
