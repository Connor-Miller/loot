#requires -Version 5
<#
.SYNOPSIS
  Wave-proof lanes demo (wayfinder map #354) -- evidence that a real
  concurrent wave (>=3 lanes, overlapping files, an interleaved out-of-wave
  land) reviews and lands with ZERO orchestrator surgery: no respawn+copy, no
  hand-merges, no folklore recovery steps.

.DESCRIPTION
  The map's destination: N agents each hold one sealed lane over one shared
  store; they open reviews and land in any order, and the *mechanism* -- not a
  human orchestrator -- absorbs every collision. This script drives that
  mechanism live and hermetically through real `loot` verbs, one act per claim:

    ACT 1 -- PURE-PROJECTION REVIEW (ADR 0039, #362). Three lanes fork from one
      base and each opens a review with `loot ferry --with-wip`. A review is a
      pure projection: it mints the provisional commit from the lane's OWN
      anchor and pushes only its `review/<lane>` ref -- no ingest, no reconcile,
      no main advance.

    ACT 2 -- AN INTERLEAVED OUT-OF-WAVE LAND. Mid-wave, a fourth change lands on
      `main` from outside the three lanes (the primary finalizes + ferries an
      edit to the shared file). Every open review's anchor is now stale.

    ACT 3 -- REVIEWS NEVER GO STALE. Lane t1 refreshes its review after main
      moved under it. The projection is byte-identical (op=up-to-date, the same
      review sha) and the lane's described working change is untouched -- the
      old `REFUSE_REVIEW_STALE_ANCHOR` respawn-and-copy failure family is
      structurally gone: a pure projection cannot go stale.

    ACT 4 -- THE SEAL-WIP GUARD (#418, this branch). One seal path survives the
      keystone: a *bare* `loot ferry` or no-arg `loot adopt` over live DESCRIBED
      WIP would fold it onto `main` PR-less. Lane t2 hits both bare verbs -- each
      refuses with the typed `RepoError::SealWip`. `--seal-wip` seals on purpose
      and prints the follow-up-round recovery recipe (the tool owns the round,
      not folklore -- #356's "Prevent + hint").

    ACT 5 -- CATCH UP OVER THE MOVED TIP, BOUNCE, RESOLVE IN-LANE. Lane t1
      (whose edit collides with the out-of-wave land on the shared file) catches
      up onto the moved `main`. The genuine same-path collision surfaces as a
      conflict -- a bounce -- with nothing lost; `loot resolve` reconciles it in
      the lane, and the resolution inherits the change's subject as
      "<subject> (conflict resolution: <path>)" (#337), folding in rather than
      trailing.

    ACT 6 -- A DISJOINT LANE CATCHES UP CLEAN. Lane t3 (a disjoint file) catches
      up over the same moved `main` with no conflict at all -- the wave does not
      make every lane pay a merge cost, only the ones that actually overlap.

    ACT 7 -- THE loot-first PR LAYER (cited, run live). The harbor land-bounce
      and the #349 "already-projected -> proceed" path live inside
      `loot-first land`, which shells out to `gh`; they cannot run in a hermetic
      script. They are proven instead by `loot-first`'s own tests, which drive
      the land policy end-to-end through the `FakeForge` seam with no network.
      This act runs `cargo test -p loot-first --lib` and asserts it green.

  Honesty: this is one machine, one identity, one shared store. "Concurrent"
  here is the wave's data model -- N sealed lanes over that store, each a
  single-writer of its own tip (ADR 0034) -- exercised by driving the lanes in
  sequence. The interleaved out-of-wave land in ACT 2 is what makes every later
  catch-up a real "behind the moved tip" reconcile, which is the whole point.
  The one-commit carry-at-land (`DagRepo::carry_line`, superseding versions) is
  a `loot-first land` behavior; the no-arg catch-up shown here folds via a merge
  (concurrent.md), which is why ACTs 5/6 need `--seal-wip` to cross the #418
  guard -- in a real wave `loot-first land` is the authorized finalizer and
  crosses it for you.

.EXAMPLE
  powershell -File docs\evidence\scripts\wave-proof-lanes-demo.ps1
#>
param(
    [string]$WorkDir = ""
)

# Continue, not Stop: native tools write to stderr; under Stop the 2>&1 capture
# in Run() raises a terminating NativeCommandError in PowerShell 5.1.
$ErrorActionPreference = "Continue"
$Root    = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$Cargo   = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
$Loot    = Join-Path $Root "target\release\loot.exe"
$RunsDir = Join-Path $Root "docs\evidence\runs"
$LogPath = Join-Path $RunsDir "wave-proof-lanes-demo.txt"
if ($WorkDir -eq "") {
    $WorkDir = Join-Path $env:TEMP ("loot-wave-" + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
}
# `loot lane new` puts a lane at "<repo>-lanes\t<n>" (a sibling of the repo dir).
$LanesRoot = "$WorkDir-lanes"
$Mirror    = Join-Path $WorkDir ".loot\git-mirror\mirror.git"
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
    # Stringify each record before Out-String: native tools write to stderr, and
    # under `2>&1` PowerShell 5.1 wraps each stderr line in an ErrorRecord whose
    # default formatting bolts on "At line:.. char:.." + CategoryInfo noise. `"$_"`
    # renders the record as its plain message, so a refusal reads as the tool
    # actually printed it -- the whole point of an evidence log.
    try { $out = (& $cmd 2>&1 | ForEach-Object { "$_" } | Out-String) } finally { Pop-Location }
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
# The mirror is a bare git repo; read its refs directly to prove projections.
function MirrorSha([string]$ref) {
    return (& git "--git-dir=$Mirror" log -1 --format=%H $ref 2>$null | Out-String).Trim()
}
function Cleanup {
    try { Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue } catch {}
    try { Remove-Item -Recurse -Force $LanesRoot -ErrorAction SilentlyContinue } catch {}
}

Log "=== loot wave-proof lanes demo (wayfinder map #354) ==="
Log ("run started (utc): " + [DateTimeOffset]::UtcNow.ToString("u"))
Log ("work dir:          " + $WorkDir)
Log ("lanes dir:         " + $LanesRoot)

# --- build (cached) ---
Log ""
Log ">>> building loot (release) -- carries the #418 seal-WIP guard"
Push-Location $Root
& $Cargo build --release -p loot-cli | Out-Null
$buildCode = $LASTEXITCODE
Pop-Location
# Gate on the build's exit, not just the binary's existence: a failed rebuild
# with a stale binary still on disk must NOT run and claim it "carries the guard".
if ($buildCode -ne 0 -or -not (Test-Path $Loot)) {
    Log "FATAL: loot release build failed (exit $buildCode)"; exit 1
}

Cleanup
New-Item -ItemType Directory -Force $WorkDir | Out-Null

try {
    # =====================================================================
    # Setup: one identity, one shared store, one base change, a bound mirror.
    # =====================================================================
    Run "init the repo (identity dev) + lay down a base change on the shared file" $WorkDir {
        & $Loot init --identity dev
    } | Out-Null
    WriteFile (Join-Path $WorkDir "shared.txt") "base line`n"
    Run "finalize the base (every lane forks from here)" $WorkDir {
        & $Loot new -m "base"
    } | Out-Null
    Run "bind a bare git mirror + project the base to main (git is a projection of loot)" $WorkDir {
        & $Loot ferry --git-dir .loot/git-mirror/mirror.git
    } | Out-Null
    $baseMain = MirrorSha "refs/heads/main"
    Check ($baseMain -ne "") "the base is projected to mirror main"

    # Spawn three lanes AT THE BASE, before anything moves -- so each is a real
    # single-writer tip behind the wave, and every later catch-up is genuine.
    foreach ($n in 1,2,3) {
        Run "spawn lane t$n (sealed over the shared store, born at the base)" $WorkDir {
            & $Loot lane new --ticket $n
        } | Out-Null
    }
    $T1 = Join-Path $LanesRoot "t1"
    $T2 = Join-Path $LanesRoot "t2"
    $T3 = Join-Path $LanesRoot "t3"
    Check ((Test-Path $T1) -and (Test-Path $T2) -and (Test-Path $T3)) "three lanes exist over one store"

    # Each lane does its work. t1 edits the SHARED file (it will collide with the
    # out-of-wave land); t2 and t3 add disjoint files.
    WriteFile (Join-Path $T1 "shared.txt")   "t1's take`n"
    WriteFile (Join-Path $T1 "featureA.txt") "t1 feature`n"
    Run "t1: edit shared.txt + add featureA, describe" $T1 { & $Loot describe -m "t1: edit shared.txt + add featureA" } | Out-Null
    WriteFile (Join-Path $T2 "featureB.txt") "t2 feature`n"
    Run "t2: add featureB, describe" $T2 { & $Loot describe -m "t2: add featureB" } | Out-Null
    WriteFile (Join-Path $T3 "featureC.txt") "t3 feature`n"
    Run "t3: add featureC (disjoint), describe" $T3 { & $Loot describe -m "t3: add featureC (disjoint)" } | Out-Null

    # =====================================================================
    # ACT 1 -- three reviews open concurrently, each a pure projection.
    # =====================================================================
    Log ""
    Log "############################################################"
    Log "# ACT 1 -- pure-projection reviews: 3 lanes, 3 review refs (ADR 0039)"
    Log "############################################################"

    $r1 = Run "t1: loot ferry --with-wip (open review/t1)" $T1 { & $Loot ferry --with-wip }
    Check ($r1 -match "branch=review/t1" -and $r1 -match "op=opened") "t1's review projects to review/t1 (op=opened)"
    $r2 = Run "t2: loot ferry --with-wip (open review/t2)" $T2 { & $Loot ferry --with-wip }
    Check ($r2 -match "branch=review/t2" -and $r2 -match "op=opened") "t2's review projects to review/t2 (op=opened)"
    $r3 = Run "t3: loot ferry --with-wip (open review/t3)" $T3 { & $Loot ferry --with-wip }
    Check ($r3 -match "branch=review/t3" -and $r3 -match "op=opened") "t3's review projects to review/t3 (op=opened)"

    $t1ReviewSha = MirrorSha "refs/heads/review/t1"
    $mainStillBase = MirrorSha "refs/heads/main"
    Check ($mainStillBase -eq $baseMain) "opening three reviews did NOT advance main (a review is not a land)"

    # =====================================================================
    # ACT 2 -- an interleaved out-of-wave land moves main under the wave.
    # =====================================================================
    Log ""
    Log "############################################################"
    Log "# ACT 2 -- an out-of-wave land moves main mid-wave"
    Log "############################################################"

    WriteFile (Join-Path $WorkDir "shared.txt") "main: sibling's out-of-wave take`n"
    Run "primary: finalize + ferry an edit to shared.txt (a land from outside the 3 lanes)" $WorkDir {
        & $Loot new -m "sibling: out-of-wave edit shared.txt"
        & $Loot ferry
    } | Out-Null
    $mainMoved = MirrorSha "refs/heads/main"
    Check ($mainMoved -ne $baseMain) "the out-of-wave land advanced main off the base -- every open review's anchor is now stale"

    # =====================================================================
    # ACT 3 -- reviews never go stale: refresh t1 against the moved main.
    # =====================================================================
    Log ""
    Log "############################################################"
    Log "# ACT 3 -- a stale-anchor review refreshes clean (no respawn, no seal)"
    Log "############################################################"

    $r1b = Run "t1: loot ferry --with-wip again -- its anchor went stale under the out-of-wave land" $T1 { & $Loot ferry --with-wip }
    Check ($r1b -match "op=up-to-date") "t1's refreshed review is a pure projection from its own anchor (op=up-to-date)"
    $t1ReviewSha2 = MirrorSha "refs/heads/review/t1"
    Check ($t1ReviewSha2 -eq $t1ReviewSha) "the review sha is byte-identical before and after main moved -- the projection did not go stale"
    $st = Run "t1: loot status -- the described working change is untouched (not sealed by the refresh)" $T1 { & $Loot status }
    Check ($st -match "t1: edit shared\.txt \+ add featureA") "t1's described WIP survived the refresh intact -- no REFUSE_REVIEW_STALE_ANCHOR, no respawn"

    # =====================================================================
    # ACT 4 -- the #418 seal-WIP guard on lane t2's live described WIP.
    # =====================================================================
    Log ""
    Log "############################################################"
    Log "# ACT 4 -- the seal-WIP guard (#418): bare sync verbs refuse to seal"
    Log "############################################################"

    $gf = Run "t2: bare loot ferry over live described WIP (expect a typed refusal)" $T2 { & $Loot ferry }
    Check (($gf -match "refusing to finalize your described working change") -and ($gf -match "loot ferry")) "a bare 'loot ferry' refuses to seal t2's described WIP (RepoError::SealWip)"
    $ga = Run "t2: bare no-arg loot adopt over live described WIP (expect a typed refusal)" $T2 { & $Loot adopt }
    Check (($ga -match "refusing to finalize your described working change") -and ($ga -match "loot adopt")) "a bare no-arg 'loot adopt' refuses to seal t2's described WIP too"
    $ov = Run "t2: loot ferry --seal-wip -- seal on purpose, print the recovery round" $T2 { & $Loot ferry --seal-wip }
    Check ($ov -match 'sealed "t2: add featureB" \(--seal-wip\)') "--seal-wip seals the described change deliberately"
    Check ($ov -match "signed line ahead of .main. with no PR" -and $ov -match "loot-first review") "the override prints the follow-up-round recovery recipe -- the tool owns the round, not folklore"

    # =====================================================================
    # ACT 5 -- t1 catches up over the moved tip, bounces, resolves in-lane.
    # =====================================================================
    Log ""
    Log "############################################################"
    Log "# ACT 5 -- catch up over the moved tip: a same-path bounce, resolved in-lane"
    Log "############################################################"

    $cu = Run "t1: loot adopt --seal-wip -- fold onto the moved main (t1 collides on shared.txt)" $T1 { & $Loot adopt --seal-wip }
    Check ($cu -match "caught up to landed main") "t1 folds its line onto the moved main"
    Check ($cu -match "path\(s\) need resolution") "the same-path collision surfaces as a conflict -- a bounce, nothing dropped"
    WriteFile (Join-Path $WorkDir "res.txt") "reconciled: t1's take + the sibling's take`n"
    $rv = Run "t1: loot resolve shared.txt <reconciled> -- reconcile the bounce in the lane" $T1 { & $Loot resolve shared.txt (Join-Path $WorkDir "res.txt") }
    Check ($rv -match "conflict resolution: shared\.txt") "the resolution inherits t1's subject as '<subject> (conflict resolution: shared.txt)' (#337) -- it folds in"
    Check ($rv -match "all conflicts resolved") "after resolve, the lane is clean -- reconciled in-lane, no orchestrator surgery"

    # =====================================================================
    # ACT 6 -- a disjoint lane catches up with no merge cost at all.
    # =====================================================================
    Log ""
    Log "############################################################"
    Log "# ACT 6 -- a disjoint lane catches up clean (overlap is the only cost)"
    Log "############################################################"

    $cc = Run "t3: loot adopt --seal-wip -- catch up over the same moved main (disjoint file)" $T3 { & $Loot adopt --seal-wip }
    Check ($cc -match "caught up to landed main") "t3 folds onto the moved main"
    Check (-not ($cc -match "path\(s\) need resolution")) "t3 catches up with NO conflict -- a disjoint lane pays no merge cost"
    $cf = Run "t3: loot conflicts (expect none)" $T3 { & $Loot conflicts }
    Check ($cf -match "no conflicts") "t3 has no conflicts to resolve"
    Check (Test-Path (Join-Path $T3 "featureC.txt")) "t3's own work is still present after the catch-up"

    # =====================================================================
    # ACT 7 -- the loot-first PR layer, proven by its own end-to-end tests.
    # =====================================================================
    Log ""
    Log "############################################################"
    Log "# ACT 7 -- the loot-first land layer (harbor bounce, #349) via its tests"
    Log "############################################################"
    Log ""
    Log "    The harbor land-bounce refusal and the #349 'already-projected -> proceed'"
    Log "    path live inside 'loot-first land', which shells to 'gh' -- they cannot run"
    Log "    in a hermetic script. loot-first drives its land policy end-to-end through"
    Log "    the FakeForge seam (no network); these are those tests. Key names:"
    Log "      gate_proceeds_on_approved / gate_refuses_* (the approval + dock gate)"
    Log "      already_projected_line_ahead_of_origin_reads_as_landable (#349)"
    Log "      a_land_finishing_after_sibling_reviews_keeps_their_rows (#336 pr-map)"
    # Compile the test binary quietly first so the run log shows the test roster,
    # not a hundred lines of dependency-compile progress.
    Push-Location $Root
    & $Cargo test -p loot-first --lib --no-run 2>&1 | Out-Null
    Pop-Location
    $tests = Run "cargo test -p loot-first --lib" $Root { & $Cargo test -p loot-first --lib }
    Check ($tests -match "test result: ok" -and -not ($tests -match "test result: FAILED")) "the loot-first land layer is green (harbor bounce + #349 + gate proven)"

    Log ""
    Log "================  RESULT  ================"
    Log "A three-lane wave over one shared store: three reviews open as pure"
    Log "projections; an out-of-wave land moves main under all of them; one review"
    Log "refreshes byte-identically (never stale); the seal-WIP guard refuses to"
    Log "seal a described change and hands over the recovery round; the colliding"
    Log "lane bounces and reconciles IN-LANE with the resolution folded into its"
    Log "subject; the disjoint lane catches up with no cost. No respawn, no"
    Log "hand-merge, no folklore -- the mechanism absorbed every collision. The"
    Log "GitHub-facing land layer is proven by loot-first's own end-to-end tests."
    Log ""
    if ($script:Failures -eq 0) {
        Log "ALL CHECKS PASSED -- the wave lands with zero orchestrator surgery."
    } else {
        Log ($script:Failures.ToString() + " CHECK(S) FAILED -- see above.")
    }
    Log ("run finished (utc): " + [DateTimeOffset]::UtcNow.ToString("u"))
}
finally {
    Cleanup
}
if ($script:Failures -ne 0) { exit 1 }
