#requires -Version 5
<#
.SYNOPSIS
  Spin up a throwaway loot repo under test-repos/ with a fresh identity, and print
  its push pubkey - the value you paste into LOOT_ALLOW_PUBKEYS for the relay
  allowlist (loot#57, ADR 0014).

.DESCRIPTION
  Builds the loot binary if needed, creates test-repos/<name>/, runs
  `loot init --identity <name>` (which generates the ed25519 keypair), seeds a
  little content (a public README and a restricted .env, to exercise per-content
  visibility), and prints the pubkey (also copied to the clipboard).

  The generated repos are gitignored; only this script is tracked.

.EXAMPLE
  ./test-repos/new-test-repo.ps1 dev
  ./test-repos/new-test-repo.ps1 agent-a -Force
#>
param(
    [string]$Name = "dev",
    [switch]$Force
)
$ErrorActionPreference = "Stop"

# Repo root = parent of this script's folder (test-repos/).
$root = Split-Path -Parent $PSScriptRoot

# Find the loot binary (prefer release), build it if neither exists.
$loot = Join-Path $root "target\release\loot.exe"
if (-not (Test-Path $loot)) { $loot = Join-Path $root "target\debug\loot.exe" }
if (-not (Test-Path $loot)) {
    Write-Host "loot binary not found - building release..." -ForegroundColor Cyan
    Push-Location $root
    try { cargo build --release -p loot-cli } finally { Pop-Location }
    $loot = Join-Path $root "target\release\loot.exe"
}

$repo = Join-Path $PSScriptRoot $Name
if (Test-Path $repo) {
    if (-not $Force) { throw "test repo '$Name' already exists at $repo - re-run with -Force to recreate it." }
    Remove-Item -Recurse -Force $repo
}
New-Item -ItemType Directory -Force -Path $repo | Out-Null

Push-Location $repo
try {
    & $loot init --identity $Name | Out-Null

    # Seed content so the repo is immediately usable and shows off per-content
    # visibility: README is public, .env is restricted to this identity.
    "# $Name test repo`n`nThrowaway loot repo for relay / identity testing." | Set-Content -Encoding utf8 README.md
    "TOKEN=example-secret" | Set-Content -Encoding utf8 .env
    "*.md public`n.env restricted=$Name" | Set-Content -Encoding utf8 .lootattributes
    & $loot status -m "seed" | Out-Null

    # Pull the pubkey out of `loot whoami`.
    $whoami = & $loot whoami
    $match = $whoami | Select-String -Pattern 'ssh-ed25519 \S+ \S+' | Select-Object -First 1
    $pub = if ($match) { $match.Matches.Value } else { $null }
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "Test repo ready: ${repo}  (identity: ${Name})" -ForegroundColor Green
if ($pub) {
    try { $pub | Set-Clipboard; $clip = " (copied to clipboard)" } catch { $clip = "" }
    Write-Host ""
    Write-Host "Push pubkey${clip} - paste into LOOT_ALLOW_PUBKEYS in scripts/.setup.env:" -ForegroundColor Cyan
    Write-Host "  $pub"
} else {
    Write-Host "Could not parse the pubkey; run 'loot whoami' in ${repo}." -ForegroundColor Yellow
}
Write-Host ""
Write-Host "Once the relay is up, from ${repo}:" -ForegroundColor DarkGray
Write-Host "  loot remote add origin https://relay.millerbyte.com"
Write-Host "  loot push"
