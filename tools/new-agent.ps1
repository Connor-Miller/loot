#requires -Version 5
<#
.SYNOPSIS
  Mint a loot agent identity (ADR 0026): clone the relay into a persistent
  working dir with a fresh keypair, register it in this repo's peer registry,
  and print the allowlist line for scripts/.setup.env.

.DESCRIPTION
  Agents are clones (ADR 0026): an agent identity IS a persistent clone dir
  plus its keypair. All ceremony happens here, once; an ephemeral agent
  session just starts in the clone dir and inherits the identity. No grants
  at bootstrap - public content arrives with the clone, restricted keys are
  withheld by construction, grants happen on demand.

  After running:
    1. paste the printed pubkey into LOOT_ALLOW_PUBKEYS in scripts/.setup.env
       (comma-separated, keep existing keys)
    2. re-run `npm run setup:loot` from the scripts repo (PowerShell) so the
       relay accepts the agent's pushes

.EXAMPLE
  ./tools/new-agent.ps1 crew
  ./tools/new-agent.ps1 review -Parent c:\work\agents
#>
param(
    [Parameter(Mandatory = $true)][string]$Name,
    [string]$Parent = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) "loot-crew"),
    [string]$Relay = "https://relay.millerbyte.com"
)
$ErrorActionPreference = "Stop"

# Repo root = parent of this script's folder (tools/).
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

$dir = Join-Path $Parent $Name
if (Test-Path $dir) {
    throw "agent dir already exists: $dir - identities are persistent; start a session there instead, or pick a new name."
}
New-Item -ItemType Directory -Force -Path $Parent | Out-Null

# Clone = init (fresh keypair for $Name) + remote add origin + pull + surface.
& $loot clone $Relay $dir --identity $Name

# Pull the new agent's pubkey out of `loot whoami` (run inside the clone).
Push-Location $dir
try {
    $whoami = & $loot whoami
    $match = $whoami | Select-String -Pattern 'ssh-ed25519 \S+ \S+' | Select-Object -First 1
    $pub = if ($match) { $match.Matches.Value } else { $null }
} finally {
    Pop-Location
}
if (-not $pub) { throw "could not parse the agent pubkey; run 'loot whoami' in $dir." }

# Dev-side registration: bind the nickname to the pubkey in THIS repo's peer
# registry (ADR 0014/0015) so grants can be issued to (and accepted from) it.
Push-Location $root
try {
    & $loot peer add $Name "$pub"
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "Agent identity ready: ${dir}  (identity: ${Name})" -ForegroundColor Green
Write-Host "Registered in this repo's peer registry as '${Name}'."
try { $pub | Set-Clipboard; $clip = " (copied to clipboard)" } catch { $clip = "" }
Write-Host ""
Write-Host "Remaining ceremony${clip}:" -ForegroundColor Cyan
Write-Host "  1. Append to LOOT_ALLOW_PUBKEYS in scripts/.setup.env (comma-separated):"
Write-Host "       $pub"
Write-Host "  2. From the scripts repo (PowerShell):  npm run setup:loot"
Write-Host ""
Write-Host "Sessions need no further ceremony - just start the agent in ${dir}." -ForegroundColor DarkGray
