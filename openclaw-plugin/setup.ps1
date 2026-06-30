param(
  [switch]$Force,
  [switch]$UninstallOnly
)

$ErrorActionPreference = "Stop"
$PluginDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PluginName = "agent-sentry"
$OpenClawConfig = Join-Path $HOME ".openclaw\openclaw.json"

Write-Host "===== AgentSentry OpenClaw Setup ====="
Write-Host "Plugin directory: $PluginDir"

$openclaw = Get-Command openclaw -ErrorAction SilentlyContinue
if (-not $openclaw) {
  throw "openclaw CLI was not found in PATH. Install or open your OpenClaw shell, then run this script again."
}

Write-Host "[1/3] Uninstalling previous $PluginName if present..."
if ($Force) {
  & openclaw plugins uninstall $PluginName --force 2>$null
} else {
  & openclaw plugins uninstall $PluginName 2>$null
}

if ($UninstallOnly) {
  Write-Host "===== Uninstall Complete ====="
  exit 0
}

Write-Host "[2/3] Building plugin..."
Push-Location $PluginDir
try {
  npm run build
} finally {
  Pop-Location
}

Write-Host "[3/4] Installing plugin..."
if ($Force) {
  & openclaw plugins install $PluginDir --dangerously-force-unsafe-install --force
} else {
  & openclaw plugins install $PluginDir --dangerously-force-unsafe-install
}

Write-Host "[4/4] Ensuring hook permissions..."
if (Test-Path $OpenClawConfig) {
  $json = Get-Content -Raw $OpenClawConfig | ConvertFrom-Json -Depth 100
  if (-not $json.plugins) {
    $json | Add-Member -NotePropertyName plugins -NotePropertyValue ([pscustomobject]@{})
  }
  if (-not $json.plugins.entries) {
    $json.plugins | Add-Member -NotePropertyName entries -NotePropertyValue ([pscustomobject]@{})
  }
  if (-not $json.plugins.entries.$PluginName) {
    $json.plugins.entries | Add-Member -NotePropertyName $PluginName -NotePropertyValue ([pscustomobject]@{})
  }
  $entry = $json.plugins.entries.$PluginName
  if (-not ($entry.PSObject.Properties.Name -contains "enabled")) {
    $entry | Add-Member -NotePropertyName enabled -NotePropertyValue $true
  } else {
    $entry.enabled = $true
  }
  if (-not $entry.hooks) {
    $entry | Add-Member -NotePropertyName hooks -NotePropertyValue ([pscustomobject]@{})
  }
  if (-not ($entry.hooks.PSObject.Properties.Name -contains "allowConversationAccess")) {
    $entry.hooks | Add-Member -NotePropertyName allowConversationAccess -NotePropertyValue $true
  } else {
    $entry.hooks.allowConversationAccess = $true
  }
  $json | ConvertTo-Json -Depth 100 | Set-Content -Encoding UTF8 $OpenClawConfig
} else {
  Write-Warning "OpenClaw config not found at $OpenClawConfig; skipping hook permission patch."
}

Write-Host ""
Write-Host "===== Setup Complete ====="
Write-Host "OpenClaw command: /agentsentry"
Write-Host "Dashboard default: http://127.0.0.1:8765"
