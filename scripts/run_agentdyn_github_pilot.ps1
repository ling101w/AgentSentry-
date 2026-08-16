param(
  [ValidateSet("agentsentry", "no-defense")]
  [string]$Defense = "agentsentry",
  [int]$MaxTrials = 20
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$cfg = Get-Content -Raw -Encoding UTF8 (Join-Path $root ".env") | ConvertFrom-StringData
$model = ([string]$cfg.model).Trim().Trim('"').Trim("'")
$baseUrl = ([string]$cfg.baseurl).Trim().Trim('"').Trim("'")
$apiKey = ([string]$cfg.key).Trim().Trim('"').Trim("'")
if (-not $model -or -not $baseUrl -or -not $apiKey) { throw ".env must define model, baseurl, and key" }

$env:PYTHONUTF8 = "1"
$env:OPENAI_COMPATIBLE_BASE_URL = $baseUrl
$env:OPENAI_COMPATIBLE_API_KEY = $apiKey
$env:AGENTSENTRY_NATIVE_JUDGE_BASE_URL = $baseUrl
$env:AGENTSENTRY_NATIVE_JUDGE_MODEL = $model
$env:AGENTSENTRY_API_KEY = $apiKey

$args = @(
  "scripts/run_agentdojo_native.py",
  "--selection", "evaluation/native/agentdyn_github_pilot_selection.json",
  "--defense", $Defense,
  "--model", "openai-compatible",
  "--model-id", $model,
  "--openai-compatible-system-role", "system",
  "--provider-timeout-seconds", "90",
  "--provider-max-retries", "2",
  "--bridge-timeout", "120",
  "--output-root", "runtime/agentdyn",
  "--allow-dirty",
  "--max-trials", $MaxTrials
)
if ($Defense -eq "agentsentry") {
  $args += @("--judge-base-url", $baseUrl, "--judge-model", $model, "--judge-timeout-ms", "90000")
}
python @args
