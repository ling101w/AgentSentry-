param(
  [int]$MaxRetryRounds = 12,
  [int]$RetryDelaySeconds = 10,
  [string]$ConfigFile = ".env",
  [switch]$AcceptCompleteForeignRuns
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$runtimeRoot = Join-Path $root "runtime/agentdojo-full-rerun"
$statusPath = Join-Path $runtimeRoot "orchestrator-status.json"
$python = "C:\Users\ling1\.workbuddy\binaries\python\envs\default\Scripts\python.exe"
$node = "C:\Users\ling1\.workbuddy\binaries\node\versions\22.22.2\node.exe"

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw "Python not found: $python" }
if (-not (Test-Path -LiteralPath $node -PathType Leaf)) { throw "Node not found: $node" }

$configPath = if ([IO.Path]::IsPathRooted($ConfigFile)) { $ConfigFile } else { Join-Path $root $ConfigFile }
$config = Get-Content -Raw -Encoding UTF8 -LiteralPath $configPath | ConvertFrom-StringData
$model = ([string]$config.model).Trim().Trim('"').Trim("'")
$baseUrl = ([string]$config.baseurl).Trim().Trim('"').Trim("'")
$apiKey = ([string]$config.key).Trim().Trim('"').Trim("'")
if (-not $model -or -not $baseUrl -or -not $apiKey) {
  throw ".env must define model, baseurl, and key"
}

$env:PYTHONUTF8 = "1"
$env:PYTHONUNBUFFERED = "1"
$env:OPENAI_COMPATIBLE_BASE_URL = $baseUrl
$env:OPENAI_COMPATIBLE_API_KEY = $apiKey
$env:AGENTSENTRY_API_KEY = $apiKey

$runs = @(
  [pscustomobject]@{ Defense = "agentsentry"; Suite = "workspace" },
  [pscustomobject]@{ Defense = "agentsentry"; Suite = "banking" },
  [pscustomobject]@{ Defense = "agentsentry"; Suite = "travel" },
  [pscustomobject]@{ Defense = "agentsentry"; Suite = "slack" },
  [pscustomobject]@{ Defense = "no-defense"; Suite = "workspace" },
  [pscustomobject]@{ Defense = "no-defense"; Suite = "banking" },
  [pscustomobject]@{ Defense = "no-defense"; Suite = "travel" },
  [pscustomobject]@{ Defense = "no-defense"; Suite = "slack" }
)

function Get-RunState {
  param([string]$Defense, [string]$Suite)

  $selectionPath = Join-Path $root "evaluation/native/native_${Suite}_full_v1_selection.json"
  $selection = Get-Content -Raw -Encoding UTF8 -LiteralPath $selectionPath | ConvertFrom-Json
  $expected = [int]$selection.expected.trials
  $outputRoot = Join-Path $runtimeRoot "$Defense/$Suite"
  $candidates = @(Get-ChildItem -LiteralPath $outputRoot -Directory -Filter "agentdojo-native-*" -ErrorAction SilentlyContinue |
    Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "checkpoint.private.json") -PathType Leaf } |
    Sort-Object LastWriteTime -Descending)
  $candidateStates = foreach ($candidate in $candidates) {
    $candidateCheckpoint = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $candidate.FullName "checkpoint.private.json") | ConvertFrom-Json
    [pscustomobject]@{
      directory = $candidate
      checkpoint = $candidateCheckpoint
      compatible = (
        $candidateCheckpoint.run_config.provider.base_url -eq $baseUrl -and
        $candidateCheckpoint.run_config.provider.model -eq $model
      )
    }
  }
  $selected = $candidateStates | Where-Object compatible | Select-Object -First 1
  $foreignComplete = $false
  if ($null -eq $selected -and $AcceptCompleteForeignRuns) {
    $selected = $candidateStates | Where-Object {
      [int]$_.checkpoint.counts.trials -eq $expected -and
      (Test-Path -LiteralPath (Join-Path $_.directory.FullName "result.public.json") -PathType Leaf) -and
      (Test-Path -LiteralPath (Join-Path $_.directory.FullName "manifest.json") -PathType Leaf)
    } | Select-Object -First 1
    $foreignComplete = $null -ne $selected
  }
  $runDirectory = if ($selected) { $selected.directory } else { $null }

  $state = [ordered]@{
    defense = $Defense
    suite = $Suite
    expected = $expected
    observed = 0
    errors = $null
    judge_failed = $null
    resume_count = 0
    run_directory = $null
    base_url = $null
    foreign_config = $false
    done = $false
  }
  if ($null -eq $runDirectory) { return [pscustomobject]$state }

  $state.run_directory = $runDirectory.FullName
  $checkpoint = $selected.checkpoint
  $state.observed = [int]$checkpoint.counts.trials
  $state.resume_count = [int]$checkpoint.resume_count
  $state.base_url = [string]$checkpoint.run_config.provider.base_url
  $state.foreign_config = $foreignComplete

  $resultPath = Join-Path $runDirectory.FullName "result.public.json"
  $manifestPath = Join-Path $runDirectory.FullName "manifest.json"
  if ((Test-Path -LiteralPath $resultPath -PathType Leaf) -and (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    $result = Get-Content -Raw -Encoding UTF8 -LiteralPath $resultPath | ConvertFrom-Json
    $manifest = Get-Content -Raw -Encoding UTF8 -LiteralPath $manifestPath | ConvertFrom-Json
    $state.errors = [int]$result.metrics.errors.count
    $state.judge_failed = [int]$manifest.semantic_judge.failed
    $state.done = if ($foreignComplete) {
      $state.observed -eq $expected -and [int]$result.coverage.observed_trials -eq $expected
    } else {
      $state.observed -eq $expected -and
      [int]$result.coverage.observed_trials -eq $expected -and
      $state.errors -eq 0 -and
      ($Defense -eq "no-defense" -or $state.judge_failed -eq 0)
    }
  }
  return [pscustomobject]$state
}

function Write-OrchestratorStatus {
  param([string]$Status, [string]$Phase, [object]$Current)

  $items = foreach ($run in $runs) { Get-RunState -Defense $run.Defense -Suite $run.Suite }
  $payload = [ordered]@{
    status = $Status
    phase = $Phase
    pid = $PID
    config_file = $configPath
    base_url = $baseUrl
    updated_at = [DateTime]::UtcNow.ToString("o")
    current = $Current
    runs = @($items)
  }
  $temporaryPath = "$statusPath.tmp"
  $payload | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -LiteralPath $temporaryPath
  Move-Item -Force -LiteralPath $temporaryPath -Destination $statusPath
}

function Invoke-NativeRun {
  param([string]$Defense, [string]$Suite, [string]$Phase)

  $before = Get-RunState -Defense $Defense -Suite $Suite
  if ($before.done) {
    Write-Output "SKIP complete: $Suite / $Defense"
    return
  }

  $current = [ordered]@{
    defense = $Defense
    suite = $Suite
    phase = $Phase
    run_directory = $before.run_directory
    started_at = [DateTime]::UtcNow.ToString("o")
  }
  Write-OrchestratorStatus -Status "running" -Phase $Phase -Current $current
  Write-Output "START: $Suite / $Defense / $Phase"

  $runnerArgs = @(
    "scripts/run_agentdojo_native.py",
    "--selection", "evaluation/native/native_${Suite}_full_v1_selection.json",
    "--defense", $Defense,
    "--allow-dirty",
    "--model", "openai-compatible",
    "--model-id", $model,
    "--openai-compatible-system-role", "system",
    "--node", $node,
    "--provider-timeout-seconds", "90",
    "--provider-max-retries", "2",
    "--output-root", "runtime/agentdojo-full-rerun/$Defense/$Suite"
  )
  if ($Defense -eq "agentsentry") {
    $runnerArgs += @(
      "--policy-profile", "competition",
      "--judge-base-url", $baseUrl,
      "--judge-model", $model,
      "--judge-timeout-ms", "20000"
    )
  }
  if ($before.run_directory) {
    $runnerArgs += @("--resume", $before.run_directory, "--retry-errors")
    if ($Defense -eq "agentsentry") { $runnerArgs += "--retry-judge-failures" }
  }

  & $python @runnerArgs
  $exitCode = $LASTEXITCODE
  $after = Get-RunState -Defense $Defense -Suite $Suite
  Write-Output "FINISH: $Suite / $Defense / exit=$exitCode observed=$($after.observed)/$($after.expected) errors=$($after.errors) judge_failed=$($after.judge_failed) done=$($after.done)"
  Write-OrchestratorStatus -Status "running" -Phase $Phase -Current $null
}

New-Item -ItemType Directory -Force -Path $runtimeRoot | Out-Null
Push-Location $root
try {
  Write-OrchestratorStatus -Status "running" -Phase "initial" -Current $null
  foreach ($run in $runs) {
    Invoke-NativeRun -Defense $run.Defense -Suite $run.Suite -Phase "initial"
  }

  for ($round = 1; $round -le $MaxRetryRounds; $round++) {
    $pending = @($runs | Where-Object { -not (Get-RunState -Defense $_.Defense -Suite $_.Suite).done })
    if ($pending.Count -eq 0) { break }
    Write-Output "RETRY ROUND ${round}: $($pending.Count) incomplete run(s)"
    foreach ($run in $pending) {
      Invoke-NativeRun -Defense $run.Defense -Suite $run.Suite -Phase "retry-$round"
      Start-Sleep -Seconds $RetryDelaySeconds
    }
  }

  $remaining = @($runs | Where-Object { -not (Get-RunState -Defense $_.Defense -Suite $_.Suite).done })
  if ($remaining.Count -eq 0) {
    Write-OrchestratorStatus -Status "complete" -Phase "finished" -Current $null
    Write-Output "ALL 8 FULL RUNS FINISHED WITHOUT TRIAL ERRORS."
    exit 0
  }

  Write-OrchestratorStatus -Status "incomplete" -Phase "retry-limit-reached" -Current $null
  Write-Error "Retry limit reached with $($remaining.Count) incomplete run(s)."
  exit 1
}
finally {
  Pop-Location
}
