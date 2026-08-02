param(
  [string]$ArchiveName = "xuanjian-openclaw-plugin-20260703.tar.gz"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$OutputDir = Join-Path $RepoRoot "output"
$ArchivePath = Join-Path $OutputDir $ArchiveName
$StageParent = Join-Path $RepoRoot ".tmp\release-archive"
$PackageName = [IO.Path]::GetFileNameWithoutExtension([IO.Path]::GetFileNameWithoutExtension($ArchiveName))
$StageRoot = Join-Path $StageParent $PackageName
$PluginRoot = Join-Path $RepoRoot "openclaw-plugin"

function Assert-UnderRoot([string]$Path, [string]$Root) {
  $fullPath = [IO.Path]::GetFullPath($Path)
  $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
  if (-not $fullPath.StartsWith($fullRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Path escapes expected root: $fullPath"
  }
}

function Get-RelativePath([string]$Root, [string]$Path) {
  $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar
  ) + [IO.Path]::DirectorySeparatorChar
  $fullPath = [IO.Path]::GetFullPath($Path)
  if (-not $fullPath.StartsWith($fullRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Path escapes expected root: $fullPath"
  }
  return $fullPath.Substring($fullRoot.Length)
}

function Copy-RelativeFile([string]$RelativePath) {
  $source = Join-Path $RepoRoot $RelativePath
  if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { return }
  $destination = Join-Path $StageRoot $RelativePath
  New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
  Copy-Item -LiteralPath $source -Destination $destination
}

function Copy-TreeFiles([string]$RelativeDirectory) {
  $sourceRoot = Join-Path $RepoRoot $RelativeDirectory
  Get-ChildItem -LiteralPath $sourceRoot -File -Recurse | ForEach-Object {
    $relativeFile = Get-RelativePath $RepoRoot $_.FullName
    Copy-RelativeFile $relativeFile
  }
}

Assert-UnderRoot $ArchivePath $OutputDir
Assert-UnderRoot $StageRoot (Join-Path $RepoRoot ".tmp")

Push-Location $PluginRoot
try {
  & npm.cmd run build
  if ($LASTEXITCODE -ne 0) { throw "plugin build failed" }
} finally {
  Pop-Location
}

if (Test-Path -LiteralPath $StageParent) {
  Remove-Item -LiteralPath $StageParent -Recurse -Force
}
New-Item -ItemType Directory -Path $StageRoot -Force | Out-Null

foreach ($file in @("README.md", "README_RELEASE.md", "PROJECT_STRUCTURE.md")) {
  Copy-RelativeFile $file
}

$trackedDeliveryFiles = & git -C $RepoRoot ls-files -- cases policies reports scripts third_party tools
if ($LASTEXITCODE -ne 0) { throw "could not enumerate tracked delivery files" }
foreach ($file in $trackedDeliveryFiles) {
  if ($file -eq "scripts/build_release_archive.ps1") { continue }
  Copy-RelativeFile $file
}
Copy-RelativeFile "scripts/build_release_archive.ps1"

foreach ($file in @(
  "openclaw-plugin/config.ts",
  "openclaw-plugin/index.ts",
  "openclaw-plugin/openclaw.plugin.json",
  "openclaw-plugin/package.json",
  "openclaw-plugin/package-lock.json",
  "openclaw-plugin/README.md",
  "openclaw-plugin/setup.ps1",
  "openclaw-plugin/setup.sh"
)) {
  Copy-RelativeFile $file
}

foreach ($directory in @(
  "openclaw-plugin/core",
  "openclaw-plugin/server",
  "openclaw-plugin/public",
  "openclaw-plugin/profiles",
  "openclaw-plugin/manifests",
  "openclaw-plugin/scripts",
  "openclaw-plugin/dist"
)) {
  Copy-TreeFiles $directory
}

$forbidden = Get-ChildItem -LiteralPath $StageRoot -File -Recurse | Where-Object {
  $relative = (Get-RelativePath $StageRoot $_.FullName).Replace("\", "/")
  $relative -match "(^|/)(node_modules|coverage|\.tmp|runtime)(/|$)" -or
    $relative -match "\.(key|pem|p12|sqlite|db|log)$" -or
    $relative -match "records\.jsonl$"
}
if ($forbidden) {
  throw "release staging contains forbidden file: $($forbidden[0].FullName)"
}

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
if (Test-Path -LiteralPath $ArchivePath) {
  Remove-Item -LiteralPath $ArchivePath -Force
}
& tar -czf $ArchivePath -C $StageParent $PackageName
if ($LASTEXITCODE -ne 0) { throw "tar archive creation failed" }

$entries = @(& tar -tzf $ArchivePath)
if ($LASTEXITCODE -ne 0) { throw "tar archive verification failed" }
foreach ($required in @(
  "$PackageName/openclaw-plugin/dist/core/path-security.js",
  "$PackageName/openclaw-plugin/dist/core/security/url.js",
  "$PackageName/openclaw-plugin/dist/core/task-spec/validator.js",
  "$PackageName/openclaw-plugin/dist/core/taint/provenance-graph.js",
  "$PackageName/openclaw-plugin/dist/core/session-registry.js",
  "$PackageName/openclaw-plugin/dist/server/dashboard.js",
  "$PackageName/tools/agentsentry-ebpf-observer.bt"
)) {
  if ($entries -notcontains $required) { throw "release archive missing required entry: $required" }
}
if ($entries | Where-Object { $_ -match "(^|/)(node_modules|coverage|\.tmp|runtime)(/|$)|\.(key|pem|p12|sqlite|db|log)$|records\.jsonl$" }) {
  throw "release archive contains a forbidden entry"
}

$hash = Get-FileHash -Algorithm SHA256 -LiteralPath $ArchivePath
$file = Get-Item -LiteralPath $ArchivePath
[pscustomobject]@{
  Archive = $file.FullName
  Bytes = $file.Length
  Entries = $entries.Count
  SHA256 = $hash.Hash
}
