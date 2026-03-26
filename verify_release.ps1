param(
  [ValidateSet("access", "tv")]
  [string]$Component = "access",

  [string]$StageDir = ""
)

$ErrorActionPreference = "Stop"

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ROOT

. (Join-Path $ROOT "packaging\desktop_components.ps1")
$meta = Get-DesktopComponentMetadata -Component $Component

function Pick-NewestStageDir {
  $stagingRoot = Join-Path $ROOT "release\_staging"
  if (-not (Test-Path -LiteralPath $stagingRoot -PathType Container)) {
    throw "Staging root not found: $stagingRoot"
  }

  $candidates = Get-ChildItem -LiteralPath $stagingRoot -Directory |
    ForEach-Object { Join-Path $_.FullName $meta.ArtifactName } |
    Where-Object { Test-Path -LiteralPath $_ -PathType Container } |
    Sort-Object { (Get-Item -LiteralPath $_).LastWriteTime } -Descending

  $stage = $candidates | Select-Object -First 1
  if (-not $stage) {
    throw "No staged payload found for $Component under $stagingRoot"
  }
  return $stage
}

if ([string]::IsNullOrWhiteSpace($StageDir)) {
  $StageDir = Pick-NewestStageDir
}

if (-not (Test-Path -LiteralPath $StageDir -PathType Container)) {
  throw "StageDir not found: $StageDir"
}

$versionPath = Join-Path $StageDir "version.json"
if (-not (Test-Path -LiteralPath $versionPath -PathType Leaf)) {
  throw "version.json not found: $versionPath"
}

$versionData = Get-Content -LiteralPath $versionPath -Raw | ConvertFrom-Json
$mainExe = [string]($versionData.mainExe)
$version = [string]($versionData.version)
$releaseId = [string]($versionData.releaseId)
$componentId = [string]($versionData.component)
$codename = [string]($versionData.codename)
$mainExePath = Join-Path $StageDir $mainExe

if ([string]::IsNullOrWhiteSpace($componentId)) { throw "component missing in $versionPath" }
if ([string]::IsNullOrWhiteSpace($mainExe)) { throw "mainExe missing in $versionPath" }
if ([string]::IsNullOrWhiteSpace($version)) { throw "version missing in $versionPath" }
if ([string]::IsNullOrWhiteSpace($releaseId)) { throw "releaseId missing in $versionPath" }
if (-not (Test-Path -LiteralPath $mainExePath -PathType Leaf)) {
  throw "Main executable not found in staged payload: $mainExePath"
}

Write-Host "Stage payload OK" -ForegroundColor Green
Write-Host "Component : $componentId"
Write-Host "Version   : $version"
if (-not [string]::IsNullOrWhiteSpace($codename)) {
  Write-Host "Codename  : $codename"
}
Write-Host "ReleaseId : $releaseId"
Write-Host "MainExe   : $mainExePath"
