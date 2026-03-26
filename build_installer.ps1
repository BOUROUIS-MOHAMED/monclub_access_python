param(
  [ValidateSet("access", "tv")]
  [string]$Component = "access",

  [string]$StageDir = "",

  [string]$IsccPath = "",

  [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ROOT

. (Join-Path $ROOT "packaging\desktop_components.ps1")
$meta = Get-DesktopComponentMetadata -Component $Component

function Resolve-Iscc {
  param([string]$Override)

  if (-not [string]::IsNullOrWhiteSpace($Override)) {
    $p = $Override.Trim('"')
    if (Test-Path -LiteralPath $p -PathType Leaf) { return $p }
    throw "ISCC.exe not found at IsccPath: $p"
  }

  $candidates = @(
    $env:INNO_ISCC,
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe"
  ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -Unique

  $candidates = @($candidates)
  if ($candidates.Count -gt 0) { return $candidates[0] }

  $cmd = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
  if ($cmd -and (Test-Path -LiteralPath $cmd.Source -PathType Leaf)) {
    return $cmd.Source
  }

  throw "ISCC.exe not found. Install Inno Setup, or set INNO_ISCC env var, or pass -IsccPath."
}

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

function Read-StageVersionInfo {
  param([string]$ResolvedStageDir)

  $versionPath = Join-Path $ResolvedStageDir "version.json"
  if (-not (Test-Path -LiteralPath $versionPath -PathType Leaf)) {
    throw "version.json not found in staged payload: $versionPath"
  }

  $data = Get-Content -LiteralPath $versionPath -Raw | ConvertFrom-Json
  $version = [string]($data.version)
  $releaseId = [string]($data.releaseId)
  $codename = [string]($data.codename)

  if ([string]::IsNullOrWhiteSpace($version)) {
    throw "version missing in $versionPath"
  }
  if ([string]::IsNullOrWhiteSpace($releaseId)) {
    throw "releaseId missing in $versionPath"
  }

  return @{
    Version = $version
    ReleaseId = $releaseId
    Codename = $codename
    VersionPath = $versionPath
  }
}

if ([string]::IsNullOrWhiteSpace($StageDir)) {
  $StageDir = Pick-NewestStageDir
}

if (-not (Test-Path -LiteralPath $StageDir -PathType Container)) {
  throw "StageDir not found: $StageDir"
}

$stageInfo = Read-StageVersionInfo -ResolvedStageDir $StageDir
$installerScript = Join-Path $ROOT (($meta.InstallerScript -replace '^\.[\\/]', ''))
if (-not (Test-Path -LiteralPath $installerScript -PathType Leaf)) {
  throw "Installer script not found: $installerScript"
}

$installerFileName = Format-DesktopInstallerFileName -Component $Component -Version $stageInfo.Version
$installerPath = Join-Path $ROOT ("release\{0}" -f $installerFileName)
$outputBaseName = [System.IO.Path]::GetFileNameWithoutExtension($installerFileName)

if ($DryRun) {
  Write-Host ("== {0} installer build ==" -f $meta.DisplayName) -ForegroundColor Cyan
  Write-Host "StageDir   : $StageDir" -ForegroundColor Cyan
  Write-Host "Version    : $($stageInfo.Version)" -ForegroundColor Cyan
  Write-Host "Codename   : $($stageInfo.Codename)" -ForegroundColor Cyan
  Write-Host "ReleaseId  : $($stageInfo.ReleaseId)" -ForegroundColor Cyan
  Write-Host "VersionJson: $($stageInfo.VersionPath)" -ForegroundColor Cyan
  Write-Host "ISS        : $installerScript" -ForegroundColor Cyan
  Write-Host "Output     : $installerPath" -ForegroundColor Cyan
  Write-Host "DryRun enabled. Installer compilation skipped." -ForegroundColor Yellow
  exit 0
}

$iscc = Resolve-Iscc -Override $IsccPath

Write-Host ("== {0} installer build ==" -f $meta.DisplayName) -ForegroundColor Cyan
Write-Host "StageDir   : $StageDir" -ForegroundColor Cyan
Write-Host "Version    : $($stageInfo.Version)" -ForegroundColor Cyan
Write-Host "Codename   : $($stageInfo.Codename)" -ForegroundColor Cyan
Write-Host "ReleaseId  : $($stageInfo.ReleaseId)" -ForegroundColor Cyan
Write-Host "VersionJson: $($stageInfo.VersionPath)" -ForegroundColor Cyan
Write-Host "ISS        : $installerScript" -ForegroundColor Cyan
Write-Host "Output     : $installerPath" -ForegroundColor Cyan

& "$iscc" `
  "$installerScript" `
  "/DAppVersion=$($stageInfo.Version)" `
  "/DReleaseId=$($stageInfo.ReleaseId)" `
  "/DStageDir=$StageDir" `
  "/DOutputBaseFilename=$outputBaseName"

if ($LASTEXITCODE -ne 0) {
  throw "ISCC compile failed with exit code $LASTEXITCODE"
}

Write-Host "Installer built OK: $installerPath" -ForegroundColor Green
