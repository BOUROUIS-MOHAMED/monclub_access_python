param(
  [ValidateSet("access", "tv")]
  [string]$Component = "access",

  [string]$ManifestPath = "",

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

function Pick-NewestManifest {
  $m = Get-ChildItem (Join-Path $ROOT "release\$($meta.ManifestGlob)") -File |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

  if (-not $m) { throw "No manifest found in .\release\ ($($meta.ManifestGlob))" }
  return $m.FullName
}

function Resolve-UpdaterSourcePath {
  $generic = Join-Path $ROOT ("installer\updater\{0}" -f $meta.UpdaterSourceExe)
  if (Test-Path -LiteralPath $generic -PathType Leaf) {
    return $generic
  }

  $legacyAccess = Join-Path $ROOT "installer\updater\MonClubAccessUpdater.exe"
  if (($Component -eq "access") -and (Test-Path -LiteralPath $legacyAccess -PathType Leaf)) {
    Write-Warning "Falling back to legacy updater binary: $legacyAccess"
    return $legacyAccess
  }

  throw @"
Updater exe not found:
  $generic

Build it first:
  dotnet publish .\updater\MonClubAccessUpdater\MonClubAccessUpdater.csproj -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true

Then copy the published EXE to:
  installer\updater\$($meta.UpdaterSourceExe)
"@
}

if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
  $ManifestPath = Pick-NewestManifest
}

if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
  throw "Manifest not found: $ManifestPath"
}

$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
$releaseId = $manifest.releaseId
$stageDir = $manifest.outputs.stagedDir

if ([string]::IsNullOrWhiteSpace($releaseId)) { throw "releaseId missing in manifest" }
if ([string]::IsNullOrWhiteSpace($stageDir)) { throw "outputs.stagedDir missing in manifest" }
if (-not (Test-Path -LiteralPath $stageDir)) { throw "stagedDir not found: $stageDir" }

$installerScript = Join-Path $ROOT (($meta.InstallerScript -replace '^\.[\\/]', ''))
if (-not (Test-Path -LiteralPath $installerScript -PathType Leaf)) {
  throw "Installer script not found: $installerScript"
}

$installerPath = Join-Path $ROOT ("release\{0}-{1}.exe" -f $meta.InstallerBaseName, $releaseId)
if ($DryRun) {
  $expectedUpdater = Join-Path $ROOT ("installer\updater\{0}" -f $meta.UpdaterSourceExe)
  Write-Host ("== {0} installer build ==" -f $meta.DisplayName) -ForegroundColor Cyan
  Write-Host "Manifest : $ManifestPath" -ForegroundColor Cyan
  Write-Host "StageDir : $stageDir" -ForegroundColor Cyan
  Write-Host "ISS      : $installerScript" -ForegroundColor Cyan
  Write-Host "Updater  : $expectedUpdater" -ForegroundColor Cyan
  Write-Host "Output   : $installerPath" -ForegroundColor Cyan
  Write-Host "DryRun enabled. Installer compilation skipped." -ForegroundColor Yellow
  exit 0
}

$updaterExe = Resolve-UpdaterSourcePath
$iscc = Resolve-Iscc -Override $IsccPath

Write-Host ("== {0} installer build ==" -f $meta.DisplayName) -ForegroundColor Cyan
Write-Host "Manifest : $ManifestPath" -ForegroundColor Cyan
Write-Host "StageDir : $stageDir" -ForegroundColor Cyan
Write-Host "ISS      : $installerScript" -ForegroundColor Cyan
Write-Host "Updater  : $updaterExe" -ForegroundColor Cyan
Write-Host "Output   : $installerPath" -ForegroundColor Cyan

& "$iscc" `
  "$installerScript" `
  "/DReleaseId=$releaseId" `
  "/DStageDir=$stageDir" `
  "/DUpdaterSourcePath=$updaterExe" `
  "/DUpdaterDestExe=$($meta.UpdaterInstalledExe)"

if ($LASTEXITCODE -ne 0) {
  throw "ISCC compile failed with exit code $LASTEXITCODE"
}

Write-Host "Installer built OK: $installerPath" -ForegroundColor Green
