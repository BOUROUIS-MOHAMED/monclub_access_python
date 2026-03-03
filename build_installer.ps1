param(
  [string]$ManifestPath = "",
  [string]$IsccPath = ""   # optional override
)

$ErrorActionPreference = "Stop"

# Always run relative paths from repo root (script directory)
$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ROOT

function Resolve-Iscc {
  param([string]$Override)

  if (-not [string]::IsNullOrWhiteSpace($Override)) {
    $p = $Override.Trim('"')
    if (Test-Path -LiteralPath $p -PathType Leaf) { return $p }
    throw "ISCC.exe not found at IsccPath: $p"
  }

  # Candidates (env var first, then common locations, then PATH)
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
  $m = Get-ChildItem ".\release\MonClubAccess-*.manifest.json" -File |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

  if (-not $m) { throw "No manifest found in .\release\ (MonClubAccess-*.manifest.json)" }
  return $m.FullName
}

# Find newest manifest if not provided
if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
  $ManifestPath = Pick-NewestManifest
}

$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json

$releaseId = $manifest.releaseId
$stageDir  = $manifest.outputs.stagedDir

if ([string]::IsNullOrWhiteSpace($releaseId)) { throw "releaseId missing in manifest" }
if ([string]::IsNullOrWhiteSpace($stageDir))  { throw "outputs.stagedDir missing in manifest" }
if (-not (Test-Path -LiteralPath $stageDir)) { throw "stagedDir not found: $stageDir" }

# IMPORTANT: updater must exist for the installer build
$updaterExe = Join-Path $ROOT "installer\updater\MonClubAccessUpdater.exe"
if (-not (Test-Path -LiteralPath $updaterExe -PathType Leaf)) {
  throw @"
Updater exe not found:
  $updaterExe

Build it first (single-file, self-contained):
  dotnet publish .\updater\MonClubAccessUpdater\MonClubAccessUpdater.csproj -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true

Then copy the published EXE to:
  installer\updater\MonClubAccessUpdater.exe
"@
}

# NEW: reject the tiny apphost exe (which causes '...Updater.dll missing')
$minSizeMb = 10
$sizeMb = (Get-Item -LiteralPath $updaterExe).Length / 1MB
if ($sizeMb -lt $minSizeMb) {
  throw @"
Updater exe looks wrong (too small: {0:N2} MB). This is likely the thin apphost that requires MonClubAccessUpdater.dll next to it.

Fix:
  dotnet publish .\updater\MonClubAccessUpdater\MonClubAccessUpdater.csproj -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true
  Copy the published EXE (publish\MonClubAccessUpdater.exe) to:
    installer\updater\MonClubAccessUpdater.exe
"@ -f $sizeMb
}

$iscc = Resolve-Iscc -Override $IsccPath

Write-Host "Using ISCC: $iscc" -ForegroundColor Cyan
Write-Host "ReleaseId: $releaseId" -ForegroundColor Cyan
Write-Host "StageDir : $stageDir" -ForegroundColor Cyan
Write-Host ("Updater  : {0} ({1:N2} MB)" -f $updaterExe, $sizeMb) -ForegroundColor Cyan

& "$iscc" ".\installer\MonClubAccess.iss" "/DReleaseId=$releaseId" "/DStageDir=$stageDir"

Write-Host "Installer built in .\release (MonClubAccessSetup-$releaseId.exe) ✅" -ForegroundColor Green
