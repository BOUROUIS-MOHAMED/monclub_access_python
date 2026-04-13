param(
  [ValidateSet("access", "tv")]
  [string]$Component = "access",

  [ValidateSet("release", "debug")]
  [string]$Profile = "release",

  [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ROOT

. (Join-Path $ROOT "packaging\desktop_components.ps1")
$meta = Get-DesktopComponentMetadata -Component $Component
$versionInfo = Get-DesktopComponentVersionInfo -Component $Component

function Sync-TauriShellVersionFiles {
  param([string]$TargetComponent)

  $syncScript = Join-Path $ROOT "packaging\sync_tauri_version_files.py"
  if (-not (Test-Path -LiteralPath $syncScript -PathType Leaf)) {
    throw "Tauri version sync script not found: $syncScript"
  }

  & python $syncScript --repo-root $ROOT --component $TargetComponent
  if ($LASTEXITCODE -ne 0) {
    throw "sync_tauri_version_files.py failed for $TargetComponent with exit code $LASTEXITCODE"
  }
}

$tauriDir = Join-Path $ROOT "tauri-ui"
$sourceExe = Join-Path $tauriDir ("src-tauri\target\{0}\monclub-access-ui.exe" -f $Profile)
$stagingDir = Join-Path $ROOT (($meta.UiStagingDir -replace '^\.[\\/]', ''))
$stagedExe = Join-Path $stagingDir $meta.UiExeName
$metadataPath = Join-Path $stagingDir "tauri-shell-metadata.json"
$iconsDir = Join-Path $tauriDir "src-tauri\icons"
$tvIconMap = [ordered]@{
  "tv-32x32.png"     = "32x32.png"
  "tv-128x128.png"   = "128x128.png"
  "tv-128x128@2x.png" = "128x128@2x.png"
  "tv-256x256.png"   = "256x256.png"
  "tv-icon.png"      = "icon.png"
  "tv-icon.ico"      = "icon.ico"
  "tv-tray.png"      = "tray.png"
}
$iconRestoreDir = $null

Write-Host "== Build Tauri shell ==" -ForegroundColor Cyan
Write-Host "Component : $($meta.DisplayName)"
Write-Host "Profile   : $Profile"
Write-Host "Version   : $($versionInfo.Version)"
Write-Host "Source EXE: $sourceExe"
Write-Host "Staged EXE: $stagedExe"

if ($DryRun) {
  Write-Host "DryRun enabled. Target resolution only." -ForegroundColor Yellow
  exit 0
}

if (-not (Test-Path $tauriDir)) {
  throw "tauri-ui folder not found: $tauriDir"
}

Write-Host "Synchronizing Tauri version metadata..." -ForegroundColor Yellow
Sync-TauriShellVersionFiles -TargetComponent $Component

Push-Location $tauriDir
try {
  if ($Component -eq "tv") {
    foreach ($sourceName in $tvIconMap.Keys) {
      $sourcePath = Join-Path $iconsDir $sourceName
      if (-not (Test-Path $sourcePath)) {
        throw "TV icon asset missing: $sourcePath"
      }
    }

    $iconRestoreDir = Join-Path ([System.IO.Path]::GetTempPath()) ("monclub-tauri-icon-backup-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force $iconRestoreDir | Out-Null

    foreach ($targetName in $tvIconMap.Values) {
      $targetPath = Join-Path $iconsDir $targetName
      if (Test-Path $targetPath) {
        Copy-Item -LiteralPath $targetPath -Destination (Join-Path $iconRestoreDir $targetName) -Force
      }
    }

    foreach ($entry in $tvIconMap.GetEnumerator()) {
      Copy-Item -LiteralPath (Join-Path $iconsDir $entry.Key) -Destination (Join-Path $iconsDir $entry.Value) -Force
    }
  }

  if (-not (Test-Path ".\node_modules")) {
    Write-Host "node_modules not found. Running npm install..." -ForegroundColor Yellow
    npm install
    if ($LASTEXITCODE -ne 0) {
      throw "npm install failed with exit code $LASTEXITCODE"
    }
  }

  Write-Host "Building frontend dist..." -ForegroundColor Yellow
  npm run build
  if ($LASTEXITCODE -ne 0) {
    throw "npm run build failed with exit code $LASTEXITCODE"
  }

  Write-Host "Compiling Tauri shell..." -ForegroundColor Yellow
  Push-Location ".\src-tauri"
  try {
    $cargoArgs = @("build")
    if ($Profile -eq "release") {
      $cargoArgs += "--release"
    }
    $cargoArgs += "--features"
    $cargoArgs += "custom-protocol"
    cargo @cargoArgs
    if ($LASTEXITCODE -ne 0) {
      throw "cargo build ($Profile) failed with exit code $LASTEXITCODE"
    }
  }
  finally {
    Pop-Location
  }
}
finally {
  if ($iconRestoreDir -and (Test-Path $iconRestoreDir)) {
    foreach ($targetName in $tvIconMap.Values) {
      $backupPath = Join-Path $iconRestoreDir $targetName
      if (Test-Path $backupPath) {
        Copy-Item -LiteralPath $backupPath -Destination (Join-Path $iconsDir $targetName) -Force
      }
    }
    Remove-Item -LiteralPath $iconRestoreDir -Recurse -Force -ErrorAction SilentlyContinue
  }
  Pop-Location
}

if (-not (Test-Path $sourceExe)) {
  throw "Built Tauri executable not found: $sourceExe"
}

New-Item -ItemType Directory -Force $stagingDir | Out-Null
Copy-Item -LiteralPath $sourceExe -Destination $stagedExe -Force

$metadata = [ordered]@{
  component = $meta.Id
  displayName = $meta.DisplayName
  productArtifact = $meta.ArtifactName
  sourceExe = $sourceExe
  stagedExe = $stagedExe
  builtAtUtc = (Get-Date).ToUniversalTime().ToString("o")
}

($metadata | ConvertTo-Json -Depth 4) | Out-File -LiteralPath $metadataPath -Encoding utf8

Write-Host "Tauri shell staged: $stagedExe" -ForegroundColor Green
