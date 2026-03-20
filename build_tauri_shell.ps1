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

$tauriDir = Join-Path $ROOT "tauri-ui"
$sourceExe = Join-Path $tauriDir ("src-tauri\target\{0}\monclub-access-ui.exe" -f $Profile)
$stagingDir = Join-Path $ROOT (($meta.UiStagingDir -replace '^\.[\\/]', ''))
$stagedExe = Join-Path $stagingDir $meta.UiExeName
$metadataPath = Join-Path $stagingDir "tauri-shell-metadata.json"

Write-Host "== Build Tauri shell ==" -ForegroundColor Cyan
Write-Host "Component : $($meta.DisplayName)"
Write-Host "Profile   : $Profile"
Write-Host "Source EXE: $sourceExe"
Write-Host "Staged EXE: $stagedExe"

if ($DryRun) {
  Write-Host "DryRun enabled. Target resolution only." -ForegroundColor Yellow
  exit 0
}

if (-not (Test-Path $tauriDir)) {
  throw "tauri-ui folder not found: $tauriDir"
}

Push-Location $tauriDir
try {
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
