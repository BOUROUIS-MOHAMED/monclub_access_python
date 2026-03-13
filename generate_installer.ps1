# generate_installer.ps1
# One-command installer generation:
# 1) Build Tauri UI release exe
# 2) Build Python release payload (zip + manifest)
# 3) Build Inno Setup installer exe

param(
  [ValidateSet("stable", "beta")]
  [string]$Channel = "stable",

  [string]$ReleaseId = "",

  [switch]$RecreateVenv,

  [switch]$SkipTauriBuild
)

$ErrorActionPreference = "Stop"

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ROOT

function Invoke-Step {
  param(
    [string]$Name,
    [scriptblock]$Action
  )

  Write-Host "`n== $Name ==" -ForegroundColor Cyan
  & $Action
}

Invoke-Step -Name "Environment summary" -Action {
  Write-Host "Root   : $ROOT"
  Write-Host "Channel: $Channel"
  if (-not [string]::IsNullOrWhiteSpace($ReleaseId)) {
    Write-Host "Release: $ReleaseId"
  }
}

if (-not $SkipTauriBuild) {
  Invoke-Step -Name "Build Tauri UI (release)" -Action {
    $tauriDir = Join-Path $ROOT "tauri-ui"
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

      npm run tauri build
      if ($LASTEXITCODE -ne 0) {
        throw "npm run tauri build failed with exit code $LASTEXITCODE"
      }
    }
    finally {
      Pop-Location
    }
  }
}
else {
  Write-Host "`nSkipping Tauri build (SkipTauriBuild enabled)." -ForegroundColor Yellow
}

Invoke-Step -Name "Build Python release payload" -Action {
  $releaseArgs = @(
    "-ExecutionPolicy", "Bypass",
    "-File", (Join-Path $ROOT "build_release.ps1"),
    "-Channel", $Channel
  )

  if ($RecreateVenv) {
    $releaseArgs += "-RecreateVenv"
  }

  if (-not [string]::IsNullOrWhiteSpace($ReleaseId)) {
    $releaseArgs += "-ReleaseId"
    $releaseArgs += $ReleaseId
  }

  & powershell @releaseArgs
  if ($LASTEXITCODE -ne 0) {
    throw "build_release.ps1 failed with exit code $LASTEXITCODE"
  }
}

Invoke-Step -Name "Build installer" -Action {
  & powershell -ExecutionPolicy Bypass -File (Join-Path $ROOT "build_installer.ps1")
  if ($LASTEXITCODE -ne 0) {
    throw "build_installer.ps1 failed with exit code $LASTEXITCODE"
  }
}

Invoke-Step -Name "Locate generated installer" -Action {
  $releaseDir = Join-Path $ROOT "release"
  if (-not (Test-Path $releaseDir)) {
    throw "Release directory not found: $releaseDir"
  }

  $latestSetup = Get-ChildItem -Path $releaseDir -Filter "MonClubAccessSetup-*.exe" -File |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

  if (-not $latestSetup) {
    throw "Installer build finished but no MonClubAccessSetup-*.exe was found in $releaseDir"
  }

  Write-Host "Installer ready: $($latestSetup.FullName)" -ForegroundColor Green
}

Write-Host "`nDone." -ForegroundColor Green
