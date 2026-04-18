param(
  [ValidateSet("access", "tv")]
  [string]$Component = "access",

  [switch]$RecreateVenv,

  [string]$ReleaseId = "",

  [ValidateSet("stable", "beta")]
  [string]$Channel = "stable",

  [switch]$SkipTauriBuild,

  [switch]$DryRun
)

$ErrorActionPreference = "Stop"

function Get-Sha256($Path) {
  return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Try-Run($Cmd, $Args) {
  try {
    $p = Start-Process -FilePath $Cmd -ArgumentList $Args -NoNewWindow -PassThru -Wait `
      -RedirectStandardOutput "$env:TEMP\mc_out.txt" -RedirectStandardError "$env:TEMP\mc_err.txt"
    $out = ""
    $err = ""
    if (Test-Path "$env:TEMP\mc_out.txt") { $out = Get-Content "$env:TEMP\mc_out.txt" -Raw }
    if (Test-Path "$env:TEMP\mc_err.txt") { $err = Get-Content "$env:TEMP\mc_err.txt" -Raw }
    return @{ ok = ($p.ExitCode -eq 0); code = $p.ExitCode; out = $out.Trim(); err = $err.Trim() }
  } catch {
    return @{ ok = $false; code = -1; out = ""; err = "$($_.Exception.Message)" }
  }
}

function Stop-IfRunning($ProcessName) {
  if ([string]::IsNullOrWhiteSpace($ProcessName)) { return }
  $procs = Get-Process $ProcessName -ErrorAction SilentlyContinue
  if ($procs) {
    Write-Host "Stopping running process: $ProcessName ..." -ForegroundColor Yellow
    $procs | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 800
  }
}

function Copy-TreeRobocopy([string]$SrcDir, [string]$DstDir) {
  if (-not (Test-Path $SrcDir)) { throw "Copy source not found: $SrcDir" }
  New-Item -ItemType Directory -Force $DstDir | Out-Null

  $args = @(
    "`"$SrcDir`"",
    "`"$DstDir`"",
    "/E",
    "/R:40",
    "/W:1",
    "/NFL","/NDL","/NJH","/NJS","/NP"
  )

  $p = Start-Process -FilePath "robocopy" -ArgumentList $args -NoNewWindow -PassThru -Wait
  if ($p.ExitCode -ge 8) {
    throw "robocopy failed with exit code $($p.ExitCode). A file may be locked permanently."
  }
}

function Test-FileReadable([string]$Path) {
  try {
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    $fs.Close()
    return $true
  } catch {
    return $false
  }
}

function Wait-StagingUnlocked([string]$Dir, [int]$TimeoutSeconds = 120) {
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ($true) {
    $locked = @()
    Get-ChildItem -LiteralPath $Dir -Recurse -File | ForEach-Object {
      if (-not (Test-FileReadable $_.FullName)) { $locked += $_.FullName }
    }

    if ($locked.Count -eq 0) { return }

    if ((Get-Date) -gt $deadline) {
      $sample = $locked | Select-Object -First 8
      throw "Staging still has locked files after ${TimeoutSeconds}s. Sample:`n$($sample -join "`n")"
    }

    Write-Host ("Waiting for unlock... locked files: {0}" -f $locked.Count) -ForegroundColor Yellow
    Start-Sleep -Seconds 2
  }
}

function Compress-ZipRobust([string]$FolderPath, [string]$ZipPath) {
  for ($i = 1; $i -le 6; $i++) {
    try {
      Wait-StagingUnlocked -Dir $FolderPath -TimeoutSeconds 120
      if (Test-Path $ZipPath) { Remove-Item -Force $ZipPath -ErrorAction SilentlyContinue }
      Write-Host "Compress-Archive attempt $i/6 ..." -ForegroundColor Yellow
      Compress-Archive -Path $FolderPath -DestinationPath $ZipPath -Force
      return
    } catch {
      if ($i -eq 6) { throw }
      Start-Sleep -Seconds 2
    }
  }
}

function Tar-ZipRobust([string]$WorkingDir, [string]$FolderName, [string]$ZipPath) {
  for ($i = 1; $i -le 6; $i++) {
    try {
      if (Test-Path $ZipPath) { Remove-Item -Force $ZipPath -ErrorAction SilentlyContinue }
      Write-Host "tar.exe attempt $i/6 ..." -ForegroundColor Yellow
      $args = @("-a","-c","-f", $ZipPath, "-C", $WorkingDir, $FolderName)
      $p = Start-Process -FilePath "tar.exe" -ArgumentList $args -NoNewWindow -PassThru -Wait
      if ($p.ExitCode -ne 0) { throw "tar.exe failed with exit code $($p.ExitCode)" }
      return
    } catch {
      if ($i -eq 6) { throw }
      Start-Sleep -Seconds 2
    }
  }
}

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ROOT

. (Join-Path $ROOT "packaging\desktop_components.ps1")
$meta = Get-DesktopComponentMetadata -Component $Component
$buildVersion = Get-DesktopComponentVersionInfo -Component $Component

$artifactName = $meta.ArtifactName
$specPath = Join-Path $ROOT (($meta.SpecPath -replace '^\.[\\/]', ''))
$uiStagingDir = Join-Path $ROOT (($meta.UiStagingDir -replace '^\.[\\/]', ''))
$stagedUiExe = Join-Path $uiStagingDir $meta.UiExeName
$releaseDir = Join-Path $ROOT "release"
$distAppDir = Join-Path $ROOT ("dist\{0}" -f $artifactName)
$distExe = Join-Path $distAppDir $meta.MainExe

Write-Host ("== {0} release build ==" -f $meta.DisplayName) -ForegroundColor Cyan
Write-Host "Root     : $ROOT"
Write-Host "Component: $Component" -ForegroundColor Cyan
Write-Host "Channel  : $Channel" -ForegroundColor Cyan
Write-Host "Version  : $($buildVersion.Version)" -ForegroundColor Cyan
if (-not [string]::IsNullOrWhiteSpace($buildVersion.Codename)) {
  Write-Host "Codename : $($buildVersion.Codename)" -ForegroundColor Cyan
}
Write-Host "Spec     : $specPath" -ForegroundColor Cyan
Write-Host "UI Stage : $stagedUiExe" -ForegroundColor Cyan

if ($DryRun) {
  Write-Host "DryRun enabled. No build commands executed." -ForegroundColor Yellow
  exit 0
}

if ($RecreateVenv -and (Test-Path ".\.venv")) {
  Write-Host "Removing existing .venv..." -ForegroundColor Yellow
  Remove-Item -Recurse -Force ".\.venv"
}

if (-not (Test-Path ".\.venv")) {
  Write-Host "Creating venv (.venv)..." -ForegroundColor Yellow
  python -m venv .venv
}

Write-Host "Activating venv..." -ForegroundColor Yellow
. ".\.venv\Scripts\Activate.ps1"

Write-Host "Checking Python architecture..." -ForegroundColor Yellow
python -c "import struct; print('Python bits:', struct.calcsize('P')*8)"
if ($LASTEXITCODE -ne 0) {
  throw "Unable to determine Python architecture."
}
if ($meta.Requires32BitPython) {
  python -c "import struct, sys; sys.exit(0 if struct.calcsize('P')*8 == 32 else 1)"
  if ($LASTEXITCODE -ne 0) {
    throw "$($meta.DisplayName) packaging must run with 32-bit Python."
  }
}

Write-Host "Upgrading pip/setuptools/wheel..." -ForegroundColor Yellow
python -m pip install --upgrade pip setuptools wheel

if (Test-Path ".\requirements.txt") {
  Write-Host "Installing requirements.txt..." -ForegroundColor Yellow
  python -m pip install -r .\requirements.txt
} else {
  Write-Host "WARNING: requirements.txt not found. Skipping." -ForegroundColor Yellow
}

Write-Host "Installing/Upgrading PyInstaller..." -ForegroundColor Yellow
python -m pip install --upgrade pyinstaller

Write-Host "Sanity import checks..." -ForegroundColor Yellow
python -c "import requests; print('requests OK', requests.__version__)"
python -c "import tkinter; print('tkinter OK')"
python -c "import importlib.util, sys; mods = ['win32com.client', 'comtypes.client']; found = [m for m in mods if importlib.util.find_spec(m) is not None]; print('COM backend modules:', ', '.join(found) if found else 'none'); sys.exit(0 if found else 1)"
if ($LASTEXITCODE -ne 0) {
  throw "Neither pywin32 nor comtypes is available in the packaging environment."
}

if ((-not $SkipTauriBuild) -or (-not (Test-Path $stagedUiExe))) {
  Write-Host "Preparing Tauri shell artifact..." -ForegroundColor Yellow
  & powershell -ExecutionPolicy Bypass -File (Join-Path $ROOT "build_tauri_shell.ps1") -Component $Component -Profile release
  if ($LASTEXITCODE -ne 0) {
    throw "build_tauri_shell.ps1 failed with exit code $LASTEXITCODE"
  }
}

Stop-IfRunning $meta.MainProcessName

Write-Host "Cleaning build/ dist/ ..." -ForegroundColor Yellow
if (Test-Path ".\build") { Remove-Item -Recurse -Force ".\build" }
if (Test-Path ".\dist")  { Remove-Item -Recurse -Force ".\dist" }

if (-not (Test-Path $specPath)) {
  throw "Spec file not found: $specPath"
}

Write-Host "Running PyInstaller..." -ForegroundColor Yellow
python -m PyInstaller --noconfirm --clean $specPath

if ($meta.RequiresSdkDlls) {
  $internalSdk = Join-Path $distAppDir "_internal\sdk"
  $publicSdk = Join-Path $distAppDir "sdk"
  if (Test-Path $internalSdk) {
    New-Item -ItemType Directory -Force $publicSdk | Out-Null
    Copy-Item (Join-Path $internalSdk "*.dll") $publicSdk -Force -ErrorAction SilentlyContinue
  }
}

if (-not (Test-Path $distExe)) {
  throw "Build failed: EXE not found at $distExe"
}

if (-not (Test-Path $stagedUiExe)) {
  throw @"
Component-specific Tauri UI executable not found.
Expected:
  $stagedUiExe

Build it with:
  powershell -ExecutionPolicy Bypass -File .\build_tauri_shell.ps1 -Component $Component
"@
}

$distUiDir = Join-Path $distAppDir "ui"
New-Item -ItemType Directory -Force $distUiDir | Out-Null
$distTauriExe = Join-Path $distUiDir $meta.UiExeName
Copy-Item -LiteralPath $stagedUiExe -Destination $distTauriExe -Force
Write-Host "Bundled Tauri UI: $distTauriExe" -ForegroundColor Green

Write-Host "`nBuild OK" -ForegroundColor Green
Write-Host "EXE: $distExe"

Write-Host "`nPackaging release..." -ForegroundColor Cyan
Stop-IfRunning $meta.MainProcessName

if ([string]::IsNullOrWhiteSpace($ReleaseId)) {
  $ReleaseId = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss'Z'")
}

$gitCmd = Get-Command git -ErrorAction SilentlyContinue
$git = @{
  available = $false
  commit = $null
  branch = $null
  dirty = $null
}
if ($gitCmd) {
  $git.available = $true
  $r1 = Try-Run "git" @("rev-parse","--short","HEAD")
  $r2 = Try-Run "git" @("rev-parse","--abbrev-ref","HEAD")
  $r3 = Try-Run "git" @("status","--porcelain")
  if ($r1.ok) { $git.commit = $r1.out }
  if ($r2.ok) { $git.branch = $r2.out }
  if ($r3.ok) { $git.dirty = (-not [string]::IsNullOrWhiteSpace($r3.out)) }
}

$baseName = "{0}-{1}" -f $artifactName, $ReleaseId
New-Item -ItemType Directory -Force $releaseDir | Out-Null

$stagingRoot = Join-Path $releaseDir "_staging"
$stagingDir = Join-Path $stagingRoot $baseName
$stagingApp = Join-Path $stagingDir $artifactName

if (Test-Path $stagingDir) { Remove-Item -Recurse -Force $stagingDir }
New-Item -ItemType Directory -Force $stagingApp | Out-Null

$versionPath = Join-Path $distAppDir "version.json"
$versionObj = [ordered]@{
  component = $meta.Id
  app = $artifactName
  displayName = $meta.DisplayName
  version = $buildVersion.Version
  codename = $buildVersion.Codename
  mainExe = $meta.MainExe
  uiExe = $meta.UiExeName
  updaterExe = $meta.UpdaterInstalledExe
  platform = "windows"
  channel = $Channel
  releaseId = $ReleaseId
  builtAtUtc = (Get-Date).ToUniversalTime().ToString("o")
}
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($versionPath, ($versionObj | ConvertTo-Json -Depth 5), $utf8NoBom)
Write-Host "Wrote version.json -> $versionPath" -ForegroundColor Green

Write-Host "Staging dist -> release staging (robocopy with retries)..." -ForegroundColor Yellow
Copy-TreeRobocopy $distAppDir $stagingApp
Wait-StagingUnlocked -Dir $stagingApp -TimeoutSeconds 180

Write-Host "`nRelease OK" -ForegroundColor Green
Write-Host "StageDir  : $stagingApp"
Write-Host "Version   : $($buildVersion.Version)"
if (-not [string]::IsNullOrWhiteSpace($buildVersion.Codename)) {
  Write-Host "Codename  : $($buildVersion.Codename)"
}
Write-Host "ReleaseId : $ReleaseId"
Write-Host "`nDone." -ForegroundColor Green
