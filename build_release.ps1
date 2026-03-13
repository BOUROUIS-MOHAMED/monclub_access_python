# build_release.ps1
# Reproducible onedir build for MonClub Access (Windows / 32-bit Python required)
# + release packaging: zip + manifest json + hashes
# Robust packaging: waits for staged files to unlock (Defender/AV), retries zip, tar fallback.

param(
  [switch]$RecreateVenv,
  [string]$ReleaseId = "",
  [ValidateSet("stable","beta")]
  [string]$Channel = "stable"
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

  # robocopy exit codes: < 8 are OK (0..7)
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
  # Wait for AV locks to clear, then retry archive a few times.
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
  # tar.exe is built into Windows. Create zip by folder name from a working dir.
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

# Go to repo root (where this script lives)
$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ROOT

Write-Host "== MonClub Access release build ==" -ForegroundColor Cyan
Write-Host "Root: $ROOT"
Write-Host "Channel: $Channel" -ForegroundColor Cyan

# (Optional) recreate venv
if ($RecreateVenv -and (Test-Path ".\.venv")) {
  Write-Host "Removing existing .venv..." -ForegroundColor Yellow
  Remove-Item -Recurse -Force ".\.venv"
}

# Ensure venv
if (-not (Test-Path ".\.venv")) {
  Write-Host "Creating venv (.venv)..." -ForegroundColor Yellow
  python -m venv .venv
}

# Activate venv
Write-Host "Activating venv..." -ForegroundColor Yellow
. ".\.venv\Scripts\Activate.ps1"

# Enforce 32-bit Python
Write-Host "Checking Python architecture..." -ForegroundColor Yellow
python -c "import struct, sys; bits=struct.calcsize('P')*8; print('Python bits:', bits); sys.exit(0 if bits==32 else 1)"
if ($LASTEXITCODE -ne 0) {
  throw "This build must run with 32-bit Python."
}

# Upgrade pip tooling
Write-Host "Upgrading pip/setuptools/wheel..." -ForegroundColor Yellow
python -m pip install --upgrade pip setuptools wheel

# Install deps
if (Test-Path ".\requirements.txt") {
  Write-Host "Installing requirements.txt..." -ForegroundColor Yellow
  python -m pip install -r .\requirements.txt
} else {
  Write-Host "WARNING: requirements.txt not found. Skipping." -ForegroundColor Yellow
}

# Ensure PyInstaller is installed
Write-Host "Installing/Upgrading PyInstaller..." -ForegroundColor Yellow
python -m pip install --upgrade pyinstaller

# Sanity imports
Write-Host "Sanity import checks..." -ForegroundColor Yellow
python -c "import requests; print('requests OK', requests.__version__)"
python -c "import tkinter; print('tkinter OK')"

# Ensure app not running (tray!)
Stop-IfRunning "MonClubAccess"

# Clean build outputs
Write-Host "Cleaning build/ dist/ ..." -ForegroundColor Yellow
if (Test-Path ".\build") { Remove-Item -Recurse -Force ".\build" }
if (Test-Path ".\dist")  { Remove-Item -Recurse -Force ".\dist" }

# Build using spec
$SPEC = ".\MonClubAccess.spec"
if (-not (Test-Path $SPEC)) {
  throw "Spec file not found: $SPEC"
}

Write-Host "Running PyInstaller..." -ForegroundColor Yellow
python -m PyInstaller --noconfirm --clean $SPEC

# Post-build: ensure SDK DLLs also exist next to the EXE (dist/<app>/sdk)
$DIST_APP_DIR = Join-Path $ROOT "dist\MonClubAccess"
$INTERNAL_SDK = Join-Path $DIST_APP_DIR "_internal\sdk"
$PUBLIC_SDK = Join-Path $DIST_APP_DIR "sdk"

if (Test-Path $INTERNAL_SDK) {
  New-Item -ItemType Directory -Force $PUBLIC_SDK | Out-Null
  Copy-Item (Join-Path $INTERNAL_SDK "*.dll") $PUBLIC_SDK -Force -ErrorAction SilentlyContinue
}

# Verify exe exists
$DIST_EXE = Join-Path $DIST_APP_DIR "MonClubAccess.exe"
if (-not (Test-Path $DIST_EXE)) {
  throw "Build failed: EXE not found at $DIST_EXE"
}

# Bundle Tauri UI executable in release payload (standalone installer runtime)
$TAURI_UI_RELEASE = Join-Path $ROOT "tauri-ui\src-tauri\target\release\monclub-access-ui.exe"
$TAURI_UI_DEBUG = Join-Path $ROOT "tauri-ui\src-tauri\target\debug\monclub-access-ui.exe"
$TAURI_UI_EXE = $null

if (Test-Path $TAURI_UI_RELEASE) {
  $TAURI_UI_EXE = $TAURI_UI_RELEASE
} elseif (Test-Path $TAURI_UI_DEBUG) {
  $TAURI_UI_EXE = $TAURI_UI_DEBUG
}

if ([string]::IsNullOrWhiteSpace($TAURI_UI_EXE)) {
  throw @"
Tauri UI executable not found.
Build it first from tauri-ui:
  npm run tauri build
Expected file:
  tauri-ui\src-tauri\target\release\monclub-access-ui.exe
"@
}

$DIST_UI_DIR = Join-Path $DIST_APP_DIR "ui"
New-Item -ItemType Directory -Force $DIST_UI_DIR | Out-Null
$DIST_TAURI_EXE = Join-Path $DIST_UI_DIR "monclub-access-ui.exe"
Copy-Item -LiteralPath $TAURI_UI_EXE -Destination $DIST_TAURI_EXE -Force
Write-Host "Bundled Tauri UI: $DIST_TAURI_EXE" -ForegroundColor Green


Write-Host "`nBuild OK" -ForegroundColor Green
Write-Host "EXE: $DIST_EXE"

# ----------------------------
# RELEASE PACKAGING
# ----------------------------
Write-Host "`nPackaging release..." -ForegroundColor Cyan
Stop-IfRunning "MonClubAccess"

# ReleaseId default (UTC)
if ([string]::IsNullOrWhiteSpace($ReleaseId)) {
  $ReleaseId = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss'Z'")
}

# Optional git info (kept inside manifest only; DO NOT affect file names)
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

# IMPORTANT: stable asset naming for backend + publish script
$baseName = "MonClubAccess-$ReleaseId"

$RELEASE_DIR = Join-Path $ROOT "release"
New-Item -ItemType Directory -Force $RELEASE_DIR | Out-Null

# Stage directory (avoid dist locks)
$STAGING_ROOT = Join-Path $RELEASE_DIR "_staging"
$STAGING_DIR  = Join-Path $STAGING_ROOT $baseName
$STAGING_APP_PARENT = $STAGING_DIR
$STAGING_APP_NAME = "MonClubAccess"
$STAGING_APP = Join-Path $STAGING_APP_PARENT $STAGING_APP_NAME

if (Test-Path $STAGING_DIR) { Remove-Item -Recurse -Force $STAGING_DIR }
New-Item -ItemType Directory -Force $STAGING_APP | Out-Null

# Write version.json into dist so it ships inside the ZIP and installed folder
$VERSION_PATH = Join-Path $DIST_APP_DIR "version.json"
$versionObj = [ordered]@{
  app = "MonClubAccess"
  platform = "windows"
  channel = $Channel
  releaseId = $ReleaseId
  builtAtUtc = (Get-Date).ToUniversalTime().ToString("o")
}
($versionObj | ConvertTo-Json -Depth 5) | Out-File -LiteralPath $VERSION_PATH -Encoding utf8
Write-Host "Wrote version.json -> $VERSION_PATH" -ForegroundColor Green

Write-Host "Staging dist -> release staging (robocopy with retries)..." -ForegroundColor Yellow
Copy-TreeRobocopy $DIST_APP_DIR $STAGING_APP

# Wait for AV locks to clear on staging
Wait-StagingUnlocked -Dir $STAGING_APP -TimeoutSeconds 180

$ZIP_PATH = Join-Path $RELEASE_DIR "$baseName.zip"
$MANIFEST_PATH = Join-Path $RELEASE_DIR "$baseName.manifest.json"

Write-Host "`nCreating zip from staging..." -ForegroundColor Yellow

# Try Compress-Archive (PowerShell) first; if it still fails, fallback to tar.exe.
try {
  Compress-ZipRobust -FolderPath $STAGING_APP -ZipPath $ZIP_PATH
} catch {
  Write-Host "Compress-Archive keeps failing. Falling back to tar.exe..." -ForegroundColor Yellow
  # tar needs folder name relative to a working directory
  Tar-ZipRobust -WorkingDir $STAGING_APP_PARENT -FolderName $STAGING_APP_NAME -ZipPath $ZIP_PATH
}

# Collect runtime versions
$pyExe = (Get-Command python).Source
$pyVersion = (python -c "import sys; print(sys.version.split()[0])").Trim()
$pyBits = (python -c "import struct; print(struct.calcsize('P')*8)").Trim()
$piVersion = (python -c "import PyInstaller; print(PyInstaller.__version__)").Trim()

# Hash shipped binaries based on STAGING (matches zip content)
$STAGED_EXE = Join-Path $STAGING_APP "MonClubAccess.exe"
$binaryExt = @(".exe",".dll",".pyd")
$files = Get-ChildItem -LiteralPath $STAGING_APP -Recurse -File |
  Where-Object { $binaryExt -contains $_.Extension.ToLowerInvariant() } |
  ForEach-Object {
    $rel = $_.FullName.Substring($STAGING_APP.Length).TrimStart("\","/")
    [ordered]@{
      path = $rel
      size = $_.Length
      sha256 = Get-Sha256 $_.FullName
    }
  }

$zipHash = Get-Sha256 $ZIP_PATH
$exeHash = Get-Sha256 $STAGED_EXE

$manifest = [ordered]@{
  app = "MonClubAccess"
  platform = "windows"
  channel = $Channel
  releaseId = $ReleaseId
  builtAtUtc = (Get-Date).ToUniversalTime().ToString("o")
  python = [ordered]@{
    executable = $pyExe
    version = $pyVersion
    bits = [int]$pyBits
  }
  pyinstaller = [ordered]@{ version = $piVersion }
  git = $git
  outputs = [ordered]@{
    distDir = $DIST_APP_DIR
    stagedDir = $STAGING_APP
    exeSha256 = $exeHash
    zip = $ZIP_PATH
    zipSha256 = $zipHash
  }
  shippedBinaries = $files
}

$manifestJson = ($manifest | ConvertTo-Json -Depth 10)
[System.IO.File]::WriteAllText($MANIFEST_PATH, $manifestJson, [System.Text.Encoding]::UTF8)

Write-Host "`nRelease OK" -ForegroundColor Green
Write-Host "ZIP      : $ZIP_PATH"
Write-Host "MANIFEST : $MANIFEST_PATH"
Write-Host "`nZIP SHA256:" -ForegroundColor Cyan
Write-Host $zipHash

Write-Host "`nDone." -ForegroundColor Green
