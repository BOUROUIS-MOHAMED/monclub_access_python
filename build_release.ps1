param(
  [ValidateSet("access", "tv")]
  [string]$Component = "access",

  [switch]$RecreateVenv,

  [string]$ReleaseId = "",

  [ValidateSet("stable", "beta")]
  [string]$Channel = "stable",

  [switch]$SkipTauriBuild,

  # Package from a working tree that does not match HEAD. OFF by default:
  # 1.4.20 and 1.4.21 were both built from an uncommitted tree, which is how a
  # broken SQL statement shipped to a client before it was ever committed.
  [switch]$AllowDirty,

  # Skip the dirty-tree and SQL-arity gates. For local experiments only: the build is then
  # NOT publishable (release file "publishable": false; publish_github_release.ps1 refuses it).
  [switch]$SkipChecks,

  # Skip the test-suite gate (D30). Explicit only; written into the release file
  # ("testsSkipped": true) and makes the build NOT publishable.
  [switch]$SkipTests,

  # Updater v2 E2E build (design.md section 9, L4): the frozen app trusts the TEST release key
  # (shared/release_keys.py PROD_KEYS is rewritten for the PyInstaller run only, then put back)
  # and the release file is signed with it. Never publishable.
  [switch]$E2ETestKeys,

  # Test-only installer failure injection (installer/update_safety.iss, design 8 step 9).
  # Refused unless -E2ETestKeys: a release build can never carry it.
  [ValidateSet("", "after_copy", "health", "crash")]
  [string]$TestFail = "",

  # Release signing key id (design 5.1). Default: the only key in shared/release_keys.py
  # PROD_KEYS. Its private key is %USERPROFILE%\.monclub\release-signing\<id>.key.
  [string]$SigningKeyId = "",

  # Release notes for the release file (not signed; design 5.2).
  [string]$ReleaseNotesFile = "",

  # Override the installer URL written into the release file (test builds served from
  # http://127.0.0.1). Default: the GitHub release asset URL.
  [string]$InstallerUrl = "",

  [string]$GithubRepo = "BOUROUIS-MOHAMED/monclub_access_python",

  # Authenticode hook (owner decision O2: no certificate yet). When given, this program or
  # script is called with the installer path as its only argument, BEFORE the SHA-256 is
  # computed, and must exit 0.
  [string]$SignTool = "",

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

# The release is built with exactly this Python minor version, taken through the py launcher
# rather than whatever `python` is first on PATH (that is how 3.11 stayed in use unnoticed).
# Python 3.14 runs on Windows 10 and newer only. The owner confirmed on 2026-09-29 that every
# client PC runs Windows 10+. No released Access reports its Windows: the heartbeat's platform
# report (Access PCs page) comes only from builds that contain it (no release tag does yet), so it
# can show a PC's Windows only after that PC has taken such a build. Both installers
# refuse older Windows (MinVersion=10.0); an update applied by zip does not run that check.
$RequiredPythonMinor = "3.14"
$pyTag = if ($meta.Requires32BitPython) { "-$RequiredPythonMinor-32" } else { "-$RequiredPythonMinor" }

if (-not (Test-Path ".\.venv")) {
  Write-Host "Creating venv (.venv) with py $pyTag..." -ForegroundColor Yellow
  py $pyTag -m venv .venv
  if ($LASTEXITCODE -ne 0) {
    throw "Could not create .venv with 'py $pyTag'. Install Python $RequiredPythonMinor$(if ($meta.Requires32BitPython) { ' (32-bit)' }) from python.org."
  }
}

Write-Host "Activating venv..." -ForegroundColor Yellow
. ".\.venv\Scripts\Activate.ps1"

Write-Host "Checking Python version and architecture..." -ForegroundColor Yellow
python -c "import struct, sys; print('Python', sys.version.split()[0], '|', struct.calcsize('P')*8, 'bit')"
if ($LASTEXITCODE -ne 0) {
  throw "Unable to determine Python architecture."
}
python -c "import sys; sys.exit(0 if '%d.%d' % sys.version_info[:2] == '$RequiredPythonMinor' else 1)"
if ($LASTEXITCODE -ne 0) {
  throw "The existing .venv is not Python $RequiredPythonMinor. Rerun with -RecreateVenv."
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

$gitCmd = Get-Command git -ErrorAction SilentlyContinue
$git = @{
  available = $false
  commit = $null
  branch = $null
  dirty = $null
}
if ($gitCmd) {
  $git.available = $true
  # Full SHA: publish_github_release.ps1 tags exactly this commit (gh --target, D31).
  $r1 = Try-Run "git" @("rev-parse","HEAD")
  $r2 = Try-Run "git" @("rev-parse","--abbrev-ref","HEAD")
  $r3 = Try-Run "git" @("status","--porcelain")
  if ($r1.ok) { $git.commit = $r1.out }
  if ($r2.ok) { $git.branch = $r2.out }
  if ($r3.ok) { $git.dirty = (-not [string]::IsNullOrWhiteSpace($r3.out)) }
}

# --------------------------------------------------------------------------
# Release gates. These run BEFORE the Tauri build and PyInstaller so a bad tree never
# gets packaged (they used to run after PyInstaller, despite this comment).
# --------------------------------------------------------------------------
if (-not $SkipChecks) {

  # Gate 1: the working tree must match HEAD.
  # Rationale: the 1.4.20/1.4.21 artifacts were built from a dirty tree, so the
  # shipped binary corresponded to no commit and could not be reproduced or
  # reviewed. $git.dirty was already computed here and then silently discarded.
  if ($git.available -and ($git.dirty -eq $true)) {
    Write-Host "" 
    Write-Host "BUILD BLOCKED - the working tree has uncommitted changes." -ForegroundColor Red
    Write-Host "  The artifact would correspond to no commit and be unreproducible." -ForegroundColor Red
    Write-Host "  Commit (or stash) first, or re-run with -AllowDirty if you accept that." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Uncommitted:" -ForegroundColor Yellow
    git status --short
    if (-not $AllowDirty) {
      throw "Refusing to build from a dirty working tree (use -AllowDirty to override)."
    }
    Write-Host "-AllowDirty given - continuing from a dirty tree." -ForegroundColor Yellow
  }

  # Gate 2: no SQL statement may bind the wrong number of values.
  # This is the exact defect that took a gym offline: sync_devices named 59
  # columns and supplied 57, so every sync raised OperationalError and the whole
  # transaction rolled back. Catching it here costs under a second.
  $arityScript = Join-Path $PSScriptRoot "tools\check_sql_arity.py"
  if (Test-Path $arityScript) {
    Write-Host "Gate: SQL statement arity..." -ForegroundColor Yellow
    python $arityScript app
    if ($LASTEXITCODE -ne 0) {
      throw "SQL arity check FAILED - see the mismatches above. This is the 1.4.21 class of bug; do not ship."
    }
  } else {
    throw "Release gate missing: $arityScript"
  }
}


# Gate 3 (always, -SkipChecks does not skip it): the release must be signable and the
# client must trust a real key (design 5.1). A publishable build refuses an empty
# PROD_KEYS or a "test-" key in it; an E2E build signs with the test key instead.
if ($TestFail -and -not $E2ETestKeys) {
  throw "-TestFail is test-only: it needs -E2ETestKeys (such a build is never publishable)."
}
if ($buildVersion.Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$') {
  throw "Version '$($buildVersion.Version)' is not MAJOR.MINOR.PATCH[-pre] (design 5.2); build metadata (+...) is refused."
}
$releaseSign = Join-Path $ROOT "tools\release_sign.py"
if ($E2ETestKeys) {
  $SigningKeyId = "test-l2-2026-10"
  $testKeyFile = Join-Path $ROOT "tests\fixtures\release_signing\$SigningKeyId.seed"
  $testPublicKey = (python $releaseSign public-key --key-file $testKeyFile).Trim()
  if ($LASTEXITCODE -ne 0 -or $testPublicKey -notmatch '^[0-9a-f]{64}$') { throw "Could not read the test release key." }
  Write-Host "E2E build: trusts and signs with the TEST key $SigningKeyId -- NOT publishable." -ForegroundColor Yellow
} else {
  Write-Host "Gate: trusted release keys..." -ForegroundColor Yellow
  python $releaseSign check-trust
  if ($LASTEXITCODE -ne 0) {
    throw "Release key gate FAILED: the client would trust no key or a test key (see above). Owner: tools\release_sign.py keygen, then shared\release_keys.py."
  }
  if ([string]::IsNullOrWhiteSpace($SigningKeyId)) {
    $prodIds = @(python $releaseSign prod-key-ids | Where-Object { $_.Trim() })
    if ($prodIds.Count -ne 1) { throw "Pass -SigningKeyId: PROD_KEYS has $($prodIds.Count) keys." }
    $SigningKeyId = $prodIds[0].Trim()
  }
  python $releaseSign check-key --key-id $SigningKeyId
  if ($LASTEXITCODE -ne 0) { throw "Signing key $SigningKeyId is missing or does not match PROD_KEYS (see above)." }
}

# Gate 4: the test suite (D30). -SkipTests must be explicit and makes the build NOT publishable.
if ($SkipTests) {
  Write-Host "-SkipTests given: the test suite was NOT run; the release file will say so." -ForegroundColor Yellow
} else {
  Write-Host "Gate: test suite (pytest tests/ -q --ignore=tests/_pydeps)..." -ForegroundColor Yellow
  python -c "import pytest" 2>$null
  if ($LASTEXITCODE -ne 0) { python -m pip install -r .\requirements-dev.txt }
  python -m pytest tests/ -q --ignore=tests/_pydeps
  if ($LASTEXITCODE -ne 0) {
    # Any non-zero, including 5 (no tests collected), refuses the build.
    throw "Test suite FAILED (pytest exit $LASTEXITCODE). Fix it, or pass -SkipTests for a non-publishable build."
  }
}

$publishable = -not ($SkipTests -or $SkipChecks -or $E2ETestKeys -or $TestFail -or ($git.dirty -eq $true))
if ($publishable -and ($git.commit -notmatch '^[0-9a-f]{40}$')) {
  throw "A publishable build needs git: the release file records the built commit (publish tags it, D31)."
}
if (-not $publishable) {
  Write-Host "This build is NOT publishable (SkipTests/SkipChecks/E2ETestKeys/TestFail/dirty tree)." -ForegroundColor Yellow
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

# -E2ETestKeys: PyInstaller reads shared/release_keys.py from this tree, so PROD_KEYS is
# rewritten to the test key for this run only and the original bytes are put back after
# (a crash in between leaves a dirty tree, which the next build's dirty-tree gate refuses).
$releaseKeysPath = Join-Path $ROOT "shared\release_keys.py"
$releaseKeysOriginal = $null
if ($E2ETestKeys) {
  if (-not (Test-Path -LiteralPath $releaseKeysPath)) { throw "E2E build: $releaseKeysPath not found (lane L3 adds it)." }
  $releaseKeysOriginal = [System.IO.File]::ReadAllBytes($releaseKeysPath)
  $text = [System.Text.Encoding]::UTF8.GetString($releaseKeysOriginal)
  $re = [regex]'(?m)^PROD_KEYS: dict\[str, str\] = \{[^\r\n]*\}[ \t]*\r?$'
  if ($re.Matches($text).Count -ne 1) { throw "E2E build: expected exactly one single-line 'PROD_KEYS: dict[str, str] = {...}' in $releaseKeysPath." }
  $text = $re.Replace($text, ('PROD_KEYS: dict[str, str] = {"' + $SigningKeyId + '": "' + $testPublicKey + '"}  # E2E BUILD ONLY'), 1)
  [System.IO.File]::WriteAllText($releaseKeysPath, $text, (New-Object System.Text.UTF8Encoding($false)))
  Write-Host "E2E build: PROD_KEYS temporarily set to the test key." -ForegroundColor Yellow
}
try {
  Write-Host "Running PyInstaller..." -ForegroundColor Yellow
  python -m PyInstaller --noconfirm --clean $specPath
  if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed with exit code $LASTEXITCODE" }
} finally {
  if ($null -ne $releaseKeysOriginal) {
    [System.IO.File]::WriteAllBytes($releaseKeysPath, $releaseKeysOriginal)
    Write-Host "E2E build: shared\release_keys.py restored." -ForegroundColor Yellow
  }
}

if ($meta.RequiresSdkDlls) {
  $internalSdk = Join-Path $distAppDir "_internal\sdk"
  $publicSdk = Join-Path $distAppDir "sdk"
  if (Test-Path $internalSdk) {
    New-Item -ItemType Directory -Force $publicSdk | Out-Null
    Copy-Item (Join-Path $internalSdk "*.dll") $publicSdk -Force -ErrorAction SilentlyContinue
    # ZKFPSensors\ capture-plugin SUBFOLDER (the flat *.dll copy above skips it) - the
    # ZK9500 capture needs these beside the public sdk DLLs.
    $internalSensors = Join-Path $internalSdk "ZKFPSensors"
    if (Test-Path $internalSensors) {
      Copy-Item $internalSensors $publicSdk -Recurse -Force -ErrorAction SilentlyContinue
    }
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
  platform = "windows"
  channel = $Channel
  releaseId = $ReleaseId
  builtAtUtc = (Get-Date).ToUniversalTime().ToString("o")
  # Provenance: previously computed and thrown away, which made it impossible to
  # tell which source a shipped exe came from. Tags are not a substitute here --
  # access_1.4.12 through access_1.4.21 all point at the same commit.
  git = $git
  publishable = $publishable
  testsSkipped = [bool]$SkipTests
  e2eTestKeys = [bool]$E2ETestKeys
}
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($versionPath, ($versionObj | ConvertTo-Json -Depth 5), $utf8NoBom)
Write-Host "Wrote version.json -> $versionPath" -ForegroundColor Green

Write-Host "Staging dist -> release staging (robocopy with retries)..." -ForegroundColor Yellow
Copy-TreeRobocopy $distAppDir $stagingApp
Wait-StagingUnlocked -Dir $stagingApp -TimeoutSeconds 180

# --------------------------------------------------------------------------
# Installer, optional Authenticode hook, SHA-256 and the signed release file (design 5.3).
# --------------------------------------------------------------------------
$installerArgs = @("-ExecutionPolicy", "Bypass", "-File", (Join-Path $ROOT "build_installer.ps1"),
                   "-Component", $Component, "-StageDir", $stagingApp)
if ($TestFail) { $installerArgs += @("-TestFail", $TestFail) }
& powershell @installerArgs
if ($LASTEXITCODE -ne 0) { throw "build_installer.ps1 failed with exit code $LASTEXITCODE" }

$installerName = Format-DesktopInstallerFileName -Component $Component -Version $buildVersion.Version
if ($TestFail) {
  $installerName = "{0}_TESTFAIL_{1}.exe" -f [System.IO.Path]::GetFileNameWithoutExtension($installerName), $TestFail
}
$installerPath = Join-Path $releaseDir $installerName
if (-not (Test-Path -LiteralPath $installerPath -PathType Leaf)) { throw "Installer not found: $installerPath" }

if (-not [string]::IsNullOrWhiteSpace($SignTool)) {
  Write-Host "Authenticode hook: $SignTool `"$installerPath`"" -ForegroundColor Yellow
  & $SignTool $installerPath
  if ($LASTEXITCODE -ne 0) { throw "-SignTool failed with exit code $LASTEXITCODE" }
}

$installerSha256 = Get-Sha256 $installerPath
$signArgs = @($releaseSign, "sign", "--installer", $installerPath, "--target", $Component,
              "--channel", $Channel, "--version", $buildVersion.Version, "--key-id", $SigningKeyId,
              "--github-repo", $GithubRepo, "--codename", [string]$buildVersion.Codename)
if ($git.commit) { $signArgs += @("--build-commit", $git.commit) }
if ($SkipTests) { $signArgs += "--tests-skipped" }
if (-not $publishable) { $signArgs += "--not-publishable" }
if ($E2ETestKeys) { $signArgs += "--allow-test-keys" }
if (-not [string]::IsNullOrWhiteSpace($InstallerUrl)) { $signArgs += @("--installer-url", $InstallerUrl) }
if (-not [string]::IsNullOrWhiteSpace($ReleaseNotesFile)) { $signArgs += @("--notes-file", $ReleaseNotesFile) }
python @signArgs
if ($LASTEXITCODE -ne 0) { throw "Signing the release FAILED (see above)." }

Write-Host "`nRelease OK" -ForegroundColor Green
Write-Host "Installer : $installerPath"
Write-Host "SHA-256   : $installerSha256"
Write-Host ("Release   : {0}" -f (Join-Path $releaseDir ("release-{0}-{1}.json" -f $Component, $buildVersion.Version)))
Write-Host "Publishable: $publishable"
Write-Host "StageDir  : $stagingApp"
Write-Host "Version   : $($buildVersion.Version)"
if (-not [string]::IsNullOrWhiteSpace($buildVersion.Codename)) {
  Write-Host "Codename  : $($buildVersion.Codename)"
}
Write-Host "ReleaseId : $ReleaseId"
Write-Host "`nDone." -ForegroundColor Green
