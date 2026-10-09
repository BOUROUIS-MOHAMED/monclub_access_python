<#
.SYNOPSIS
    TEST-ONLY: builds stub payload stage folders and compiles the REAL installer scripts
    (installer\MonClubAccess.iss / MonClubTV.iss) around them, for the updater-v2 installer
    end-to-end runs (design.md section 8 step 11). Nothing here is used by a release.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\updater_e2e\build_stub_payloads.ps1 `
        -Component access -Version 9.0.1 -Mode ok -OutDir D:\tmp\stub
    -> D:\tmp\stub\stage\access-9.0.1-ok\MonClubAccess.exe (+ version.json, stub_mode.txt)
       D:\tmp\stub\monclub_access_9.0.1.exe (installer; -TestFail adds _TESTFAIL_<mode>)
#>
param(
    [ValidateSet('access', 'tv')] [string] $Component = 'access',
    [Parameter(Mandatory = $true)] [string] $Version,
    [ValidateSet('ok', 'noboot', 'crash')] [string] $Mode = 'ok',
    [ValidateSet('', 'after_copy', 'health', 'crash')] [string] $TestFail = '',
    [Parameter(Mandatory = $true)] [string] $OutDir,
    # Extra files copied into the stage (e.g. a real sdk\ folder for the zkemkeeper check).
    [string] $ExtraDir = '',
    [string] $IsccPath = 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe'
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

$exeName = if ($Component -eq 'access') { 'MonClubAccess.exe' } else { 'MonClubTV.exe' }
$iss = if ($Component -eq 'access') { 'MonClubAccess.iss' } else { 'MonClubTV.iss' }
$base = if ($Component -eq 'access') { 'monclub_access' } else { 'monclub_tv' }

$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $csc)) { throw "csc.exe not found: $csc" }

$stage = Join-Path $OutDir ("stage\{0}-{1}-{2}" -f $Component, $Version, $Mode)
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null

& $csc /nologo /target:winexe /platform:x86 ("/out:" + (Join-Path $stage $exeName)) (Join-Path $PSScriptRoot 'stub_app.cs')
if ($LASTEXITCODE -ne 0) { throw "csc failed ($LASTEXITCODE)" }

$versionJson = [ordered]@{ component = $Component; version = $Version; mainExe = $exeName; stub = $true }
[IO.File]::WriteAllText((Join-Path $stage 'version.json'), ($versionJson | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
[IO.File]::WriteAllText((Join-Path $stage 'stub_mode.txt'), $Mode)
# A few nested files so the backup / restore copy a real tree.
New-Item -ItemType Directory -Path (Join-Path $stage '_internal\nested') -Force | Out-Null
[IO.File]::WriteAllText((Join-Path $stage '_internal\nested\payload.txt'), "stub $Component $Version $Mode")
if ($ExtraDir) { Copy-Item -Path (Join-Path $ExtraDir '*') -Destination $stage -Recurse -Force }

$outBase = "{0}_{1}" -f $base, $Version
$defs = @("/DAppVersion=$Version", "/DReleaseId=STUB", "/DStageDir=$stage", "/DOutputBaseFilename=$outBase", "/O$OutDir")
if ($TestFail) { $defs += "/DUPDATER_TEST_FAIL=$TestFail" }
& $IsccPath /Q @defs (Join-Path $repo "installer\$iss")
if ($LASTEXITCODE -ne 0) { throw "ISCC failed ($LASTEXITCODE)" }
$name = if ($TestFail) { "{0}_TESTFAIL_{1}.exe" -f $outBase, $TestFail } else { "$outBase.exe" }
Write-Host ("installer: {0}" -f (Join-Path $OutDir $name))
