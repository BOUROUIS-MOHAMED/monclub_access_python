# _pullsdk_read.ps1 - the ONLY file of the C3 export that touches plcommpro.dll.
# Dot-sourced by export_c3_panel_readonly.ps1:   . "$PSScriptRoot\_pullsdk_read.ps1"
#
# It declares exactly six plcommpro.dll entry points, and no other:
#   Connect, Disconnect                       - the connection itself
#   GetDeviceData, GetDeviceDataCount         - read a table / count its rows
#   GetDeviceParam                            - read device parameters
#   PullLastError                             - the DLL's last error code (diagnostics)
# Nothing here can set, delete, clear or control anything on a panel: the functions
# that would (SetDeviceData, DeleteDeviceData, ControlDevice, SetDeviceParam) are not
# declared, and the real-time log reads (GetRTLog, GetRTLogExt) are left out too - they
# consume the panel's live event buffer, so they are not reads of stored data.
# tests/test_c3_panel_export_readonly.py fails the build if any other entry point is
# declared here or if a write name appears in either file outside a comment.
#
# Wire formats are copied from app/sdk/pullsdk.py (PullSDK / PullSDKDevice):
#   connection string  protocol=TCP,ipaddress=..,port=..,timeout=..,passwd=..
#   table read ladder  1 MB -> 2 MB -> 4 MB -> 8 MB, retry only on rc -3/-112/-114/-115
#   param read ladder  64 KB -> 128 KB -> 256 KB -> 512 KB -> 1 MB, same retry codes
#   strings            ANSI code page both ways (pullsdk.py: encode_ansi / mbcs)

$ErrorActionPreference = 'Stop'

function Write-Title { param([string]$t)
    Write-Host ""; Write-Host ("=" * 64) -ForegroundColor DarkCyan
    Write-Host "  $t" -ForegroundColor Cyan
    Write-Host ("=" * 64) -ForegroundColor DarkCyan
}
function Write-Ok   { param([string]$m) Write-Host "[OK]   $m" -ForegroundColor Green }
function Write-Err  { param([string]$m) Write-Host "[FAIL] $m" -ForegroundColor Red }
function Write-Warn { param([string]$m) Write-Host "[!]    $m" -ForegroundColor Yellow }
function Write-Info { param([string]$m) Write-Host "[i]    $m" -ForegroundColor Gray }

# plcommpro.dll is 32-bit: relaunch in the 32-bit PowerShell when started from a 64-bit one.
function Enter-32Bit {
    param([string]$ScriptPath, [object[]]$ScriptArgs)
    if (-not [Environment]::Is64BitProcess) { return }
    $ps32 = Join-Path $env:WINDIR 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path $ps32)) { Write-Warn "32-bit PowerShell not found; continuing 64-bit (the DLL will not load)"; return }
    Write-Host "[i] relaunching in 32-bit PowerShell (plcommpro.dll is x86)..." -ForegroundColor DarkGray
    & $ps32 -NoProfile -ExecutionPolicy Bypass -File $ScriptPath @ScriptArgs
    exit $LASTEXITCODE
}

# Where plcommpro.dll is looked for, first match wins: -DllPath, this folder's sdk\,
# the MB2000 script pack's sdk\ (same DLL build, pullsdk_guide.md section 4.1), then
# the installed MonClub Access (PyInstaller puts the sdk DLLs under _internal\sdk,
# MonClubAccess.spec; build_release.ps1 also copies them next to the exe).
function Resolve-PlcommproDll {
    param([string]$Explicit, [string]$Here)
    $candidates = @()
    if ($Explicit) { $candidates += $Explicit }
    $candidates += (Join-Path $Here 'sdk\plcommpro.dll')
    $candidates += (Join-Path $Here '..\mb2000_scripts\sdk\plcommpro.dll')
    if ($env:LOCALAPPDATA) {
        $candidates += (Join-Path $env:LOCALAPPDATA 'MonClubAccess\current\sdk\plcommpro.dll')
        $candidates += (Join-Path $env:LOCALAPPDATA 'MonClubAccess\current\_internal\sdk\plcommpro.dll')
    }
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) { return (Resolve-Path -LiteralPath $c).Path }
    }
    return $null
}

$script:PullReadSource = @'
using System;
using System.Runtime.InteropServices;
public static class MonClubPullRead {
    [DllImport("plcommpro.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    public static extern IntPtr Connect(string parameters);
    [DllImport("plcommpro.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern int Disconnect(IntPtr handle);
    [DllImport("plcommpro.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    public static extern int GetDeviceData(IntPtr handle, byte[] buffer, int bufferSize, string table, string fieldNames, string filter, string options);
    [DllImport("plcommpro.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    public static extern int GetDeviceDataCount(IntPtr handle, string table, string filter, string options);
    [DllImport("plcommpro.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    public static extern int GetDeviceParam(IntPtr handle, byte[] buffer, int bufferSize, string itemValues);
    [DllImport("plcommpro.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern int PullLastError();
    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr LoadLibrary(string path);
    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetDllDirectory(string path);
}
'@

$script:RetryCodes = @(-3, -112, -114, -115)

function ConvertFrom-AnsiBuffer { param([byte[]]$Buffer)
    $n = [Array]::IndexOf($Buffer, [byte]0)
    if ($n -lt 0) { $n = $Buffer.Length }
    return [Text.Encoding]::Default.GetString($Buffer, 0, $n)
}

# Returns an object with the six calls as methods. The export script reaches the DLL only
# through this object ($sdk.<Method>(...)), which the test replaces with a fake.
function New-PullSdk {
    param([string]$DllPath)
    if (-not $DllPath -or -not (Test-Path -LiteralPath $DllPath)) { throw "plcommpro.dll not found (use -DllPath)" }
    if (-not ('MonClubPullRead' -as [type])) { Add-Type -TypeDefinition $script:PullReadSource }
    $dir = Split-Path -Parent $DllPath
    [void][MonClubPullRead]::SetDllDirectory($dir)
    # Load THIS copy by full path first, so the DllImport name binds to it.
    $h = [MonClubPullRead]::LoadLibrary($DllPath)
    if ($h -eq [IntPtr]::Zero) { throw ("LoadLibrary({0}) failed, Win32 error {1}" -f $DllPath, [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }

    $o = [pscustomobject]@{ dll = $DllPath }
    $o | Add-Member -MemberType ScriptMethod -Name 'Connect' -Value {
        param([string]$connStr) [MonClubPullRead]::Connect($connStr) }
    $o | Add-Member -MemberType ScriptMethod -Name 'Disconnect' -Value {
        param($handle) [void][MonClubPullRead]::Disconnect($handle) }
    $o | Add-Member -MemberType ScriptMethod -Name 'PullLastError' -Value {
        [MonClubPullRead]::PullLastError() }
    $o | Add-Member -MemberType ScriptMethod -Name 'GetDeviceDataCount' -Value {
        param($handle, [string]$table, [string]$filter, [string]$options)
        [MonClubPullRead]::GetDeviceDataCount($handle, $table, $filter, $options) }
    $o | Add-Member -MemberType ScriptMethod -Name 'GetDeviceData' -Value {
        param($handle, [string]$table, [string]$fields, [string]$filter, [string]$options)
        $last = $null
        foreach ($size in @(1048576, 2097152, 4194304, 8388608)) {
            $buf = New-Object byte[] $size
            $rc = [MonClubPullRead]::GetDeviceData($handle, $buf, $size, $table, $fields, $filter, $options)
            if ($rc -ge 0) { return [pscustomobject]@{ rc = $rc; text = (ConvertFrom-AnsiBuffer $buf); size = $size } }
            $last = $rc
            if ($script:RetryCodes -notcontains $rc) { break }
        }
        return [pscustomobject]@{ rc = $last; text = ''; size = 0 } }
    $o | Add-Member -MemberType ScriptMethod -Name 'GetDeviceParam' -Value {
        param($handle, [string]$items)
        $last = $null
        foreach ($size in @(65536, 131072, 262144, 524288, 1048576)) {
            $buf = New-Object byte[] $size
            $rc = [MonClubPullRead]::GetDeviceParam($handle, $buf, $size, $items)
            if ($rc -ge 0) { return [pscustomobject]@{ rc = $rc; text = (ConvertFrom-AnsiBuffer $buf) } }
            $last = $rc
            if ($script:RetryCodes -notcontains $rc) { break }
        }
        return [pscustomobject]@{ rc = $last; text = '' } }
    return $o
}
