# _common.ps1 - shared helpers for the MB2000/zkemkeeper dev-script folder.
# Dot-sourced by every numbered script:   . "$PSScriptRoot\_common.ps1"
#
# WHY THIS FOLDER: fix each script alone on the gym PC (no .exe rebuild),
# then merge the proven calls into MonClub Access (app/sdk/zk_standalone.py).
# Everything runs in 32-BIT PowerShell because zkemkeeper.dll is 32-bit COM -
# Assert-32Bit relaunches the script under SysWOW64 automatically.

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- bundled DLLs
# The pack ships the x86 SDK DLLs in .\sdk\ (zkemkeeper.dll + its plcommpro dep,
# and the ZK9500 libzkfp/libzkfpcsharp set). Put that folder on PATH so the COM
# object and the .NET wrapper's native deps resolve without any system install.
$script:SdkDir = Join-Path $PSScriptRoot 'sdk'
if (Test-Path $script:SdkDir) {
    if (($env:PATH -split ';') -notcontains $script:SdkDir) {
        $env:PATH = "$script:SdkDir;$env:PATH"
    }
}

# ZK9500 wrapper loader (script 4). PATH is not enough: Windows searches
# System32/SysWOW64 BEFORE PATH, so if a ZKFinger SDK is also installed on the
# PC, libzkfp.dll mixes with a different-version algorithm module (fpslib/ZKFPCap)
# and ZKFPM_Init returns -1 (see app/sdk/zkfinger.py:597). Same fix the app uses:
# preload the companions AND libzkfp itself from sdk\ BY FULL PATH so the pinned
# copies win by base-name match - one consistent SDK build, no mixing.
function Load-ZkfpWrapper {
    if (-not (Test-Path $script:SdkDir)) { throw "sdk\ folder not found next to the scripts" }
    if (-not ('Mb.Native' -as [type])) {
        Add-Type -Namespace 'Mb' -Name 'Native' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Unicode)]
public static extern System.IntPtr LoadLibrary(string path);
[System.Runtime.InteropServices.DllImport("kernel32", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Unicode)]
public static extern bool SetDllDirectory(string path);
'@
    }
    [void][Mb.Native]::SetDllDirectory($script:SdkDir)
    # companions first, then libzkfp - all pinned from sdk\ by full path
    foreach ($d in 'ZKFPCap.dll', 'fpslib.dll', 'libzkfp.dll') {
        $p = Join-Path $script:SdkDir $d
        if (Test-Path $p) {
            $h = [Mb.Native]::LoadLibrary($p)
            if ($h -eq [IntPtr]::Zero) {
                Write-Warn ("preload {0} failed (Win32 error {1})" -f $d, [Runtime.InteropServices.Marshal]::GetLastWin32Error())
            } else { Write-Info "pinned $d from sdk\" }
        } else { Write-Warn "$d missing from sdk\ (enroll may hit mixed-version -1)" }
    }
    $wrapper = Join-Path $script:SdkDir 'libzkfpcsharp.dll'
    if (-not (Test-Path $wrapper)) { throw "sdk\libzkfpcsharp.dll not found" }
    Add-Type -Path $wrapper
    return [libzkfpcsharp.zkfp2]
}

# ---------------------------------------------------------------- 32-bit shim
function Assert-32Bit {
    param([string]$ScriptPath, [object[]]$ScriptArgs)
    if (-not [Environment]::Is64BitProcess) { return }
    $ps32 = Join-Path $env:WINDIR 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path $ps32)) { Write-Warn "32-bit PowerShell not found; continuing 64-bit (COM will fail)"; return }
    Write-Host "[i] relaunching in 32-bit PowerShell (zkemkeeper.dll is x86)..." -ForegroundColor DarkGray
    & $ps32 -NoProfile -ExecutionPolicy Bypass -File $ScriptPath @ScriptArgs
    exit $LASTEXITCODE
}

# ---------------------------------------------------------------- pretty output
function Write-Title { param([string]$t)
    Write-Host ""; Write-Host ("=" * 64) -ForegroundColor DarkCyan
    Write-Host "  $t" -ForegroundColor Cyan
    Write-Host ("=" * 64) -ForegroundColor DarkCyan
}
function Write-Ok   { param([string]$m) Write-Host "[OK]   $m" -ForegroundColor Green }
function Write-Err  { param([string]$m) Write-Host "[FAIL] $m" -ForegroundColor Red }
function Write-Warn { param([string]$m) Write-Host "[!]    $m" -ForegroundColor Yellow }
function Write-Info { param([string]$m) Write-Host "[i]    $m" -ForegroundColor Gray }
function Pause-End  { Write-Host ""; Read-Host "Press ENTER to close" | Out-Null }

# ---------------------------------------------------------------- config.json
# Remembers device IP/port/comm key + DLL paths so you never retype them.
$script:ConfigPath = Join-Path $PSScriptRoot 'config.json'

function Get-Config {
    $defaults = [ordered]@{
        deviceIp      = '192.168.1.201'
        devicePort    = 4370
        commKey       = ''            # device COMM > Security key ('' = none)
        machineNumber = 1
        zkfingerDll   = ''            # path to libzkfpcsharp.dll (ZK9500 .NET wrapper)
        zkemkeeperDll = ''            # path to zkemkeeper.dll (for 1_register)
    }
    if (Test-Path $script:ConfigPath) {
        try {
            $j = Get-Content $script:ConfigPath -Raw | ConvertFrom-Json
            foreach ($k in @($defaults.Keys)) {
                if ($null -ne $j.$k -and "$($j.$k)" -ne '') { $defaults[$k] = $j.$k }
            }
        } catch { Write-Warn "config.json unreadable - using defaults ($_)" }
    }
    return $defaults
}

function Save-Config { param($cfg)
    ($cfg | ConvertTo-Json) | Set-Content -Path $script:ConfigPath -Encoding UTF8
    Write-Info "saved $script:ConfigPath"
}

function Ask-Default { param([string]$prompt, [string]$default)
    $v = Read-Host "$prompt [$default]"
    if ([string]::IsNullOrWhiteSpace($v)) { return $default }
    return $v.Trim()
}

# ---------------------------------------------------------------- zkemkeeper
# SIGNATURES USED (fix here once if a firmware disagrees - all scripts inherit):
#   New-Object -ComObject zkemkeeper.CZKEM   (fallback: zkemkeeper.ZKEM)
#   $zk.SetCommPassword([int]$key)           # BEFORE Connect_Net when key set
#   $zk.Connect_Net($ip, $port) -> bool
function New-Zkem {
    foreach ($progId in @('zkemkeeper.CZKEM', 'zkemkeeper.ZKEM')) {
        try { return New-Object -ComObject $progId } catch { }
    }
    Write-Err "zkemkeeper COM object not registered. Run 1_register_zkemkeeper.ps1 first."
    Pause-End; exit 1
}

function Connect-Zkem {
    param($cfg)
    $zk = New-Zkem
    if ("$($cfg.commKey)" -ne '') {
        try { [void]$zk.SetCommPassword([int]$cfg.commKey) }
        catch { Write-Warn "SetCommPassword failed: $_" }
    }
    Write-Info "connecting to $($cfg.deviceIp):$($cfg.devicePort) ..."
    $ok = $zk.Connect_Net($cfg.deviceIp, [int]$cfg.devicePort)
    if (-not $ok) {
        Write-Err "Connect_Net returned FALSE - check IP/port, network, device COMM key."
        Pause-End; exit 1
    }
    Write-Ok "connected"
    return $zk
}

function Disconnect-Zkem { param($zk)
    try { $zk.Disconnect() } catch { }
}

# ---------------------------------------------------------------- local template store
# One JSON per member: templates\<pin>.json
#   { pin, name, card, fingers: [ { fingerId, template (base64/SDK string), size, capturedAt, source } ] }
$script:StoreDir = Join-Path $PSScriptRoot 'templates'

function Get-StoreDir {
    if (-not (Test-Path $script:StoreDir)) { New-Item -ItemType Directory -Path $script:StoreDir | Out-Null }
    return $script:StoreDir
}

function Get-MemberFile { param([string]$pin) Join-Path (Get-StoreDir) ("{0}.json" -f $pin) }

function Load-Member { param([string]$pin)
    $f = Get-MemberFile $pin
    if (Test-Path $f) { return Get-Content $f -Raw | ConvertFrom-Json }
    return $null
}

function Save-Member { param($member)
    $f = Get-MemberFile $member.pin
    ($member | ConvertTo-Json -Depth 6) | Set-Content -Path $f -Encoding UTF8
    Write-Ok "saved $f"
}

function List-Members {
    Get-ChildItem (Get-StoreDir) -Filter '*.json' -ErrorAction SilentlyContinue | ForEach-Object {
        try { Get-Content $_.FullName -Raw | ConvertFrom-Json } catch { $null }
    } | Where-Object { $_ -ne $null }
}

function Show-MemberTable { param($members)
    if (-not $members -or @($members).Count -eq 0) { Write-Warn "local store is empty ($(Get-StoreDir))"; return }
    Write-Host ""
    Write-Host ("{0,-10} {1,-24} {2,-14} {3}" -f 'PIN', 'NAME', 'CARD', 'FINGERS') -ForegroundColor Cyan
    foreach ($m in $members) {
        $fids = (@($m.fingers) | ForEach-Object { $_.fingerId }) -join ','
        Write-Host ("{0,-10} {1,-24} {2,-14} {3}" -f $m.pin, $m.name, $m.card, "[$fids]")
    }
    Write-Host ""
}
