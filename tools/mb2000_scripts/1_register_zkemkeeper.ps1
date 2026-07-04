# 1_register_zkemkeeper.ps1 — register the 32-bit zkemkeeper COM DLL on this PC.
# Run FIRST on every new PC. Self-elevates to admin. After success, every other
# script in this folder can create the COM object.
#
# WHERE TO GET THE DLL: ZKTeco "Standalone SDK" (Communication Protocol SDK,
# 32-bit) — copy its whole SDK folder next to this script (e.g. .\sdk\) so
# regsvr32 finds zkemkeeper.dll AND its dependency DLLs (commpro.dll etc. must
# sit in the SAME folder as zkemkeeper.dll or registration/creation fails).
. "$PSScriptRoot\_common.ps1"
Assert-32Bit $PSCommandPath $args
Write-Title "1) Register zkemkeeper.dll (32-bit COM)"

$cfg = Get-Config

# ---- locate the DLL ---------------------------------------------------------
$candidates = @(
    $cfg.zkemkeeperDll,
    (Join-Path $PSScriptRoot 'zkemkeeper.dll'),
    (Join-Path $PSScriptRoot 'sdk\zkemkeeper.dll')
) | Where-Object { $_ -and (Test-Path $_) }

$dll = $candidates | Select-Object -First 1
if (-not $dll) {
    Write-Warn "zkemkeeper.dll not found next to the script."
    $dll = Read-Host "Full path to zkemkeeper.dll"
    if (-not (Test-Path $dll)) { Write-Err "not found: $dll"; Pause-End; exit 1 }
}
$dll = (Resolve-Path $dll).Path
$cfg.zkemkeeperDll = $dll
Save-Config $cfg
Write-Info "DLL: $dll"

# ---- elevate + register (32-bit regsvr32) -----------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Info "elevation required — accept the admin prompt..."
    $ps32 = Join-Path $env:WINDIR 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path $ps32)) { $ps32 = 'powershell.exe' }
    Start-Process $ps32 -Verb RunAs -Wait -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`""
    )
    # the elevated child did the work + verification; re-verify here unelevated:
} else {
    $reg32 = Join-Path $env:WINDIR 'SysWOW64\regsvr32.exe'
    if (-not (Test-Path $reg32)) { $reg32 = 'regsvr32.exe' }   # 32-bit OS
    Write-Info "registering with $reg32 ..."
    $p = Start-Process $reg32 -Wait -PassThru -ArgumentList @('/s', "`"$dll`"")
    if ($p.ExitCode -ne 0) {
        Write-Err "regsvr32 exit code $($p.ExitCode) — check that ALL SDK DLLs sit beside zkemkeeper.dll"
        Pause-End; exit 1
    }
    Write-Ok "regsvr32 succeeded"
}

# ---- verify by creating the COM object --------------------------------------
try {
    $zk = New-Object -ComObject zkemkeeper.CZKEM
    Write-Ok "COM object 'zkemkeeper.CZKEM' created — registration WORKS"
} catch {
    try {
        $zk = New-Object -ComObject zkemkeeper.ZKEM
        Write-Ok "COM object 'zkemkeeper.ZKEM' created — registration WORKS"
    } catch {
        Write-Err "registration ran but the COM object cannot be created: $_"
        Write-Warn "usual cause: missing dependency DLLs — keep the FULL SDK folder together."
        Pause-End; exit 1
    }
}
Pause-End
