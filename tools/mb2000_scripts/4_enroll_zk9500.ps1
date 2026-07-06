# 4_enroll_zk9500.ps1 - capture a fingerprint on the ZK9500 USB desk reader
# (3 samples merged into one registered template) and SAVE IT LOCALLY into
# templates\<pin>.json. No device/network needed. Push later with script 5.
#
# REQUIREMENT: the ZKFinger SDK's .NET wrapper 'libzkfpcsharp.dll' (and its
# native libzkfp.dll) - install the ZKFinger SDK or copy its x86 DLLs into a
# folder; the script asks once and remembers the path in config.json.
# NOTE: use the x86 (32-bit) wrapper - this script runs 32-bit like the others.
#
# API USED (libzkfpcsharp.zkfp2, fix alone if wrapper version differs):
#   Init() -> 0 ok | GetDeviceCount() | OpenDevice(0) -> IntPtr
#   AcquireFingerprint(h, imgBuf, tmpBuf, ref size) -> 0 on capture
#   DBInit() -> IntPtr | DBMerge(db, t1,t2,t3, regTmp, ref regSize) -> 0
#   BlobToBase64(buf, size) | CloseDevice(h) | Terminate()
. "$PSScriptRoot\_common.ps1"
Assert-32Bit $PSCommandPath $args
Write-Title "4) Enroll fingerprint from ZK9500 -> local store"

$cfg = Get-Config

# ---- load the .NET wrapper ---------------------------------------------------
# PREFERRED: the bundled sdk\ set, loaded via Load-ZkfpWrapper which preloads
# libzkfp + its companions (fpslib/ZKFPCap) BY FULL PATH from sdk\ so a ZKFinger
# SDK also installed on the PC cannot mix versions into it (the rc=-1 cause).
$zkfp = $null
if (Test-Path (Join-Path $PSScriptRoot 'sdk\libzkfpcsharp.dll')) {
    try { $zkfp = Load-ZkfpWrapper }
    catch { Write-Err "loading bundled ZKFinger DLLs failed: $_"; Pause-End; exit 1 }
} else {
    # FALLBACK: no bundle - use an installed ZKFinger SDK wrapper.
    $dllPath = $cfg.zkfingerDll
    if (-not ($dllPath -and (Test-Path $dllPath))) {
        $guess = @(
            (Join-Path $PSScriptRoot 'libzkfpcsharp.dll'),
            'C:\Program Files (x86)\ZKTeco\ZKFinger SDK\lib\libzkfpcsharp.dll',
            'C:\Windows\SysWOW64\libzkfpcsharp.dll'
        ) | Where-Object { Test-Path $_ } | Select-Object -First 1
        $dllPath = if ($guess) { $guess } else { Read-Host "Full path to libzkfpcsharp.dll (x86)" }
    }
    if (-not (Test-Path $dllPath)) { Write-Err "not found: $dllPath"; Pause-End; exit 1 }
    $cfg.zkfingerDll = (Resolve-Path $dllPath).Path
    Save-Config $cfg
    try { Add-Type -Path $cfg.zkfingerDll } catch { Write-Err "Add-Type failed: $_"; Pause-End; exit 1 }
    $zkfp = [libzkfpcsharp.zkfp2]
}

# ---- member identity ----------------------------------------------------------
$pin  = Read-Host "Member PIN (numeric, max 9 digits)"
if ($pin -notmatch '^\d{1,9}$') { Write-Err "PIN must be 1-9 digits"; Pause-End; exit 1 }
$existing = Load-Member $pin
$name = Ask-Default "Name"        $(if ($existing) { $existing.name } else { '' })
$card = Ask-Default "Card number" $(if ($existing) { $existing.card } else { '' })
$fid  = [int](Ask-Default "Finger ID (0-9)" '6')
if ($fid -lt 0 -or $fid -gt 9) { Write-Err "fingerId 0-9"; Pause-End; exit 1 }

# ---- open reader ---------------------------------------------------------------
# ZKFinger error codes (pyzkfp/standard SDK): -1 = algorithm library init failed,
# -2 = capture library init failed, -3 = NO device connected. So a -1 here is NOT
# "no reader" - the algorithm library could not initialize. On a laptop with a
# built-in fingerprint sensor (Windows Hello), the Windows Biometric Framework
# claims the ZK9500 and the SDK cannot get exclusive access -> algorithm init -1.
$initRc = $zkfp::Init()
if ($initRc -ne 0) {
    $meaning = switch ($initRc) {
        -1 { "algorithm library failed to init (NOT a missing reader)" }
        -2 { "capture library failed to init (companion DLL problem)" }
        -3 { "no device connected" }
        default { "generic failure" }
    }
    Write-Err "ZKFPM_Init() returned $initRc - $meaning."
    Write-Host ""

    # Is a reader enumerated at all?
    Write-Info "1) Does Windows see a fingerprint reader?"
    $seen = $null
    try {
        $seen = Get-PnpDevice -PresentOnly -ErrorAction Stop | Where-Object {
            ($_.FriendlyName -match 'finger|ZKTeco|ZK9500|SLK20|biometric') -or ($_.Class -eq 'Biometric')
        }
    } catch {
        try { $seen = Get-WmiObject Win32_PnPEntity -ErrorAction Stop | Where-Object {
            ($_.Name -match 'finger|ZKTeco|ZK9500|SLK20|biometric') -or ($_.PNPClass -eq 'Biometric') } } catch { }
    }
    $hasZk = $false; $hasOther = $false
    foreach ($d in @($seen)) {
        $nm = if ($d.FriendlyName) { $d.FriendlyName } else { $d.Name }
        Write-Info ("   present: '$nm'  status=$(if ($d.Status){$d.Status}else{'?'})")
        if ($nm -match 'ZK|SLK') { $hasZk = $true } else { $hasOther = $true }
    }
    if (-not $seen) {
        Write-Err "   NO reader enumerated -> plug the ZK9500 into THIS PC, check Device Manager."
        Write-Host ""; Pause-End; exit 1
    }

    # Reader present but algorithm init failed -> the Windows biometric stack is the usual cause.
    Write-Host ""
    Write-Info "2) Windows Biometric Service (it claims the reader for Windows Hello):"
    $wbio = $null
    try { $wbio = Get-Service -Name 'WbioSrvc' -ErrorAction Stop } catch {}
    if ($wbio) { Write-Info ("   WbioSrvc status = $($wbio.Status)  startType = $($wbio.StartType)") }
    else { Write-Info "   WbioSrvc not found." }

    Write-Host ""
    if ($hasOther -and $initRc -eq -1) {
        Write-Warn "LIKELY CAUSE: this PC has ANOTHER fingerprint sensor (Windows Hello), so the"
        Write-Warn "Windows Biometric Framework is holding the ZK9500 and the ZKTeco SDK cannot"
        Write-Warn "get exclusive access. This is a known ZKTeco-on-laptops issue."
    }
    Write-Warn "TRY THIS (in an ADMIN PowerShell), then re-run this script:"
    Write-Warn "  a) Stop + disable the Windows Biometric Service:"
    Write-Warn "       Stop-Service WbioSrvc -Force"
    Write-Warn "       Set-Service WbioSrvc -StartupType Disabled"
    Write-Warn "     (re-enable later with: Set-Service WbioSrvc -StartupType Manual)"
    Write-Warn "  b) Windows 11 only: Settings > Accounts > Sign-in options ->"
    Write-Warn "     turn OFF 'Sign-in Security (Enhanced)'/ESS, reboot, retry."
    Write-Warn "  c) Close MonClub Access / any app that may hold the reader."
    Write-Warn "  d) Cross-check with the ZKFinger SDK's own Demo.exe - if it ALSO fails"
    Write-Warn "     with WbioSrvc running and WORKS once it's disabled, that confirms it."
    Write-Host ""
    Pause-End; exit 1
}
try {
    $devCount = $zkfp::GetDeviceCount()
    Write-Info "readers detected: $devCount"
    if ($devCount -lt 1) { Write-Err "Init OK but no ZK9500 detected - plug it in / try another port"; Pause-End; exit 1 }
    $h = $zkfp::OpenDevice(0)
    if ($h -eq [IntPtr]::Zero) { Write-Err "OpenDevice failed"; Pause-End; exit 1 }
    Write-Ok "reader open"

    $imgBuf = New-Object byte[] (300 * 400 * 4)   # generous image buffer
    $samples = @()
    $db = $zkfp::DBInit()

    try {
        for ($i = 1; $i -le 3; $i++) {
            Write-Host ""
            Write-Host ">>> Sample $i / 3 - PLACE the finger on the reader..." -ForegroundColor Yellow
            $tmpBuf = New-Object byte[] 2048
            $deadline = (Get-Date).AddSeconds(30)
            $got = $false
            while ((Get-Date) -lt $deadline) {
                $size = $tmpBuf.Length
                $rc = $zkfp::AcquireFingerprint($h, $imgBuf, $tmpBuf, [ref]$size)
                if ($rc -eq 0) {
                    $samples += ,@($tmpBuf[0..($size - 1)])
                    Write-Ok "sample $i captured ($size bytes) - LIFT the finger"
                    Start-Sleep -Milliseconds 900
                    $got = $true; break
                }
                Start-Sleep -Milliseconds 120
            }
            if (-not $got) { Write-Err "timeout waiting for finger (30s)"; Pause-End; exit 1 }
        }

        Write-Info "merging 3 samples into one registered template..."
        $regTmp = New-Object byte[] 2048
        $regSize = $regTmp.Length
        $rc = $zkfp::DBMerge($db, $samples[0], $samples[1], $samples[2], $regTmp, [ref]$regSize)
        if ($rc -ne 0) { Write-Err "DBMerge failed rc=$rc (use the SAME finger 3 times)"; Pause-End; exit 1 }
        $b64 = $zkfp::BlobToBase64($regTmp, $regSize)
        Write-Ok "registered template: $regSize bytes (ZKFinger 10)"

        # ---- save locally ------------------------------------------------------
        $member = $existing
        if (-not $member) { $member = [pscustomobject]@{ pin = $pin; name = $name; card = $card; fingers = @() } }
        $member.name = $name; $member.card = $card
        $member.fingers = @(@($member.fingers) | Where-Object { $_.fingerId -ne $fid }) + @([ordered]@{
            fingerId   = $fid
            template   = $b64
            size       = $regSize
            capturedAt = (Get-Date).ToString('s')
            source     = 'zk9500'
        })
        Save-Member $member
        Write-Ok "member $pin now has $(@($member.fingers).Count) local finger(s) - push with 5_push_member_to_device.ps1"
    } finally {
        if ($db -ne [IntPtr]::Zero) { [void]$zkfp::DBFree($db) }
        [void]$zkfp::CloseDevice($h)
    }
} finally { [void]$zkfp::Terminate() }
Pause-End
