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

# ---- preflight: is the whole ZKFinger algorithm chain present? ---------------
# The #1 cause of ZKFPM_Init -1 in the field is a MISSING chain DLL (fppswsk12.dll
# is often left out of hand-assembled SDK folders). Name it before we even try.
$missingDlls = Test-ZkfpRuntime
if ($missingDlls.Count -gt 0) {
    Write-Err ("ZKFinger runtime INCOMPLETE - missing: {0}" -f ($missingDlls -join ', '))
    Write-Warn "The fingerprint algorithm library cannot initialize without these"
    Write-Warn "(the chain is libzkfp -> fpslib -> zkfpsliblow -> fppswsk12 + ZKFPCap)."
    Write-Warn "FIX: install the COMPLETE official ZKFinger SDK for Windows (as admin),"
    Write-Warn "     which places the full runtime incl. fppswsk12.dll into SysWOW64;"
    Write-Warn "     OR drop the missing file(s) into this pack's sdk\ folder."
    Write-Warn "     Do NOT grab DLLs from random 'dll download' sites (biometric access!)."
    Pause-End; exit 1
}

# ---- load the .NET wrapper ---------------------------------------------------
# PREFERRED: the bundled sdk\ set, loaded via Load-ZkfpWrapper which preloads
# libzkfp + its companions BY FULL PATH from sdk\ so a separately installed
# ZKFinger SDK cannot mix versions into it.
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
# ZKFinger error codes (ZKFinger Reader SDK C API): -1 = algorithm library init
# failed, -2 = capture library init failed, -3 = NO device connected.
# EVIDENCE (tested, do not re-guess): with the COMPLETE matched runtime bundled in
# sdk\ (libzkfp/fpslib/zkfpslibLow/fppswsk12/ZKFPCap all present + same build),
# ZKFPM_Init still returns -1 on a PC with NO reader attached. So -1 here is NOT a
# missing/mismatched DLL, and NOT (as earlier believed) the Windows Biometric
# Framework - that was disproven (disabling WbioSrvc and a reader-less PC both
# still gave -1). The remaining unproven variable is the READER itself: this SDK
# build appears to need the ZK9500 present for the algorithm to initialize.
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

    # WbioSrvc state - informational only. NOTE: disabling it was already tested and
    # did NOT fix -1, so it is NOT the cause; we just record it.
    Write-Host ""
    Write-Info "2) Windows Biometric Service (recorded for the log, NOT the cause):"
    $wbio = $null
    try { $wbio = Get-Service -Name 'WbioSrvc' -ErrorAction Stop } catch {}
    if ($wbio) { Write-Info ("   WbioSrvc status = $($wbio.Status)  startType = $($wbio.StartType)") }
    else { Write-Info "   WbioSrvc not found." }

    Write-Host ""
    Write-Info "VERDICT (evidence-based):"
    if (-not $hasZk -and -not $seen) {
        Write-Warn "  No ZK9500 is enumerated on THIS PC. The bundled runtime is complete, so"
        Write-Warn "  -1 here is consistent with 'no reader'. Plug the ZK9500 in and retry."
    } elseif ($hasZk) {
        Write-Err  "  A ZK9500 IS present AND the complete matched runtime is bundled, yet Init"
        Write-Err  "  is -1. That rules out DLLs and WBF. This is the REAL defect to escalate."
        Write-Err  "  Next, on THIS SAME PC: run the ZKFinger SDK's own Demo.exe. If Demo ALSO"
        Write-Err  "  fails -1, the fault is the reader's driver binding / the device, not our"
        Write-Err  "  code. If Demo WORKS, capture its DLL load list vs ours and compare."
    } else {
        Write-Warn "  A non-ZK biometric sensor is present but no ZK9500. Plug in the ZK9500."
    }
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
