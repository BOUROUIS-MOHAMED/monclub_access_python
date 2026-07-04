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
$dllPath = $cfg.zkfingerDll
if (-not ($dllPath -and (Test-Path $dllPath))) {
    $guess = @(
        (Join-Path $PSScriptRoot 'sdk\libzkfpcsharp.dll'),   # bundled with the pack
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

# ---- member identity ----------------------------------------------------------
$pin  = Read-Host "Member PIN (numeric, max 9 digits)"
if ($pin -notmatch '^\d{1,9}$') { Write-Err "PIN must be 1-9 digits"; Pause-End; exit 1 }
$existing = Load-Member $pin
$name = Ask-Default "Name"        $(if ($existing) { $existing.name } else { '' })
$card = Ask-Default "Card number" $(if ($existing) { $existing.card } else { '' })
$fid  = [int](Ask-Default "Finger ID (0-9)" '6')
if ($fid -lt 0 -or $fid -gt 9) { Write-Err "fingerId 0-9"; Pause-End; exit 1 }

# ---- open reader ---------------------------------------------------------------
if ($zkfp::Init() -ne 0) { Write-Err "zkfp Init failed - reader plugged in? drivers installed?"; Pause-End; exit 1 }
try {
    if ($zkfp::GetDeviceCount() -lt 1) { Write-Err "no ZK9500 reader detected"; Pause-End; exit 1 }
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
