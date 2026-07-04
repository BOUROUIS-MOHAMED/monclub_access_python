# 9_unlock_door.ps1 - fire the device's lock relay (ACUnlock). Listen for the
# click and check the turnstile actually releases - this verifies BOTH the SDK
# call AND the physical wiring (lock contacts -> turnstile).
#
# SIGNATURE USED:  ACUnlock(1, delayDeciseconds) -> bool   (10 = 1 second)
# If this PASSES on the real MB2000, flip supports_open_door=True in
# app/sdk/zk_standalone.py (it ships False until proven).
. "$PSScriptRoot\_common.ps1"
Assert-32Bit $PSCommandPath $args
Write-Title "9) Unlock door (relay test)"

$cfg = Get-Config
$cfg.deviceIp = Ask-Default "Device IP" $cfg.deviceIp
Save-Config $cfg
$seconds = [double](Ask-Default "Open duration in seconds" '1')

$zk = Connect-Zkem $cfg
try {
    $delayDs = [int][math]::Max(1, [math]::Round($seconds * 10))
    Write-Info "ACUnlock($($cfg.machineNumber), $delayDs) ..."
    $ok = $zk.ACUnlock([int]$cfg.machineNumber, $delayDs)
    if ($ok) {
        Write-Ok "ACUnlock returned TRUE - did you HEAR the relay and did the turnstile release?"
        Write-Info "TRUE + no physical release = wiring problem, not SDK."
    } else {
        Write-Err "ACUnlock returned FALSE - likely unsupported on this firmware; keep open_door disabled in the app."
    }
} finally { Disconnect-Zkem $zk }
Pause-End
