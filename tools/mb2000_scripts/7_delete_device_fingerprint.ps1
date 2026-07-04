# 7_delete_device_fingerprint.ps1 - delete enrollment data ON THE DEVICE.
#
# SIGNATURE USED:  SSR_DeleteEnrollData(1, pin, backupNumber) -> bool
#   backupNumber:  0..9  = that single fingerprint
#                  10    = password
#                  11/13 = ALL fingerprints of the user (firmware-dependent; try 11 then 13)
#                  12    = the WHOLE USER (fingerprints + card + password)
. "$PSScriptRoot\_common.ps1"
Assert-32Bit $PSCommandPath $args
Write-Title "7) Delete fingerprint / user ON THE DEVICE"

$cfg = Get-Config
$cfg.deviceIp = Ask-Default "Device IP" $cfg.deviceIp
Save-Config $cfg

$pin = Read-Host "Member PIN on the device"
Write-Host ""
Write-Host "  [0-9] delete that ONE finger"
Write-Host "  [F]   delete ALL fingerprints (keeps user + card)"
Write-Host "  [U]   delete the WHOLE USER (fingers + card + password)  <-- careful"
$choice = (Read-Host "Choice").Trim().ToUpper()

$zk = Connect-Zkem $cfg
$mn = [int]$cfg.machineNumber
try {
    switch -regex ($choice) {
        '^[0-9]$' {
            $ok = $zk.SSR_DeleteEnrollData($mn, $pin, [int]$choice)
            if ($ok) { Write-Ok "finger $choice deleted for pin $pin" } else { Write-Err "returned FALSE" }
        }
        '^F$' {
            $ok = $zk.SSR_DeleteEnrollData($mn, $pin, 11)
            if (-not $ok) { Write-Warn "backup 11 returned FALSE - trying 13"; $ok = $zk.SSR_DeleteEnrollData($mn, $pin, 13) }
            if ($ok) { Write-Ok "all fingerprints deleted for pin $pin" } else { Write-Err "returned FALSE (11 and 13)" }
        }
        '^U$' {
            if ((Ask-Default "Really delete USER $pin entirely from the device? (y/n)" 'n') -ne 'y') { Write-Info "cancelled"; break }
            $ok = $zk.SSR_DeleteEnrollData($mn, $pin, 12)
            if ($ok) { Write-Ok "user $pin deleted from the device" } else { Write-Err "returned FALSE" }
        }
        default { Write-Warn "unknown choice '$choice'" }
    }
    try { [void]$zk.RefreshData($mn) } catch { }
} finally { Disconnect-Zkem $zk }
Pause-End
