# 0_MENU.ps1 - start here. Lists every script, shows the saved config, runs your pick.
. "$PSScriptRoot\_common.ps1"
Assert-32Bit $PSCommandPath $args

while ($true) {
    $cfg = Get-Config
    Write-Title "MB2000 / zkemkeeper dev scripts"
    Write-Host ("  device: {0}:{1}   commKey: {2}   store: {3} member(s)" -f `
        $cfg.deviceIp, $cfg.devicePort, $(if ("$($cfg.commKey)") { 'set' } else { 'none' }), @(List-Members).Count) -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [1]  Register zkemkeeper.dll (run once per PC, admin)"
    Write-Host "  [2]  Get member templates FROM the device (all / search)"
    Write-Host "  [3]  Device info (firmware, counts, clock)"
    Write-Host "  [4]  Enroll fingerprint on ZK9500 -> save locally"
    Write-Host "  [5]  Push member + local fingerprints TO the device"
    Write-Host "  [6]  Delete LOCAL fingerprint / member file"
    Write-Host "  [7]  Delete fingerprint / user ON the device"
    Write-Host "  [8]  LIVE punch monitor"
    Write-Host "  [9]  Unlock door (relay test)"
    Write-Host "  [10] Backup / restore ALL device users + templates"
    Write-Host "  [11] Portability test: ZK9500 desk capture -> live match (GATE 3) ***" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [C]  Edit config (IP / port / comm key)"
    Write-Host "  [Q]  Quit"
    Write-Host ""
    $c = (Read-Host "Choice").Trim().ToUpper()
    switch ($c) {
        'Q' { exit 0 }
        'C' {
            $cfg.deviceIp   = Ask-Default "Device IP" $cfg.deviceIp
            $cfg.devicePort = [int](Ask-Default "Port" $cfg.devicePort)
            $cfg.commKey    = Ask-Default "Comm key (empty = none)" "$($cfg.commKey)"
            Save-Config $cfg
        }
        default {
            $map = @{
                '1' = '1_register_zkemkeeper.ps1';  '2' = '2_get_member_templates.ps1'
                '3' = '3_get_device_info.ps1';      '4' = '4_enroll_zk9500.ps1'
                '5' = '5_push_member_to_device.ps1';'6' = '6_delete_local_fingerprint.ps1'
                '7' = '7_delete_device_fingerprint.ps1'; '8' = '8_live_monitor.ps1'
                '9' = '9_unlock_door.ps1';          '10' = '10_backup_restore_device.ps1'
                '11' = '11_portability_test.ps1'
            }
            if ($map.ContainsKey($c)) {
                & (Join-Path $PSScriptRoot $map[$c])
            } else { Write-Warn "unknown choice '$c'" }
        }
    }
}
