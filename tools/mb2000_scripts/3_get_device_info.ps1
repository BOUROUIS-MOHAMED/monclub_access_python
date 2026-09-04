# 3_get_device_info.ps1 - identity + capacity + clock of the device.
# Every read is independent (try/catch) so one unsupported call never hides the rest.
#
# SIGNATURES USED:
#   GetFirmwareVersion(1,[ref]s)  GetSerialNumber(1,[ref]s)  GetDeviceMAC(1,[ref]s)
#   GetPlatform(1,[ref]s)         GetDeviceIP(1,[ref]s)      GetVendor([ref]s)
#   GetDeviceStatus(1,idx,[ref]n)   idx: 1=admins 2=users 3=fingerprints 6=att logs
#   GetDeviceTime(1,[ref]y,[ref]mo,[ref]d,[ref]h,[ref]mi,[ref]s)
. "$PSScriptRoot\_common.ps1"
Assert-32Bit $PSCommandPath $args
Write-Title "3) Device info"

$cfg = Get-Config
$cfg.deviceIp = Ask-Default "Device IP" $cfg.deviceIp
Save-Config $cfg
$zk = Connect-Zkem $cfg
$mn = [int]$cfg.machineNumber

function Read-Str { param($label, [scriptblock]$call)
    try { $v = ''; if (& $call ([ref]$v)) { Write-Host ("  {0,-22} {1}" -f $label, $v) } else { Write-Host ("  {0,-22} (returned false)" -f $label) -ForegroundColor DarkGray } }
    catch { Write-Host ("  {0,-22} (unsupported: {1})" -f $label, $_.Exception.Message) -ForegroundColor DarkGray }
}

try {
    Write-Host ""
    Write-Host "IDENTITY" -ForegroundColor Cyan
    Read-Str 'Firmware'   { param($r) $zk.GetFirmwareVersion($mn, $r) }
    Read-Str 'Serial'     { param($r) $zk.GetSerialNumber($mn, $r) }
    Read-Str 'MAC'        { param($r) $zk.GetDeviceMAC($mn, $r) }
    Read-Str 'Platform'   { param($r) $zk.GetPlatform($mn, $r) }
    Read-Str 'Vendor'     { param($r) $zk.GetVendor($r) }
    Read-Str 'Device IP'  { param($r) $zk.GetDeviceIP($mn, $r) }

    Write-Host ""
    Write-Host "COUNTS (GetDeviceStatus)" -ForegroundColor Cyan
    # Pairs, NOT [ordered]@{ 1 = 'admins'; ... }. In PowerShell an ordered dictionary
    # indexed with an INTEGER returns the entry at that POSITION, not the entry with
    # that KEY - so $map[6] is out of range and $map[1] is the SECOND entry. Written
    # with a hashtable this loop silently mislabels the counters (the admin count
    # printed as "users", and no label at all for indexes 6 and 8). Verified in 5.1.
    # GetDeviceStatus index: 1=admins 2=users 3=fingerprints 6=att logs 8=face.
    $statusFields = @(
        @(1, 'Admins'), @(2, 'Users'), @(3, 'Fingerprints'),
        @(6, 'Attendance logs'), @(8, 'Face templates')
    )
    foreach ($sf in $statusFields) {
        $idx = [int]$sf[0]
        $label = [string]$sf[1]
        try {
            $n = 0
            if ($zk.GetDeviceStatus($mn, $idx, [ref]$n)) {
                Write-Host ("  {0,-22} {1}" -f $label, $n)
            }
        } catch { Write-Host ("  {0,-22} (unsupported)" -f $label) -ForegroundColor DarkGray }
    }

    Write-Host ""
    Write-Host "CLOCK" -ForegroundColor Cyan
    try {
        $y=0;$mo=0;$d=0;$h=0;$mi=0;$s=0
        if ($zk.GetDeviceTime($mn, [ref]$y, [ref]$mo, [ref]$d, [ref]$h, [ref]$mi, [ref]$s)) {
            $devTime = Get-Date -Year $y -Month $mo -Day $d -Hour $h -Minute $mi -Second $s
            $skew = [math]::Round(($devTime - (Get-Date)).TotalSeconds, 1)
            Write-Host ("  {0,-22} {1}   (skew vs this PC: {2}s)" -f 'Device time', $devTime.ToString('yyyy-MM-dd HH:mm:ss'), $skew)
            if ([math]::Abs($skew) -gt 30) { Write-Warn "clock skew > 30s - fix before trusting event times" }
            if ((Ask-Default "Set device clock to this PC's time? (y/n)" 'n') -eq 'y') {
                $now = Get-Date
                if ($zk.SetDeviceTime2($mn, $now.Year, $now.Month, $now.Day, $now.Hour, $now.Minute, $now.Second)) {
                    Write-Ok "device clock set"
                } else { Write-Err "SetDeviceTime2 returned false" }
            }
        }
    } catch { Write-Host "  Device time          (unsupported: $($_.Exception.Message))" -ForegroundColor DarkGray }
} finally { Disconnect-Zkem $zk }
Pause-End
