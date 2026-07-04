# 8_live_monitor.ps1 - watch punches (fingerprint/card) appear in real time.
# THE most useful script while testing: shows WHO verified, HOW, and WHEN.
#
# HOW IT WORKS: PowerShell cannot host COM event sinks reliably, so this polls
# the attendance log every 2s and prints only NEW records. Good enough for dev;
# the production app (zk_standalone.py) uses the true real-time channel.
#
# SIGNATURES USED:
#   ReadNewGLogData(1) -> bool     (new-records-only read; some firmwares)
#   ReadGeneralLogData(1) -> bool  (full read fallback)
#   SSR_GetGeneralLogData(1,[ref]pin,[ref]verifyMode,[ref]inOut,[ref]y,[ref]mo,
#                         [ref]d,[ref]h,[ref]mi,[ref]s,[ref]workcode) -> bool (loop)
#   verifyMode: 0=password 1=fingerprint 2=card (multi-verify firmwares shift values
#   - record what YOUR device prints; that table goes into the app driver)
. "$PSScriptRoot\_common.ps1"
Assert-32Bit $PSCommandPath $args
Write-Title "8) LIVE punch monitor (CTRL+C to stop)"

$cfg = Get-Config
$cfg.deviceIp = Ask-Default "Device IP" $cfg.deviceIp
Save-Config $cfg
$zk = Connect-Zkem $cfg
$mn = [int]$cfg.machineNumber

$verifyLabel = @{ 0 = 'PASSWORD'; 1 = 'FINGER'; 2 = 'CARD'; 3 = 'CARD(multi)' }
$seen = New-Object 'System.Collections.Generic.HashSet[string]'
$startedAt = (Get-Date).AddMinutes(-1)   # show anything from just before start
$first = $true

Write-Host ""
Write-Host ("{0,-20} {1,-10} {2,-12} {3,-6} {4}" -f 'TIME', 'PIN', 'VERIFY', 'INOUT', 'RAW(verify/inout/work)') -ForegroundColor Cyan

try {
    while ($true) {
        $readOk = $false
        try { $readOk = $zk.ReadNewGLogData($mn) } catch { }
        if (-not $readOk) { try { $readOk = $zk.ReadGeneralLogData($mn) } catch { } }
        if ($readOk) {
            while ($true) {
                $pin=''; $vm=0; $io=0; $y=0; $mo=0; $d=0; $h=0; $mi=0; $s=0; $wc=0
                $ok = $false
                try {
                    $ok = $zk.SSR_GetGeneralLogData($mn, [ref]$pin, [ref]$vm, [ref]$io,
                        [ref]$y, [ref]$mo, [ref]$d, [ref]$h, [ref]$mi, [ref]$s, [ref]$wc)
                } catch { $ok = $false }
                if (-not $ok) { break }
                $ts = Get-Date -Year $y -Month $mo -Day $d -Hour $h -Minute $mi -Second $s
                $key = "$pin|$($ts.ToString('s'))|$vm"
                if ($seen.Add($key) -and ($ts -ge $startedAt -or -not $first)) {
                    $label = if ($verifyLabel.ContainsKey([int]$vm)) { $verifyLabel[[int]$vm] } else { "?($vm)" }
                    $color = if ([int]$vm -eq 1) { 'Green' } elseif ([int]$vm -ge 2) { 'Cyan' } else { 'Gray' }
                    Write-Host ("{0,-20} {1,-10} {2,-12} {3,-6} {4}/{5}/{6}" -f `
                        $ts.ToString('yyyy-MM-dd HH:mm:ss'), $pin, $label, $io, $vm, $io, $wc) -ForegroundColor $color
                }
            }
            $first = $false
        }
        Start-Sleep -Seconds 2
    }
} finally { Disconnect-Zkem $zk }
