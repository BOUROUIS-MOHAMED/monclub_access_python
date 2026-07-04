# 10_backup_restore_device.ps1 — dump EVERY user (pin/name/card) + all their
# fingerprint templates from the device into one timestamped JSON file, or
# restore such a backup onto a device. Your safety net before wiping/replacing
# a terminal, and the fastest way to CLONE one terminal onto the other two.
#
# SIGNATURES: same as scripts 2 and 5 (enumerate + SSR_GetUserTmpStr /
# SSR_SetUserInfo + SetUserTmpExStr). Restores are delta-style, no EnableDevice.
. "$PSScriptRoot\_common.ps1"
Assert-32Bit $PSCommandPath $args
Write-Title "10) Backup / restore ALL device users + templates"

$cfg = Get-Config
$mode = (Ask-Default "Mode: [B]ackup device -> file, or [R]estore file -> device" 'B').ToUpper()
$cfg.deviceIp = Ask-Default "Device IP" $cfg.deviceIp
Save-Config $cfg
$mn = [int]$cfg.machineNumber

$backupDir = Join-Path $PSScriptRoot 'backups'
if (-not (Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir | Out-Null }

if ($mode -eq 'B') {
    $zk = Connect-Zkem $cfg
    try {
        if (-not $zk.ReadAllUserID($mn)) { Write-Err "ReadAllUserID failed"; Pause-End; exit 1 }
        $all = @()
        $userN = 0; $fpN = 0
        while ($true) {
            $pin=''; $name=''; $pwd=''; $priv=0; $enabled=$true
            if (-not $zk.SSR_GetAllUserInfo($mn, [ref]$pin, [ref]$name, [ref]$pwd, [ref]$priv, [ref]$enabled)) { break }
            $card = ''
            try { [void]$zk.GetStrCardNumber([ref]$card) } catch { }
            $fingers = @()
            for ($fid = 0; $fid -le 9; $fid++) {
                $tmp=''; $len=0
                $ok = $false
                try { $ok = $zk.SSR_GetUserTmpStr($mn, "$pin", $fid, [ref]$tmp, [ref]$len) } catch { }
                if ($ok -and "$tmp" -ne '') {
                    $fingers += [ordered]@{ fingerId = $fid; template = "$tmp"; size = [int]$len }
                    $fpN++
                }
            }
            $all += [ordered]@{ pin = "$pin"; name = "$name"; card = "$card"; enabled = $enabled; fingers = $fingers }
            $userN++
            if ($userN % 25 -eq 0) { Write-Info "... $userN users read ($fpN templates)" }
        }
        $file = Join-Path $backupDir ("device_{0}_{1}.json" -f ($cfg.deviceIp -replace '\W', '-'), (Get-Date -Format 'yyyyMMdd_HHmmss'))
        ([ordered]@{
            device = $cfg.deviceIp; takenAt = (Get-Date).ToString('s'); users = $all
        } | ConvertTo-Json -Depth 8) | Set-Content -Path $file -Encoding UTF8
        Write-Ok "backup: $userN users, $fpN templates -> $file"
    } finally { Disconnect-Zkem $zk }

} elseif ($mode -eq 'R') {
    $files = Get-ChildItem $backupDir -Filter '*.json' | Sort-Object LastWriteTime -Descending
    if ($files.Count -eq 0) { Write-Err "no backups in $backupDir"; Pause-End; exit 1 }
    Write-Host ""
    for ($i = 0; $i -lt [Math]::Min(9, $files.Count); $i++) { Write-Host ("  [{0}] {1}" -f ($i + 1), $files[$i].Name) }
    $idx = [int](Ask-Default "Restore which backup" '1') - 1
    $data = Get-Content $files[$idx].FullName -Raw | ConvertFrom-Json
    Write-Warn "restoring $(@($data.users).Count) users onto $($cfg.deviceIp) (existing same-pin data is overwritten)"
    if ((Ask-Default "Continue? (y/n)" 'n') -ne 'y') { Write-Info "cancelled"; Pause-End; exit 0 }

    $zk = Connect-Zkem $cfg
    try {
        $okN = 0; $failN = 0
        foreach ($u in $data.users) {
            try {
                try { [void]$zk.SetStrCardNumber(("$($u.card)" -replace '\D', '')) } catch { }
                if (-not $zk.SSR_SetUserInfo($mn, "$($u.pin)", "$($u.name)", '', 0, $true)) { $failN++; continue }
                foreach ($f in @($u.fingers)) {
                    try { [void]$zk.SSR_DelUserTmpExt($mn, "$($u.pin)", [int]$f.fingerId) } catch { }
                    [void]$zk.SetUserTmpExStr($mn, "$($u.pin)", [int]$f.fingerId, 1, "$($f.template)")
                }
                $okN++
                if ($okN % 25 -eq 0) { Write-Info "... $okN users restored" }
            } catch { $failN++ }
        }
        try { [void]$zk.RefreshData($mn) } catch { }
        Write-Ok "restore done: $okN ok, $failN failed"
    } finally { Disconnect-Zkem $zk }
} else { Write-Warn "unknown mode" }
Pause-End
