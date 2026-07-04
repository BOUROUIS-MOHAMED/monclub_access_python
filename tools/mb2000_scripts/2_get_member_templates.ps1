# 2_get_member_templates.ps1 — list the users ON THE DEVICE and read their
# fingerprint templates (all members, or search by pin/name/card). Optionally
# save what you read into the local store (templates\<pin>.json) so script 5
# can push it to another device.
#
# SIGNATURES USED (fix alone if firmware disagrees):
#   $zk.ReadAllUserID(1) -> bool                      # load user table to PC buffer
#   $zk.SSR_GetAllUserInfo(1,[ref]pin,[ref]name,[ref]pwd,[ref]priv,[ref]enabled) -> bool (loop)
#   $zk.GetStrCardNumber([ref]card) -> bool           # card of the user JUST enumerated
#   $zk.SSR_GetUserTmpStr(1,pin,fingerId,[ref]tmp,[ref]len) -> bool
. "$PSScriptRoot\_common.ps1"
Assert-32Bit $PSCommandPath $args
Write-Title "2) Get member templates from the device"

$cfg = Get-Config
$cfg.deviceIp = Ask-Default "Device IP" $cfg.deviceIp
Save-Config $cfg
$zk = Connect-Zkem $cfg
$mn = [int]$cfg.machineNumber

try {
    # ---- enumerate users -----------------------------------------------------
    Write-Info "reading user table..."
    if (-not $zk.ReadAllUserID($mn)) { Write-Err "ReadAllUserID failed"; exit 1 }

    $users = @()
    while ($true) {
        $pin = ''; $name = ''; $pwd = ''; $priv = 0; $enabled = $true
        $ok = $zk.SSR_GetAllUserInfo($mn, [ref]$pin, [ref]$name, [ref]$pwd, [ref]$priv, [ref]$enabled)
        if (-not $ok) { break }
        $card = ''
        try { [void]$zk.GetStrCardNumber([ref]$card) } catch { $card = '' }
        $users += [pscustomobject]@{ pin = "$pin"; name = "$name"; card = "$card"; enabled = $enabled }
    }
    Write-Ok "$($users.Count) user(s) on the device"

    # ---- optional search ------------------------------------------------------
    $q = Read-Host "Search (pin / name / card — ENTER for ALL)"
    $sel = if ([string]::IsNullOrWhiteSpace($q)) { $users } else {
        $qq = $q.Trim().ToLower()
        $users | Where-Object {
            $_.pin.ToLower().Contains($qq) -or $_.name.ToLower().Contains($qq) -or $_.card.ToLower().Contains($qq)
        }
    }
    if (@($sel).Count -eq 0) { Write-Warn "no match"; Pause-End; exit 0 }

    Write-Host ""
    Write-Host ("{0,-10} {1,-24} {2,-14} {3}" -f 'PIN', 'NAME', 'CARD', 'FINGERS') -ForegroundColor Cyan

    $saveAnswered = $false; $save = $false
    foreach ($u in $sel) {
        # ---- read templates for fingers 0..9 ----------------------------------
        $fingers = @()
        for ($fid = 0; $fid -le 9; $fid++) {
            $tmp = ''; $len = 0
            $ok = $false
            try { $ok = $zk.SSR_GetUserTmpStr($mn, $u.pin, $fid, [ref]$tmp, [ref]$len) } catch { $ok = $false }
            if ($ok -and "$tmp" -ne '') {
                $fingers += [ordered]@{
                    fingerId   = $fid
                    template   = "$tmp"
                    size       = [int]$len
                    capturedAt = (Get-Date).ToString('s')
                    source     = "device:$($cfg.deviceIp)"
                }
            }
        }
        $fids = ($fingers | ForEach-Object { $_.fingerId }) -join ','
        Write-Host ("{0,-10} {1,-24} {2,-14} [{3}]" -f $u.pin, $u.name, $u.card, $fids)

        if ($fingers.Count -gt 0) {
            if (-not $saveAnswered) {
                $saveAnswered = $true
                $save = (Ask-Default "Save templates found into the local store? (y/n)" 'y') -eq 'y'
            }
            if ($save) {
                $member = Load-Member $u.pin
                if (-not $member) {
                    $member = [ordered]@{ pin = $u.pin; name = $u.name; card = $u.card; fingers = @() }
                }
                # merge: device copy wins per fingerId
                $kept = @($member.fingers) | Where-Object { $f = $_; -not ($fingers | Where-Object { $_.fingerId -eq $f.fingerId }) }
                $member.fingers = @($kept) + @($fingers)
                $member.name = $u.name; $member.card = $u.card
                Save-Member ([pscustomobject]$member)
            }
        }
    }
} finally { Disconnect-Zkem $zk }
Pause-End
