# 5_push_member_to_device.ps1 — push ONE member (user + card + local templates)
# from templates\<pin>.json to the device. This is the on-hardware test of the
# exact sequence MonClub Access uses (app/sdk/zk_standalone.py push_roster):
#
#   SetStrCardNumber(card)                # BEFORE SSR_SetUserInfo
#   SSR_SetUserInfo(1, pin, name, '', 0, true)   # auto-creates the user
#   SSR_DelUserTmpExt(1, pin, fingerId)   # slot must be EMPTY before upload
#   SetUserTmpExStr(1, pin, fingerId, 1, template)   # Flag 1 = valid
#   RefreshData(1)
#
# TEMPLATE NOTE: templates saved by script 4 are BASE64 (ZK9500/ZKFinger10);
# templates saved by script 2 are in the device's own string encoding. If an
# upload returns FALSE, the encoding may not match this firmware's BASE64
# property — that finding goes straight into the app driver.
. "$PSScriptRoot\_common.ps1"
Assert-32Bit $PSCommandPath $args
Write-Title "5) Push member + fingerprints to the device"

$cfg = Get-Config
$members = @(List-Members)
Show-MemberTable $members
if ($members.Count -eq 0) { Pause-End; exit 0 }

$pin = Read-Host "PIN to push"
$member = Load-Member $pin
if (-not $member) { Write-Err "no templates\$pin.json in the local store"; Pause-End; exit 1 }

$cfg.deviceIp = Ask-Default "Device IP" $cfg.deviceIp
Save-Config $cfg
$zk = Connect-Zkem $cfg
$mn = [int]$cfg.machineNumber

try {
    $card = ("$($member.card)" -replace '\D', '')
    Write-Info "user: pin=$($member.pin) name='$($member.name)' card='$card' fingers=$(@($member.fingers).Count)"

    try { [void]$zk.SetStrCardNumber($card) } catch { Write-Warn "SetStrCardNumber failed: $_" }
    $ok = $zk.SSR_SetUserInfo($mn, "$($member.pin)", "$($member.name)", '', 0, $true)
    if (-not $ok) { Write-Err "SSR_SetUserInfo returned FALSE"; Pause-End; exit 1 }
    Write-Ok "user row written (card included)"

    $pushed = 0
    foreach ($f in @($member.fingers)) {
        $fid = [int]$f.fingerId
        try { [void]$zk.SSR_DelUserTmpExt($mn, "$($member.pin)", $fid) } catch { }
        $ok = $false
        try { $ok = $zk.SetUserTmpExStr($mn, "$($member.pin)", $fid, 1, "$($f.template)") } catch { Write-Warn "SetUserTmpExStr threw: $_" }
        if ($ok) { Write-Ok "finger $fid uploaded ($($f.size) bytes, source=$($f.source))"; $pushed++ }
        else     { Write-Err "finger $fid upload returned FALSE (encoding/version? see header note)" }
    }

    try { [void]$zk.RefreshData($mn) } catch { }
    Write-Host ""
    if ($pushed -gt 0) {
        Write-Ok "$pushed finger(s) on the device — NOW PLACE THE REAL FINGER on the terminal to verify the match"
        Write-Info "(a successful live match here = GATE 3 template-portability PASS)"
    } else {
        Write-Warn "no finger uploaded — user+card were still written"
    }
} finally { Disconnect-Zkem $zk }
Pause-End
