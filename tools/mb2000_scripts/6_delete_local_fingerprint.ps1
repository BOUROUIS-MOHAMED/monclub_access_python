# 6_delete_local_fingerprint.ps1 - remove a finger (or a whole member) from the
# LOCAL store (templates\<pin>.json). Never touches the device (script 7 does).
. "$PSScriptRoot\_common.ps1"
Assert-32Bit $PSCommandPath $args
Write-Title "6) Delete LOCAL fingerprint(s)"

$members = @(List-Members)
Show-MemberTable $members
if ($members.Count -eq 0) { Pause-End; exit 0 }

$pin = Read-Host "PIN"
$member = Load-Member $pin
if (-not $member) { Write-Err "no templates\$pin.json"; Pause-End; exit 1 }

$fids = (@($member.fingers) | ForEach-Object { $_.fingerId }) -join ','
Write-Info "member '$($member.name)' has fingers [$fids]"
$choice = Read-Host "Finger ID to delete (0-9), or ALL to delete the whole member file"

if ($choice.Trim().ToUpper() -eq 'ALL') {
    if ((Ask-Default "Delete templates\$pin.json entirely? (y/n)" 'n') -eq 'y') {
        Remove-Item (Get-MemberFile $pin) -Force
        Write-Ok "member file deleted"
    } else { Write-Info "cancelled" }
} else {
    $fid = [int]$choice
    $before = @($member.fingers).Count
    $member.fingers = @(@($member.fingers) | Where-Object { [int]$_.fingerId -ne $fid })
    if (@($member.fingers).Count -eq $before) { Write-Warn "finger $fid was not in the file" }
    else { Save-Member $member; Write-Ok "finger $fid removed ($(@($member.fingers).Count) left)" }
}
Pause-End
