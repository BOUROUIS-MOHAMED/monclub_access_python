# 11_portability_test.ps1 — the decisive on-site experiment (plan GATE 3):
# does a fingerprint captured at the desk on the ZK9500 (script 4, source=zk9500)
# actually MATCH a live finger on the MB2000?  Automates: push -> watch the
# attendance log up to 90s -> print PASS / FAIL, instead of eyeballing the terminal.
#
# RUN THIS BEFORE ENROLLING REAL MEMBERS AT THE GYM. Its answer decides the
# onboarding workflow:
#   PASS  -> desk (ZK9500) enrollment works; the app's dashboard->desktop->device
#            flow stands as designed.
#   FAIL at upload  -> template FORMAT/encoding not accepted (compare script 3's
#            ~ZKFPVersion with the capture version; note it).
#   FAIL at match   -> members must be enrolled ON the terminal (device menu /
#            StartEnrollEx) -> the gym's onboarding workflow changes.
#
# Uses the SAME calls as scripts 5 (push) and 8 (log poll) so a fix here ports 1:1.
. "$PSScriptRoot\_common.ps1"
Assert-32Bit $PSCommandPath $args
Write-Title "11) Template portability test  (ZK9500 desk capture -> MB2000 live match)"

$cfg = Get-Config
$members = @(List-Members)
Show-MemberTable $members
if ($members.Count -eq 0) { Write-Warn "enroll one with script 4 first"; Pause-End; exit 0 }

$pin = Read-Host "PIN to test"
$member = Load-Member $pin
if (-not $member) { Write-Err "no templates\$pin.json in the local store"; Pause-End; exit 1 }

# Prefer the ZK9500 desk-captured fingers — those are what this test is ABOUT.
# (Fingers pulled back from the device with script 2 would trivially match and
#  prove nothing about desk-capture portability.)
$allFingers  = @($member.fingers)
$deskFingers = @($allFingers | Where-Object { "$($_.source)" -match 'zk9500' })
$testFingers = if ($deskFingers.Count -gt 0) { $deskFingers } else { $allFingers }

if ($deskFingers.Count -eq 0) {
    Write-Warn "this member has no source=zk9500 finger — testing all fingers, but a"
    Write-Warn "match only proves portability if the template was ZK9500-captured (script 4)."
}
Write-Info ("testing finger id(s): [{0}]" -f (($testFingers | ForEach-Object { $_.fingerId }) -join ','))

$cfg.deviceIp = Ask-Default "Device IP" $cfg.deviceIp
Save-Config $cfg
$zk = Connect-Zkem $cfg
$mn = [int]$cfg.machineNumber

try {
    # ---------------------------------------------------- push (mirrors script 5)
    $card = ("$($member.card)" -replace '\D', '')
    try { [void]$zk.SetStrCardNumber($card) } catch { Write-Warn "SetStrCardNumber failed: $_" }
    $ok = $zk.SSR_SetUserInfo($mn, "$($member.pin)", "$($member.name)", '', 0, $true)
    if (-not $ok) { Write-Err "SSR_SetUserInfo returned FALSE — aborting"; Pause-End; exit 1 }
    Write-Ok "user row written (pin=$($member.pin), card='$card')"

    $uploaded = 0
    foreach ($f in $testFingers) {
        $fid = [int]$f.fingerId
        try { [void]$zk.SSR_DelUserTmpExt($mn, "$($member.pin)", $fid) } catch { }   # slot must be empty
        $up = $false
        try { $up = $zk.SetUserTmpExStr($mn, "$($member.pin)", $fid, 1, "$($f.template)") } catch { Write-Warn "SetUserTmpExStr threw: $_" }
        if ($up) { Write-Ok "finger $fid uploaded (source=$($f.source), $($f.size) bytes)"; $uploaded++ }
        else     { Write-Err "finger $fid UPLOAD REJECTED (SetUserTmpExStr=FALSE)" }
    }
    try { [void]$zk.RefreshData($mn) } catch { }

    if ($uploaded -eq 0) {
        Write-Host ""
        Write-Err "RESULT: FAIL at UPLOAD — no desk template accepted by this firmware."
        Write-Info "Compare script 3's ~ZKFPVersion with the capture version; record the encoding."
        Pause-End; exit 1
    }

    # ---------------------------------------------------- live verify (mirrors script 8)
    Write-Host ""
    Write-Host ">>> NOW place the ENROLLED FINGER of pin=$($member.pin) on the MB2000 sensor <<<" -ForegroundColor Yellow
    Write-Info "watching the attendance log for up to 90s ..."

    # Ignore any log record older than 'now' so we only react to THIS test's punch.
    $startAt  = Get-Date
    $deadline = $startAt.AddSeconds(90)
    $matched  = $false
    $sawUser  = $false

    while ((Get-Date) -lt $deadline -and -not $matched) {
        $readOk = $false
        try { $readOk = $zk.ReadNewGLogData($mn) } catch { }
        if (-not $readOk) { try { $readOk = $zk.ReadGeneralLogData($mn) } catch { } }
        if ($readOk) {
            while ($true) {
                $lpin=''; $vm=0; $io=0; $y=0; $mo=0; $d=0; $h=0; $mi=0; $s=0; $wc=0
                $g = $false
                try {
                    $g = $zk.SSR_GetGeneralLogData($mn, [ref]$lpin, [ref]$vm, [ref]$io,
                        [ref]$y, [ref]$mo, [ref]$d, [ref]$h, [ref]$mi, [ref]$s, [ref]$wc)
                } catch { $g = $false }
                if (-not $g) { break }
                $ts = Get-Date -Year $y -Month $mo -Day $d -Hour $h -Minute $mi -Second $s
                if ($ts -lt $startAt.AddSeconds(-2)) { continue }   # old record, skip
                if ("$lpin" -ne "$($member.pin)")   { continue }    # a different user punched
                $sawUser = $true
                $vmi = [int]$vm
                Write-Info ("event: pin=$lpin verify=$vmi(" + (@{0='pw';1='FINGER';2='card';3='card-multi'}[$vmi]) + ") inout=$io")
                if ($vmi -eq 1) { $matched = $true; break }   # fingerprint verify for this user
            }
        }
        Start-Sleep -Milliseconds 800
    }

    Write-Host ""
    if ($matched) {
        Write-Ok "RESULT:  ***** PASS *****  — ZK9500 desk enrollment MATCHES on the MB2000."
        Write-Info "The dashboard -> Access -> device fingerprint flow stands as designed."
    } elseif ($sawUser) {
        Write-Err "RESULT:  PARTIAL — the user punched but not via FINGERPRINT (or match failed)."
        Write-Info "Retry a clean finger placement; if it never verifies=1, treat as FAIL-match."
    } else {
        Write-Err "RESULT:  ***** FAIL / NO MATCH *****  — upload accepted but the live finger"
        Write-Err "         did not verify within 90s."
        Write-Info "If consistent: enroll fingerprints ON the terminal (device menu / StartEnrollEx)"
        Write-Info "-> change the gym onboarding workflow BEFORE enrolling real members."
    }
} finally { Disconnect-Zkem $zk }
Pause-End
