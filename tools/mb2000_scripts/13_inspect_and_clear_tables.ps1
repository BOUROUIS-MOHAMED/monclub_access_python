# 13_inspect_and_clear_tables.ps1 - inspect the device's data tables, then clear ONE.
#
# THREE STEPS, in this order, deliberately:
#   1) connect
#   2) show every table's COUNT, with an option to dump its CONTENT
#   3) pick ONE table to clear
#
# Nothing is deleted until step 3, and step 3 clears exactly one table per run.
#
# ADMINISTRATORS ARE NEVER TOUCHED.
#   On ZKTeco firmware an administrator is not a separate table - it is a user row
#   with privilege > 0. So every credential option below enumerates users, SKIPS
#   privilege > 0, and prints the preserved admins before asking to proceed.
#   This is also why ClearData()/ClearKeeperData() are NOT used anywhere in this
#   script: they are table-wide wipes that would take the admins with them, and
#   their DataFlag values are not documented anywhere in this repo.
#
# SIGNATURES USED, and how far each is actually proven ON THIS HARDWARE:
#   GetDeviceStatus(mn, idx, [ref]n)                  counts          [see note below]
#   ReadAllUserID(mn) + SSR_GetAllUserInfo(...)       enumerate       used by script 10
#   GetStrCardNumber([ref]card)                       card of the last user read
#   SSR_GetUserTmpStr(mn, pin, fid, [ref]t, [ref]l)   one finger slot used by script 10
#   SSR_DelUserTmpExt(mn, pin, fid)                   clear one slot  [FIELD] 943/943 on
#                                                     occupied slots, Oxyfit 2026-09-06.
#                                                     Returns FALSE on an ALREADY-EMPTY
#                                                     slot - that is normal, not an error.
#   SetStrCardNumber(card) + SSR_SetUserInfo(...)     rewrite a user  [FIELD] the app's
#                                                     own push path, 898/898 members.
#   SSR_DeleteEnrollData(mn, pin, 10 | 12)            password | whole user  [UNVERIFIED]
#   ClearGLog(mn)                                     attendance log  [UNVERIFIED]
#
# MUST NOT: SSR_DeleteEnrollData with a FINGER index (0..9). On this firmware that
# call never returns - it is what wedged the STA thread in v1.4.25. Finger slots are
# cleared with SSR_DelUserTmpExt only. See zkemkeeper_guide.md.
#
# Every destructive call is logged to logs\ BEFORE it is issued, so if the device
# stops answering the last line in the log names the PIN it died on.

. "$PSScriptRoot\_common.ps1"
Assert-32Bit $PSCommandPath $args
Write-Title "13) Inspect device tables, then clear ONE"

# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

$logDir = Join-Path $PSScriptRoot 'logs'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
$script:LogFile = Join-Path $logDir ("clear_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

function Write-Log {
    param([string]$line)
    $stamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')
    Add-Content -Path $script:LogFile -Value "$stamp  $line" -Encoding UTF8
}

# Pairs, NOT [ordered]@{ 1 = '...' }. An ordered dictionary indexed with an INTEGER
# returns the entry at that POSITION, not the entry with that KEY - the trap that
# already mislabelled the counters in script 3.
#
# The index -> label mapping is [UNVERIFIED] and the repo contradicts itself:
# 3_get_device_info.ps1 reads 6 = attendance and 8 = face, while the driver's
# _STATUS_FIELDS reads 4 = attendance and 8 = user capacity. So EVERY index is shown
# with its raw number and the label is printed as a guess. Trust the number, and use
# the arithmetic check below (used + free == capacity) to decide which labels hold.
$StatusIdx = @(
    @(1, 'admins            (guess)'),
    @(2, 'users             (guess)'),
    @(3, 'fingerprints      (guess)'),
    @(4, 'attendance recs   (guess)'),
    @(5, 'passwords         (guess)'),
    @(6, 'att logs / face   (guess - the two sources disagree)'),
    @(7, 'fingerprint cap   (guess)'),
    @(8, 'user cap / face   (guess - the two sources disagree)'),
    @(9, 'attendance cap    (guess)'),
    @(10, 'fingerprints free (guess)'),
    @(11, 'users free        (guess)'),
    @(12, 'attendance free   (guess)')
)

function Get-Counts {
    param($zk, [int]$mn)
    $out = @{}
    foreach ($pair in $StatusIdx) {
        $idx = [int]$pair[0]
        try {
            $n = 0
            if ($zk.GetDeviceStatus($mn, $idx, [ref]$n)) { $out[$idx] = [int]$n }
        } catch { }
    }
    return $out
}

function Show-Counts {
    param($zk, [int]$mn, [string]$title = 'TABLE COUNTS (GetDeviceStatus)')
    Write-Host ""
    Write-Host $title -ForegroundColor Cyan
    $counts = Get-Counts $zk $mn
    foreach ($pair in $StatusIdx) {
        $idx = [int]$pair[0]
        $label = [string]$pair[1]
        if ($counts.ContainsKey($idx)) {
            Write-Host ("  [{0,2}] {1,-34} {2}" -f $idx, $label, $counts[$idx])
        } else {
            Write-Host ("  [{0,2}] {1,-34} (unsupported)" -f $idx, $label) -ForegroundColor DarkGray
        }
    }
    # Arithmetic cross-check: on the Oxyfit MB2000 both of these closed exactly
    # (1838+1162=3000, 2017+983=3000), which is what makes those four labels
    # trustworthy even though the mapping as a whole is unverified.
    Write-Host ""
    foreach ($t in @(@(2, 11, 8, 'users'), @(3, 10, 7, 'fingerprints'))) {
        $u = [int]$t[0]; $f = [int]$t[1]; $c = [int]$t[2]; $what = [string]$t[3]
        if ($counts.ContainsKey($u) -and $counts.ContainsKey($f) -and $counts.ContainsKey($c)) {
            $sum = $counts[$u] + $counts[$f]
            $mark = if ($sum -eq $counts[$c]) { 'OK  ' } else { 'MISMATCH' }
            Write-Host ("  check {0,-13} {1} + {2} = {3} vs capacity {4}  [{5}]" -f `
                $what, $counts[$u], $counts[$f], $sum, $counts[$c], $mark) -ForegroundColor DarkGray
        }
    }
    return $counts
}

function Read-Users {
    param($zk, [int]$mn, [switch]$WithFingers)
    if (-not $zk.ReadAllUserID($mn)) { Write-Err "ReadAllUserID failed"; return $null }
    $users = @()
    while ($true) {
        $pin = ''; $name = ''; $pwd = ''; $priv = 0; $enabled = $true
        if (-not $zk.SSR_GetAllUserInfo($mn, [ref]$pin, [ref]$name, [ref]$pwd, [ref]$priv, [ref]$enabled)) { break }
        $card = ''
        try { [void]$zk.GetStrCardNumber([ref]$card) } catch { }
        $fingers = @()
        if ($WithFingers) {
            for ($fid = 0; $fid -le 9; $fid++) {
                $tmp = ''; $len = 0
                $ok = $false
                try { $ok = $zk.SSR_GetUserTmpStr($mn, "$pin", $fid, [ref]$tmp, [ref]$len) } catch { }
                if ($ok -and "$tmp" -ne '') { $fingers += $fid }
            }
        }
        $users += [pscustomobject]@{
            pin = "$pin"; name = "$name"; card = "$card"
            priv = [int]$priv; enabled = [bool]$enabled
            haspwd = ("$pwd" -ne ''); fingers = $fingers
        }
        if ($users.Count % 100 -eq 0) { Write-Info "... $($users.Count) users read" }
    }
    return $users
}

function Confirm-Destructive {
    param([string]$what, [int]$affected, [int]$adminsKept, [string]$ip)
    Write-Host ""
    Write-Warn "ABOUT TO CLEAR: $what"
    Write-Warn "  device        : $ip"
    Write-Warn "  rows affected : $affected"
    Write-Warn "  admins kept   : $adminsKept"
    Write-Host ""
    Write-Host "  This cannot be undone from the device. Type the word CLEAR to proceed." -ForegroundColor Yellow
    $typed = (Read-Host "  confirm").Trim()
    if ($typed -cne 'CLEAR') { Write-Info "cancelled (you typed '$typed')"; return $false }
    return $true
}

# --------------------------------------------------------------------------- #
# STEP 1 - connect
# --------------------------------------------------------------------------- #

$cfg = Get-Config
$cfg.deviceIp = Ask-Default "Device IP" $cfg.deviceIp
Save-Config $cfg

$zk = Connect-Zkem $cfg
$mn = [int]$cfg.machineNumber
Write-Log "connected to $($cfg.deviceIp):$($cfg.devicePort) mn=$mn"

try {
    # ----------------------------------------------------------------------- #
    # STEP 2 - counts, and optionally content
    # ----------------------------------------------------------------------- #
    $before = Show-Counts $zk $mn

    $users = $null
    while ($true) {
        Write-Host ""
        Write-Host "STEP 2 - inspect content (nothing is deleted here)" -ForegroundColor Cyan
        Write-Host "  [1] list USERS            (pin, name, card, privilege, enabled)"
        Write-Host "  [2] list USERS + FINGERS  (slow: 10 extra reads per user)"
        Write-Host "  [3] list ADMINS only      (privilege > 0)"
        Write-Host "  [4] list users WITH a card"
        Write-Host "  [5] re-read the counts"
        Write-Host "  [6] EXPORT all users to CSV   (1838 rows do not fit on a screen)"
        Write-Host "  [N] done inspecting - go to step 3"
        $c = (Read-Host "Choice").Trim().ToUpper()

        if ($c -eq 'N') { break }
        elseif ($c -eq '5') { $before = Show-Counts $zk $mn }
        elseif ($c -eq '6') {
            if (-not $users) { $users = Read-Users $zk $mn }
            if (-not $users) { Write-Err "could not read users"; continue }
            $csv = Join-Path $logDir ("users_{0}_{1}.csv" -f ($cfg.deviceIp -replace '\W', '-'), (Get-Date -Format 'yyyyMMdd_HHmmss'))
            $users | Select-Object pin, name, card, priv, enabled, haspwd,
                @{n = 'fingers'; e = { ($_.fingers -join ' ') } } |
                Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
            Write-Ok "exported $($users.Count) users -> $csv"
        }
        elseif ($c -in @('1', '2', '3', '4')) {
            if ($c -eq '2') {
                Write-Warn "reading all 10 finger slots for every user - on ~1800 users this is ~18000 calls (many minutes)."
                if ((Ask-Default "Continue? (y/n)" 'n') -ne 'y') { continue }
                $users = Read-Users $zk $mn -WithFingers
            } elseif (-not $users) {
                $users = Read-Users $zk $mn
            }
            if (-not $users) { Write-Err "could not read users"; continue }

            $view = switch ($c) {
                '3' { @($users | Where-Object { $_.priv -gt 0 }) }
                '4' { @($users | Where-Object { "$($_.card)" -ne '' -and "$($_.card)" -ne '0' }) }
                default { @($users) }
            }
            Write-Host ""
            Write-Host ("  {0,-12} {1,-24} {2,-14} {3,-5} {4,-7} {5}" -f 'PIN', 'NAME', 'CARD', 'PRIV', 'ENABLED', 'FINGERS') -ForegroundColor Cyan
            foreach ($u in $view) {
                $fp = if ($u.fingers.Count) { ($u.fingers -join ',') } else { '' }
                Write-Host ("  {0,-12} {1,-24} {2,-14} {3,-5} {4,-7} {5}" -f `
                    $u.pin, $u.name.PadRight(24).Substring(0, 24), $u.card, $u.priv, $u.enabled, $fp)
            }
            Write-Host ""
            Write-Info "$($view.Count) row(s). Total users read: $($users.Count)."
            $adm = @($users | Where-Object { $_.priv -gt 0 })
            if ($adm.Count) { Write-Info "administrators present: $($adm.Count) (pins: $(($adm | ForEach-Object { $_.pin }) -join ', '))" }
            else { Write-Warn "NO administrator found on this device - nothing will be preserved as admin." }
        }
        else { Write-Warn "unknown choice '$c'" }
    }

    # ----------------------------------------------------------------------- #
    # STEP 3 - clear ONE table
    # ----------------------------------------------------------------------- #
    Write-Host ""
    Write-Host "STEP 3 - clear ONE table" -ForegroundColor Cyan
    Write-Host "  [F] FINGERPRINTS   all templates, keeps users + cards      [proven on this hardware]"
    Write-Host "  [C] CARDS          blanks the card, keeps users + fingers  [proven on this hardware]"
    Write-Host "  [P] PASSWORDS      user passwords only                     [UNVERIFIED api]"
    Write-Host "  [U] USERS          whole rows: fingers + card + password   [UNVERIFIED api]"
    Write-Host "  [L] ATTENDANCE LOG no credentials touched                  [UNVERIFIED api]"
    Write-Host "  [Q] quit without deleting anything"
    Write-Host ""
    Write-Host "  Administrators (privilege > 0) are skipped by F, C, P and U." -ForegroundColor Gray
    $target = (Read-Host "Choice").Trim().ToUpper()

    if ($target -eq 'Q' -or $target -eq '') { Write-Info "nothing deleted"; Pause-End; exit 0 }

    if ($target -eq 'L') {
        if (-not (Confirm-Destructive 'ATTENDANCE LOG' -affected 0 -adminsKept 0 -ip $cfg.deviceIp)) { Pause-End; exit 0 }
        Write-Log "ClearGLog mn=$mn"
        $ok = $false
        try { $ok = $zk.ClearGLog($mn) } catch { Write-Err "ClearGLog raised: $_" }
        Write-Log "ClearGLog -> $ok"
        if ($ok) { Write-Ok "attendance log cleared" } else { Write-Err "ClearGLog returned FALSE" }
        try { [void]$zk.RefreshData($mn) } catch { }
        Show-Counts $zk $mn 'TABLE COUNTS AFTER' | Out-Null
        Pause-End; exit 0
    }

    if (-not $users) { $users = Read-Users $zk $mn }
    if (-not $users) { Write-Err "could not read users - refusing to delete blind"; Pause-End; exit 1 }

    $admins = @($users | Where-Object { $_.priv -gt 0 })
    $victims = @($users | Where-Object { $_.priv -le 0 })

    # ----------------------------------------------------------------------- #
    # SCOPE - all non-admin users, or only the pins named in a file.
    #
    # The file form is the surgical one. At Oxyfit the real problem is not "too
    # many users" but DUPLICATES: 353 members were imported from another system
    # that still drives the same turnstile, so the same finger is enrolled twice -
    # once under the old system's pin, once under MonClub's activeMembershipId.
    # Deleting the old copy fixes the double match and costs those members nothing,
    # because MonClub's pin still carries them. Clearing everything would also
    # delete ~577 users that ONLY the other system knows about.
    # ----------------------------------------------------------------------- #
    Write-Host ""
    Write-Host "SCOPE" -ForegroundColor Cyan
    Write-Host "  [A] ALL non-admin users on the device  ($($victims.Count))"
    Write-Host "  [S] ONLY the pins listed in a file     (one pin per line, # = comment)"
    $scope = (Read-Host "Choice").Trim().ToUpper()

    if ($scope -eq 'S') {
        $listPath = (Read-Host "Path to the pin list").Trim().Trim('"')
        if (-not (Test-Path $listPath)) { Write-Err "no such file: $listPath"; Pause-End; exit 1 }
        $wanted = @{}
        foreach ($line in (Get-Content $listPath)) {
            $p = "$line".Trim()
            if ($p -eq '' -or $p.StartsWith('#')) { continue }
            $wanted[$p] = $true
        }
        if ($wanted.Count -eq 0) { Write-Err "the list is empty"; Pause-End; exit 1 }
        $matched = @($victims | Where-Object { $wanted.ContainsKey("$($_.pin)") })
        $missing = $wanted.Count - $matched.Count
        Write-Info "list has $($wanted.Count) pin(s); $($matched.Count) found on this device, $missing not present here"
        if ($matched.Count -eq 0) { Write-Err "none of those pins are on this device - nothing to do"; Pause-End; exit 0 }
        $victims = $matched
        Write-Log "SCOPE=file '$listPath' listed=$($wanted.Count) matched=$($matched.Count) missing=$missing"
    } elseif ($scope -ne 'A') {
        Write-Warn "unknown scope '$scope' - nothing done"; Pause-End; exit 0
    } else {
        Write-Log "SCOPE=all non-admin victims=$($victims.Count)"
    }

    Write-Host ""
    if ($admins.Count) {
        Write-Ok "PRESERVING $($admins.Count) administrator(s): $(($admins | ForEach-Object { "$($_.pin) ($($_.name))" }) -join ', ')"
    } else {
        Write-Warn "no administrator on this device - none to preserve"
    }

    $who = if ($scope -eq 'S') { "the $($victims.Count) listed pin(s)" } else { "ALL $($victims.Count) non-admin users" }
    $label = switch ($target) {
        'F' { "FINGERPRINTS of $who" }
        'C' { "CARDS of $who" }
        'P' { "PASSWORDS of $who" }
        'U' { "WHOLE USER ROWS (fingers + card + password) of $who" }
        default { $null }
    }
    if (-not $label) { Write-Warn "unknown choice '$target'"; Pause-End; exit 0 }

    if ($target -eq 'U') {
        Write-Warn "SSR_DeleteEnrollData(pin, 12) has never been confirmed on this firmware."
        Write-Warn "Each PIN is written to the log BEFORE the call, so if the device stops"
        Write-Warn "answering, the last line of $($script:LogFile) names the PIN it died on."
    }

    if (-not (Confirm-Destructive $label -affected $victims.Count -adminsKept $admins.Count -ip $cfg.deviceIp)) {
        Pause-End; exit 0
    }

    Write-Log "TARGET=$target label='$label' victims=$($victims.Count) admins_kept=$($admins.Count)"
    $done = 0; $failed = 0; $i = 0

    foreach ($u in $victims) {
        $i++
        $pin = "$($u.pin)"
        switch ($target) {
            'F' {
                # Only slots this user actually has, when we know them; otherwise 0..9.
                # SSR_DelUserTmpExt returns FALSE on an already-empty slot - expected,
                # not an error, so it is not counted as a failure.
                $slots = if ($u.fingers.Count) { $u.fingers } else { 0..9 }
                foreach ($fid in $slots) {
                    Write-Log "DelUserTmpExt pin=$pin finger=$fid"
                    try { [void]$zk.SSR_DelUserTmpExt($mn, $pin, [int]$fid) } catch { $failed++ }
                }
                $done++
            }
            'C' {
                Write-Log "SetStrCardNumber('') + SSR_SetUserInfo pin=$pin"
                try {
                    [void]$zk.SetStrCardNumber('')
                    if ($zk.SSR_SetUserInfo($mn, $pin, "$($u.name)", '', [int]$u.priv, $u.enabled)) { $done++ } else { $failed++ }
                } catch { $failed++ }
            }
            'P' {
                Write-Log "SSR_DeleteEnrollData pin=$pin backup=10"
                try { if ($zk.SSR_DeleteEnrollData($mn, $pin, 10)) { $done++ } else { $failed++ } } catch { $failed++ }
            }
            'U' {
                Write-Log "SSR_DeleteEnrollData pin=$pin backup=12"
                try { if ($zk.SSR_DeleteEnrollData($mn, $pin, 12)) { $done++ } else { $failed++ } } catch { $failed++ }
            }
        }
        if ($i % 50 -eq 0) { Write-Info "... $i / $($victims.Count) (ok=$done fail=$failed)" }
    }

    try { [void]$zk.RefreshData($mn) } catch { }
    Write-Log "DONE ok=$done failed=$failed"
    Write-Host ""
    if ($failed) { Write-Warn "finished: $done ok, $failed failed" } else { Write-Ok "finished: $done ok, 0 failed" }
    Write-Info "log: $($script:LogFile)"

    # ----------------------------------------------------------------------- #
    # verification - counts before vs after, and the admins must still be there
    # ----------------------------------------------------------------------- #
    $after = Show-Counts $zk $mn 'TABLE COUNTS AFTER'
    Write-Host ""
    Write-Host "BEFORE -> AFTER" -ForegroundColor Cyan
    foreach ($pair in $StatusIdx) {
        $idx = [int]$pair[0]
        if ($before.ContainsKey($idx) -and $after.ContainsKey($idx) -and $before[$idx] -ne $after[$idx]) {
            Write-Host ("  [{0,2}] {1,-34} {2} -> {3}" -f $idx, [string]$pair[1], $before[$idx], $after[$idx])
        }
    }

    if ($admins.Count) {
        $still = Read-Users $zk $mn
        $stillAdm = @($still | Where-Object { $_.priv -gt 0 })
        if ($stillAdm.Count -ge $admins.Count) {
            Write-Ok "administrators intact: $($stillAdm.Count) still present"
        } else {
            Write-Err "ADMIN LOST: had $($admins.Count), now $($stillAdm.Count) - do not run this again until that is understood"
            Write-Log "ADMIN LOST before=$($admins.Count) after=$($stillAdm.Count)"
        }
    }
} finally {
    Disconnect-Zkem $zk
}
Pause-End
