# 14_export_terminal_readonly.ps1 - READ-ONLY export of ONE MB2000 terminal to a file.
#
# What it writes (one JSON file in exports\ next to this script, plus a .sha256 file):
#   * the terminal's identity (firmware, serial, MAC, platform, vendor, IP, clock skew)
#   * its capacity counters (GetDeviceStatus 1-12, 21, 22) and its fingerprint
#     algorithm version (~ZKFPVersion)
#   * EVERY user: pin, name, card, privilege, enabled, has-a-password (never the value)
#   * with -Fingers: for every user, which finger slots 0-9 hold a template, the
#     template's size and its SHA-256 (never the template itself), under "slots"
#   * with -IncludeTemplates: the template strings too, under "fingers". The file is then
#     a BACKUP that 10_backup_restore_device.ps1 can restore (copy it into backups\
#     first). It holds BIOMETRIC data: keep it private, never email it, delete it when
#     the cutover is over.
#
# It is READ-ONLY by construction. The complete list of calls it makes on the terminal:
#   through _common.ps1 : SetCommPassword (the PC side of the COMM key, only when a key
#                         is configured), Connect_Net, Disconnect
#   in this file        : GetFirmwareVersion, GetSerialNumber, GetDeviceMAC, GetPlatform,
#                         GetVendor, GetDeviceIP, GetDeviceTime, GetDeviceStatus,
#                         GetSysOption, ReadAllUserID, SSR_GetAllUserInfo,
#                         GetStrCardNumber, SSR_GetUserTmpStr
# Every one of them is documented by the ZKTeco standalone SDK as a read (or, for the
# first three, as the connection itself). There is no call here that sets, deletes,
# clears, enables, disables or refreshes anything on the terminal.
# tests/test_mb2000_export_readonly.py fails the build if a call outside that list ever
# appears in this file or in _common.ps1.
#
# Proven on hardware: the enumeration and the template read are the same calls, in the
# same order, as the Backup mode of 10_backup_restore_device.ps1 and the inspect mode of
# 13_inspect_and_clear_tables.ps1. GetSysOption('~ZKFPVersion') is the call the Access
# driver makes (app/sdk/zk_standalone.py::_read_fp_version); from PowerShell it has not
# been run on an MB2000 - if it fails, the file says fpVersion=null and nothing else
# changes.
#
# BEFORE YOU RUN IT: stop MonClub Access on EVERY PC of the gym (see the cutover plan).
# Whether the terminal accepts this connection while Access holds its own is not known,
# and the gym must be closed: while it runs, nobody should need the turnstile.
#
# USAGE
#   .\14_export_terminal_readonly.ps1                          interactive, asks everything
#   .\14_export_terminal_readonly.ps1 -DeviceIp 192.168.1.247 -Label device10 -Auto
#                                                              users + counters only (fast)
#   .\14_export_terminal_readonly.ps1 -DeviceIp 192.168.1.247 -Label device10 -Fingers -Auto
#                                                              + finger slots (slow part)
#   .\14_export_terminal_readonly.ps1 -DeviceIp 192.168.1.247 -Label device10 -IncludeTemplates -Auto
#                                                              + template strings (backup)
#   add -MaxUsers 50 to time a sample before a full run.
#
# EXIT CODES: 0 = complete export written, 1 = setup / connect failure,
#             2 = the read stopped early (a partial file is written, marked complete=false)
param(
    [string] $DeviceIp         = '',   # '' = ask / config.json
    [int]    $Port             = 0,    # 0  = config.json (4370)
    [int]    $MachineNumber    = 0,    # 0  = config.json (1)
    [string] $Label            = '',   # e.g. device8 ; '' = ask / derived from the IP
    [int]    $MaxUsers         = 0,    # 0  = every user ; N = stop after N (timing sample)
    [switch] $Fingers,                 # read finger slots 0-9 of every user (slow)
    [switch] $IncludeTemplates,        # also save the template strings (implies -Fingers)
    [switch] $Auto                     # no prompts, no pause, meaningful exit code
)

. "$PSScriptRoot\_common.ps1"

# ---------------------------------------------------------------- 32-bit relaunch
# Same forwarding as 12_force_open_door.ps1: a param() block consumes the arguments, so
# $args is empty here and must be rebuilt from $PSBoundParameters.
$forwardArgs = @()
foreach ($bp in $PSBoundParameters.GetEnumerator()) {
    $val = $bp.Value
    if ($val -is [switch]) {
        if ($val.IsPresent) { $forwardArgs += "-$($bp.Key)" }
    } elseif ($val -is [string] -and $val -eq '') {
        continue
    } else {
        $forwardArgs += "-$($bp.Key)"
        $forwardArgs += "$val"
    }
}
Assert-32Bit $PSCommandPath $forwardArgs

function Stop-Run { param([int]$code)
    if (-not $Auto) { Pause-End }
    exit $code
}

Write-Title "14) READ-ONLY terminal export (users, finger slots, counters)"
Write-Host "  This script only READS the terminal. It never writes, deletes or changes anything on it." -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------- settings
$cfg = Get-Config
if ($DeviceIp -ne '') { $cfg.deviceIp = $DeviceIp }
elseif (-not $Auto)   { $cfg.deviceIp = Ask-Default "Terminal IP" $cfg.deviceIp }
if ($Port -gt 0)          { $cfg.devicePort = $Port }
if ($MachineNumber -gt 0) { $cfg.machineNumber = $MachineNumber }
$mn = [int]$cfg.machineNumber

if ($Label -eq '') {
    $defaultLabel = 'ip-' + ($cfg.deviceIp -replace '\W', '-')
    if ($Auto) { $Label = $defaultLabel } else { $Label = Ask-Default "Label for this terminal (e.g. device8, device10)" $defaultLabel }
}
$Label = ($Label -replace '[^A-Za-z0-9_-]', '-')

if ($IncludeTemplates) { $Fingers = [switch]$true }
if (-not $Auto -and -not $PSBoundParameters.ContainsKey('Fingers') -and -not $IncludeTemplates) {
    $ans = Ask-Default "Also read every user's finger slots? This is the SLOW part (10 reads per user). (y/n)" 'n'
    if ($ans -eq 'y') { $Fingers = [switch]$true }
}
if ($Fingers -and -not $Auto -and -not $PSBoundParameters.ContainsKey('IncludeTemplates')) {
    $ans = Ask-Default "Also SAVE the fingerprint templates (a restorable backup - biometric data, keep the file private)? (y/n)" 'n'
    if ($ans -eq 'y') { $IncludeTemplates = [switch]$true }
}

# The Access app on THIS PC must not hold the terminal while we read it. Other PCs of the
# gym cannot be checked from here - the plan says how to stop them.
$running = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like 'MonClubAccess*' })
if ($running.Count -gt 0) {
    Write-Warn ("MonClub Access is running on this PC ({0}). Stop it before exporting (see the cutover plan)." -f (($running | ForEach-Object { $_.ProcessName }) -join ', '))
    if ($Auto) { Write-Err "refusing to run with -Auto while MonClub Access is running"; Stop-Run 1 }
    if ((Ask-Default "Continue anyway? (y/n)" 'n') -ne 'y') { Write-Info "cancelled"; Stop-Run 1 }
}

Save-Config $cfg

$exportDir = Join-Path $PSScriptRoot 'exports'
if (-not (Test-Path $exportDir)) { New-Item -ItemType Directory -Path $exportDir | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$outFile = Join-Path $exportDir ("terminal_{0}_{1}.json" -f $Label, $stamp)

# ---------------------------------------------------------------- helpers (no device calls)
$sha = [System.Security.Cryptography.SHA256]::Create()
function Get-TemplateDigest { param([string]$s)
    # SHA-256 of the DECODED bytes when the string is base64 (what the Access app pushes
    # with SetUserTmpExStr), so it can be compared with MonClub's own template bytes.
    $kind = 'base64'
    try { $bytes = [Convert]::FromBase64String($s) }
    catch { $bytes = [Text.Encoding]::UTF8.GetBytes($s); $kind = 'text' }
    $h = $sha.ComputeHash($bytes)
    return [ordered]@{
        sha256 = ([BitConverter]::ToString($h) -replace '-', '').ToLowerInvariant()
        decodedBytes = $bytes.Length
        hashedAs = $kind
    }
}

$calls = [ordered]@{}
function Count-Call { param([string]$name) if ($calls.Contains($name)) { $calls[$name]++ } else { $calls[$name] = 1 } }

$statusIdx = @(
    @(1, 'admins'), @(2, 'users'), @(3, 'fingerprints'), @(4, 'passwords'),
    @(5, 'operation_records'), @(6, 'attendance_records'), @(7, 'fingerprint_capacity'),
    @(8, 'user_capacity'), @(9, 'attendance_capacity'), @(10, 'fingerprints_free'),
    @(11, 'users_free'), @(12, 'attendance_free'), @(21, 'faces'), @(22, 'face_capacity')
)

$clock = [Diagnostics.Stopwatch]::StartNew()
$timings = [ordered]@{}
$device = [ordered]@{ ip = $cfg.deviceIp; port = [int]$cfg.devicePort; machineNumber = $mn; label = $Label }
$counters = [ordered]@{}
$users = New-Object System.Collections.Generic.List[object]
$complete = $false
$stopReason = $null
$fingerCalls = 0
$fingerMs = 0

# ---------------------------------------------------------------- read
$t0 = $clock.ElapsedMilliseconds
$zk = Connect-Zkem $cfg
Count-Call 'Connect_Net'
$timings.connectMs = $clock.ElapsedMilliseconds - $t0
try {
    # identity - every read independent, like 3_get_device_info.ps1
    $v = ''; try { Count-Call 'GetFirmwareVersion'; if ($zk.GetFirmwareVersion($mn, [ref]$v)) { $device.firmware = "$v" } } catch { }
    $v = ''; try { Count-Call 'GetSerialNumber';    if ($zk.GetSerialNumber($mn, [ref]$v))    { $device.serial = "$v" } } catch { }
    $v = ''; try { Count-Call 'GetDeviceMAC';       if ($zk.GetDeviceMAC($mn, [ref]$v))       { $device.mac = "$v" } } catch { }
    $v = ''; try { Count-Call 'GetPlatform';        if ($zk.GetPlatform($mn, [ref]$v))        { $device.platform = "$v" } } catch { }
    $v = ''; try { Count-Call 'GetVendor';          if ($zk.GetVendor([ref]$v))               { $device.vendor = "$v" } } catch { }
    $v = ''; try { Count-Call 'GetDeviceIP';        if ($zk.GetDeviceIP($mn, [ref]$v))        { $device.reportedIp = "$v" } } catch { }
    $device.fpVersion = $null
    $v = ''; try { Count-Call 'GetSysOption';       if ($zk.GetSysOption($mn, '~ZKFPVersion', [ref]$v)) { $device.fpVersion = "$v" } } catch { }
    try {
        $y=0;$mo=0;$d=0;$h=0;$mi=0;$s=0
        Count-Call 'GetDeviceTime'
        if ($zk.GetDeviceTime($mn, [ref]$y, [ref]$mo, [ref]$d, [ref]$h, [ref]$mi, [ref]$s)) {
            $devTime = Get-Date -Year $y -Month $mo -Day $d -Hour $h -Minute $mi -Second $s
            $device.deviceTime = $devTime.ToString('yyyy-MM-dd HH:mm:ss')
            $device.clockSkewSec = [math]::Round(($devTime - (Get-Date)).TotalSeconds, 1)
        }
    } catch { }

    # counters - like 13_inspect_and_clear_tables.ps1::Get-Counts
    $t0 = $clock.ElapsedMilliseconds
    foreach ($pair in $statusIdx) {
        $idx = [int]$pair[0]
        try {
            $n = 0
            Count-Call 'GetDeviceStatus'
            if ($zk.GetDeviceStatus($mn, $idx, [ref]$n)) { $counters["$idx"] = [ordered]@{ name = [string]$pair[1]; value = [int]$n } }
        } catch { }
    }
    $timings.countersMs = $clock.ElapsedMilliseconds - $t0
    Write-Info ("counters: users={0} fingerprints={1} admins={2} faces={3} users_free={4} fingerprints_free={5} fpVersion={6}" -f `
        $counters['2'].value, $counters['3'].value, $counters['1'].value, $counters['21'].value, $counters['11'].value, $counters['10'].value, $device.fpVersion)

    # users (+ finger slots) - the loop of 10_backup_restore_device.ps1 (Backup) and
    # 13_inspect_and_clear_tables.ps1::Read-Users, same calls, same order
    $t0 = $clock.ElapsedMilliseconds
    Count-Call 'ReadAllUserID'
    if (-not $zk.ReadAllUserID($mn)) {
        $stopReason = 'ReadAllUserID returned false'
        Write-Err $stopReason
    } else {
        while ($true) {
            if ($MaxUsers -gt 0 -and $users.Count -ge $MaxUsers) { $stopReason = "stopped after -MaxUsers $MaxUsers"; break }
            $pin=''; $name=''; $pwd=''; $priv=0; $enabled=$true
            Count-Call 'SSR_GetAllUserInfo'
            if (-not $zk.SSR_GetAllUserInfo($mn, [ref]$pin, [ref]$name, [ref]$pwd, [ref]$priv, [ref]$enabled)) { break }
            $card = ''
            try { Count-Call 'GetStrCardNumber'; [void]$zk.GetStrCardNumber([ref]$card) } catch { }
            $u = [ordered]@{
                pin = "$pin"; name = "$name"; card = "$card"
                privilege = [int]$priv; enabled = [bool]$enabled; hasPassword = ("$pwd" -ne '')
            }
            if ($Fingers) {
                # "slots" = what is on the terminal (no template). "fingers" is written ONLY
                # with -IncludeTemplates, in the shape 10_backup_restore_device.ps1 restores:
                # its Restore clears every slot named in "fingers" before writing the
                # template, so a "fingers" list without templates must never exist.
                $slots = @()
                $restorable = @()
                $f0 = $clock.ElapsedMilliseconds
                for ($fid = 0; $fid -le 9; $fid++) {
                    $tmp=''; $len=0; $ok=$false
                    try { $fingerCalls++; Count-Call 'SSR_GetUserTmpStr'; $ok = $zk.SSR_GetUserTmpStr($mn, "$pin", $fid, [ref]$tmp, [ref]$len) } catch { }
                    if ($ok -and "$tmp" -ne '') {
                        $slot = [ordered]@{ fingerId = $fid; size = [int]$len }
                        $dg = Get-TemplateDigest "$tmp"
                        foreach ($k in $dg.Keys) { $slot[$k] = $dg[$k] }
                        $slots += $slot
                        if ($IncludeTemplates) { $restorable += [ordered]@{ fingerId = $fid; template = "$tmp"; size = [int]$len } }
                    }
                }
                $fingerMs += ($clock.ElapsedMilliseconds - $f0)
                $u.slots = $slots
                if ($IncludeTemplates) { $u.fingers = $restorable }
            }
            $users.Add($u)
            if ($users.Count % 100 -eq 0) { Write-Info ("... {0} users read ({1:N0} s)" -f $users.Count, ($clock.ElapsedMilliseconds / 1000)) }
        }
        if (-not $stopReason) { $complete = $true }
    }
    $timings.usersMs = $clock.ElapsedMilliseconds - $t0
} catch {
    $stopReason = "read stopped by an error: $($_.Exception.Message)"
    Write-Err $stopReason
} finally {
    Disconnect-Zkem $zk
    Count-Call 'Disconnect'
}
$timings.fingersMs = $fingerMs
$timings.fingerReads = $fingerCalls
$timings.msPerFingerRead = if ($fingerCalls -gt 0) { [math]::Round($fingerMs / $fingerCalls, 1) } else { $null }
$timings.totalMs = $clock.ElapsedMilliseconds

# ---------------------------------------------------------------- summary + file
$withFingers = @($users | Where-Object { $_.Contains('slots') -and @($_.slots).Count -gt 0 }).Count
$slotsTotal = 0; foreach ($u in $users) { if ($u.Contains('slots')) { $slotsTotal += @($u.slots).Count } }
$summary = [ordered]@{
    users            = $users.Count
    privileged       = @($users | Where-Object { $_.privilege -gt 0 }).Count
    disabled         = @($users | Where-Object { -not $_.enabled }).Count
    withCard         = @($users | Where-Object { $_.card -ne '' -and $_.card -ne '0' }).Count
    withPassword     = @($users | Where-Object { $_.hasPassword }).Count
    withFingers      = if ($Fingers) { $withFingers } else { $null }
    fingerSlots      = if ($Fingers) { $slotsTotal } else { $null }
}

$doc = [ordered]@{
    schema     = 'monclub.mb2000.terminal_export/1'
    tool       = '14_export_terminal_readonly.ps1'
    takenAt    = (Get-Date).ToString('s')
    pc         = $env:COMPUTERNAME
    complete   = $complete
    stopReason = $stopReason
    options    = [ordered]@{ fingers = [bool]$Fingers; includeTemplates = [bool]$IncludeTemplates; maxUsers = $MaxUsers; fingerRange = '0-9' }
    device     = $device
    counters   = $counters
    timings    = $timings
    calls      = $calls
    summary    = $summary
    users      = $users
}
# 10_backup_restore_device.ps1 restores from "users" (pin, name, card,
# fingers[].fingerId/template) - the same keys, so an -IncludeTemplates export is a
# backup it can restore. It restores every user as privilege 0, enabled, with no
# password, and it WRITES to the terminal: use it only as the rollback the plan
# describes. This script writes into exports\, never into backups\, so a restore always
# needs a deliberate copy.
($doc | ConvertTo-Json -Depth 8) | Set-Content -Path $outFile -Encoding UTF8
$fileHash = (Get-FileHash -Path $outFile -Algorithm SHA256).Hash.ToLowerInvariant()
"$fileHash  $(Split-Path $outFile -Leaf)" | Set-Content -Path ($outFile + '.sha256') -Encoding ASCII

Write-Host ""
Write-Host "EXPORT" -ForegroundColor Cyan
Write-Host ("  terminal        {0} ({1})  serial {2}  firmware {3}" -f $device.ip, $Label, $device.serial, $device.firmware)
Write-Host ("  users           {0}   privileged {1}   disabled {2}   with card {3}" -f $summary.users, $summary.privileged, $summary.disabled, $summary.withCard)
if ($Fingers) { Write-Host ("  finger slots    {0} on {1} users   ({2} reads, {3} ms per read)" -f $summary.fingerSlots, $summary.withFingers, $fingerCalls, $timings.msPerFingerRead) }
Write-Host ("  counters        users={0} fingerprints={1} faces={2}" -f $counters['2'].value, $counters['3'].value, $counters['21'].value)
Write-Host ("  took            {0:N1} s" -f ($timings.totalMs / 1000))
Write-Host ("  calls made      {0}" -f (($calls.Keys | ForEach-Object { "$_ x$($calls[$_])" }) -join ', '))
Write-Host ("  file            {0}" -f $outFile)
Write-Host ("  file SHA-256    {0}" -f $fileHash)
if ($IncludeTemplates) { Write-Warn "this file holds fingerprint templates (biometric data): keep it private" }
if ($complete) { Write-Ok "complete - nothing was written to the terminal"; Stop-Run 0 }
Write-Warn "PARTIAL export ($stopReason) - nothing was written to the terminal"
Stop-Run 2
