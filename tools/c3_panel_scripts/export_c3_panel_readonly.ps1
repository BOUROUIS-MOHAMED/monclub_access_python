# export_c3_panel_readonly.ps1 - READ-ONLY export of ONE PullSDK access panel (C3-400,
# C3-200, C2-...) to a file. Written for the gym 58 cutover
# (docs/plans/2026-09-26_gym58_cutover_plan.md); the MB2000 equivalent is
# tools/mb2000_scripts/14_export_terminal_readonly.ps1.
#
# What it writes (one JSON file in exports\ next to this script, plus a .sha256 file):
#   * the panel's parameters - the list MonClub Access itself reads for its device page
#     (local_access_api_v2.py::_handle_device_info) - and its clock skew
#     ("DateTime", as PullSDKDevice.get_device_time reads it)
#   * row counts of user, userauthorize, transaction, templatev10, template, timezone, holiday
#   * EVERY row of the user table: pin, name, card, and whether a password is set (never
#     the value), plus the other columns the firmware returns (group, start/end time, ...)
#   * the userauthorize rows (pin, time zone, door mask) and, per pin, which finger ids
#     templatev10 holds (FingerID, Valid, Size - never the template itself)
#
# It is READ-ONLY by construction. It reaches plcommpro.dll only through
# _pullsdk_read.ps1, which declares Connect, Disconnect, GetDeviceData,
# GetDeviceDataCount, GetDeviceParam and PullLastError and nothing else.
# tests/test_c3_panel_export_readonly.py checks that, and runs this script against a
# fake panel that has only those six calls. What the firmware does inside a read is
# beyond any test on a fake. The real-time log is never read (GetRTLog would consume
# the panel's live events).
#
# BEFORE YOU RUN IT: stop MonClub Access on EVERY PC of the gym (see the plan). Whether
# the panel accepts a second connection while Access holds one is not known here.
#
# USAGE (from START EXPORT.cmd, or in 32-bit PowerShell; it relaunches itself if needed)
#   .\export_c3_panel_readonly.ps1 -DeviceIp 192.168.0.202 -Label device5 -Auto
#   add -Password <device password> when /gym-devices shows one for this panel
#   add -DllPath <path to plcommpro.dll> when the sdk\ folder is not found
#
# EXIT CODES: 0 = complete export written, 1 = setup / connect failure,
#             2 = a table read failed (a partial file is written, marked complete=false)
param(
    [string] $DeviceIp  = '',
    [int]    $Port      = 4370,
    [string] $Password  = '',
    [int]    $TimeoutMs = 5000,
    [string] $Label     = '',
    [string] $DllPath   = '',
    [switch] $Auto
)

. "$PSScriptRoot\_pullsdk_read.ps1"

# A param() block consumes the arguments: rebuild them for the 32-bit relaunch.
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
Enter-32Bit $PSCommandPath $forwardArgs

function Stop-Run { param([int]$code)
    if (-not $Auto) { Write-Host ""; Read-Host "Press ENTER to close" | Out-Null }
    exit $code
}

Write-Title "READ-ONLY panel export (PullSDK: users, cards, door rights, counts)"
Write-Host "  This script only READS the panel. It never writes, deletes or changes anything on it." -ForegroundColor Green
Write-Host ""

if ($DeviceIp -eq '') {
    if ($Auto) { Write-Err "-DeviceIp is required with -Auto"; Stop-Run 1 }
    $DeviceIp = Read-Host "Panel IP (type it in full, e.g. 192.168.0.202)"
}
if ($Label -eq '') { $Label = 'ip-' + ($DeviceIp -replace '\W', '-') }
$Label = ($Label -replace '[^A-Za-z0-9_-]', '-')

$running = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like 'MonClubAccess*' })
if ($running.Count -gt 0) {
    Write-Err ("MonClub Access is running on this PC ({0}). Quit it first (tray icon > Quit)." -f (($running | ForEach-Object { $_.ProcessName }) -join ', '))
    Stop-Run 1
}

$dll = Resolve-PlcommproDll -Explicit $DllPath -Here $PSScriptRoot
if (-not $dll) { Write-Err "plcommpro.dll not found: pass -DllPath, or copy tools\mb2000_scripts\sdk next to this folder"; Stop-Run 1 }
Write-Info "plcommpro.dll: $dll"

$exportDir = Join-Path $PSScriptRoot 'exports'
if (-not (Test-Path $exportDir)) { New-Item -ItemType Directory -Path $exportDir | Out-Null }
$outFile = Join-Path $exportDir ("panel_{0}_{1}.json" -f $Label, (Get-Date -Format 'yyyyMMdd_HHmmss'))

# ---------------------------------------------------------------- helpers (no device calls)
$calls = [ordered]@{}
function Count-Call { param([string]$name) if ($calls.Contains($name)) { $calls[$name]++ } else { $calls[$name] = 1 } }

# app/core/utils.py::parse_device_text: either "K=V<TAB>K=V" rows, or a header line of
# comma-separated field names followed by comma-separated rows.
function ConvertFrom-DeviceText { param([string]$Text)
    $lines = @(($Text -replace "`r", '') -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    $rows = New-Object System.Collections.Generic.List[object]
    $bad = 0
    if ($lines.Count -eq 0) { return [pscustomobject]@{ rows = $rows; malformed = 0 } }
    if ($lines[0].Contains('=') -and $lines[0].Contains("`t")) {
        foreach ($ln in $lines) {
            $kv = [ordered]@{}
            foreach ($p in ($ln -split "`t")) { if ($p.Contains('=')) { $i = $p.IndexOf('='); $kv[$p.Substring(0, $i).Trim()] = $p.Substring($i + 1).Trim() } }
            if ($kv.Count -gt 0) { $rows.Add($kv) }
        }
        return [pscustomobject]@{ rows = $rows; malformed = 0 }
    }
    $headers = @($lines[0] -split ',' | ForEach-Object { $_.Trim() })
    for ($r = 1; $r -lt $lines.Count; $r++) {
        $cols = @($lines[$r] -split ',' | ForEach-Object { $_.Trim() })
        if ($cols.Count -ne $headers.Count) { $bad++ }
        $kv = [ordered]@{}
        for ($i = 0; $i -lt [Math]::Min($headers.Count, $cols.Count); $i++) { if ($headers[$i]) { $kv[$headers[$i]] = $cols[$i] } }
        if ($kv.Count -gt 0) { $rows.Add($kv) }
    }
    return [pscustomobject]@{ rows = $rows; malformed = $bad }
}

function Get-Field { param($row, [string[]]$names)
    foreach ($n in $names) { foreach ($k in $row.Keys) { if ($k -ieq $n) { return "$($row[$k])" } } }
    return ''
}

# pullsdk.py::zk_datetime_decode
function ConvertFrom-ZkDateTime { param([long]$v)
    $t = $v
    $s = $t % 60; $t = [math]::Floor($t / 60)
    $mi = $t % 60; $t = [math]::Floor($t / 60)
    $h = $t % 24; $t = [math]::Floor($t / 24)
    $d = ($t % 31) + 1; $t = [math]::Floor($t / 31)
    $mo = ($t % 12) + 1; $t = [math]::Floor($t / 12)
    return Get-Date -Year ([int]$t + 2000) -Month ([int]$mo) -Day ([int]$d) -Hour ([int]$h) -Minute ([int]$mi) -Second ([int]$s)
}

# local_access_api_v2.py::_handle_device_info's default item list and table list.
$paramItems = @('~DeviceName', '~SerialNumber', 'FirmVer', 'MachineType', 'LockCount', 'ReaderCount',
    'AuxInCount', 'AuxOutCount', 'IPAddress', 'NetMask', 'GATEIPAddress', 'MAC', '~MaxUserCount',
    '~MaxAttLogCount', '~MaxUserFingerCount', 'AntiPassback', 'InterLock', 'DeviceID',
    'Door1Drivertime', 'Door2Drivertime', 'Door3Drivertime', 'Door4Drivertime',
    'Door1SensorType', 'Door2SensorType', 'Door3SensorType', 'Door4SensorType',
    'Door1VerifyType', 'Door2VerifyType', 'Door3VerifyType', 'Door4VerifyType')
$countTables = @('user', 'userauthorize', 'transaction', 'templatev10', 'template', 'timezone', 'holiday')

$clock = [Diagnostics.Stopwatch]::StartNew()
$timings = [ordered]@{}
$device = [ordered]@{ ip = $DeviceIp; port = $Port; label = $Label; passwordGiven = ($Password -ne '') }
$params = [ordered]@{}
$counts = [ordered]@{}
$errors = New-Object System.Collections.Generic.List[string]
$users = New-Object System.Collections.Generic.List[object]
$authorize = New-Object System.Collections.Generic.List[object]
$fingerIdsByPin = @{}
$complete = $false

# ---------------------------------------------------------------- read
$sdk = New-PullSdk -DllPath $dll
$conn = "protocol=TCP,ipaddress=$DeviceIp,port=$Port,timeout=$TimeoutMs,passwd=$Password"
$t0 = $clock.ElapsedMilliseconds
Count-Call 'Connect'
$h = $sdk.Connect($conn)
$timings.connectMs = $clock.ElapsedMilliseconds - $t0
if ($null -eq $h -or $h -eq [IntPtr]::Zero) {
    Count-Call 'PullLastError'
    $err = $sdk.PullLastError()
    Write-Err ("CONNECT FAILED to {0}:{1} (PullLastError={2}, {3} ms). Nothing was read and nothing was written." -f $DeviceIp, $Port, $err, $timings.connectMs)
    Stop-Run 1
}
Write-Ok ("connected to {0}:{1} in {2} ms" -f $DeviceIp, $Port, $timings.connectMs)

try {
    # parameters: the whole list in one call, as Access does; one by one if the panel refuses it
    $t0 = $clock.ElapsedMilliseconds
    Count-Call 'GetDeviceParam'
    $res = $sdk.GetDeviceParam($h, ($paramItems -join ','))
    $raw = if ($res.rc -ge 0) { $res.text } else { '' }
    if ($res.rc -lt 0) {
        $errors.Add("GetDeviceParam(all) rc=$($res.rc)")
        $parts = @()
        foreach ($it in $paramItems) {
            Count-Call 'GetDeviceParam'
            $one = $sdk.GetDeviceParam($h, $it)
            if ($one.rc -ge 0) { $parts += $one.text } else { $params[$it] = $null }
        }
        $raw = $parts -join ','
    }
    foreach ($seg in (($raw -replace "`r`n", "`n" -replace "`r", "`n") -split "[`n,]")) {
        $seg = $seg.Trim()
        if ($seg.Contains('=')) { $i = $seg.IndexOf('='); $params[$seg.Substring(0, $i).Trim()] = $seg.Substring($i + 1).Trim() }
    }
    Count-Call 'GetDeviceParam'
    $dt = $sdk.GetDeviceParam($h, 'DateTime')
    if ($dt.rc -ge 0) {
        $v = if ($dt.text.Contains('=')) { $dt.text.Split('=', 2)[1].Trim() } else { $dt.text.Trim() }
        try {
            $devTime = ConvertFrom-ZkDateTime ([long]$v)
            $device.deviceTime = $devTime.ToString('yyyy-MM-dd HH:mm:ss')
            $device.clockSkewSec = [math]::Round(($devTime - (Get-Date)).TotalSeconds, 1)
        } catch { $errors.Add("DateTime not decodable: $v") }
    } else { $errors.Add("GetDeviceParam(DateTime) rc=$($dt.rc)") }
    $timings.paramsMs = $clock.ElapsedMilliseconds - $t0

    $t0 = $clock.ElapsedMilliseconds
    foreach ($t in $countTables) {
        Count-Call 'GetDeviceDataCount'
        $counts[$t] = [int]$sdk.GetDeviceDataCount($h, $t, '', '')
    }
    $timings.countsMs = $clock.ElapsedMilliseconds - $t0
    Write-Info ("counts: " + (($counts.Keys | ForEach-Object { "$_=$($counts[$_])" }) -join ' '))

    # the user table, every column the firmware returns
    $t0 = $clock.ElapsedMilliseconds
    Count-Call 'GetDeviceData'
    $res = $sdk.GetDeviceData($h, 'user', '*', '', '')
    $timings.userReadMs = $clock.ElapsedMilliseconds - $t0
    if ($res.rc -lt 0) { throw "GetDeviceData(user) rc=$($res.rc)" }
    $parsed = ConvertFrom-DeviceText $res.text
    $device.userRowsMalformed = $parsed.malformed
    foreach ($r in $parsed.rows) {
        $extra = [ordered]@{}
        foreach ($k in $r.Keys) {
            if ($k -notin @('Pin', 'Name', 'CardNo', 'Password')) { $extra[$k] = "$($r[$k])" }
        }
        $users.Add([ordered]@{
            pin = (Get-Field $r @('Pin')); name = (Get-Field $r @('Name')); card = (Get-Field $r @('CardNo'))
            privilege = 0; enabled = $true; hasPassword = ((Get-Field $r @('Password')) -ne '')
            other = $extra
        })
    }

    $t0 = $clock.ElapsedMilliseconds
    Count-Call 'GetDeviceData'
    $res = $sdk.GetDeviceData($h, 'userauthorize', '*', '', '')
    $timings.authorizeReadMs = $clock.ElapsedMilliseconds - $t0
    if ($res.rc -lt 0) { throw "GetDeviceData(userauthorize) rc=$($res.rc)" }
    foreach ($r in (ConvertFrom-DeviceText $res.text).rows) {
        $authorize.Add([ordered]@{
            pin = (Get-Field $r @('Pin'))
            timezone = (Get-Field $r @('AuthorizeTimezoneId', 'TimeZoneID', 'TimeZone'))
            doors = (Get-Field $r @('AuthorizeDoorId', 'DoorID'))
        })
    }

    # finger ids per pin - only the fields named, never the Template column
    if ($counts['templatev10'] -gt 0) {
        $t0 = $clock.ElapsedMilliseconds
        Count-Call 'GetDeviceData'
        $res = $sdk.GetDeviceData($h, 'templatev10', "Pin`tFingerID`tValid`tSize", '', '')
        $timings.templateListMs = $clock.ElapsedMilliseconds - $t0
        if ($res.rc -lt 0) { throw "GetDeviceData(templatev10) rc=$($res.rc)" }
        foreach ($r in (ConvertFrom-DeviceText $res.text).rows) {
            $p = Get-Field $r @('Pin')
            if (-not $fingerIdsByPin.ContainsKey($p)) { $fingerIdsByPin[$p] = New-Object System.Collections.Generic.List[object] }
            $fingerIdsByPin[$p].Add([ordered]@{ fingerId = (Get-Field $r @('FingerID')); valid = (Get-Field $r @('Valid')); size = (Get-Field $r @('Size')) })
        }
    }
    $complete = $true
} catch {
    $errors.Add("read stopped: $($_.Exception.Message)")
    Write-Err "read stopped: $($_.Exception.Message)"
} finally {
    Count-Call 'Disconnect'
    $sdk.Disconnect($h)
}
$timings.totalMs = $clock.ElapsedMilliseconds

# ---------------------------------------------------------------- summary + file
$doorsByPin = @{}
foreach ($a in $authorize) { $doorsByPin[$a.pin] = $a.doors }
foreach ($u in $users) {
    $u.doors = if ($doorsByPin.ContainsKey($u.pin)) { $doorsByPin[$u.pin] } else { $null }
    $u.fingerIds = if ($fingerIdsByPin.ContainsKey($u.pin)) { @($fingerIdsByPin[$u.pin] | ForEach-Object { $_.fingerId }) } else { @() }
}
$userPins = @{}; foreach ($u in $users) { $userPins[$u.pin] = $true }
$summary = [ordered]@{
    users              = $users.Count
    withCard           = @($users | Where-Object { $_.card -ne '' -and $_.card -ne '0' }).Count
    withPassword       = @($users | Where-Object { $_.hasPassword }).Count
    withDoorRights     = @($users | Where-Object { $null -ne $_.doors }).Count
    withFingers        = @($users | Where-Object { @($_.fingerIds).Count -gt 0 }).Count
    authorizeRows      = $authorize.Count
    authorizeWithoutUser = @($authorize | Where-Object { -not $userPins.ContainsKey($_.pin) }).Count
    templateRowsListed = (@($fingerIdsByPin.Values | ForEach-Object { $_.Count }) | Measure-Object -Sum).Sum
}

$doc = [ordered]@{
    schema   = 'monclub.pullsdk.panel_export/1'
    tool     = 'export_c3_panel_readonly.ps1'
    takenAt  = (Get-Date).ToString('s')
    pc       = $env:COMPUTERNAME
    complete = $complete
    errors   = $errors
    options  = [ordered]@{ fingers = $false; includeTemplates = $false }
    device   = $device
    params   = $params
    counts   = $counts
    timings  = $timings
    calls    = $calls
    summary  = $summary
    users    = $users
    authorize = $authorize
}
($doc | ConvertTo-Json -Depth 8) | Set-Content -Path $outFile -Encoding UTF8
$sha = [System.Security.Cryptography.SHA256]::Create()
try { $fileHash = ([System.BitConverter]::ToString($sha.ComputeHash([System.IO.File]::ReadAllBytes($outFile))) -replace '-','').ToLowerInvariant() }
finally { $sha.Dispose() }
"$fileHash  $(Split-Path $outFile -Leaf)" | Set-Content -Path ($outFile + '.sha256') -Encoding ASCII

Write-Host ""
Write-Host "EXPORT" -ForegroundColor Cyan
Write-Host ("  panel           {0} ({1})  serial {2}  firmware {3}" -f $DeviceIp, $Label, $params['~SerialNumber'], $params['FirmVer'])
Write-Host ("  users           {0}   with card {1}   with door rights {2}   with fingers {3}" -f $summary.users, $summary.withCard, $summary.withDoorRights, $summary.withFingers)
Write-Host ("  counts          " + (($counts.Keys | ForEach-Object { "$_=$($counts[$_])" }) -join ' '))
Write-Host ("  clock skew      {0} s" -f $device.clockSkewSec)
Write-Host ("  took            {0:N1} s" -f ($timings.totalMs / 1000))
Write-Host ("  calls made      {0}" -f (($calls.Keys | ForEach-Object { "$_ x$($calls[$_])" }) -join ', '))
Write-Host ("  file            {0}" -f $outFile)
Write-Host ("  file SHA-256    {0}" -f $fileHash)
if ($complete) { Write-Ok "complete - nothing was written to the panel"; Stop-Run 0 }
Write-Warn "PARTIAL export - nothing was written to the panel"
Stop-Run 2
