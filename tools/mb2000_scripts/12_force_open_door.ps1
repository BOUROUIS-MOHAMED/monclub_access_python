# 12_force_open_door.ps1 - SUSTAINED force-open of the door relay (ACUnlock), with a
# log file you can send back. Script 9 stays the minimal one-shot relay test; run THIS
# one when the desk needs the door held open, or when a single pulse was inconclusive
# and you want a repeated, timed, fully logged run.
#
# SIGNATURE USED - the only thing about ACUnlock this repo can prove:
#   ACUnlock(machineNumber, delayDeciseconds) -> bool
#   [CODE: zkemkeeper_guide.md section "Door" -- zk.ACUnlock(1, int(delay_ds)) -> bool ;
#    delay is in DECISECONDS]        10 deciseconds = 1 second.
#
# WHAT THIS SCRIPT DOES NOT KNOW. Do not let its output imply otherwise:
#
#  [UNKNOWN]    The MAXIMUM delay ACUnlock accepts. zkemkeeper_guide.md documents NO
#               SDK maximum, so none is assumed here. -MaxDeciseconds defaults to 600
#               (= 60 s) only because 60 s is the largest pulse MonClub Access itself
#               can ever send (app/api/local_access_api_v2.py clamps pulseSeconds to
#               1..60) [CODE], the same 1..600 ds the driver itself clamps to [CODE].
#               That is an APP ceiling, NOT a proven SDK limit. Raise it on purpose
#               with -MaxDeciseconds if you want to probe higher - you are then in
#               undocumented territory, and what happens is a finding.
#
#  [UNKNOWN]    Whether the delay argument holds the relay closed for that duration at
#               all, or merely triggers a fixed pulse configured on the device.
#
#  [UNKNOWN]    What a second ACUnlock arriving BEFORE the previous delay expires does
#               (extend / restart / ignore / error). -Repeat deliberately does exactly
#               that. Whatever happens is DATA to report, not supported behaviour.
#
#  [UNKNOWN]    Whether the firmware exposes a REASON for a FALSE return.
#               zkemkeeper_guide.md documents no error-detail call for this SDK, so
#               this script does not invent one: FALSE is logged as FALSE, no reason.
#
#  [UNVERIFIED] Whether ACUnlock physically releases THIS turnstile (GATE 4). Since
#               2026-09-04 MonClub Access ISSUES the call by default on the standalone
#               family (per-device switch; _OPEN_DOOR_FAMILY_DEFAULT = True in
#               app/sdk/zk_standalone.py) [CODE] - but that is a software DECISION,
#               not evidence. Only an operator reporting a PASS from script 9 or from
#               this one settles whether the relay actually releases. A
#               "DOOR_OPEN result=ok" line in the app log does not settle it either:
#               it means the COM call returned True.
#
#  [COMMENT]    ACUnlock returning TRUE with no physical release is a WIRING fault, not
#               an SDK one (zkemkeeper_guide.md section 8).
#
# MEASUREMENT CAVEAT: the elapsed ms printed per attempt is the duration of the COM
# CALL. It says nothing about how long the relay actually stayed closed.
#
# FIDELITY CAVEAT: MonClub Access hardcodes ACUnlock(1, ds) in _do_open_door
# (app/sdk/zk_standalone.py) [CODE]. This script defaults to config.json machineNumber
# (1). A PASS obtained with a different -MachineNumber does NOT transfer to the app.
#
# EXIT CODES (for -Auto / scripted use):
#   0 = every ACUnlock returned TRUE       2 = at least one returned FALSE
#   1 = setup / connect failure            3 = at least one call threw
#
# USAGE
#   .\12_force_open_door.ps1                                  interactive, asks all
#   .\12_force_open_door.ps1 -Seconds 10                      one 10 s pulse
#   .\12_force_open_door.ps1 -Seconds 10 -Repeat 30 -IntervalSeconds 9 -Auto
#                                                             ~4.5 min sustained, silent
param(
    [double] $Seconds         = 0,    # 0  = ask (interactive) / 5 with -Auto
    [int]    $Repeat          = 0,    # 0  = ask (interactive) / 1 with -Auto
    [double] $IntervalSeconds = -1,   # <0 = ask (interactive) / = -Seconds with -Auto
    [string] $DeviceIp        = '',   # '' = use config.json
    [int]    $MachineNumber   = 0,    # 0  = use config.json (1)
    [int]    $MaxDeciseconds  = 600,  # script-local ceiling, NOT an SDK limit (see header)
    [switch] $Auto                    # no prompts, no Read-Host, meaningful exit code
)

. "$PSScriptRoot\_common.ps1"

# ---------------------------------------------------------------- 32-bit relaunch
# A param() block CONSUMES the arguments, so $args is EMPTY here - passing $args to
# Assert-32Bit (as the parameterless scripts do) would relaunch under SysWOW64 with
# DEFAULTS and silently discard -Seconds/-Repeat/-Auto. Rebuild the argument list from
# $PSBoundParameters instead. Numbers are formatted with the INVARIANT culture: on a
# French-locale PC "2,5" would not bind back to [double].
$forwardArgs = @()
foreach ($bp in $PSBoundParameters.GetEnumerator()) {
    $val = $bp.Value
    if ($val -is [switch]) {
        if ($val.IsPresent) { $forwardArgs += "-$($bp.Key)" }
    } elseif ($val -is [string] -and $val -eq '') {
        # An empty string does not survive "powershell -File ... -Key ''": the next
        # token would bind to -Key instead. It is also the default for every string
        # parameter here, so dropping it changes nothing.
        continue
    } else {
        $forwardArgs += "-$($bp.Key)"
        if ($val -is [double] -or $val -is [single] -or $val -is [decimal]) {
            $forwardArgs += [Convert]::ToString($val, [Globalization.CultureInfo]::InvariantCulture)
        } else {
            $forwardArgs += "$val"
        }
    }
}
Assert-32Bit $PSCommandPath $forwardArgs

# ---------------------------------------------------------------- run log
# One file per run in logs\ - this is what the operator sends back.
$script:LogPath = $null
$script:LogBroken = $false

function Start-RunLog {
    # Never let logging kill the run: the pack is often on a USB stick, which can be
    # read-only. On failure the script keeps going and says so at the end.
    try {
        $dir = Join-Path $PSScriptRoot 'logs'
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
        $base = Join-Path $dir ("force_open_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
        $path = "$base.log"
        $n = 2
        # Two launches inside the same second must not share one file.
        while (Test-Path -LiteralPath $path) { $path = "{0}_{1}.log" -f $base, $n; $n++ }
        $script:LogPath = $path
    } catch {
        $script:LogBroken = $true
        Write-Warn ("cannot create the log folder ({0}) - console output only." -f $_.Exception.Message)
    }
    return $script:LogPath
}

function Write-Log {
    param([string]$Line, [string]$Level = 'i')
    $rec = "{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Line
    if ($script:LogPath) {
        try { Add-Content -LiteralPath $script:LogPath -Value $rec -Encoding UTF8 }
        catch {
            if (-not $script:LogBroken) {
                $script:LogBroken = $true
                Write-Warn ("log write FAILED ({0}) - the console text is the only record from here on." -f $_.Exception.Message)
            }
        }
    }
    switch ($Level) {
        'ok'    { Write-Ok   $Line }
        'err'   { Write-Err  $Line }
        'warn'  { Write-Warn $Line }
        default { Write-Info $Line }
    }
}

# Says where the record is - or that there isn't one, so nobody is told to send a file
# that was never written (a read-only USB stick does exactly that).
function Write-RunLogPointer {
    if ($script:LogBroken -or -not $script:LogPath) {
        Write-Warn "NO LOG FILE was written (see the warning above) - copy this console text instead."
    } else {
        Write-Log ("SEND THIS FILE BACK: {0}" -f $script:LogPath) 'ok'
    }
}

# Locale-tolerant number parse: the desk PC may be French ("2,5").
function ConvertTo-Num {
    param([string]$Text, [double]$Fallback)
    $t = "$Text".Trim().Replace(',', '.')
    $out = 0.0
    if ([double]::TryParse($t, [Globalization.NumberStyles]::Float,
                           [Globalization.CultureInfo]::InvariantCulture, [ref]$out)) { return $out }
    return $Fallback
}

# ---------------------------------------------------------------- connect (no prompts)
# _common.ps1's Connect-Zkem ends its failure path with Pause-End (Read-Host), which
# would hang forever in -Auto at the desk. Same documented sequence, but it returns
# $null instead of blocking. Signatures are the ones _common.ps1 records:
#   New-Object -ComObject zkemkeeper.CZKEM  (fallback zkemkeeper.ZKEM)
#   SetCommPassword([int]$key)  BEFORE  Connect_Net($ip, [int]$port) -> bool
function Connect-ZkemQuiet {
    param($cfg)
    $zk = $null
    foreach ($progId in @('zkemkeeper.CZKEM', 'zkemkeeper.ZKEM')) {
        try { $zk = New-Object -ComObject $progId; Write-Log ("COM object created ({0})" -f $progId); break }
        catch { }
    }
    if ($null -eq $zk) {
        Write-Log "zkemkeeper COM object not registered - run 1_register_zkemkeeper.ps1 (admin) first." 'err'
        return $null
    }
    # Whether a COMM key is set is the first thing to check when Connect_Net says FALSE,
    # so record THAT (never the key itself - this file gets emailed).
    if ("$($cfg.commKey)" -ne '') {
        Write-Log "comm key: set"
        try { [void]$zk.SetCommPassword([int]$cfg.commKey) }
        catch { Write-Log ("SetCommPassword failed: {0}" -f $_.Exception.Message) 'warn' }
    } else {
        Write-Log "comm key: none"
    }
    Write-Log ("connecting to {0}:{1} ..." -f $cfg.deviceIp, $cfg.devicePort)
    $ok = $false
    try { $ok = $zk.Connect_Net($cfg.deviceIp, [int]$cfg.devicePort) }
    catch { Write-Log ("Connect_Net threw: {0}" -f $_.Exception.Message) 'err'; return $null }
    if (-not $ok) {
        Write-Log "Connect_Net returned FALSE - check IP/port, network, device COMM key (menu -> C)." 'err'
        return $null
    }
    Write-Log "connected" 'ok'
    return $zk
}

# ---------------------------------------------------------------- device snapshot
# Same reads as 3_get_device_info.ps1 (identity + counts + clock), each independent so
# one unsupported call never hides the rest. Taken BEFORE and AFTER the attempts: the
# att-log counter and the clock skew are what make this log readable a week later.
function Write-DeviceSnapshot {
    param($zk, [int]$mn, [string]$Tag)

    Write-Log ("---------------- device snapshot [{0}] ----------------" -f $Tag)

    try { $s = ''; if ($zk.GetFirmwareVersion($mn, [ref]$s)) { Write-Log ("  firmware        {0}" -f $s) } else { Write-Log "  firmware        (returned false)" } }
    catch { Write-Log ("  firmware        (unsupported: {0})" -f $_.Exception.Message) }

    try { $s = ''; if ($zk.GetSerialNumber($mn, [ref]$s)) { Write-Log ("  serial          {0}" -f $s) } else { Write-Log "  serial          (returned false)" } }
    catch { Write-Log ("  serial          (unsupported: {0})" -f $_.Exception.Message) }

    try { $s = ''; if ($zk.GetDeviceMAC($mn, [ref]$s)) { Write-Log ("  mac             {0}" -f $s) } else { Write-Log "  mac             (returned false)" } }
    catch { Write-Log ("  mac             (unsupported: {0})" -f $_.Exception.Message) }

    try { $s = ''; if ($zk.GetPlatform($mn, [ref]$s)) { Write-Log ("  platform        {0}" -f $s) } else { Write-Log "  platform        (returned false)" } }
    catch { Write-Log ("  platform        (unsupported: {0})" -f $_.Exception.Message) }

    try { $s = ''; if ($zk.GetVendor([ref]$s)) { Write-Log ("  vendor          {0}" -f $s) } else { Write-Log "  vendor          (returned false)" } }
    catch { Write-Log ("  vendor          (unsupported: {0})" -f $_.Exception.Message) }

    try { $s = ''; if ($zk.GetDeviceIP($mn, [ref]$s)) { Write-Log ("  device ip       {0}" -f $s) } else { Write-Log "  device ip       (returned false)" } }
    catch { Write-Log ("  device ip       (unsupported: {0})" -f $_.Exception.Message) }

    # Pairs, NOT [ordered]@{ 1 = 'admins'; ... }. In PowerShell an ordered dictionary
    # indexed with an INTEGER returns the entry at that POSITION, not the entry with
    # that KEY - so $map[6] is out of range and $map[1] is the SECOND entry. Written
    # with a hashtable this loop silently mislabels the counters (the admin count
    # printed as "users", and no label at all for indexes 6 and 8). Verified in 5.1.
    # GetDeviceStatus index: 1=admins 2=users 3=fingerprints 6=att logs 8=face.
    $statusFields = @(
        @(1, 'admins'), @(2, 'users'), @(3, 'fingerprints'),
        @(6, 'att logs'), @(8, 'face templates')
    )
    foreach ($sf in $statusFields) {
        $idx = [int]$sf[0]
        $label = [string]$sf[1]
        try {
            $n = 0
            if ($zk.GetDeviceStatus($mn, $idx, [ref]$n)) { Write-Log ("  {0,-15} {1}" -f $label, $n) }
            else { Write-Log ("  {0,-15} (returned false)" -f $label) }
        } catch { Write-Log ("  {0,-15} (unsupported)" -f $label) }
    }

    try {
        $y = 0; $mo = 0; $d = 0; $h = 0; $mi = 0; $sec = 0
        if ($zk.GetDeviceTime($mn, [ref]$y, [ref]$mo, [ref]$d, [ref]$h, [ref]$mi, [ref]$sec)) {
            $devTime = Get-Date -Year $y -Month $mo -Day $d -Hour $h -Minute $mi -Second $sec
            $skew = [math]::Round(($devTime - (Get-Date)).TotalSeconds, 1)
            Write-Log ("  device time     {0}  (skew vs this PC: {1}s)" -f $devTime.ToString('yyyy-MM-dd HH:mm:ss'), $skew)
        } else { Write-Log "  device time     (returned false)" }
    } catch { Write-Log ("  device time     (unsupported: {0})" -f $_.Exception.Message) }
}

# ================================================================ run
$logPath = Start-RunLog
Write-Title "12) Force-open door - sustained ACUnlock (GATE 4)"

$bitness = '64-bit'
if (-not [Environment]::Is64BitProcess) { $bitness = '32-bit' }
Write-Log ("script 12 start   process={0}   auto={1}" -f $bitness, [bool]$Auto)
# Echoed so the log itself proves the 32-bit relaunch preserved the parameters.
Write-Log ("parameters: Seconds={0} Repeat={1} IntervalSeconds={2} DeviceIp='{3}' MachineNumber={4} MaxDeciseconds={5}" -f `
    $Seconds, $Repeat, $IntervalSeconds, $DeviceIp, $MachineNumber, $MaxDeciseconds)
Write-Log ("log file: {0}" -f $logPath)

$cfg = Get-Config
if ($DeviceIp -ne '') { $cfg.deviceIp = $DeviceIp }
if (-not $Auto) {
    $cfg.deviceIp = Ask-Default "Device IP" $cfg.deviceIp
    Save-Config $cfg
}

$mn = [int]$cfg.machineNumber
if ($MachineNumber -gt 0) { $mn = $MachineNumber }
if ($mn -ne 1) {
    Write-Log ("machineNumber={0}, but MonClub Access always calls ACUnlock(1, ds). A PASS here does NOT transfer to the app." -f $mn) 'warn'
}

if ($Seconds -le 0) {
    if ($Auto) { $Seconds = 5 }
    else { $Seconds = ConvertTo-Num (Ask-Default "Open duration in seconds" '5') 5 }
}
if ($Repeat -le 0) {
    if ($Auto) { $Repeat = 1 }
    else { $Repeat = [int](ConvertTo-Num (Ask-Default "How many times to re-fire it (1 = single pulse)" '1') 1) }
}
if ($Repeat -lt 1) { $Repeat = 1 }

# ---- duration -> deciseconds, with the script-local ceiling (NOT an SDK limit) ----
# Clamp BEFORE the [int] cast: [int] on a double past Int32 throws, and with
# $ErrorActionPreference = 'Stop' that would kill the run (mid-loop, for the interval).
# Clamp BEFORE resolving the interval too: the default gap between re-fires is the
# EFFECTIVE open duration. Deriving it from the pre-clamp -Seconds would leave a hole
# (ask for 120 s, get a 60 s pulse re-fired every 120 s = a 60 s gap on the door).
if ($MaxDeciseconds -lt 1) { $MaxDeciseconds = 1 }
$requestedDs = [math]::Round([double]$Seconds * 10.0)
$delayDs = 1
if ($requestedDs -gt [double]$MaxDeciseconds) {
    Write-Log ("CLAMPED: requested {0} ds ({1} s) is above this script's ceiling of {2} ds; using {2} ds. That ceiling is the MonClub Access limit (pulseSeconds 1..60), NOT a proven SDK maximum - raise it with -MaxDeciseconds to probe higher." -f `
        $requestedDs, $Seconds, $MaxDeciseconds) 'warn'
    $delayDs = $MaxDeciseconds
} elseif ($requestedDs -ge 1) {
    $delayDs = [int]$requestedDs
}
$effectiveSec = $delayDs / 10.0

if ($IntervalSeconds -lt 0) {
    if ($Auto) { $IntervalSeconds = $effectiveSec }
    else {
        $defaultInterval = [Convert]::ToString($effectiveSec, [Globalization.CultureInfo]::InvariantCulture)
        $IntervalSeconds = ConvertTo-Num (Ask-Default "Seconds between re-fires" $defaultInterval) $effectiveSec
    }
}

# Same guard for the gap between re-fires: cap at one hour so a fat-fingered value
# cannot overflow Start-Sleep's [int] milliseconds halfway through the loop.
$maxIntervalSec = 3600
if ($IntervalSeconds -gt $maxIntervalSec) {
    Write-Log ("CLAMPED: interval {0} s is above this script's ceiling of {1} s; using {1} s." -f $IntervalSeconds, $maxIntervalSec) 'warn'
    $IntervalSeconds = $maxIntervalSec
}
if ($Repeat -gt 1 -and $IntervalSeconds -gt $effectiveSec) {
    Write-Log ("NOTE: the gap between re-fires ({0} s) is longer than the open duration ({1} s), so this is a repeated pulse, not a sustained open." -f `
        $IntervalSeconds, $effectiveSec) 'warn'
}
Write-Log ("plan: ACUnlock({0}, {1}) x{2}, every {3} s   (delay is in DECISECONDS; {1} ds = {4} s nominal)" -f `
    $mn, $delayDs, $Repeat, $IntervalSeconds, ($delayDs / 10.0))

$zk = Connect-ZkemQuiet $cfg
if ($null -eq $zk) {
    Write-Log "aborting: not connected, nothing was attempted." 'err'
    Write-RunLogPointer
    if (-not $Auto) { Pause-End }
    exit 1
}

$trueCount  = 0
$falseCount = 0
$errCount   = 0

try {
    Write-DeviceSnapshot $zk $mn 'BEFORE'

    Write-Log "---------------- attempts ----------------"
    for ($i = 1; $i -le $Repeat; $i++) {
        # Logged BEFORE the call on purpose: this SDK has no call timeout, so a wedged
        # ACUnlock never returns and would otherwise leave no trace at all - a hung run
        # and an operator-killed run would look identical in the file.
        Write-Log ("attempt {0}/{1}  calling ACUnlock({2}, {3}) ..." -f $i, $Repeat, $mn, $delayDs)
        $sw  = [Diagnostics.Stopwatch]::StartNew()
        $ret = $null
        $exc = ''
        try { $ret = $zk.ACUnlock([int]$mn, [int]$delayDs) }
        catch { $exc = $_.Exception.Message }
        $sw.Stop()
        $ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 1)

        if ($exc -ne '') {
            $errCount++
            Write-Log ("attempt {0}/{1}  ACUnlock({2}, {3})  THREW after {4} ms: {5}" -f $i, $Repeat, $mn, $delayDs, $ms, $exc) 'err'
        } elseif ($ret) {
            $trueCount++
            Write-Log ("attempt {0}/{1}  ACUnlock({2}, {3}) -> TRUE   call took {4} ms" -f $i, $Repeat, $mn, $delayDs, $ms) 'ok'
        } else {
            $falseCount++
            Write-Log ("attempt {0}/{1}  ACUnlock({2}, {3}) -> FALSE  call took {4} ms  (this SDK reports no reason - see header)" -f $i, $Repeat, $mn, $delayDs, $ms) 'err'
        }

        if ($i -lt $Repeat -and $IntervalSeconds -gt 0) {
            Start-Sleep -Milliseconds ([int][math]::Round($IntervalSeconds * 1000))
        }
    }

    Write-DeviceSnapshot $zk $mn 'AFTER'
} finally {
    Disconnect-Zkem $zk
    Write-Log "disconnected"
}

# ---------------------------------------------------------------- verdict
$exitCode = 0
if ($errCount -gt 0) { $exitCode = 3 }
elseif ($falseCount -gt 0) { $exitCode = 2 }

Write-Log ("summary: attempts={0} true={1} false={2} threw={3} delay_ds={4} interval_s={5} machine={6}" -f `
    $Repeat, $trueCount, $falseCount, $errCount, $delayDs, $IntervalSeconds, $mn)

Write-Host ""
if ($exitCode -eq 0) {
    Write-Log "SDK RESULT: PASS - every ACUnlock returned TRUE. The call is accepted by this firmware." 'ok'
    Write-Log "THE PHYSICAL CHECK IS THE REAL TEST: did you HEAR the relay, and did the turnstile RELEASE?" 'warn'
    Write-Log "ACUnlock TRUE + no physical release = wiring problem, not SDK." 'warn'
} elseif ($exitCode -eq 2) {
    Write-Log "SDK RESULT: FAIL - ACUnlock returned FALSE. The firmware refused the call; this SDK gives no reason." 'err'
    Write-Log "Send this log back, and switch the door command OFF for this device (Devices page, or MONCLUB_ZK_STANDALONE_OPEN_DOOR=0) so the desk stops pressing it." 'err'
} else {
    Write-Log "SDK RESULT: FAIL - ACUnlock threw. The exception text is above; send this log back." 'err'
}

if (-not $Auto) {
    $ansRaw = (Ask-Default "Did the turnstile PHYSICALLY release? (y/n/unsure)" 'unsure')
    # Accept the answers a French desk actually types: oui/non as well as yes/no/1/0.
    $a = "$ansRaw".Trim().ToLower()
    $ans = 'unsure'
    if ($a -like 'y*' -or $a -like 'o*' -or $a -eq '1') { $ans = 'y' }
    elseif ($a -like 'n*' -or $a -eq '0') { $ans = 'n' }
    Write-Log ("operator answer - physical release: '{0}' read as {1}" -f $ansRaw, $ans)
    if ($exitCode -eq 0 -and $ans -eq 'y') {
        Write-Log ("GATE 4 CANDIDATE PASS: ACUnlock TRUE + physical release, on THIS device, machineNumber {0}." -f $mn) 'ok'
        Write-Log "SEND THE LOG: zkemkeeper_guide.md section 8 stays [UNVERIFIED] until this report is in." 'ok'
    } elseif ($exitCode -eq 0 -and $ans -eq 'n') {
        Write-Log "WIRING PROBLEM, NOT SDK: the SDK accepted the command and the door did not move." 'warn'
        Write-Log "Check the relay output -> turnstile input wiring. No software change can fix this." 'warn'
    } elseif ($exitCode -eq 0) {
        Write-Log "INCONCLUSIVE: TRUE from the SDK, but nobody confirmed the door. Re-run in front of the turnstile." 'warn'
    }
} else {
    Write-Log "-Auto: nobody confirmed the physical release. TRUE here proves only that the SDK accepted the call." 'warn'
}

Write-Host ""
Write-RunLogPointer
if (-not $Auto) { Pause-End }
exit $exitCode
