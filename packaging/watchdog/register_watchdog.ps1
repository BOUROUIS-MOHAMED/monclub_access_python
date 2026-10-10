<#
.SYNOPSIS
    Registers (or removes) the per-user scheduled task that keeps MonClub Access alive.

.DESCRIPTION
    Creates a Task Scheduler task that runs monclub_access_watchdog.ps1:
      * at logon of the current user, and
      * every $IntervalMinutes thereafter, indefinitely.

    That gives the gym PC two things it does not have today:
      * the app starts automatically when the gym user logs in (there is no
        autostart entry in MonClubAccess.iss at all), and
      * the app comes back on its own if the Python process dies.

    PER-USER, NOT SYSTEM -- deliberately. The installer runs with
    PrivilegesRequired=lowest, and MonClub Access needs the interactive desktop
    session for its tray icon and Tauri window. A SYSTEM task would start it in
    session 0 where nobody can see or use it.

    Registering a per-user task for yourself needs no elevation.

    The Windows task's own state is the preference (design section 12, owner
    decision O7): Enabled = on, Disabled = off (an operator, the cutover runbook or
    the Access Settings switch chose it), missing = never decided. The installer
    runs this script on EVERY install and update, silent or not:
      * a task that already exists and is DISABLED stays disabled: it is registered
        again with the current definition, still disabled -- an update never
        switches the watchdog back on;
      * a task that exists and is enabled is refreshed and stays enabled;
      * a MISSING task is registered in the -WhenMissing state: Enabled (the
        default -- the one-time switch-on for PCs installed before the box existed)
        or Disabled (a fresh install whose box was unticked: the choice is recorded,
        so later updates do not switch it on).
    To turn it on: the Access Settings switch, or
        Enable-ScheduledTask -TaskName 'MonClub Access Watchdog'

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File register_watchdog.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File register_watchdog.ps1 -WhenMissing Disabled

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File register_watchdog.ps1 -Remove
#>

[CmdletBinding()]
param(
    [string] $TaskName = 'MonClub Access Watchdog',
    [string] $InstallRoot = (Join-Path $env:LOCALAPPDATA 'MonClubAccess'),
    [string] $WatchdogScript,
    [int]    $IntervalMinutes = 2,
    # State of a task that does not exist yet (see .DESCRIPTION). An existing task
    # keeps its own state whatever this says.
    [ValidateSet('Enabled', 'Disabled')]
    [string] $WhenMissing = 'Enabled',
    [switch] $Remove
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $WatchdogScript -or [string]::IsNullOrWhiteSpace($WatchdogScript)) {
    $WatchdogScript = Join-Path $PSScriptRoot 'monclub_access_watchdog.ps1'
}

function Remove-WatchdogTask {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed scheduled task '$TaskName'."
    } else {
        Write-Host "Scheduled task '$TaskName' was not registered; nothing to remove."
    }
}

# Every run writes its outcome to <InstallRoot>\logs\watchdog-register.log. The
# installer runs this script hidden and reads no exit code, and the in-app update
# starts the installer with no /LOG, so a failed registration used to leave no
# trace anywhere.
$RegisterLogPath = Join-Path $InstallRoot 'logs\watchdog-register.log'
$launchMode = '(not chosen yet)'

function Write-RegisterLog {
    param([string] $Outcome, [string] $Message)
    try {
        $dir = Split-Path -Parent $RegisterLogPath
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        if ((Test-Path -LiteralPath $RegisterLogPath) -and
            ((Get-Item -LiteralPath $RegisterLogPath).Length -gt 1MB)) {
            Move-Item -LiteralPath $RegisterLogPath -Destination "$RegisterLogPath.1" -Force
        }
        $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
        Add-Content -LiteralPath $RegisterLogPath -Encoding UTF8 `
            -Value ('{0} | {1} | {2} | task: {3}' -f $stamp, $Outcome, $Message, $TaskName)
    } catch {
        # Logging must never be the reason the registration fails.
    }
}

# "Disabled" is read from the task's DEFINITION (Settings.Enabled), not only from
# its runtime State. Microsoft's TASK_STATE_DISABLED means "disabled and no
# instances of the task are queued or running", so a disabled task whose check is
# running at this moment reads 'Running' -- and was re-registered ENABLED.
function Test-WatchdogTaskDisabled {
    param($Task)
    if ([string] $Task.State -eq 'Disabled') { return $true }
    $settingsProp = $Task.PSObject.Properties['Settings']
    if ($settingsProp -and $settingsProp.Value) {
        $enabledProp = $settingsProp.Value.PSObject.Properties['Enabled']
        if ($enabledProp -and $enabledProp.Value -eq $false) { return $true }
    }
    return $false
}

# At least one task of that name, and every one of them disabled.
function Test-WatchdogTaskKeptDisabled {
    $tasks = @(Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
    return ($tasks.Count -gt 0 -and
            @($tasks | Where-Object { -not (Test-WatchdogTaskDisabled $_) }).Count -eq 0)
}

function Get-WatchdogTaskSummary {
    try {
        $tasks = @(Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
        if ($tasks.Count -eq 0) { return 'no task' }
        return (@($tasks | ForEach-Object {
            if (Test-WatchdogTaskDisabled $_) { 'Disabled' } else { [string] $_.State }
        }) -join ', ')
    } catch {
        return "unknown ($($_.Exception.Message))"
    }
}

# Any error that ends the run is logged, then ends it as before (break rethrows:
# the caller sees the same error, and powershell -File exits non-zero). A trap
# covers the whole script, lines above it too, where the log is not set up yet:
# the try keeps the trap itself from failing and hiding the original error.
trap {
    try {
        Write-RegisterLog 'FAILED' ('{0} | Launch mode: {1} | task now: {2}' -f
            $_.Exception.Message, $launchMode, (Get-WatchdogTaskSummary))
    } catch { }
    break
}

if ($Remove) {
    $before = Get-WatchdogTaskSummary
    Remove-WatchdogTask
    Write-RegisterLog 'OK' ('Remove | task before: {0} | after: {1}' -f $before, (Get-WatchdogTaskSummary))
    exit 0
}

if (-not (Test-Path -LiteralPath $WatchdogScript)) {
    throw "Watchdog script not found: $WatchdogScript"
}
$WatchdogScript = (Resolve-Path -LiteralPath $WatchdogScript).Path

# Launch through wscript.exe, not powershell.exe directly.
#
# Task Scheduler starts the action with a normal window, and powershell.exe is a
# console program, so Windows draws a VISIBLE console before PowerShell has even
# read -WindowStyle Hidden -- that switch only hides the window afterwards. On the
# front-desk screen that is a black window flashing every couple of minutes.
# wscript.exe is a GUI program with no console of its own, and the launcher starts
# PowerShell with window style 0, so the console is created hidden and never drawn.
#
# VBScript can be switched off (group policy, antivirus, later Windows releases).
# A launcher that silently does nothing would be the worst outcome -- no crash
# recovery and nobody told -- so prove the whole chain works here, now, and fall
# back to the direct launch (which flashes, but works) if it does not.
$psExe      = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$wscriptExe = Join-Path $env:SystemRoot 'System32\wscript.exe'
$launcher   = Join-Path (Split-Path -Parent $WatchdogScript) 'monclub_access_watchdog_hidden.vbs'

function Test-HiddenLauncher {
    if (-not (Test-Path -LiteralPath $wscriptExe) -or -not (Test-Path -LiteralPath $launcher)) {
        return $false
    }
    # Under %TEMP%, which on a gym PC sits inside a user folder with a space in its
    # name ("OXYGENE_FIT P1") -- and the probe folder has a space of its own -- so
    # this also proves the launcher's quoting.
    $probeDir = Join-Path ([IO.Path]::GetTempPath()) ('mca watchdog probe ' + [guid]::NewGuid().ToString('N'))
    try {
        New-Item -ItemType Directory -Path $probeDir -Force | Out-Null
        $probeScript = Join-Path $probeDir 'probe.ps1'
        $marker      = Join-Path $probeDir 'ran.txt'
        Set-Content -LiteralPath $probeScript -Encoding ASCII `
            -Value 'param([string] $Out) Set-Content -LiteralPath $Out -Value ok'
        $wsArgs = @('//B', '//Nologo', "`"$launcher`"", "`"$probeScript`"", '-Out', "`"$marker`"") -join ' '
        $p = Start-Process -FilePath $wscriptExe -ArgumentList $wsArgs -PassThru
        # A blocked script can sit on a prompt nobody can see; never hang the install.
        if (-not $p.WaitForExit(30000)) {
            try { $p.Kill() } catch { }
            return $false
        }
        return (Test-Path -LiteralPath $marker)
    } catch {
        return $false
    } finally {
        Remove-Item -LiteralPath $probeDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if (Test-HiddenLauncher) {
    $wsArgLine = @(
        '//B'
        '//Nologo'
        "`"$launcher`""
        "`"$WatchdogScript`""
        '-InstallRoot'
        "`"$InstallRoot`""
    ) -join ' '
    $action = New-ScheduledTaskAction -Execute $wscriptExe -Argument $wsArgLine
    $launchMode = 'hidden (no window)'
} else {
    $argLine = @(
        '-NoProfile'
        '-NonInteractive'
        '-ExecutionPolicy Bypass'
        '-WindowStyle Hidden'
        "-File `"$WatchdogScript`""
        "-InstallRoot `"$InstallRoot`""
    ) -join ' '
    $action = New-ScheduledTaskAction -Execute $psExe -Argument $argLine
    $launchMode = 'VISIBLE - the hidden launcher did not work on this PC, so a window will flash at each check'
    Write-Warning "The hidden launcher did not work on this PC ($launcher). Falling back to a direct PowerShell launch: the watchdog still works, but a window will flash at each check."
}

$trigger = New-ScheduledTaskTrigger -AtLogOn -User ([Security.Principal.WindowsIdentity]::GetCurrent().Name)

# Repetition is not exposed as a parameter for an -AtLogOn trigger, so borrow the
# object from a throwaway -Once trigger and graft it on.
#
# Do NOT pass -RepetitionDuration here. The obvious value, [TimeSpan]::MaxValue,
# serialises to P99999999DT23H59M59S and Task Scheduler REJECTS the whole
# registration with "The task XML contains a value which is incorrectly
# formatted or out of range". Omitting it leaves Duration empty, which is the
# schema's way of saying "repeat indefinitely" -- which is what we want.
#
# This is silent-failure territory: get it wrong and you ship a task that runs
# once at logon and never again, i.e. autostart with no crash recovery, while the
# task description still promises both. Verified by registering the task and
# reading Repetition.Interval back (see README).
$trigger.Repetition = (New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)).Repetition

# A SECOND trigger that starts repeating NOW. The logon trigger above is not
# enough on its own: an AtLogOn trigger only fires on a FUTURE logon, never for
# the session that is already open when the task is registered. Every install
# happens inside such a session (the app's user must be logged in to run it),
# so with the logon trigger alone the task sat with an empty NextRunTime and
# never ran until the next reboot -- no crash recovery on install day, while
# Interval still read PT2M and looked healthy. A manual Start-ScheduledTask
# runs the action once but does not open the repetition window either.
#
# Both triggers are kept on purpose. This one covers the current session and,
# being a time trigger, normally keeps its schedule across reboots; the logon
# trigger still guarantees a repeating schedule after every logon if it does
# not. When both repeat, checks simply run more often. That is harmless: the
# only action is starting the app when it is absent, and MonClub Access
# refuses to run twice (single-instance mutex in access/main.py).
#
# Same rule as above: NO -RepetitionDuration (empty Duration = indefinite).
$heartbeatTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

# A gym PC is not always online and the app must come up regardless.
$settings.DisallowStartIfOnBatteries = $false
$settings.RunOnlyIfNetworkAvailable  = $false
$settings.Hidden                     = $false

# Normal priority. Task Scheduler's default is 7 = BELOW_NORMAL_PRIORITY_CLASS for
# the process the task starts, and a process started by a below-normal one inherits
# that class (Microsoft, "Scheduling Priorities") -- so Access, started by this task
# through wscript.exe and PowerShell, probably ran below normal [UNVERIFIED], and
# Access makes the door decisions. 4-6 are NORMAL_PRIORITY_CLASS (Microsoft,
# TaskSettings.Priority). A task registered by an older script keeps 7 until this
# script registers it again.
$settings.Priority                   = 5

$principal = New-ScheduledTaskPrincipal `
    -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) `
    -LogonType Interactive `
    -RunLevel Limited

# A task someone DISABLED stays disabled. The installer runs this script at every
# install and update where the box is ticked (UsePreviousTasks=yes re-ticks it),
# and re-registering used to bring the task back ENABLED -- silently undoing an
# operator's Disable-ScheduledTask, e.g. the cutover runbook's, whose whole point
# is that a Quit stays a Quit (the watchdog starts Access again within minutes).
# So read the state BEFORE removing the task and register the new definition in
# that same state: the action and triggers are refreshed, but the task stays off
# until someone runs Enable-ScheduledTask. No task, or an enabled one, is
# registered enabled, as before. "Disabled" is the definition's, not only the
# runtime State (Test-WatchdogTaskDisabled).
#
# A MISSING task takes the -WhenMissing state (design section 12): Disabled only for
# a fresh install whose box was unticked. It goes through the same "keep it
# disabled" path below -- read back, disabled again, never left enabled.
#
# "Missing" must mean missing: -ErrorAction SilentlyContinue cannot tell "no such task" from a
# query that failed (CIM hiccup), and a failed read of a DISABLED task would then register it
# ENABLED -- on every update since design section 12. Only ObjectNotFound (what Get-ScheduledTask
# raises for an unknown name; an enum, not localized text) counts as missing; any other error
# ends the run before the task is touched (review #6).
try {
    $existingTasks = @(Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop)
} catch {
    if ($_.CategoryInfo.Category -ne [System.Management.Automation.ErrorCategory]::ObjectNotFound) {
        throw "Could not read scheduled task '$TaskName' (left untouched): $($_.Exception.Message)"
    }
    $existingTasks = @()
}
$keepDisabled = @($existingTasks | Where-Object { Test-WatchdogTaskDisabled $_ }).Count -gt 0
$disabledLabel = 'Disabled (kept)'
if ($existingTasks.Count -eq 0 -and $WhenMissing -eq 'Disabled') {
    $keepDisabled = $true
    $disabledLabel = 'Disabled (chosen at install)'
}
if ($keepDisabled) {
    $settings.Enabled = $false
}

# Keep the current task's definition, to put it back if registering the new one
# fails. The old task is removed first, so without this a failed registration
# would leave NO task -- and the next install, box still ticked, would register a
# new ENABLED one over what had been a disabled watchdog. The exported XML holds
# the task's own <Enabled> flag, so a disabled task comes back disabled. (Our task
# lives at the root folder; that is where it is registered below.)
$previousXml = $null
if (Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction SilentlyContinue) {
    $previousXml = Export-ScheduledTask -TaskName $TaskName -TaskPath '\'
}

# Where the task had been DISABLED, never leave an ENABLED one behind, whatever
# happened before: read back every task of that name, disable it if it is not, and
# REMOVE it if even that does not hold -- no task beats an enabled one. The next
# install with the box ticked then registers it again, enabled; acceptable only
# because this PC just proved it cannot keep that task disabled, and the log and the
# runbook's state checks show "no task". Returns what it left.
function Confirm-NoEnabledWatchdogTask {
    if (@(Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue).Count -eq 0) {
        return 'there is no watchdog task now'
    }
    if (Test-WatchdogTaskKeptDisabled) { return 'the task is disabled' }
    try { Disable-ScheduledTask -TaskName $TaskName | Out-Null } catch { }
    if (Test-WatchdogTaskKeptDisabled) { return 'the task was disabled again' }
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    } catch {
        return ("a task is ENABLED and could not be removed ($($_.Exception.Message)); " +
                "run: Disable-ScheduledTask -TaskName '$TaskName'")
    }
    if (@(Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue).Count -gt 0) {
        return "a task is still there and not disabled; run: Disable-ScheduledTask -TaskName '$TaskName'"
    }
    return 'it came back enabled and could not be disabled, so it was removed: there is NO watchdog task now'
}

# Puts the task that was there before back from its export. Task Scheduler's
# handling of the exported <Enabled>false</Enabled> has not been run here
# [UNVERIFIED], so where the task had been disabled every outcome -- the put-back
# worked or failed -- ends with Confirm-NoEnabledWatchdogTask.
# Returns what it left, for the warning and the log.
function Restore-PreviousWatchdogTask {
    if (-not $previousXml) {
        $said = 'there was no previous task to put back'
    } else {
        try {
            Register-ScheduledTask -TaskName $TaskName -Xml $previousXml | Out-Null
            $said = if ($keepDisabled) { 'the previous task was put back' } else { 'the previous task was put back as it was' }
        } catch {
            $said = "putting the previous task back failed too: $($_.Exception.Message)"
        }
    }
    if (-not $keepDisabled) { return $said }
    return "$said; $(Confirm-NoEnabledWatchdogTask)"
}

# Re-register rather than update: an older task may have a different action.
Remove-WatchdogTask

try {
    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $action `
        -Trigger @($trigger, $heartbeatTrigger) `
        -Settings $settings `
        -Principal $principal `
        -Description ("Restarts MonClub Access if its backend process dies, and starts it at logon. " +
                      "Stands down while an install or update is in progress.") | Out-Null
} catch {
    $registerError = $_
    # Its own try: an error in the put-back must not replace the registration's
    # error, which is the one the run fails with.
    try {
        $left = Restore-PreviousWatchdogTask
    } catch {
        $left = "putting the previous task back stopped with an error ($($_.Exception.Message))"
    }
    Write-Warning "Registering the new task failed; $left."
    Write-RegisterLog 'WARN' "registering the new task failed; $left"
    throw $registerError
}

if ($keepDisabled) {
    # Settings.Enabled = $false should already register it disabled. Read it back
    # (from the definition, Test-WatchdogTaskDisabled) and disable it explicitly if
    # not: a task that came back enabled is exactly the defect this guards against.
    if (-not (Test-WatchdogTaskKeptDisabled)) {
        try { Disable-ScheduledTask -TaskName $TaskName | Out-Null } catch { }
    }
    if (-not (Test-WatchdogTaskKeptDisabled)) {
        # The new definition will not stay disabled on this PC. Do not leave it
        # enabled: remove it and put the old, disabled task back from its export.
        $newRemoved = $false
        try {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            $newRemoved = $true
        } catch {
            $left = ("the new task could not be removed ($($_.Exception.Message)); " +
                     (Confirm-NoEnabledWatchdogTask))
        }
        if ($newRemoved) {
            try {
                $left = Restore-PreviousWatchdogTask
            } catch {
                $left = ("the new task was removed; putting the previous task back stopped with an " +
                         "error ($($_.Exception.Message)); task now: $(Get-WatchdogTaskSummary)")
            }
        }
        throw ("Scheduled task '$TaskName' was to stay disabled ($disabledLabel) and could not be kept disabled; " +
               "$left (task now: $(Get-WatchdogTaskSummary)). If it reads Ready or Running, run: " +
               "Disable-ScheduledTask -TaskName '$TaskName'")
    }
    if ($disabledLabel -eq 'Disabled (kept)') {
        Write-Host "Registered scheduled task '$TaskName' and KEPT IT DISABLED, as it was before."
    } else {
        Write-Host "Registered scheduled task '$TaskName' DISABLED: the install was told to leave the watchdog off."
    }
    Write-Host "It runs no check until you enable it: Enable-ScheduledTask -TaskName '$TaskName'"
} else {
    Write-Host "Registered scheduled task '$TaskName' (every $IntervalMinutes min, and at logon)."
}
Write-Host "Watchdog script: $WatchdogScript"
Write-Host "Install root:    $InstallRoot"
Write-Host "Launch mode:     $launchMode"
Write-Host "State:           $(if ($keepDisabled) { $disabledLabel } else { 'Enabled' })"
Write-RegisterLog 'OK' ('State: {0} | Launch mode: {1} | task now: {2} | install root: {3}' -f
    $(if ($keepDisabled) { $disabledLabel } else { 'Enabled' }), $launchMode,
    (Get-WatchdogTaskSummary), $InstallRoot)
