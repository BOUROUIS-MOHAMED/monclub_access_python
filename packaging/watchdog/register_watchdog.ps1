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

    A task that already exists and is DISABLED stays disabled: it is registered
    again with the current definition, still disabled. The installer runs this
    script on every install and update where its box is ticked, so this is what
    keeps an update from switching the watchdog back on. To turn it on:
        Enable-ScheduledTask -TaskName 'MonClub Access Watchdog'

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File register_watchdog.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File register_watchdog.ps1 -Remove
#>

[CmdletBinding()]
param(
    [string] $TaskName = 'MonClub Access Watchdog',
    [string] $InstallRoot = (Join-Path $env:LOCALAPPDATA 'MonClubAccess'),
    [string] $WatchdogScript,
    [int]    $IntervalMinutes = 2,
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

if ($Remove) {
    Remove-WatchdogTask
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
# registered enabled, as before.
$keepDisabled = @(
    Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq 'Disabled' }
).Count -gt 0
if ($keepDisabled) {
    $settings.Enabled = $false
}

# Re-register rather than update: an older task may have a different action.
Remove-WatchdogTask

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger @($trigger, $heartbeatTrigger) `
    -Settings $settings `
    -Principal $principal `
    -Description ("Restarts MonClub Access if its backend process dies, and starts it at logon. " +
                  "Stands down while an install or update is in progress.") | Out-Null

if ($keepDisabled) {
    # Settings.Enabled = $false should already register it disabled. Read it back
    # and disable it explicitly if not: a task that came back enabled is exactly
    # the defect this guards against.
    # @() at the call site too: a function's output is unrolled, so one state
    # comes back as a bare string, and Windows PowerShell 5.1 under StrictMode
    # has no .Count on a string.
    function Get-WatchdogStates {
        Get-ScheduledTask -TaskName $TaskName | ForEach-Object { [string] $_.State }
    }
    $states = @(Get-WatchdogStates)
    if ($states.Count -eq 0 -or @($states | Where-Object { $_ -ne 'Disabled' }).Count -gt 0) {
        Disable-ScheduledTask -TaskName $TaskName | Out-Null
        $states = @(Get-WatchdogStates)
    }
    if ($states.Count -eq 0 -or @($states | Where-Object { $_ -ne 'Disabled' }).Count -gt 0) {
        throw ("Scheduled task '$TaskName' was disabled before and could not be kept disabled " +
               "(state now: $($states -join ', ')). Run: Disable-ScheduledTask -TaskName '$TaskName'")
    }
    Write-Host "Registered scheduled task '$TaskName' and KEPT IT DISABLED, as it was before."
    Write-Host "It runs no check until you enable it: Enable-ScheduledTask -TaskName '$TaskName'"
} else {
    Write-Host "Registered scheduled task '$TaskName' (every $IntervalMinutes min, and at logon)."
}
Write-Host "Watchdog script: $WatchdogScript"
Write-Host "Install root:    $InstallRoot"
Write-Host "Launch mode:     $launchMode"
Write-Host "State:           $(if ($keepDisabled) { 'Disabled (kept)' } else { 'Enabled' })"
