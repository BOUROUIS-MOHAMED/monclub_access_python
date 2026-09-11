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

# -NonInteractive and -WindowStyle Hidden keep a console window from flashing on
# the gym's front-desk screen every couple of minutes.
$psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$argLine = @(
    '-NoProfile'
    '-NonInteractive'
    '-ExecutionPolicy Bypass'
    '-WindowStyle Hidden'
    "-File `"$WatchdogScript`""
    "-InstallRoot `"$InstallRoot`""
) -join ' '

$action = New-ScheduledTaskAction -Execute $psExe -Argument $argLine

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

# Re-register rather than update: an older task may have a different action.
Remove-WatchdogTask

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Description ("Restarts MonClub Access if its backend process dies, and starts it at logon. " +
                  "Stands down while an install or update is in progress.") | Out-Null

Write-Host "Registered scheduled task '$TaskName' (every $IntervalMinutes min, and at logon)."
Write-Host "Watchdog script: $WatchdogScript"
Write-Host "Install root:    $InstallRoot"
