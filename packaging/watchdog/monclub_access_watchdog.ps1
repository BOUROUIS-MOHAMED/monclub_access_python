<#
.SYNOPSIS
    Restarts MonClub Access if it has died, without fighting an install or update.

.DESCRIPTION
    MonClubAccess.exe is the Python process that serves the local HTTP API on
    127.0.0.1 and drives the turnstiles. It is also the PARENT of the Tauri UI
    shell (monclub-access-ui.exe), which SURVIVES it. So when the Python process
    dies, the gym sees a window that still looks alive but whose pages fail with
    "TypeError: Failed to fetch", doors stop opening from the keyboard, and no
    enrolment can start -- until a human notices and restarts the app.

    Nothing in the product restarts it today: there is no service, no scheduled
    task, and no supervisor. This script plus register_watchdog.ps1 is that
    missing piece.

    IT MUST NOT RESTART THE APP AT THE WRONG MOMENT. The Inno Setup installer
    (PrepareToInstall: stop the app, back up current\ to previous\, empty and refill
    current\, then start the new version and wait for it to prove healthy -- or roll
    back) legitimately keeps the app down for a while and relaunches it itself.
    Racing it can lock files inside current\ mid-swap and break the update. These
    guards prevent that:

      1. An installer/setup process is running    -> stand down.
      2. An install journal is left behind        -> recover it first (below).
      3. The pause sentinel file exists and is    -> stand down.
         fresh (the installer writes it before
         killing and removes it at its result)
      4. The app exe is missing (current\ is      -> stand down.
         mid-swap)
      5. Only the FIRST miss is observed          -> wait, confirm next tick.

    Guard 5 means an ordinary restart has to be missing across two consecutive
    ticks before we act, which covers short legitimate gaps.

    Guard 2 is the install-journal rule (design.md section 8.0 / 8 step 12): a Setup
    killed mid-swap (power cut) leaves {app}\state\install_journal.json and possibly a
    half-filled current\ -- with the exe missing (guard 4) and a fresh sentinel
    (guard 3), so it MUST run before those two or the app would never come back.
    update_helper.ps1 -Action recover restores previous\ when the journal is stale
    (no Setup running and older than 10 min or written before the last boot),
    records ROLLED_BACK "interrupted" in state\last_update.json and clears the
    sentinel; the watchdog then starts the app at once.

    The misses must also be spread in TIME, not only counted: a miss counts only
    when it comes at least $MinSecondsBetweenMisses (90 s) after the previous
    counted one. The task has two repeating 2-minute triggers on different starts
    (register_watchdog.ps1), so two checks can land seconds apart -- counted per
    check, a tray Quit could be "confirmed" and Access restarted seconds after it.

    A restart-rate cap stops a crash-looping build from being relaunched
    hundreds of times an hour; past the cap the script logs and gives up until
    the window rolls over.

    Exit code is always 0: a scheduled task that reports failure produces noise
    in Task Scheduler for a condition this script handles by design.

.NOTES
    Per-user by design. The installer runs with PrivilegesRequired=lowest and
    the app needs the interactive desktop session (tray icon + Tauri window), so
    this must run as the logged-in gym user, NOT as SYSTEM.
#>

[CmdletBinding()]
param(
    # Install root, i.e. the folder containing current\. Defaults to the
    # standard per-user install location used by MonClubAccess.iss.
    [string] $InstallRoot = (Join-Path $env:LOCALAPPDATA 'MonClubAccess'),

    # Consecutive ticks the app must be absent before we restart it.
    [int] $RequiredConsecutiveMisses = 2,

    # A miss counts only this long after the previous counted miss (see
    # .DESCRIPTION): below one 2-minute interval, above two checks that landed
    # close together.
    [int] $MinSecondsBetweenMisses = 90,

    # Restart-rate cap.
    [int] $MaxRestartsPerWindow = 5,
    [int] $RateWindowMinutes = 60,

    # How long the installer's pause sentinel is honoured before it is treated
    # as stale debris from an aborted install (which must not disable the
    # watchdog forever).
    [int] $SentinelMaxAgeMinutes = 30,

    # Report what would happen without starting anything. (The install-journal
    # recovery below still restores files: it is not a start.)
    [switch] $WhatIfOnly,

    # update_helper.ps1, installed beside this script by MonClubAccess.iss. A
    # parameter only so the tests can point it at installer/update_helper.ps1.
    [string] $HelperPath = (Join-Path $PSScriptRoot 'update_helper.ps1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$AppExeName      = 'MonClubAccess.exe'
$UiExeName       = 'monclub-access-ui.exe'
$AppProcessName  = 'MonClubAccess'

$CurrentDir   = Join-Path $InstallRoot 'current'
$AppExePath   = Join-Path $CurrentDir  $AppExeName
$LogDir       = Join-Path $InstallRoot 'logs'
$LogPath      = Join-Path $LogDir      'watchdog.log'
$StatePath    = Join-Path $LogDir      'watchdog-state.json'
$SentinelPath = Join-Path $InstallRoot '.update-in-progress'
$JournalPath  = Join-Path $InstallRoot 'state\install_journal.json'

function Write-Log {
    param([string] $Level, [string] $Message)
    $line = '{0} | {1} | {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    try {
        if (-not (Test-Path -LiteralPath $LogDir)) {
            New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
        }
        # Keep the log from growing without bound on a PC that runs for months.
        if ((Test-Path -LiteralPath $LogPath) -and
            ((Get-Item -LiteralPath $LogPath).Length -gt 1MB)) {
            Move-Item -LiteralPath $LogPath -Destination "$LogPath.1" -Force
        }
        Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
    } catch {
        # Logging must never be the reason the watchdog fails.
    }
    Write-Verbose $line
}

# Restart timestamps are stored as UNIX EPOCH SECONDS, never as date strings.
#
# They used to be ISO-8601 strings, and that was a real bug with a bad failure
# mode. ConvertFrom-Json silently coerces an ISO-looking string into a
# [DateTime]; ConvertTo-Json then wrote it back in the machine's CURRENT culture
# ("09/11/2026 10:35:26"), and [datetime]::Parse read that back under a culture
# that disagreed about day/month order. A restart from 90 minutes ago parsed as
# 9 November -- in the FUTURE -- so it counted as "recent", the rate cap latched
# at 5/5, and the watchdog then refused to restart the app AT ALL. The guard
# meant to stop a crash-loop would instead have permanently disabled recovery on
# any gym PC whose locale is not US-English.
#
# Integers have no culture. Do not reintroduce date strings here.
function Get-NowEpoch { [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }

function Read-State {
    # missAt: epoch seconds of the last COUNTED miss (0 = none), same rule as the
    # restart stamps -- an integer or nothing.
    $default = [pscustomobject]@{ misses = 0; missAt = [long] 0; restarts = @() }
    if (-not (Test-Path -LiteralPath $StatePath)) { return $default }
    try {
        $raw = Get-Content -LiteralPath $StatePath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return $default }
        $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
        $misses = 0
        if ($parsed.PSObject.Properties.Name -contains 'misses') {
            $misses = [int] $parsed.misses
        }
        $missAt = [long] 0
        if ($parsed.PSObject.Properties.Name -contains 'missAt' -and
            ($parsed.missAt -is [int] -or $parsed.missAt -is [long])) {
            $missAt = [long] $parsed.missAt
        }
        $restarts = @()
        if ($parsed.PSObject.Properties.Name -contains 'restarts' -and $parsed.restarts) {
            foreach ($r in @($parsed.restarts)) {
                # Anything that is not a plain integer is legacy or corrupt --
                # drop it rather than guess what it meant.
                try {
                    $n = [long] $r
                    if ($n -gt 0) { $restarts += $n }
                } catch { }
            }
        }
        return [pscustomobject]@{ misses = $misses; missAt = $missAt; restarts = $restarts }
    } catch {
        # A corrupt state file must not wedge the watchdog -- start over.
        return $default
    }
}

function Write-State {
    # -MissAt 0 (the default) clears the miss time: every reset of the misses does.
    param([int] $Misses, [long[]] $Restarts, [long] $MissAt = 0)
    try {
        if (-not (Test-Path -LiteralPath $LogDir)) {
            New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
        }
        [pscustomobject]@{ misses = $Misses; missAt = $MissAt; restarts = @($Restarts) } |
            ConvertTo-Json -Compress |
            Set-Content -LiteralPath $StatePath -Encoding UTF8
    } catch {
        Write-Log 'WARN' "could not persist state: $($_.Exception.Message)"
    }
}

function Test-ProcessRunning {
    param([string[]] $Names)
    foreach ($n in $Names) {
        try {
            if (@(Get-Process -Name $n -ErrorAction SilentlyContinue).Count -gt 0) { return $true }
        } catch { }
    }
    return $false
}

function Test-InstallerRunning {
    <#
        Match ONLY our own Inno Setup installer, whose OutputBaseFilename is
        "monclub_access" and which ships as monclub_access_<version>.exe.

        This pattern was deliberately narrowed. It started as
        '^(monclub_access.*|.*setup.*|.*install.*)$' and that matched the Windows
        built-in AppInstallerPythonRedirector on a plain dev box -- and would
        equally match SetupHost.exe, which runs for the whole of a Windows
        Update. A false positive here is the worst possible failure for this
        script: it stands the watchdog down silently, so the app stays dead and
        nobody learns why. Broad name heuristics are not worth that.

        The installer's own pause sentinel (guard 3) is the reliable signal;
        this is only a backstop for a setup run that never got to write one.
    #>
    try {
        $procs = Get-Process -ErrorAction SilentlyContinue |
                 Where-Object { $_.ProcessName -match '^monclub_access(_[0-9][0-9a-zA-Z._\-]*)?$' }
        return (@($procs).Count -gt 0)
    } catch {
        return $false
    }
}

function Test-PauseSentinel {
    if (-not (Test-Path -LiteralPath $SentinelPath)) { return $false }
    try {
        $age = (Get-Date) - (Get-Item -LiteralPath $SentinelPath).LastWriteTime
        if ($age.TotalMinutes -gt $SentinelMaxAgeMinutes) {
            $msg = 'pause sentinel is stale ({0:N0} min) -- ignoring it; an install probably aborted' `
                   -f $age.TotalMinutes
            Write-Log 'WARN' $msg
            return $false
        }
        return $true
    } catch {
        return $false
    }
}

# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------
try {
    $state = Read-State

    if (Test-ProcessRunning -Names @($AppProcessName)) {
        if ($state.misses -ne 0 -or $state.missAt -ne 0) { Write-State -Misses 0 -Restarts $state.restarts }
        exit 0                      # healthy: the overwhelmingly common path, logged silently
    }

    # --- stand-down guards, most specific first ---
    if (Test-InstallerRunning) {
        Write-Log 'INFO' 'app is down but an installer appears to be running -- standing down'
        Write-State -Misses 0 -Restarts $state.restarts
        exit 0
    }
    $claims = @(Get-ChildItem -LiteralPath (Split-Path -Parent $JournalPath) -Filter 'install_journal.restoring-*.json' -ErrorAction SilentlyContinue)
    if ((Test-Path -LiteralPath $JournalPath) -or $claims.Count -gt 0) {
        # Guard 2 (see .DESCRIPTION): BEFORE the sentinel and exe-missing guards. A live
        # claim (install_journal.restoring-<pid>.json) means another restorer is at work:
        # update_helper answers 22 and we stand down instead of starting it mid-restore.
        if (-not (Test-Path -LiteralPath $HelperPath)) {
            Write-Log 'ERROR' "install journal found but $HelperPath is missing -- cannot recover"
        } else {
            $helperLog = Join-Path $LogDir 'update-recover.log'
            & $HelperPath -Action recover -InstallRoot $InstallRoot -AppExe $AppExeName `
                -UiExe $UiExeName -LogPath $helperLog | Out-Null
            $rc = $LASTEXITCODE
            if ($rc -eq 20) {
                Write-Log 'WARN' "an interrupted install was rolled back to previous\ ($helperLog) -- starting $AppExePath"
                if ($WhatIfOnly) { exit 0 }
                Start-Process -FilePath $AppExePath -WorkingDirectory $CurrentDir | Out-Null
                $recent = @($state.restarts) + @(Get-NowEpoch)
                Write-State -Misses 0 -Restarts $recent
                exit 0
            }
            if ($rc -eq 22) {
                Write-Log 'INFO' 'app is down and an install journal is not stale yet, or a restore is in progress -- standing down'
                Write-State -Misses 0 -Restarts $state.restarts
                exit 0
            }
            if ($rc -eq 23) {
                Write-Log 'ERROR' "an interrupted install could NOT be rolled back ($helperLog) -- needs a human"
                Write-State -Misses 0 -Restarts $state.restarts
                exit 0
            }
            # 21: dropped (current\ was never touched) -- carry on with the normal checks.
            Write-Log 'INFO' "install journal handled by update_helper (exit $rc)"
        }
    }
    if (Test-PauseSentinel) {
        Write-Log 'INFO' 'app is down but the install pause sentinel is set -- standing down'
        Write-State -Misses 0 -Restarts $state.restarts
        exit 0
    }
    if (-not (Test-Path -LiteralPath $AppExePath)) {
        Write-Log 'WARN' "app is down and $AppExePath is missing -- current\ may be mid-swap; standing down"
        Write-State -Misses 0 -Restarts $state.restarts
        exit 0
    }

    # --- confirm across two ticks, at least $MinSecondsBetweenMisses apart ---
    $nowEpoch = Get-NowEpoch
    if ([int] $state.misses -gt 0) {
        $sinceLastMiss = $nowEpoch - [long] $state.missAt
        if ([long] $state.missAt -le 0 -or $sinceLastMiss -lt 0) {
            # No time for the earlier miss (a state file from an older script, or a
            # value that was not an integer), or a time in the future (the clock
            # moved back). Count from now: waiting for the clock to catch up could
            # stand the watchdog down for as long as the jump.
            Write-Log 'INFO' ("app not running (miss 1/$RequiredConsecutiveMisses; the earlier miss has no " +
                              "usable time, so the count starts again) -- will confirm on a later tick")
            Write-State -Misses 1 -Restarts $state.restarts -MissAt $nowEpoch
            exit 0
        }
        if ($sinceLastMiss -lt $MinSecondsBetweenMisses) {
            # Two checks that landed close together (two triggers): not a second miss.
            Write-Log 'INFO' ("app not running -- not counted: only $sinceLastMiss s since the previous miss " +
                              "(need $MinSecondsBetweenMisses s; miss $($state.misses)/$RequiredConsecutiveMisses)")
            exit 0
        }
    }
    $misses = [int] $state.misses + 1
    if ($misses -lt $RequiredConsecutiveMisses) {
        Write-Log 'INFO' "app not running (miss $misses/$RequiredConsecutiveMisses) -- will confirm next tick"
        Write-State -Misses $misses -Restarts $state.restarts -MissAt $nowEpoch
        exit 0
    }

    # --- restart-rate cap (epoch seconds; see Read-State) ---
    $cutoffEpoch = (Get-NowEpoch) - ($RateWindowMinutes * 60)
    $recent = @()
    foreach ($r in @($state.restarts)) {
        if ($r -gt $cutoffEpoch) { $recent += $r }
    }
    if ($recent.Count -ge $MaxRestartsPerWindow) {
        $msg = ('app is down but it has already been restarted {0} time(s) in the last {1} min -- ' +
                'NOT restarting again. This build is crash-looping and needs a human.') `
               -f $recent.Count, $RateWindowMinutes
        Write-Log 'ERROR' $msg
        Write-State -Misses $misses -Restarts $recent -MissAt $nowEpoch
        exit 0
    }

    if ($WhatIfOnly) {
        Write-Log 'INFO' "WHATIF: would start $AppExePath"
        exit 0
    }

    Write-Log 'WARN' "app is not running and no install/update is in progress -- starting $AppExePath"
    Start-Process -FilePath $AppExePath -WorkingDirectory $CurrentDir | Out-Null

    $recent += (Get-NowEpoch)
    Write-State -Misses 0 -Restarts $recent
    Write-Log 'INFO' 'restart issued'
    exit 0
} catch {
    Write-Log 'ERROR' "watchdog failed: $($_.Exception.Message)"
    exit 0     # never surface a task failure for something we handle by design
}
