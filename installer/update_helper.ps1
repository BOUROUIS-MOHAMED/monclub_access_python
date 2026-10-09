<#
.SYNOPSIS
    Safe-swap helper for the MonClub Access / MonClub TV installers (updater v2, design section 8).

.DESCRIPTION
    Called by the Inno Setup [Code] of installer\MonClubAccess.iss and installer\MonClubTV.iss
    (extracted to {tmp}), and by the Access watchdog (installed copy in {app}\watchdog).

    Actions
      backup      current\* -> previous\ (fresh mirror), then empty current\ (files only; the
                  folder itself stays). NEVER renames current\: Windows refuses to rename a
                  folder that is any live process's working directory, and both the watchdog
                  (-WorkingDirectory current) and the 1.4.35 client (Setup started with no cwd,
                  i.e. inside current\) make that true (design section 8.0).
                  Exit 0 = backed up and current\ emptied; 2 = failed, current\ intact
                  (restored if it had been touched); 3 = failed AND current\ could not be put
                  back (journal kept so a later start-up / watchdog restores it).
      restore     previous\* -> current\ (mirror). Exit 0 / 3.
      launch-wait Start current\<exe> (working directory current\, as gyms do) and wait up to
                  -TimeoutSec for state\boot_ok.json carrying -ToVersion.
                  Exit 0 healthy; 10 the process died first (crash); 11 timeout (process
                  killed); 12 could not be started.
      relaunch    Start current\<exe> unless a process of that exe already runs from current\.
                  Exit 0 / 12.
      recover     The journal rule of design section 8.0 (stale journal -> claim -> restore or drop ->
                  last_update.json). Exit 0 no journal; 20 restored; 21 dropped (no restore
                  needed); 22 journal present but not stale (stand down); 23 restore failed.

    The install journal ({app}\state\install_journal.json) and last_update.json formats are
    the L2/L3 contract in design.md section 8.0. All JSON is written ASCII-only, without BOM.

    Never `Set-Location` into current\ here: this process would then pin current\ itself.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('backup', 'restore', 'launch-wait', 'relaunch', 'recover')]
    [string] $Action,

    [Parameter(Mandatory = $true)]
    [string] $InstallRoot,

    [Parameter(Mandatory = $true)]
    [string] $AppExe,

    [string] $UiExe = '',
    [string] $FromVersion = '',
    [string] $ToVersion = '',
    [int] $TimeoutSec = 300,
    [string] $LogPath = '',

    # Test-only failure injection, passed by an installer compiled with /DUPDATER_TEST_FAIL
    # (build_release.ps1 refuses that define for a publishable build).
    [ValidateSet('', 'health', 'crash')]
    [string] $TestFail = '',

    # recover: journal age (minutes) after which it is stale.
    [int] $StaleMinutes = 10,

    # Seconds of retries for a locked file while emptying current\ (antivirus, a lingering UI).
    [int] $LockedRetrySec = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$InstallRoot  = $InstallRoot.TrimEnd('\')
$CurrentDir   = Join-Path $InstallRoot 'current'
$PreviousDir  = Join-Path $InstallRoot 'previous'
$StateDir     = Join-Path $InstallRoot 'state'
$JournalPath  = Join-Path $StateDir 'install_journal.json'
$LastUpdate   = Join-Path $StateDir 'last_update.json'
$BootOkPath   = Join-Path $StateDir 'boot_ok.json'
$SentinelPath = Join-Path $InstallRoot '.update-in-progress'
# Our installer images: monclub_access_<ver>.exe and Inno's monclub_access_<ver>.tmp; test
# builds add _TESTFAIL_<mode> (hence "_"). Same pattern as lane L3's client (design 8.0).
$SetupImageRe = '^monclub_(access|tv)_[0-9][0-9A-Za-z._\-]*\.(exe|tmp)$'

function Write-HelperLog([string] $Message) {
    $line = '{0} | update_helper {1} | {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Action, $Message
    if ($LogPath) {
        try { Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8 } catch { }
    }
    # Write-Host, not Write-Output: callers return values through the pipeline.
    Write-Host $line
}

function Get-UtcStamp { [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'") }

function ConvertTo-AsciiJson($Object) {
    $json = $Object | ConvertTo-Json -Compress -Depth 4
    # Escape every non-ASCII char so the file is plain ASCII whatever the reader's codec.
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $json.ToCharArray()) {
        if ([int] $ch -gt 127) { [void] $sb.AppendFormat('\u{0:x4}', [int] $ch) } else { [void] $sb.Append($ch) }
    }
    return $sb.ToString()
}

function Write-JsonAtomic([string] $Path, $Object) {
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $tmp = "$Path.tmp-$PID"
    [System.IO.File]::WriteAllText($tmp, (ConvertTo-AsciiJson $Object), (New-Object System.Text.UTF8Encoding($false)))
    if (Test-Path -LiteralPath $Path) {
        [System.IO.File]::Replace($tmp, $Path, [NullString]::Value)
    } else {
        [System.IO.File]::Move($tmp, $Path)
    }
}

function Get-SetupPid {
    # This helper is started by the Inno ".tmp" process: our parent is Setup.
    try {
        $me = Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction Stop
        return [int] $me.ParentProcessId
    } catch { return 0 }
}

function Write-Journal([string] $Phase) {
    Write-JsonAtomic $JournalPath ([ordered]@{
        phase    = $Phase
        from     = $FromVersion
        to       = $ToVersion
        at       = (Get-UtcStamp)
        setupPid = (Get-SetupPid)
    })
    Write-HelperLog "journal phase=$Phase"
}

function Write-LastUpdate([string] $Result, [string] $From, [string] $To, [string] $Reason) {
    Write-JsonAtomic $LastUpdate ([ordered]@{
        result = $Result
        from   = $From
        to     = $To
        reason = $Reason
        log    = $LogPath
        at     = (Get-UtcStamp)
    })
    Write-HelperLog "last_update.json result=$Result reason=$Reason from=$From to=$To"
}

function Get-ProcessesFromCurrent([string[]] $ExeNames) {
    $prefix = (Join-Path $CurrentDir '').ToLowerInvariant()
    $found = @()
    foreach ($name in $ExeNames) {
        if (-not $name) { continue }
        try {
            $procs = Get-CimInstance Win32_Process -Filter ("Name='{0}'" -f $name.Replace("'", "''")) -ErrorAction Stop
        } catch { $procs = @() }
        foreach ($p in @($procs)) {
            $path = [string] $p.ExecutablePath
            if ($path -and $path.ToLowerInvariant().StartsWith($prefix)) { $found += $p }
        }
    }
    return $found
}

function Stop-ProcessesFromCurrent {
    foreach ($p in (Get-ProcessesFromCurrent @($AppExe, $UiExe))) {
        Write-HelperLog ("stopping pid {0} ({1})" -f $p.ProcessId, $p.ExecutablePath)
        try { Stop-Process -Id ([int] $p.ProcessId) -Force -ErrorAction Stop } catch { }
    }
}

function Invoke-Robocopy([string] $Src, [string] $Dst, [int] $Retries) {
    # /MIR: Dst becomes an exact copy (extras deleted). Files with the same size and time are
    # skipped -- a file another process still holds open but that is identical is no failure.
    if (-not (Test-Path -LiteralPath $Dst)) { New-Item -ItemType Directory -Path $Dst -Force | Out-Null }
    $robo = Join-Path $env:SystemRoot 'System32\robocopy.exe'
    if (-not (Test-Path -LiteralPath $robo)) { $robo = 'robocopy.exe' }
    $out = & $robo $Src $Dst /MIR /COPY:DAT /DCOPY:T /R:$Retries /W:1 /NP /NFL /NDL /NJH /NJS 2>&1
    $code = $LASTEXITCODE
    foreach ($l in @($out)) { if ("$l".Trim()) { Write-HelperLog "robocopy: $l" } }
    Write-HelperLog "robocopy '$Src' -> '$Dst' exit=$code"
    return ($code -lt 8)
}

function Get-TreeSignature([string] $Dir) {
    $files = @(Get-ChildItem -LiteralPath $Dir -Recurse -Force -File -ErrorAction Stop)
    $bytes = 0L
    foreach ($f in $files) { $bytes += $f.Length }
    return '{0} files / {1} bytes' -f $files.Count, $bytes
}

function Test-PayloadComplete([string] $Dir) {
    return (Test-Path -LiteralPath (Join-Path $Dir $AppExe)) -and
           (Test-Path -LiteralPath (Join-Path $Dir 'version.json'))
}

function Read-PayloadVersion([string] $Dir) {
    try {
        $v = Get-Content -LiteralPath (Join-Path $Dir 'version.json') -Raw | ConvertFrom-Json
        return [string] $v.version
    } catch { return '' }
}

function Clear-DirectoryContents([string] $Dir) {
    # Deletes everything INSIDE $Dir; the folder itself stays (it may be a process's cwd).
    # Retries a locked item for up to $LockedRetrySec seconds after the last progress.
    $deadline = (Get-Date).AddSeconds($LockedRetrySec)
    while ($true) {
        $left = @(Get-ChildItem -LiteralPath $Dir -Force -ErrorAction SilentlyContinue)
        if ($left.Count -eq 0) { return $true }
        $progress = $false
        # Files first (deepest paths first), then directories bottom-up.
        $files = @(Get-ChildItem -LiteralPath $Dir -Recurse -Force -File -ErrorAction SilentlyContinue)
        foreach ($f in $files) {
            try {
                if ($f.Attributes -band [IO.FileAttributes]::ReadOnly) { $f.Attributes = 'Normal' }
                [System.IO.File]::Delete($f.FullName); $progress = $true
            } catch { }
        }
        $dirs = @(Get-ChildItem -LiteralPath $Dir -Recurse -Force -Directory -ErrorAction SilentlyContinue |
                  Sort-Object { $_.FullName.Length } -Descending)
        foreach ($d in $dirs) {
            try { [System.IO.Directory]::Delete($d.FullName, $false); $progress = $true } catch { }
        }
        if ($progress) { $deadline = (Get-Date).AddSeconds($LockedRetrySec) }
        if ((Get-Date) -gt $deadline) {
            $sample = @(Get-ChildItem -LiteralPath $Dir -Recurse -Force -File -ErrorAction SilentlyContinue |
                        Select-Object -First 5 | ForEach-Object { $_.FullName })
            Write-HelperLog ("could not empty {0}; still locked: {1}" -f $Dir, ($sample -join '; '))
            return $false
        }
        Start-Sleep -Milliseconds 500
    }
}

function Invoke-Restore {
    Stop-ProcessesFromCurrent
    if (-not (Test-PayloadComplete $PreviousDir)) {
        Write-HelperLog "previous\ is incomplete ($PreviousDir) -- cannot restore"
        return $false
    }
    $ok = Invoke-Robocopy $PreviousDir $CurrentDir 15
    if ($ok -and (Test-PayloadComplete $CurrentDir)) {
        Write-HelperLog ("restored current\ from previous\ (version {0}; {1})" -f (Read-PayloadVersion $CurrentDir), (Get-TreeSignature $CurrentDir))
        return $true
    }
    return $false
}

function Start-AppFromCurrent {
    $exe = Join-Path $CurrentDir $AppExe
    if (-not (Test-Path -LiteralPath $exe)) { throw "app exe missing: $exe" }
    return Start-Process -FilePath $exe -WorkingDirectory $CurrentDir -PassThru
}

function Test-SetupRunning {
    try {
        foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
            if ([string] $p.Name -match $SetupImageRe) { return $true }
        }
    } catch { }
    return $false
}

function Get-LastBootUtc {
    try { return (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime() } catch { return $null }
}

# ----------------------------------------------------------------------------------------
$script:CurrentTouched = $false
try {
    Write-HelperLog ("start root='{0}' exe={1} from={2} to={3}" -f $InstallRoot, $AppExe, $FromVersion, $ToVersion)

    switch ($Action) {

        'backup' {
            if (-not (Test-PayloadComplete $CurrentDir)) {
                Write-HelperLog "current\ has no complete payload -- nothing to back up"
                exit 2
            }
            Write-Journal 'backing_up'
            $copied = $false
            try {
                $copied = Invoke-Robocopy $CurrentDir $PreviousDir 3
            } catch { Write-HelperLog "backup copy threw: $($_.Exception.Message)" }
            $sigCur = Get-TreeSignature $CurrentDir
            $sigPrev = if (Test-Path -LiteralPath $PreviousDir) { Get-TreeSignature $PreviousDir } else { '' }
            if (-not $copied -or -not (Test-PayloadComplete $PreviousDir) -or $sigCur -ne $sigPrev) {
                Write-HelperLog "backup FAILED (current: $sigCur; previous: $sigPrev) -- current\ untouched"
                Remove-Item -LiteralPath $JournalPath -Force -ErrorAction SilentlyContinue
                exit 2
            }
            Write-HelperLog "previous\ complete ($sigPrev)"
            Write-Journal 'copying'
            $script:CurrentTouched = $true
            if (Clear-DirectoryContents $CurrentDir) {
                Write-HelperLog 'current\ emptied -- ready for the new files'
                exit 0
            }
            Write-Journal 'restoring'
            if (Invoke-Restore) {
                Remove-Item -LiteralPath $JournalPath -Force -ErrorAction SilentlyContinue
                Write-HelperLog 'backup aborted: current\ put back as it was'
                exit 2
            }
            Write-HelperLog 'backup aborted AND current\ could not be put back -- journal kept for recovery'
            exit 3
        }

        'restore' {
            Write-Journal 'restoring'
            if (Invoke-Restore) { exit 0 }
            Write-HelperLog 'restore FAILED -- journal kept for recovery'
            exit 3
        }

        'launch-wait' {
            Write-Journal 'verifying'
            Remove-Item -LiteralPath $BootOkPath -Force -ErrorAction SilentlyContinue
            try {
                $proc = Start-AppFromCurrent
            } catch {
                Write-HelperLog "could not start the new version: $($_.Exception.Message)"
                exit 12
            }
            Write-HelperLog ("started {0} pid={1}; waiting up to {2} s for boot_ok.json version {3}" -f $AppExe, $proc.Id, $TimeoutSec, $ToVersion)
            if ($TestFail -eq 'crash') {
                Write-HelperLog 'TEST (UPDATER_TEST_FAIL=crash): killing the new process now'
                Start-Sleep -Seconds 2
                try { Stop-Process -Id $proc.Id -Force -ErrorAction Stop } catch { }
            }
            $started = Get-Date
            $deadline = $started.AddSeconds($TimeoutSec)
            while ($true) {
                if ($TestFail -ne 'health' -and (Test-Path -LiteralPath $BootOkPath)) {
                    try {
                        $boot = Get-Content -LiteralPath $BootOkPath -Raw | ConvertFrom-Json
                        $bv = ([string] $boot.version).Trim()
                        if ($bv -ieq $ToVersion.Trim()) {
                            Write-HelperLog ("healthy: boot_ok.json version={0} pid={1} after {2:N0} s" -f $bv, $boot.pid, ((Get-Date) - $started).TotalSeconds)
                            exit 0
                        }
                        Write-HelperLog "boot_ok.json carries version '$bv', waiting for '$ToVersion'"
                    } catch { }  # half-written file: read again next second
                }
                $proc.Refresh()
                if ($proc.HasExited) {
                    Write-HelperLog ("the new process exited (code {0}) after {1:N0} s without boot_ok -- crash" -f $proc.ExitCode, ((Get-Date) - $started).TotalSeconds)
                    Stop-ProcessesFromCurrent
                    exit 10
                }
                if ((Get-Date) -gt $deadline) {
                    Write-HelperLog "no boot_ok.json after $TimeoutSec s -- health timeout; stopping it"
                    try { Stop-Process -Id $proc.Id -Force -ErrorAction Stop } catch { }
                    Stop-ProcessesFromCurrent
                    exit 11
                }
                Start-Sleep -Seconds 1
            }
        }

        'relaunch' {
            $running = @(Get-ProcessesFromCurrent @($AppExe))
            if ($running.Count -gt 0) {
                Write-HelperLog ("already running from current\ (pid {0})" -f $running[0].ProcessId)
                exit 0
            }
            try {
                $p = Start-AppFromCurrent
                Write-HelperLog ("relaunched {0} pid={1}" -f $AppExe, $p.Id)
                exit 0
            } catch {
                Write-HelperLog "relaunch FAILED: $($_.Exception.Message)"
                exit 12
            }
        }

        'recover' {
            # A claim left by a restorer (app start-up, wrapper, watchdog, us): alive = a restore
            # is in progress, stand down; dead = it died mid-restore, hand the journal back.
            foreach ($claim in @(Get-ChildItem -LiteralPath $StateDir -Filter 'install_journal.restoring-*.json' -ErrorAction SilentlyContinue)) {
                $claimPid = 0
                if ($claim.Name -match '^install_journal\.restoring-(\d+)\.json$') { $claimPid = [int] $Matches[1] }
                if ($claimPid -gt 0 -and (Get-Process -Id $claimPid -ErrorAction SilentlyContinue)) {
                    Write-HelperLog "a restore is in progress (claim $($claim.Name), pid alive) -- standing down"
                    exit 22
                }
                if (Test-Path -LiteralPath $JournalPath) {
                    Remove-Item -LiteralPath $claim.FullName -Force -ErrorAction SilentlyContinue
                } else {
                    try { [System.IO.File]::Move($claim.FullName, $JournalPath) } catch { }
                }
                Write-HelperLog "stale claim $($claim.Name) (restorer gone) -- journal handed back"
            }
            if (-not (Test-Path -LiteralPath $JournalPath)) { exit 0 }
            if (Test-SetupRunning) {
                Write-HelperLog 'install journal present but a Setup is running -- standing down'
                exit 22
            }
            $journal = $null
            try { $journal = Get-Content -LiteralPath $JournalPath -Raw | ConvertFrom-Json } catch { }
            $phase = ''; $jFrom = ''; $jTo = ''; $at = $null; $jSetupPid = 0
            if ($journal) {
                if ($journal.PSObject.Properties.Name -contains 'setupPid') {
                    try { $jSetupPid = [int] $journal.setupPid } catch { $jSetupPid = 0 }
                }
                if ($journal.PSObject.Properties.Name -contains 'phase') { $phase = [string] $journal.phase }
                if ($journal.PSObject.Properties.Name -contains 'from') { $jFrom = [string] $journal.from }
                if ($journal.PSObject.Properties.Name -contains 'to') { $jTo = [string] $journal.to }
                if ($journal.PSObject.Properties.Name -contains 'at') {
                    try {
                        $at = [DateTime]::ParseExact([string] $journal.at, "yyyy-MM-dd'T'HH:mm:ss'Z'",
                            [Globalization.CultureInfo]::InvariantCulture,
                            [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)
                    } catch { $at = $null }
                }
            }
            if ($null -eq $at) {
                # No usable time: fall back to the file's own time (never culture-parsed).
                $at = (Get-Item -LiteralPath $JournalPath).LastWriteTimeUtc
            }
            $nowUtc = [DateTime]::UtcNow
            $boot = Get-LastBootUtc
            # The Setup that wrote it is gone (killed / crashed): no need to wait the 10 minutes.
            # Liveness by PID, not by name, so a renamed installer still counts as running.
            $setupGone = $jSetupPid -gt 0 -and -not (Get-Process -Id $jSetupPid -ErrorAction SilentlyContinue)
            $stale = (($nowUtc - $at).TotalMinutes -gt $StaleMinutes) -or ($null -ne $boot -and $at -lt $boot) -or $setupGone
            if (-not $stale) {
                Write-HelperLog ("install journal phase={0} is only {1:N0} s old and no reboot since -- not stale yet" -f $phase, ($nowUtc - $at).TotalSeconds)
                exit 22
            }
            # Claim it atomically; whoever renames first owns the recovery.
            $claimed = Join-Path $StateDir ("install_journal.restoring-{0}.json" -f $PID)
            try { [System.IO.File]::Move($JournalPath, $claimed) } catch {
                Write-HelperLog 'install journal claimed by someone else -- backing off'
                exit 22
            }
            Write-HelperLog ("claimed stale journal phase={0} from={1} to={2} at={3:o}" -f $phase, $jFrom, $jTo, $at)
            Remove-Item -LiteralPath $SentinelPath -Force -ErrorAction SilentlyContinue
            $doRestore = $phase -in @('copying', 'verifying', 'restoring')
            if ($phase -eq 'backing_up') { $doRestore = $false }
            elseif (-not $doRestore) { $doRestore = Test-PayloadComplete $PreviousDir }
            if (-not $doRestore) {
                Write-LastUpdate 'ABORTED' $jFrom $jTo 'interrupted'
                Remove-Item -LiteralPath $claimed -Force -ErrorAction SilentlyContinue
                Write-HelperLog 'interrupted before current\ was touched -- journal dropped, no restore'
                exit 21
            }
            if (Invoke-Restore) {
                Write-LastUpdate 'ROLLED_BACK' $jTo $jFrom 'interrupted'
                Remove-Item -LiteralPath $claimed -Force -ErrorAction SilentlyContinue
                exit 20
            }
            # Put the journal back so the next attempt retries the restore.
            try { [System.IO.File]::Move($claimed, $JournalPath) } catch { }
            Write-LastUpdate 'ROLLED_BACK' $jTo $jFrom 'restore_failed'
            exit 23
        }
    }
} catch {
    Write-HelperLog "FAILED: $($_.Exception.Message)"
    if ($Action -eq 'backup') { if ($script:CurrentTouched) { exit 3 } else { exit 2 } }
    if ($Action -eq 'launch-wait' -or $Action -eq 'relaunch') { exit 12 }
    if ($Action -eq 'recover') { exit 23 }
    exit 3
}
