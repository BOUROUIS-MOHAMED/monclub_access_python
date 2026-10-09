<#
.SYNOPSIS
    TEST-ONLY: runs ONE silent installer case the way a client launches it, then records the
    evidence and checks the outcome (updater v2 lane L2 E2E, design.md section 8).

.DESCRIPTION
    1. Stops the app (the client quits before Setup runs).
    2. Starts Setup silently:
         -Launcher legacy  : like the 1.4.35 client -- /VERYSILENT /SUPPRESSMSGBOXES, no /LOG,
                             and Setup's working directory INSIDE {app}\current (design 8.0 trap);
         -Launcher wrapper : like the v2 wrapper -- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
                             /LOG=<root>\logs\update-<ver>-<ts>.log, working directory {app}\state.
       -LockFile <relative path under current\> keeps that file open (no delete sharing) while
       Setup runs.
    3. Waits for Setup, waits -SettleSec, then writes <EvidenceDir>\<Name>\: summary.json,
       last_update.json, the Setup log, stub.log, the helper logs Setup copied into its log.
    4. PASS when: last_update result/reason are the expected ones; exactly one app process
       runs, from {app}\current; current\version.json has -ExpectVersion; no journal left;
       no pause sentinel left.
#>
param(
    [ValidateSet('access', 'tv')] [string] $Component = 'access',
    [Parameter(Mandatory = $true)] [string] $Installer,
    [Parameter(Mandatory = $true)] [string] $Name,
    [Parameter(Mandatory = $true)] [string] $EvidenceDir,
    [ValidateSet('legacy', 'wrapper')] [string] $Launcher = 'wrapper',
    [string] $LockFile = '',
    [Parameter(Mandatory = $true)] [string] $ExpectResult,
    [string] $ExpectReason = '',
    [Parameter(Mandatory = $true)] [string] $ExpectVersion,
    [int] $SettleSec = 6,
    [int] $SetupTimeoutSec = 600
)
$ErrorActionPreference = 'Stop'
$exe = if ($Component -eq 'access') { 'MonClubAccess.exe' } else { 'MonClubTV.exe' }
$root = Join-Path $env:LOCALAPPDATA ($(if ($Component -eq 'access') { 'MonClubAccess' } else { 'MonClubTV' }))
$out = Join-Path $EvidenceDir $Name
if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Recurse -Force }
New-Item -ItemType Directory -Path $out -Force | Out-Null

function Get-AppProcs {
    @(Get-CimInstance Win32_Process -Filter "Name='$exe'" | Select-Object ProcessId, ExecutablePath)
}

# 1. the client quits first
foreach ($p in (Get-AppProcs)) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 1
Remove-Item -LiteralPath (Join-Path $root 'state\last_update.json') -Force -ErrorAction SilentlyContinue
$before = [ordered]@{
    currentVersion = $(try { (Get-Content (Join-Path $root 'current\version.json') -Raw | ConvertFrom-Json).version } catch { '' })
    previousVersion = $(try { (Get-Content (Join-Path $root 'previous\version.json') -Raw | ConvertFrom-Json).version } catch { '' })
}

$holder = $null
if ($LockFile) {
    $lockPath = Join-Path (Join-Path $root 'current') $LockFile
    # FileShare.Read only: the file can be read (backup copy) but not deleted.
    $code = "`$f=[IO.File]::Open('$lockPath','Open','Read','Read'); Start-Sleep -Seconds 180; `$f.Close()"
    $holder = Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile', '-Command', $code -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 2
}

# 2. Setup, launched like the client
$stamp = Get-Date -Format 'yyyyMMddHHmmss'
$started = Get-Date
if ($Launcher -eq 'legacy') {
    $p = Start-Process -FilePath $Installer -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES' `
        -WorkingDirectory (Join-Path $root 'current') -PassThru
} else {
    New-Item -ItemType Directory -Path (Join-Path $root 'logs'), (Join-Path $root 'state') -Force | Out-Null
    $setupLog = Join-Path $root "logs\update-$Name-$stamp.log"
    $p = Start-Process -FilePath $Installer -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/LOG=`"$setupLog`"" `
        -WorkingDirectory (Join-Path $root 'state') -PassThru
}
$exited = $p.WaitForExit($SetupTimeoutSec * 1000)
$setupSec = ((Get-Date) - $started).TotalSeconds
$exitCode = if ($exited) { $p.ExitCode } else { 'TIMEOUT' }
if ($holder) { Stop-Process -Id $holder.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds $SettleSec

# 3. evidence
$last = $null
$lastPath = Join-Path $root 'state\last_update.json'
if (Test-Path -LiteralPath $lastPath) {
    Copy-Item -LiteralPath $lastPath (Join-Path $out 'last_update.json')
    $last = Get-Content -LiteralPath $lastPath -Raw | ConvertFrom-Json
}
$logFile = if ($last -and $last.log) { [string] $last.log } elseif ($Launcher -eq 'wrapper') { $setupLog } else { '' }
if ($logFile -and (Test-Path -LiteralPath $logFile)) { Copy-Item -LiteralPath $logFile (Join-Path $out 'setup.log') }
$stubLog = Join-Path $root 'logs\stub.log'
if (Test-Path -LiteralPath $stubLog) { Get-Content -LiteralPath $stubLog -Tail 6 | Set-Content (Join-Path $out 'stub.log.tail.txt') }

$procs = @(Get-AppProcs)
$curVersion = $(try { (Get-Content (Join-Path $root 'current\version.json') -Raw | ConvertFrom-Json).version } catch { '' })
$prevVersion = $(try { (Get-Content (Join-Path $root 'previous\version.json') -Raw | ConvertFrom-Json).version } catch { '' })
$journal = Test-Path -LiteralPath (Join-Path $root 'state\install_journal.json')
$sentinel = Test-Path -LiteralPath (Join-Path $root '.update-in-progress')
$fromCurrent = @($procs | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.ToLower().StartsWith((Join-Path $root 'current\').ToLower()) })

$checks = [ordered]@{
    result        = ($last -and $last.result -eq $ExpectResult)
    reason        = ($last -and [string] $last.reason -eq $ExpectReason)
    oneAppRunning = ($procs.Count -eq 1)
    fromCurrent   = ($fromCurrent.Count -eq 1)
    version       = ($curVersion -eq $ExpectVersion)
    noJournal     = (-not $journal)
    noSentinel    = (-not $sentinel)
}
$pass = -not ($checks.Values -contains $false)
$summary = [ordered]@{
    case = $Name; component = $Component; installer = (Split-Path -Leaf $Installer); launcher = $Launcher
    lockFile = $LockFile; at = (Get-Date).ToString('o'); before = $before
    setupExitCode = $exitCode; setupSeconds = [math]::Round($setupSec, 1)
    lastUpdate = $last; currentVersion = $curVersion; previousVersion = $prevVersion
    appProcesses = $procs; journalLeft = $journal; sentinelLeft = $sentinel
    expected = [ordered]@{ result = $ExpectResult; reason = $ExpectReason; version = $ExpectVersion }
    checks = $checks; PASS = $pass
}
$summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $out 'summary.json') -Encoding UTF8
Write-Host ("{0}: {1}  (setup exit {2}, {3:N0} s; last_update {4}/{5}; current {6}; procs {7})" -f `
    $Name, $(if ($pass) { 'PASS' } else { 'FAIL' }), $exitCode, $setupSec, $last.result, $last.reason, $curVersion, $procs.Count)
if (-not $pass) { $checks.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object { Write-Host "  failed check: $($_.Key)" } }
