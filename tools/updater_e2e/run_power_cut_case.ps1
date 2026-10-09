<#
.SYNOPSIS
    TEST-ONLY (updater v2 lane L2, design 8 step 12): simulates a power cut while Setup waits for
    the new version (journal phase "verifying"): Setup, its helper and the new app are killed
    together, then ONE tick of the INSTALLED watchdog (as the scheduled task runs it) must
    restore previous\, record ROLLED_BACK "interrupted" and start the app from current\.
#>
param(
    [Parameter(Mandatory = $true)] [string] $Installer,
    [Parameter(Mandatory = $true)] [string] $Name,
    [Parameter(Mandatory = $true)] [string] $EvidenceDir,
    [Parameter(Mandatory = $true)] [string] $ExpectVersion
)
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:LOCALAPPDATA 'MonClubAccess'
$out = Join-Path $EvidenceDir $Name
if (Test-Path -LiteralPath $out) { Get-ChildItem -LiteralPath $out | ForEach-Object { $_.Delete() } }
New-Item -ItemType Directory -Path $out -Force | Out-Null

Get-CimInstance Win32_Process -Filter "Name='MonClubAccess.exe'" | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
$lastPath = Join-Path $root 'state\last_update.json'
if (Test-Path -LiteralPath $lastPath) { [IO.File]::Delete($lastPath) }
$setupLog = Join-Path $root 'logs\update-power-cut.log'
Start-Process -FilePath $Installer -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/LOG=`"$setupLog`"" `
    -WorkingDirectory (Join-Path $root 'state') | Out-Null

$journalPath = Join-Path $root 'state\install_journal.json'
$deadline = (Get-Date).AddSeconds(90)
do {
    Start-Sleep -Milliseconds 500
    $j = $null
    try { $j = Get-Content -LiteralPath $journalPath -Raw -ErrorAction Stop | ConvertFrom-Json } catch { }
} until (($j -and $j.phase -eq 'verifying') -or (Get-Date) -gt $deadline)
Start-Sleep -Seconds 3
Get-Content -LiteralPath $journalPath -Raw | Set-Content (Join-Path $out 'journal_at_power_cut.json')

# The power cut: everything dies at once.
$killed = @()
foreach ($p in @(Get-CimInstance Win32_Process)) {
    if ($p.Name -match '^monclub_access_[0-9]' -or $p.Name -eq 'MonClubAccess.exe' -or
        ($p.Name -eq 'powershell.exe' -and [string] $p.CommandLine -like '*update_helper.ps1*')) {
        $killed += "$($p.Name) $($p.ProcessId)"
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
    }
}
Start-Sleep -Seconds 2
$afterCut = [ordered]@{
    killed = $killed
    currentVersion = (Get-Content (Join-Path $root 'current\version.json') -Raw | ConvertFrom-Json).version
    previousVersion = (Get-Content (Join-Path $root 'previous\version.json') -Raw | ConvertFrom-Json).version
    sentinel = (Test-Path (Join-Path $root '.update-in-progress'))
    journal = (Test-Path $journalPath)
}

# One watchdog tick, installed copy, real run.
$tickStart = Get-Date
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'watchdog\monclub_access_watchdog.ps1') | Out-Null
Start-Sleep -Seconds 6
Get-Content (Join-Path $root 'logs\watchdog.log') -Tail 4 | Set-Content (Join-Path $out 'watchdog.log.tail.txt')
foreach ($f in @('logs\update-recover.log', 'state\last_update.json')) {
    $src = Join-Path $root $f
    if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination $out }
}
if (Test-Path -LiteralPath $setupLog) { Copy-Item -LiteralPath $setupLog -Destination (Join-Path $out 'setup.log') }
Get-Content (Join-Path $root 'logs\stub.log') -Tail 2 | Set-Content (Join-Path $out 'stub.log.tail.txt')

$procs = @(Get-CimInstance Win32_Process -Filter "Name='MonClubAccess.exe'" | Select-Object ProcessId, ExecutablePath)
$last = Get-Content -LiteralPath $lastPath -Raw | ConvertFrom-Json
$res = [ordered]@{
    case = $Name; afterPowerCut = $afterCut; watchdogTickSeconds = [math]::Round(((Get-Date) - $tickStart).TotalSeconds, 1)
    lastUpdate = $last
    currentVersion = (Get-Content (Join-Path $root 'current\version.json') -Raw | ConvertFrom-Json).version
    appProcesses = $procs
    journalLeft = (Test-Path $journalPath)
    claimsLeft = @(Get-ChildItem (Join-Path $root 'state') -Filter 'install_journal.restoring-*').Count
    sentinelLeft = (Test-Path (Join-Path $root '.update-in-progress'))
}
$prefix = (Join-Path $root 'current\').ToLower()
$res.PASS = ($last.result -eq 'ROLLED_BACK' -and $last.reason -eq 'interrupted' -and $res.currentVersion -eq $ExpectVersion -and
             $procs.Count -eq 1 -and $procs[0].ExecutablePath.ToLower().StartsWith($prefix) -and
             -not $res.journalLeft -and $res.claimsLeft -eq 0 -and -not $res.sentinelLeft)
$res | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $out 'summary.json') -Encoding UTF8
Write-Host ("{0}: {1} (current {2}, last_update {3}/{4}, procs {5})" -f $Name, $(if ($res.PASS) { 'PASS' } else { 'FAIL' }),
    $res.currentVersion, $last.result, $last.reason, $procs.Count)
