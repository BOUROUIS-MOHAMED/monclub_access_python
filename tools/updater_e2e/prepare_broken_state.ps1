<#
.SYNOPSIS
    TEST-ONLY (updater v2 lane L2 E2E): puts the installed MonClub Access into a broken state a
    killed Setup can leave, so the next installer run must repair it.
      half-copy      : current\MonClubAccess.exe deleted (version.json stays), no journal
      stale-journal  : previous\ = the current version, current\ half-written (exe deleted,
                       version.json says -ToVersion), journal phase "copying" with a dead setupPid
#>
param(
    [ValidateSet('half-copy', 'stale-journal')] [string] $Mode,
    [string] $ToVersion = '1.5.1'
)
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:LOCALAPPDATA 'MonClubAccess'
Get-CimInstance Win32_Process -Filter "Name='MonClubAccess.exe'" | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Start-Sleep -Seconds 1
$cur = Join-Path $root 'current'
$fromVersion = (Get-Content (Join-Path $cur 'version.json') -Raw | ConvertFrom-Json).version
if ($Mode -eq 'stale-journal') {
    & robocopy $cur (Join-Path $root 'previous') /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
    [IO.File]::WriteAllText((Join-Path $cur 'version.json'), ('{"version":"' + $ToVersion + '"}'))
    $dead = Start-Process -FilePath cmd.exe -ArgumentList '/c', 'exit' -PassThru -WindowStyle Hidden
    $dead.WaitForExit()
    $at = [DateTime]::UtcNow.AddMinutes(-1).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture)
    $j = '{"phase":"copying","from":"' + $fromVersion + '","to":"' + $ToVersion + '","at":"' + $at + '","setupPid":' + $dead.Id + '}'
    [IO.File]::WriteAllText((Join-Path $root 'state\install_journal.json'), $j)
}
[IO.File]::Delete((Join-Path $cur 'MonClubAccess.exe'))
Write-Host ("{0}: exe present={1}; current version.json={2}; previous={3}; journal={4}" -f $Mode,
    (Test-Path (Join-Path $cur 'MonClubAccess.exe')),
    (Get-Content (Join-Path $cur 'version.json') -Raw),
    $(try { (Get-Content (Join-Path $root 'previous\version.json') -Raw | ConvertFrom-Json).version } catch { '-' }),
    (Test-Path (Join-Path $root 'state\install_journal.json')))
