<#
.SYNOPSIS
    TEST-ONLY: silent uninstall of MonClub Access or MonClub TV and a record of which data
    folders survived (updater v2 lane L2, D26). DELETES DATA under the shared data root --
    snapshot %ProgramData%\MonClub Access first.
#>
param(
    [ValidateSet('access', 'tv')] [string] $Component,
    [Parameter(Mandatory = $true)] [string] $Name,
    [Parameter(Mandatory = $true)] [string] $EvidenceDir
)
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:LOCALAPPDATA ($(if ($Component -eq 'access') { 'MonClubAccess' } else { 'MonClubTV' }))
$dataRoots = @((Join-Path $env:ProgramData 'MonClub Access'), (Join-Path $env:LOCALAPPDATA 'MonClub Access'))
$out = Join-Path $EvidenceDir $Name
if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Recurse -Force }
New-Item -ItemType Directory -Path $out -Force | Out-Null

function Get-DataState {
    $s = [ordered]@{}
    foreach ($r in $dataRoots) {
        $s[$r] = if (Test-Path -LiteralPath $r) { @(Get-ChildItem -LiteralPath $r -Force | ForEach-Object Name) } else { 'ABSENT' }
    }
    return $s
}
function Get-Installed {
    $u = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
    [ordered]@{
        access = Test-Path "$u\{9B77A9C2-2B97-4F62-A9E8-4B4C65F3A9B1}_is1"
        tv     = Test-Path "$u\{4A8D6A8A-7AC6-4C87-862D-2E5A6B644D27}_is1"
    }
}

$before = [ordered]@{ installed = Get-Installed; data = Get-DataState; appRootExists = (Test-Path $root) }
$unins = Join-Path $root 'unins000.exe'
$log = Join-Path $out 'uninstall.log'
$started = Get-Date
$p = Start-Process -FilePath $unins -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/LOG=`"$log`"" -PassThru
$p.WaitForExit(300000) | Out-Null
# unins000.exe re-launches itself from %TEMP% and returns at once: wait for that copy too.
$deadline = (Get-Date).AddSeconds(120)
while ((Get-Date) -lt $deadline -and @(Get-CimInstance Win32_Process | Where-Object { $_.Name -like '_iu*.tmp' -or $_.Name -like 'Un_*.exe' }).Count -gt 0) { Start-Sleep -Seconds 1 }
Start-Sleep -Seconds 3
$after = [ordered]@{ installed = Get-Installed; data = Get-DataState; appRootExists = (Test-Path $root) }
[ordered]@{ case = $Name; component = $Component; seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
            exitCode = $p.ExitCode; before = $before; after = $after } |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $out 'summary.json') -Encoding UTF8
Write-Host "$Name"
Write-Host ("  before: " + ($before | ConvertTo-Json -Depth 4 -Compress))
Write-Host ("  after : " + ($after | ConvertTo-Json -Depth 4 -Compress))
