param(
  [ValidateSet("access", "tv", "both")]
  [string]$Component = "both",

  [ValidateSet("stable", "beta")]
  [string]$Channel = "stable",

  [string]$ReleaseId = "",

  [switch]$RecreateVenv,

  [switch]$SkipTauriBuild,

  [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ROOT

. (Join-Path $ROOT "packaging\desktop_components.ps1")

function Invoke-Step {
  param(
    [string]$Name,
    [scriptblock]$Action
  )

  Write-Host "`n== $Name ==" -ForegroundColor Cyan
  & $Action
}

function Resolve-ComponentList([string]$Value) {
  if ($Value -eq "both") { return @("access", "tv") }
  return @($Value)
}

function Invoke-ReleaseBuild([string]$TargetComponent, [string]$ResolvedReleaseId) {
  $args = @(
    "-ExecutionPolicy", "Bypass",
    "-File", (Join-Path $ROOT "build_release.ps1"),
    "-Component", $TargetComponent,
    "-Channel", $Channel
  )

  if ($RecreateVenv) {
    $args += "-RecreateVenv"
  }
  if ($SkipTauriBuild) {
    $args += "-SkipTauriBuild"
  }
  if ($DryRun) {
    $args += "-DryRun"
  }
  if (-not [string]::IsNullOrWhiteSpace($ResolvedReleaseId)) {
    $args += "-ReleaseId"
    $args += $ResolvedReleaseId
  }

  & powershell @args
  if ($LASTEXITCODE -ne 0) {
    throw "build_release.ps1 failed for $TargetComponent with exit code $LASTEXITCODE"
  }
}

function Invoke-InstallerBuild([string]$TargetComponent) {
  $args = @(
    "-ExecutionPolicy", "Bypass",
    "-File", (Join-Path $ROOT "build_installer.ps1"),
    "-Component", $TargetComponent
  )
  if ($DryRun) {
    $args += "-DryRun"
  }

  & powershell @args
  if ($LASTEXITCODE -ne 0) {
    throw "build_installer.ps1 failed for $TargetComponent with exit code $LASTEXITCODE"
  }
}

function Find-InstallerArtifact([string]$TargetComponent) {
  $versionInfo = Get-DesktopComponentVersionInfo -Component $TargetComponent
  $installerPath = Join-Path $ROOT ("release\{0}" -f $versionInfo.InstallerFileName)
  if (-not (Test-Path -LiteralPath $installerPath -PathType Leaf)) {
    throw "Installer not found for ${TargetComponent}: $installerPath"
  }
  return $installerPath
}

$components = Resolve-ComponentList $Component
if ([string]::IsNullOrWhiteSpace($ReleaseId)) {
  $ReleaseId = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss'Z'")
}

Invoke-Step -Name "Environment summary" -Action {
  Write-Host "Root      : $ROOT"
  Write-Host "Component : $Component"
  Write-Host "Channel   : $Channel"
  Write-Host "ReleaseId : $ReleaseId"
  if ($DryRun) {
    Write-Host "DryRun    : true"
  }
}

foreach ($targetComponent in $components) {
  $targetMeta = Get-DesktopComponentMetadata -Component $targetComponent
  $versionInfo = Get-DesktopComponentVersionInfo -Component $targetComponent

  Invoke-Step -Name ("Build release payload ({0})" -f $targetMeta.DisplayName) -Action {
    Invoke-ReleaseBuild -TargetComponent $targetComponent -ResolvedReleaseId $ReleaseId
  }

  Invoke-Step -Name ("Build unified installer ({0})" -f $targetMeta.DisplayName) -Action {
    if ($DryRun) {
      $expectedPath = Join-Path $ROOT ("release\{0}" -f $versionInfo.InstallerFileName)
      Write-Host ("DryRun installer target: {0}" -f $expectedPath) -ForegroundColor Yellow
    } else {
      Invoke-InstallerBuild -TargetComponent $targetComponent
    }
  }
}

Invoke-Step -Name "Locate generated outputs" -Action {
  foreach ($targetComponent in $components) {
    $targetMeta = Get-DesktopComponentMetadata -Component $targetComponent
    $versionInfo = Get-DesktopComponentVersionInfo -Component $targetComponent
    $installerText = if ($DryRun) {
      Join-Path $ROOT ("release\{0}" -f $versionInfo.InstallerFileName)
    } else {
      Find-InstallerArtifact -TargetComponent $targetComponent
    }

    Write-Host "$($targetMeta.DisplayName) installer: $installerText" -ForegroundColor Green
  }
}

Write-Host "`nDone." -ForegroundColor Green
