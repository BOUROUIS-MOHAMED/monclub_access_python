param(
  [ValidateSet("access", "tv", "both")]
  [string]$Component = "both",

  [ValidateSet("stable", "beta")]
  [string]$Channel = "stable",

  [string]$ReleaseId = "",

  [switch]$RecreateVenv,

  [switch]$SkipTauriBuild,

  # Passed through to build_release.ps1 (see its parameters).
  [switch]$SkipTests,
  [switch]$E2ETestKeys,
  [string]$SigningKeyId = "",
  [string]$ReleaseNotesFile = "",
  [string]$SignTool = "",

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
  if ($SkipTests) { $args += "-SkipTests" }
  if ($E2ETestKeys) { $args += "-E2ETestKeys" }
  if ($SigningKeyId) { $args += @("-SigningKeyId", $SigningKeyId) }
  if ($ReleaseNotesFile) { $args += @("-ReleaseNotesFile", $ReleaseNotesFile) }
  if ($SignTool) { $args += @("-SignTool", $SignTool) }
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

  # build_release.ps1 runs the gates, builds the payload, compiles the installer and writes
  # the signed release file (releaseelease-<component>-<version>.json).
  Invoke-Step -Name ("Build, package and sign ({0})" -f $targetMeta.DisplayName) -Action {
    Invoke-ReleaseBuild -TargetComponent $targetComponent -ResolvedReleaseId $ReleaseId
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
