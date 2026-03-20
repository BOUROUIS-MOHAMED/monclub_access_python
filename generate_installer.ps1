param(
  [ValidateSet("access", "tv", "both")]
  [string]$Component = "access",

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

function Find-LatestArtifact([hashtable]$Meta, [string]$SuffixPattern) {
  $releaseDir = Join-Path $ROOT "release"
  $item = Get-ChildItem -Path $releaseDir -Filter $SuffixPattern -File |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
  return $item
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

  Invoke-Step -Name ("Build release payload ({0})" -f $targetMeta.DisplayName) -Action {
    Invoke-ReleaseBuild -TargetComponent $targetComponent -ResolvedReleaseId $ReleaseId
  }

  Invoke-Step -Name ("Build installer ({0})" -f $targetMeta.DisplayName) -Action {
    if ($DryRun) {
      Write-Host ("DryRun installer target: release\{0}-{1}.exe" -f $targetMeta.InstallerBaseName, $ReleaseId) -ForegroundColor Yellow
    } else {
      Invoke-InstallerBuild -TargetComponent $targetComponent
    }
  }
}

Invoke-Step -Name "Locate generated outputs" -Action {
  foreach ($targetComponent in $components) {
    $targetMeta = Get-DesktopComponentMetadata -Component $targetComponent
    $installer = $null
    $manifest = $null
    $zip = $null
    if (-not $DryRun) {
      $installer = Find-LatestArtifact -Meta $targetMeta -SuffixPattern ("{0}-{1}.exe" -f $targetMeta.InstallerBaseName, $ReleaseId)
      $manifest = Find-LatestArtifact -Meta $targetMeta -SuffixPattern ("{0}-{1}.manifest.json" -f $targetMeta.ArtifactName, $ReleaseId)
      $zip = Find-LatestArtifact -Meta $targetMeta -SuffixPattern ("{0}-{1}.zip" -f $targetMeta.ArtifactName, $ReleaseId)
    }

    if (-not $DryRun) {
      if (-not $installer) { throw "Installer not found for $targetComponent" }
      if (-not $manifest) { throw "Manifest not found for $targetComponent" }
      if (-not $zip) { throw "ZIP not found for $targetComponent" }
    }

    $installerText = if ($installer) { $installer.FullName } else { Join-Path $ROOT ("release\{0}-{1}.exe" -f $targetMeta.InstallerBaseName, $ReleaseId) }
    $manifestText = if ($manifest) { $manifest.FullName } else { Join-Path $ROOT ("release\{0}-{1}.manifest.json" -f $targetMeta.ArtifactName, $ReleaseId) }
    $zipText = if ($zip) { $zip.FullName } else { Join-Path $ROOT ("release\{0}-{1}.zip" -f $targetMeta.ArtifactName, $ReleaseId) }

    Write-Host "$($targetMeta.DisplayName) installer: $installerText" -ForegroundColor Green
    Write-Host "$($targetMeta.DisplayName) manifest : $manifestText" -ForegroundColor Green
    Write-Host "$($targetMeta.DisplayName) zip      : $zipText" -ForegroundColor Green
  }
}

if (($components.Count -gt 1) -and (-not $DryRun)) {
  Invoke-Step -Name "Write ecosystem bundle manifest" -Action {
    $bundlePath = Join-Path $ROOT ("release\MonClubDesktopEcosystem-{0}.bundle.json" -f $ReleaseId)
    $bundle = [ordered]@{
      releaseId = $ReleaseId
      channel = $Channel
      builtAtUtc = (Get-Date).ToUniversalTime().ToString("o")
      components = [ordered]@{}
    }

    foreach ($targetComponent in $components) {
      $targetMeta = Get-DesktopComponentMetadata -Component $targetComponent
      $bundle.components[$targetComponent] = [ordered]@{
        artifact = $targetMeta.ArtifactName
        installer = (Join-Path $ROOT ("release\{0}-{1}.exe" -f $targetMeta.InstallerBaseName, $ReleaseId))
        manifest = (Join-Path $ROOT ("release\{0}-{1}.manifest.json" -f $targetMeta.ArtifactName, $ReleaseId))
        zip = (Join-Path $ROOT ("release\{0}-{1}.zip" -f $targetMeta.ArtifactName, $ReleaseId))
      }
    }

    ($bundle | ConvertTo-Json -Depth 6) | Out-File -LiteralPath $bundlePath -Encoding utf8
    Write-Host "Ecosystem bundle manifest: $bundlePath" -ForegroundColor Green
  }
}

Write-Host "`nDone." -ForegroundColor Green
