$script:DesktopComponentsRepoRoot = Split-Path -Parent $PSScriptRoot
$script:DesktopComponentsVersionSourcePath = Join-Path $script:DesktopComponentsRepoRoot "update.json"

function Get-DesktopComponentMetadata {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("access", "tv")]
    [string]$Component
  )

  switch ($Component) {
    "access" {
      return @{
        Id = "access"
        ArtifactName = "MonClubAccess"
        DisplayName = "MonClub Access"
        MainExe = "MonClubAccess.exe"
        MainProcessName = "MonClubAccess"
        SpecPath = ".\MonClubAccess.spec"
        InstallerScript = ".\installer\MonClubAccess.iss"
        InstallerBaseName = "monclub_access"
        UiExeName = "monclub-access-ui.exe"
        UiStagingDir = ".\tauri-ui\component-shells\MonClubAccess"
        DefaultInstallRootName = "MonClubAccess"
        UpdaterInstalledExe = "MonClubAccessUpdater.exe"
        UpdaterSourceExe = "MonClubDesktopUpdater.exe"
        RequiresSdkDlls = $true
        Requires32BitPython = $true
      }
    }
    "tv" {
      return @{
        Id = "tv"
        ArtifactName = "MonClubTV"
        DisplayName = "MonClub TV"
        MainExe = "MonClubTV.exe"
        MainProcessName = "MonClubTV"
        SpecPath = ".\MonClubTV.spec"
        InstallerScript = ".\installer\MonClubTV.iss"
        InstallerBaseName = "monclub_tv"
        UiExeName = "monclub-tv-ui.exe"
        UiStagingDir = ".\tauri-ui\component-shells\MonClubTV"
        DefaultInstallRootName = "MonClubTV"
        UpdaterInstalledExe = "MonClubTVUpdater.exe"
        UpdaterSourceExe = "MonClubDesktopUpdater.exe"
        RequiresSdkDlls = $false
        Requires32BitPython = $false
      }
    }
  }
}

function Get-DesktopComponentVersionInfo {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("access", "tv")]
    [string]$Component
  )

  if (-not (Test-Path -LiteralPath $script:DesktopComponentsVersionSourcePath -PathType Leaf)) {
    throw "Version source file not found: $script:DesktopComponentsVersionSourcePath"
  }

  $source = Get-Content -LiteralPath $script:DesktopComponentsVersionSourcePath -Raw | ConvertFrom-Json
  $entry = $source.$Component
  if (-not $entry) {
    throw "Component '$Component' not found in version source: $script:DesktopComponentsVersionSourcePath"
  }

  $version = [string]($entry.version)
  $codename = [string]($entry.codename)
  if ([string]::IsNullOrWhiteSpace($version)) {
    throw "Version is missing for component '$Component' in $script:DesktopComponentsVersionSourcePath"
  }
  if ($version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z\.-]+)?$') {
    throw "Version '$version' for component '$Component' is not a supported semantic version."
  }

  $meta = Get-DesktopComponentMetadata -Component $Component
  return @{
    Version = $version
    Codename = $codename
    VersionSourcePath = $script:DesktopComponentsVersionSourcePath
    InstallerFileName = (Format-DesktopInstallerFileName -Component $Component -Version $version)
  }
}

function Format-DesktopInstallerFileName {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("access", "tv")]
    [string]$Component,

    [Parameter(Mandatory = $true)]
    [string]$Version
  )

  $meta = Get-DesktopComponentMetadata -Component $Component
  return ("{0}_{1}.exe" -f $meta.InstallerBaseName, $Version)
}
