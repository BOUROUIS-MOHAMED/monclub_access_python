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
        InstallerBaseName = "MonClubAccessSetup"
        ManifestGlob = "MonClubAccess-*.manifest.json"
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
        InstallerBaseName = "MonClubTVSetup"
        ManifestGlob = "MonClubTV-*.manifest.json"
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
