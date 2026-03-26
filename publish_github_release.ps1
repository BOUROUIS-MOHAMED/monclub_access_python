param(
  [ValidateSet("access", "tv")]
  [string]$Component = "access",

  [ValidateSet("stable","beta")]
  [string]$Channel = "stable",

  [string]$InstallerPath = "",

  [string]$Repo = "BOUROUIS-MOHAMED/monclub_access_python",

  [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ROOT

. (Join-Path $ROOT "packaging\desktop_components.ps1")
$meta = Get-DesktopComponentMetadata -Component $Component
$versionInfo = Get-DesktopComponentVersionInfo -Component $Component

if ([string]::IsNullOrWhiteSpace($InstallerPath)) {
  $InstallerPath = Join-Path $ROOT ("release\{0}" -f $versionInfo.InstallerFileName)
}

if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
  throw "Installer not found: $InstallerPath (run generate_installer.ps1 -Component $Component first)"
}

$tag = "{0}-win-{1}-v{2}" -f $Component, $Channel, $versionInfo.Version
$title = "{0} Windows ({1}) - v{2}" -f $meta.DisplayName, $Channel, $versionInfo.Version
$notes = "Automated unified installer build for $($meta.DisplayName) v$($versionInfo.Version)."

$extraFlags = @("-R", $Repo, "--title", $title, "--notes", $notes)
if ($Channel -eq "beta") {
  $extraFlags += "--prerelease"
  $extraFlags += "--latest=false"
} else {
  $extraFlags += "--latest"
}

Write-Host "Creating release: $tag" -ForegroundColor Cyan
Write-Host "Asset: $InstallerPath" -ForegroundColor Cyan

if ($DryRun) {
  Write-Host "DryRun enabled. GitHub release creation skipped." -ForegroundColor Yellow
  exit 0
}

gh release create $tag $InstallerPath @extraFlags
Write-Host "Done." -ForegroundColor Green
