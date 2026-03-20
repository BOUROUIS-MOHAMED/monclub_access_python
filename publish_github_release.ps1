param(
  [ValidateSet("access", "tv")]
  [string]$Component = "access",

  [ValidateSet("stable","beta")]
  [string]$Channel = "stable",

  [string]$ManifestPath = "",

  [string]$Repo = "BOUROUIS-MOHAMED/monclub_access_python",

  [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ROOT

. (Join-Path $ROOT "packaging\desktop_components.ps1")
$meta = Get-DesktopComponentMetadata -Component $Component

function Pick-NewestManifest {
  $m = Get-ChildItem (Join-Path $ROOT "release\$($meta.ManifestGlob)") -File |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
  if (-not $m) { throw "No manifest found in .\release\ ($($meta.ManifestGlob))" }
  return $m.FullName
}

if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
  $ManifestPath = Pick-NewestManifest
}

if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
  throw "Manifest not found: $ManifestPath"
}

$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
$releaseId = $manifest.releaseId
if ([string]::IsNullOrWhiteSpace($releaseId)) { throw "releaseId missing in manifest" }

$releaseDir = Join-Path (Get-Location) "release"
$setupExe = Join-Path $releaseDir ("{0}-{1}.exe" -f $meta.InstallerBaseName, $releaseId)
$zipPath = Join-Path $releaseDir ("{0}-{1}.zip" -f $meta.ArtifactName, $releaseId)

if (-not (Test-Path -LiteralPath $setupExe -PathType Leaf)) {
  throw "Installer not found: $setupExe (run build_installer.ps1 -Component $Component first)"
}
if (-not (Test-Path -LiteralPath $zipPath -PathType Leaf)) {
  throw "Release ZIP not found: $zipPath (run build_release.ps1 -Component $Component first)"
}

$assets = @($setupExe, $ManifestPath, $zipPath)
$tag = "{0}-win-{1}-{2}" -f $Component, $Channel, $releaseId
$title = "{0} Windows ({1}) - {2}" -f $meta.ArtifactName, $Channel, $releaseId

$extraFlags = @("-R", $Repo, "--title", $title, "--notes", "Automated build $releaseId")
if ($Channel -eq "beta") {
  $extraFlags += "--prerelease"
  $extraFlags += "--latest=false"
} else {
  $extraFlags += "--latest"
}

Write-Host "Creating release: $tag" -ForegroundColor Cyan
Write-Host "Assets:" -ForegroundColor Cyan
$assets | ForEach-Object { Write-Host " - $_" }

if ($DryRun) {
  Write-Host "DryRun enabled. GitHub release creation skipped." -ForegroundColor Yellow
  exit 0
}

gh release create $tag @assets @extraFlags
Write-Host "Done." -ForegroundColor Green
