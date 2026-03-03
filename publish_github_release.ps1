param(
  [ValidateSet("stable","beta")]
  [string]$Channel = "stable",

  # If empty: auto-pick newest manifest in .\release\
  [string]$ManifestPath = "",

  # Your repo
  [string]$Repo = "BOUROUIS-MOHAMED/monclub_access_python"
)

$ErrorActionPreference = "Stop"

# Always run relative paths from repo root (script directory)
$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ROOT

function Pick-NewestManifest {
  $m = Get-ChildItem ".\release\MonClubAccess-*.manifest.json" -File |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
  if (-not $m) { throw "No manifest found in .\release\ (MonClubAccess-*.manifest.json)" }
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

# Resolve expected assets (MUST match build_release.ps1 naming)
$releaseDir = Join-Path (Get-Location) "release"
$setupExe   = Join-Path $releaseDir ("MonClubAccessSetup-{0}.exe" -f $releaseId)
$zipPath    = Join-Path $releaseDir ("MonClubAccess-{0}.zip" -f $releaseId)

if (-not (Test-Path -LiteralPath $setupExe -PathType Leaf)) {
  throw "Installer not found: $setupExe (run build_installer.ps1 first)"
}

# Update system REQUIREMENT: ZIP must exist (download target)
if (-not (Test-Path -LiteralPath $zipPath -PathType Leaf)) {
  throw @"
Release ZIP not found:
  $zipPath

Your backend/update flow needs the ZIP as downloadable asset.
Run build_release.ps1 again (it should produce MonClubAccess-$releaseId.zip).
"@
}

$assets = @($setupExe, $ManifestPath, $zipPath)

# Tag strategy (simple + explicit)
$tag = "win-{0}-{1}" -f $Channel, $releaseId
$title = "MonClubAccess Windows ($Channel) - $releaseId"

# Flags per channel
$extraFlags = @("-R", $Repo, "--title", $title, "--notes", "Automated build $releaseId")
if ($Channel -eq "beta") {
  $extraFlags += "--prerelease"     # beta = prerelease
  $extraFlags += "--latest=false"   # don't override latest stable
} else {
  $extraFlags += "--latest"         # mark stable as Latest
}

Write-Host "Creating release: $tag" -ForegroundColor Cyan
Write-Host "Assets:" -ForegroundColor Cyan
$assets | ForEach-Object { Write-Host " - $_" }

# Requires: gh auth login
gh release create $tag @assets @extraFlags
Write-Host "Done." -ForegroundColor Green
