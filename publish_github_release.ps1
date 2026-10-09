param(
  [ValidateSet("access", "tv")]
  [string]$Component = "access",

  [ValidateSet("stable","beta")]
  [string]$Channel = "stable",

  [string]$InstallerPath = "",

  # The signed release file build_release.ps1 wrote next to the installer (design 5.3).
  # Default: release\release-<component>-<version>.json
  [string]$ReleaseFile = "",

  [string]$Repo = "BOUROUIS-MOHAMED/monclub_access_python",

  [switch]$DryRun
)

# Publishes ONE built release: the installer AND its signed release file, on a tag that points
# at the exact commit that was built (gh --target <sha>, D31) -- not at whatever the remote
# default branch is at that moment. Refuses anything build_release.ps1 marked not publishable
# (test key, skipped tests, skipped checks, dirty tree, test-fail installer), a release file
# whose signature does not verify against the PROD keys, or an installer whose bytes differ
# from the signed manifest. Creating a real release needs the owner's OK (design.md 9).

$ErrorActionPreference = "Stop"

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ROOT

. (Join-Path $ROOT "packaging\desktop_components.ps1")
$meta = Get-DesktopComponentMetadata -Component $Component
$versionInfo = Get-DesktopComponentVersionInfo -Component $Component

if ([string]::IsNullOrWhiteSpace($InstallerPath)) {
  $InstallerPath = Join-Path $ROOT ("release\{0}" -f $versionInfo.InstallerFileName)
}
if ([string]::IsNullOrWhiteSpace($ReleaseFile)) {
  $ReleaseFile = Join-Path $ROOT ("release\release-{0}-{1}.json" -f $Component, $versionInfo.Version)
}

if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
  throw "Installer not found: $InstallerPath (run generate_installer.ps1 -Component $Component first)"
}
if (-not (Test-Path -LiteralPath $ReleaseFile -PathType Leaf)) {
  throw "Release file not found: $ReleaseFile (build_release.ps1 writes it after signing)"
}

# Signature (PROD keys only), installer hash/size/name, and "publishable": true.
$python = if (Test-Path ".\.venv\Scripts\python.exe") { ".\.venv\Scripts\python.exe" } else { "python" }
& $python (Join-Path $ROOT "tools\release_sign.py") verify --release-file $ReleaseFile --installer $InstallerPath --require-publishable
if ($LASTEXITCODE -ne 0) {
  throw "Release file refused (see above): not publishing."
}

$release = Get-Content -LiteralPath $ReleaseFile -Raw | ConvertFrom-Json
$manifest = $release.signedManifest | ConvertFrom-Json
if ($manifest.target -ne $Component -or $manifest.channel -ne $Channel -or $manifest.version -ne $versionInfo.Version) {
  throw ("Release file is for {0}/{1}/{2}, not {3}/{4}/{5}." -f $manifest.target, $manifest.channel, $manifest.version, $Component, $Channel, $versionInfo.Version)
}
$commit = [string]$release.buildCommit
if ($commit -notmatch '^[0-9a-f]{40}$') { throw "Release file has no full build commit: '$commit'." }
git cat-file -e "$commit^{commit}" 2>$null
if ($LASTEXITCODE -ne 0) { throw "Build commit $commit is not in this repository." }
# gh ignores --target when the tag already exists, and GitHub can only tag a pushed commit.
$remoteBranches = @(git branch -r --contains $commit 2>$null | Where-Object { $_.Trim() })
if ($remoteBranches.Count -eq 0) { throw "Build commit $commit is not on any remote branch: push it first." }

$tag = [string]$release.githubTag   # tools/release_sign.py release_tag(): the one tag format
$expectedUrl = "https://github.com/$Repo/releases/download/$tag/$($manifest.installerName)"
if ($release.installerUrl -ne $expectedUrl) {
  throw "Release file installerUrl '$($release.installerUrl)' does not match this upload ($expectedUrl)."
}

$title = "{0} Windows ({1}) - v{2}" -f $meta.DisplayName, $Channel, $versionInfo.Version
$notes = if ([string]::IsNullOrWhiteSpace([string]$release.releaseNotes)) {
  "MonClub $($meta.DisplayName) v$($versionInfo.Version). Signed release file attached."
} else { [string]$release.releaseNotes }

$extraFlags = @("-R", $Repo, "--title", $title, "--notes", $notes, "--target", $commit)
if ($Channel -eq "beta") {
  $extraFlags += "--prerelease"
  $extraFlags += "--latest=false"
} else {
  $extraFlags += "--latest"
}

gh release view $tag -R $Repo 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { throw "Release $tag already exists: gh would ignore --target. Not publishing over it." }
git ls-remote --exit-code --tags origin "refs/tags/$tag" 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { throw "Tag $tag already exists on origin: it may point at another commit. Not publishing." }

Write-Host "Creating release: $tag" -ForegroundColor Cyan
Write-Host "Target commit : $commit" -ForegroundColor Cyan
Write-Host "Asset         : $InstallerPath" -ForegroundColor Cyan
Write-Host "Release file  : $ReleaseFile" -ForegroundColor Cyan

if ($DryRun) {
  Write-Host "DryRun enabled. GitHub release creation skipped." -ForegroundColor Yellow
  exit 0
}

gh release create $tag $InstallerPath $ReleaseFile @extraFlags
if ($LASTEXITCODE -ne 0) { throw "gh release create failed with exit code $LASTEXITCODE" }
Write-Host "Done. Import $ReleaseFile on the dashboard (Releases -> Import release file)." -ForegroundColor Green
