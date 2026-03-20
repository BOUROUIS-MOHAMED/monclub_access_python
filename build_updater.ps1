param(
  [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ROOT

$csproj = Join-Path $ROOT "updater\MonClubAccessUpdater\MonClubAccessUpdater.csproj"
$publishDir = Join-Path $ROOT "updater\MonClubAccessUpdater\bin\Release\net8.0\win-x64\publish"
$publishedExe = Join-Path $publishDir "MonClubDesktopUpdater.exe"
$installerExe = Join-Path $ROOT "installer\updater\MonClubDesktopUpdater.exe"

Write-Host "== Build shared desktop updater ==" -ForegroundColor Cyan
Write-Host "Project : $csproj"
Write-Host "Publish : $publishedExe"
Write-Host "Installer cache : $installerExe"

if ($DryRun) {
  Write-Host "DryRun enabled. Updater publish skipped." -ForegroundColor Yellow
  exit 0
}

dotnet publish $csproj -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true
if ($LASTEXITCODE -ne 0) {
  throw "dotnet publish failed with exit code $LASTEXITCODE"
}

if (-not (Test-Path -LiteralPath $publishedExe -PathType Leaf)) {
  throw "Published updater exe not found: $publishedExe"
}

New-Item -ItemType Directory -Force (Split-Path -Parent $installerExe) | Out-Null
Copy-Item -LiteralPath $publishedExe -Destination $installerExe -Force

Write-Host "Shared updater ready: $installerExe" -ForegroundColor Green
