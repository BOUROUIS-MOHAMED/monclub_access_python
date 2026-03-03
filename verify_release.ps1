param(
  [Parameter(Mandatory=$true)][string]$ZipPath,
  [Parameter(Mandatory=$true)][string]$ManifestPath
)

$ErrorActionPreference = "Stop"

function Sha256($p) {
  (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash.ToLowerInvariant()
}

function Resolve-PayloadRoot([string]$ExtractRoot) {
  $exeName = "MonClubAccess.exe"

  # common: <root>\MonClubAccess\MonClubAccess.exe
  $p1 = Join-Path $ExtractRoot "MonClubAccess"
  if (Test-Path (Join-Path $p1 $exeName)) { return $p1 }

  # alternative: <root>\current\MonClubAccess.exe
  $p2 = Join-Path $ExtractRoot "current"
  if (Test-Path (Join-Path $p2 $exeName)) { return $p2 }

  # alternative: <root>\MonClubAccess.exe
  if (Test-Path (Join-Path $ExtractRoot $exeName)) { return $ExtractRoot }

  # shallow search
  $found = Get-ChildItem -LiteralPath $ExtractRoot -Recurse -File -Filter $exeName -ErrorAction SilentlyContinue |
    Select-Object -First 1
  if ($found) { return (Split-Path -Parent $found.FullName) }

  throw "Could not locate MonClubAccess.exe inside the ZIP content."
}

if (-not (Test-Path -LiteralPath $ZipPath -PathType Leaf)) { throw "ZIP not found: $ZipPath" }
if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { throw "Manifest not found: $ManifestPath" }

$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json

if ([string]::IsNullOrWhiteSpace($manifest.releaseId)) { throw "manifest.releaseId missing/empty" }
if ([string]::IsNullOrWhiteSpace($manifest.outputs.zipSha256)) { throw "manifest.outputs.zipSha256 missing/empty" }

$zipHash = Sha256 $ZipPath
if ($zipHash -ne $manifest.outputs.zipSha256) {
  throw "ZIP SHA256 mismatch. Expected $($manifest.outputs.zipSha256) got $zipHash"
}

Write-Host "ZIP SHA256 OK ✅ $zipHash" -ForegroundColor Green
Write-Host "ReleaseId : $($manifest.releaseId)"
Write-Host "BuiltAtUtc: $($manifest.builtAtUtc)"

# Content verification (exe + version.json)
$tmp = Join-Path $env:TEMP ("mc_verify_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force $tmp | Out-Null

try {
  Expand-Archive -LiteralPath $ZipPath -DestinationPath $tmp -Force

  $payload = Resolve-PayloadRoot $tmp

  $exePath = Join-Path $payload "MonClubAccess.exe"
  if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
    throw "MonClubAccess.exe not found where expected: $exePath"
  }

  $verPath = Join-Path $payload "version.json"
  if (-not (Test-Path -LiteralPath $verPath -PathType Leaf)) {
    throw "version.json not found next to exe: $verPath"
  }

  Write-Host "ZIP content OK ✅ (MonClubAccess.exe + version.json found)" -ForegroundColor Green
}
finally {
  try { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue } catch {}
}
