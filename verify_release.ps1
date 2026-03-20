param(
  [Parameter(Mandatory=$true)][string]$ZipPath,
  [Parameter(Mandatory=$true)][string]$ManifestPath
)

$ErrorActionPreference = "Stop"

function Sha256($p) {
  (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash.ToLowerInvariant()
}

function Resolve-PayloadRoot([string]$ExtractRoot, [string]$RootFolderName, [string]$ExeName) {
  $candidateRoot = Join-Path $ExtractRoot $RootFolderName
  if (Test-Path (Join-Path $candidateRoot $ExeName)) { return $candidateRoot }

  $currentRoot = Join-Path $ExtractRoot "current"
  if (Test-Path (Join-Path $currentRoot $ExeName)) { return $currentRoot }

  if (Test-Path (Join-Path $ExtractRoot $ExeName)) { return $ExtractRoot }

  $found = Get-ChildItem -LiteralPath $ExtractRoot -Recurse -File -Filter $ExeName -ErrorAction SilentlyContinue |
    Select-Object -First 1
  if ($found) { return (Split-Path -Parent $found.FullName) }

  throw "Could not locate $ExeName inside the ZIP content."
}

if (-not (Test-Path -LiteralPath $ZipPath -PathType Leaf)) { throw "ZIP not found: $ZipPath" }
if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { throw "Manifest not found: $ManifestPath" }

$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json

if ([string]::IsNullOrWhiteSpace($manifest.releaseId)) { throw "manifest.releaseId missing/empty" }
if ([string]::IsNullOrWhiteSpace($manifest.outputs.zipSha256)) { throw "manifest.outputs.zipSha256 missing/empty" }
if ([string]::IsNullOrWhiteSpace($manifest.app)) { throw "manifest.app missing/empty" }
if ([string]::IsNullOrWhiteSpace($manifest.mainExe)) { throw "manifest.mainExe missing/empty" }

$zipHash = Sha256 $ZipPath
if ($zipHash -ne $manifest.outputs.zipSha256) {
  throw "ZIP SHA256 mismatch. Expected $($manifest.outputs.zipSha256) got $zipHash"
}

Write-Host "ZIP SHA256 OK ✅ $zipHash" -ForegroundColor Green
Write-Host "App       : $($manifest.app)"
Write-Host "ReleaseId : $($manifest.releaseId)"
Write-Host "BuiltAtUtc: $($manifest.builtAtUtc)"

$tmp = Join-Path $env:TEMP ("mc_verify_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force $tmp | Out-Null

try {
  Expand-Archive -LiteralPath $ZipPath -DestinationPath $tmp -Force

  $payload = Resolve-PayloadRoot $tmp $manifest.app $manifest.mainExe

  $exePath = Join-Path $payload $manifest.mainExe
  if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
    throw "$($manifest.mainExe) not found where expected: $exePath"
  }

  $verPath = Join-Path $payload "version.json"
  if (-not (Test-Path -LiteralPath $verPath -PathType Leaf)) {
    throw "version.json not found next to exe: $verPath"
  }

  Write-Host "ZIP content OK ✅ ($($manifest.mainExe) + version.json found)" -ForegroundColor Green
}
finally {
  try { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue } catch {}
}
