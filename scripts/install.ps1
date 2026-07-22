# Bastionscan CLI installer for Windows (optional companion).
# Requires Go on PATH.
$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$OutDir = Join-Path $env:USERPROFILE "bin"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Out = Join-Path $OutDir "bastionscan.exe"
Push-Location (Join-Path $RepoRoot "engine")
go build -trimpath -ldflags="-s -w" -o $Out ./cmd/bastionscan
Pop-Location
Write-Host "Installed $Out"
Write-Host "Add $OutDir to PATH if needed."
