# =============================================================================
# Build and Place Unified start.exe Loader Script
#
# Builds the unified start.exe binary and copies it directly to the repository
# root at d:\harfile\killswitch\start.exe, then executes --verify self-diagnostics.
# =============================================================================

[CmdletBinding()]
param(
    [switch]$SkipVerify
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

Write-Host "[BUILD] Compiling unified start.exe release binary..." -ForegroundColor Cyan
cargo build --package killswitch-cli --bin start --release

$SourceExe = Join-Path $RepoRoot "target\release\start.exe"
$DestExe = Join-Path $RepoRoot "start.exe"

if (-not (Test-Path $SourceExe)) {
    throw "Target binary not found at $SourceExe"
}

Write-Host "[COPY] Placing binary at $DestExe..." -ForegroundColor Cyan
Copy-Item -Path $SourceExe -Destination $DestExe -Force

if (-not (Test-Path $DestExe)) {
    throw "Failed to place binary at $DestExe"
}

$Item = Get-Item $DestExe
$SizeMb = [math]::Round($Item.Length / 1MB, 2)
Write-Host "[SUCCESS] Placed start.exe ($SizeMb MB) at $DestExe" -ForegroundColor Green

if (-not $SkipVerify) {
    Write-Host "`n[VERIFY] Executing $DestExe --verify..." -ForegroundColor Cyan
    & $DestExe --verify
    if ($LASTEXITCODE -ne 0) {
        throw "Verification diagnostics failed with exit code $LASTEXITCODE"
    }
    Write-Host "[VERIFY] start.exe --verify passed with exit code 0!" -ForegroundColor Green
}
