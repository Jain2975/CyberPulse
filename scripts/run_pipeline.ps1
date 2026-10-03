# run_pipeline.ps1 — CyberPulse Windows pipeline launcher
# Usage: .\scripts\run_pipeline.ps1 [target_url] [patched_target_url]
# Example: .\scripts\run_pipeline.ps1 http://localhost:5000 http://localhost:5001

param(
    [string]$Target = "http://localhost:5000",
    [string]$PatchedTarget = "http://localhost:5001"
)

$ErrorActionPreference = "Stop"

Write-Host "=== CyberPulse Pipeline ===" -ForegroundColor Cyan
Write-Host "Target:         $Target" -ForegroundColor White
Write-Host "Patched target: $PatchedTarget" -ForegroundColor White
Write-Host ""

# 1. Start vulnapp
Write-Host "[1/4] Starting vulnapp container..." -ForegroundColor Yellow
docker compose up -d vulnapp

# 2. Wait for health
Write-Host "[2/4] Waiting for target to be healthy..." -ForegroundColor Yellow
$retries = 0
do {
    Start-Sleep -Seconds 2
    $retries++
    try {
        $resp = Invoke-WebRequest -Uri "$Target/health" -UseBasicParsing -TimeoutSec 3 -ErrorAction SilentlyContinue
        if ($resp.StatusCode -eq 200) { break }
    } catch {}
} while ($retries -lt 15)

if ($retries -ge 15) {
    Write-Host "ERROR: Target did not become healthy in time." -ForegroundColor Red
    exit 1
}
Write-Host "Target is healthy." -ForegroundColor Green

# 3. Run full pipeline
Write-Host "[3/4] Running full pipeline..." -ForegroundColor Yellow
python main.py --target $Target --patched-target $PatchedTarget --mode full

# 4. Start patched container (optional)
Write-Host "[4/4] Starting patched container (profile: patched)..." -ForegroundColor Yellow
docker compose --profile patched up -d vulnapp_patched

Write-Host ""
Write-Host "=== Pipeline complete. Report: state/final_report.md ===" -ForegroundColor Green
