#!/usr/bin/env bash
# run_pipeline.sh — CyberPulse One-Shot Pipeline Runner
# Usage: ./scripts/run_pipeline.sh [TARGET_URL] [PATCHED_TARGET_URL]
#
# Scanner toggles (WSL2 / Docker recommended):
#   WITH_SAST=1  ./scripts/run_pipeline.sh     → add Semgrep static analysis
#   WITH_DAST=1  ./scripts/run_pipeline.sh     → add OWASP ZAP dynamic analysis
#   PATCH_SAST=1 WITH_SAST=1 ./scripts/run_pipeline.sh  → also fix SAST-reported types

set -e

TARGET="${1:-http://localhost:5000}"
PATCHED="${2:-http://localhost:5001}"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Optional scanner flags (empty when unset)
SCAN_FLAGS=""
if [ "${WITH_SAST:-0}" = "1" ];  then SCAN_FLAGS="$SCAN_FLAGS --with-sast";  fi
if [ "${WITH_DAST:-0}" = "1" ];  then SCAN_FLAGS="$SCAN_FLAGS --with-dast";  fi
if [ "${PATCH_SAST:-0}" = "1" ]; then SCAN_FLAGS="$SCAN_FLAGS --patch-sast"; fi

echo "=================================================="
echo "  CyberPulse - Autonomous Pentest Swarm"
echo "  Target:         $TARGET"
echo "  Patched Target: $PATCHED"
echo "  Scanner flags:  ${SCAN_FLAGS:-none}"
echo "=================================================="

# Reset state
echo "[*] Resetting state..."
python "$PROJECT_ROOT/scripts/reset_state.py"

# Start VulnApp if not already running
if ! curl -sf "$TARGET/health" > /dev/null 2>&1; then
    echo "[*] Starting VulnApp via Docker Compose..."
    docker compose -f "$PROJECT_ROOT/docker-compose.yml" up -d vulnapp
    echo "[*] Waiting for VulnApp to become healthy..."
    sleep 5
fi

# Run full pipeline
echo "[*] Running full pipeline..."
# shellcheck disable=SC2086
python "$PROJECT_ROOT/main.py" \
    --target "$TARGET" \
    --patched-target "$PATCHED" \
    --mode full \
    --timeout 10 \
    $SCAN_FLAGS

echo ""
echo "[✓] Pipeline complete!"
echo "[✓] Final report: $PROJECT_ROOT/state/final_report.md"
if [ -f "$PROJECT_ROOT/state/sast_report.json" ]; then
    echo "[✓] SAST report:  $PROJECT_ROOT/state/sast_report.json"
fi
if [ -f "$PROJECT_ROOT/state/dast_report.json" ]; then
    echo "[✓] DAST report:  $PROJECT_ROOT/state/dast_report.json"
fi
