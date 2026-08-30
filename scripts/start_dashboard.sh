#!/usr/bin/env bash
# 1-Click Dashboard Launcher for Linux & macOS
set -euo pipefail

echo "======================================================================"
echo "          Universal Log Pre-processing Framework (ULPF)               "
echo "======================================================================"

# Ingest sample data if output folder empty
python3 -m ulpf.cli ingest --input ulpf/sample_logs/ --output output/ >/dev/null 2>&1 || true

# Open default browser
if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "http://127.0.0.1:8000" >/dev/null 2>&1 &
elif command -v open >/dev/null 2>&1; then
    open "http://127.0.0.1:8000" >/dev/null 2>&1 &
fi

echo "[*] Starting ULPF Dashboard Server on port 8000..."
echo "[INFO] Press Ctrl+C to stop the server."
python3 -m ulpf.dashboard.app --port 8000 --output-dir output
