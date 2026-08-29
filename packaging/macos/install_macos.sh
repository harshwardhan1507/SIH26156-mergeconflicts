#!/usr/bin/env bash
# ULPF macOS Native Installer
set -euo pipefail

echo "=========================================================="
echo "  Universal Log Pre-processing Framework (ULPF) macOS     "
echo "=========================================================="

WHEEL=$(ls ulpf-*.whl 2>/dev/null | head -n 1 || true)
if [ -n "$WHEEL" ]; then
    echo "Installing from local wheel: $WHEEL..."
    python3 -m pip install --upgrade "$WHEEL"
else
    echo "Installing ulpf via pip..."
    python3 -m pip install ulpf
fi

echo "Verifying ULPF CLI..."
ulpf list-parsers

echo ""
echo "Installation complete!"
echo "Run 'ulpf dashboard' to launch the web interface at http://127.0.0.1:8000"
