#!/usr/bin/env bash
# Universal Log Pre-processing Framework (ULPF) Linux Native Installer
set -euo pipefail

echo "======================================================================"
echo "      Universal Log Pre-processing Framework (ULPF) Linux Setup       "
echo "======================================================================"

INSTALL_DIR="${HOME}/.local/share/ulpf"
BIN_DIR="${HOME}/.local/bin"
DESKTOP_DIR="${HOME}/.local/share/applications"
ICON_DIR="${HOME}/.local/share/icons/hicolor/256x256/apps"

mkdir -p "${INSTALL_DIR}" "${BIN_DIR}" "${DESKTOP_DIR}" "${ICON_DIR}"

# 1. Install Python package
echo "[1/4] Installing Python components..."
if ls ulpf-*.whl 1> /dev/null 2>&1; then
    pip3 install --upgrade $(ls ulpf-*.whl | head -n 1)
else
    pip3 install -e .
fi

# 2. Install Desktop Launcher Icon
echo "[2/4] Installing application icon..."
if [ -f "packaging/linux/ulpf_icon.png" ]; then
    cp "packaging/linux/ulpf_icon.png" "${ICON_DIR}/ulpf.png"
elif [ -f "ulpf_icon.png" ]; then
    cp "ulpf_icon.png" "${ICON_DIR}/ulpf.png"
fi

# 3. Install .desktop Application Entry
echo "[3/4] Registering Linux Desktop application entry..."
if [ -f "packaging/linux/ulpf.desktop" ]; then
    cp "packaging/linux/ulpf.desktop" "${DESKTOP_DIR}/ulpf.desktop"
    chmod +x "${DESKTOP_DIR}/ulpf.desktop"
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database "${DESKTOP_DIR}" || true
    fi
fi

# 4. Configure optional Systemd service
echo "[4/4] Setting up systemd background service..."
SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"
mkdir -p "${SYSTEMD_USER_DIR}"
if [ -f "packaging/linux/ulpf-dashboard.service" ]; then
    cp "packaging/linux/ulpf-dashboard.service" "${SYSTEMD_USER_DIR}/"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl --user daemon-reload || true
        echo "  [i] To enable background dashboard: systemctl --user enable --now ulpf-dashboard"
    fi
fi

echo ""
echo "======================================================================"
echo "  INSTALLATION COMPLETE!"
echo "  Run 'ulpf dashboard' or launch 'ULPF Operations Dashboard' from your app menu."
echo "======================================================================"
