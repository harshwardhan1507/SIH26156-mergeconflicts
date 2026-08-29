#!/usr/bin/env bash
# Builds macOS flat .pkg installer for ULPF
set -euo pipefail

VERSION="1.1.0"
PKG_ROOT="dist/macos_root"
PKG_OUT="dist/ULPF-${VERSION}-macos-universal.pkg"

echo "=== Building ULPF macOS Package v${VERSION} ==="

mkdir -p "${PKG_ROOT}/usr/local/share/ulpf"
cp dist/ulpf-${VERSION}-py3-none-any.whl "${PKG_ROOT}/usr/local/share/ulpf/"
cp packaging/macos/install_macos.sh "${PKG_ROOT}/usr/local/share/ulpf/"

if command -v pkgbuild >/dev/null 2>&1; then
    pkgbuild --root "${PKG_ROOT}" \
             --identifier "com.noturnio.ulpf" \
             --version "${VERSION}" \
             --install-location "/" \
             "${PKG_OUT}"
    echo "macOS Package created: ${PKG_OUT}"
fi
