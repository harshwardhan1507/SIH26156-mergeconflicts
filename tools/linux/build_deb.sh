#!/usr/bin/env bash
# Builds Debian/Ubuntu .deb package for ULPF
set -euo pipefail

VERSION="1.1.0"
ARCH="amd64"
PKG_DIR="dist/ulpf_${VERSION}_${ARCH}"

echo "=== Building ULPF Debian Package v${VERSION} ==="

mkdir -p "${PKG_DIR}/DEBIAN"
mkdir -p "${PKG_DIR}/usr/local/bin"
mkdir -p "${PKG_DIR}/etc/systemd/system"
mkdir -p "${PKG_DIR}/var/lib/ulpf"

# Control file
cat << EOF > "${PKG_DIR}/DEBIAN/control"
Package: ulpf
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${ARCH}
Depends: python3 (>= 3.11), python3-pip
Maintainer: ULPF Project <info@ulpf.local>
Description: Universal Log Pre-processing Framework (ULPF)
 Enterprise multi-vendor log normalization, forensic raw store, and operations dashboard.
EOF

# Install systemd service
cp packaging/linux/ulpf-dashboard.service "${PKG_DIR}/etc/systemd/system/"

# Post-install script
cat << 'EOF' > "${PKG_DIR}/DEBIAN/postinst"
#!/bin/bash
pip3 install --no-cache-dir ulpf
systemctl daemon-reload || true
echo "ULPF installed successfully."
EOF
chmod 755 "${PKG_DIR}/DEBIAN/postinst"

if command -v dpkg-deb >/dev/null 2>&1; then
    dpkg-deb --build "${PKG_DIR}" "dist/ulpf_${VERSION}_${ARCH}.deb"
    echo "Debian package created: dist/ulpf_${VERSION}_${ARCH}.deb"
fi
