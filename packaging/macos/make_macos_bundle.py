"""
Generate macOS native application bundle (ULPF.app), 1-click installer (.command), and distribution tarball.
"""
import os
import shutil
import sys
import tarfile
from pathlib import Path

VERSION = "1.2.0"

INFO_PLIST_CONTENT = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>ULPF</string>
    <key>CFBundleDisplayName</key>
    <string>ULPF Operations Dashboard</string>
    <key>CFBundleIdentifier</key>
    <string>com.noturnio.ulpf.dashboard</string>
    <key>CFBundleVersion</key>
    <string>{VERSION}</string>
    <key>CFBundleShortVersionString</key>
    <string>{VERSION}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleSignature</key>
    <string>ULPF</string>
    <key>CFBundleExecutable</key>
    <string>ULPF</string>
    <key>CFBundleIconFile</key>
    <string>ulpf_icon</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.15</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
"""

MACOS_LAUNCHER_SCRIPT = """#!/usr/bin/env bash
# macOS Application Launcher for ULPF
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESOURCES_DIR="$(cd "${DIR}/../Resources" && pwd)"

export PATH="/usr/local/bin:/opt/homebrew/bin:${PATH}"

# Open browser
(sleep 1.2 && open "http://127.0.0.1:8000") &

# Start dashboard backend
if command -v ulpf >/dev/null 2>&1; then
    exec ulpf dashboard --port 8000
elif command -v python3 >/dev/null 2>&1; then
    exec python3 -m ulpf.dashboard.app --port 8000
else
    osascript -e 'display dialog "Python 3 is required to run ULPF. Please install Python from https://www.python.org/ or Homebrew." buttons {"OK"} default button 1 with icon stop'
fi
"""

MACOS_ONE_CLICK_INSTALLER = f"""#!/usr/bin/env bash
# ULPF 1-Click Installer for macOS (Double-Clickable .command)
set -e

DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
echo "=========================================================="
echo "      Installing ULPF v{VERSION} for macOS in 1-Click     "
echo "=========================================================="

# 1. Install to /Applications
if [ -d "${{DIR}}/ULPF.app" ]; then
    echo "[*] Installing ULPF.app to /Applications/..."
    cp -R "${{DIR}}/ULPF.app" /Applications/
    xattr -cr /Applications/ULPF.app 2>/dev/null || true
fi

# 2. Install Python package
WHEEL=$(ls "${{DIR}}"/ulpf-*.whl 2>/dev/null | head -n 1 || true)
if [ -n "$WHEEL" ]; then
    echo "[*] Installing ULPF Python CLI from package wheel..."
    python3 -m pip install --upgrade --quiet "$WHEEL" || pip3 install --upgrade --user "$WHEEL" || true
elif command -v pip3 >/dev/null 2>&1; then
    pip3 install --upgrade --quiet ulpf || true
fi

# 3. Create CLI symlinks
if [ -d "/usr/local/bin" ] && [ -w "/usr/local/bin" ]; then
    ln -sf "$(command -v ulpf || echo '/usr/local/bin/ulpf')" /usr/local/bin/ulpf 2>/dev/null || true
fi

echo "=========================================================="
echo "  [SUCCESS] ULPF installed to /Applications/ULPF.app!"
echo "  Opening ULPF Operations Dashboard now..."
echo "=========================================================="

open /Applications/ULPF.app 2>/dev/null || open "http://127.0.0.1:8000"
exit 0
"""

def create_macos_bundle(root_dir: Path, dist_dir: Path) -> Path:
    app_dir = dist_dir / "ULPF.app"
    contents_dir = app_dir / "Contents"
    macos_dir = contents_dir / "MacOS"
    resources_dir = contents_dir / "Resources"

    if app_dir.exists():
        shutil.rmtree(app_dir)

    macos_dir.mkdir(parents=True, exist_ok=True)
    resources_dir.mkdir(parents=True, exist_ok=True)

    # 1. Write Info.plist
    (contents_dir / "Info.plist").write_text(INFO_PLIST_CONTENT, encoding="utf-8")

    # 2. Write PkgInfo
    (contents_dir / "PkgInfo").write_text("APPLULPF", encoding="utf-8")

    # 3. Write Executable
    launcher_file = macos_dir / "ULPF"
    launcher_file.write_text(MACOS_LAUNCHER_SCRIPT, encoding="utf-8")

    # 4. Copy Icons & Resources
    icon_src = root_dir / "packaging" / "windows" / "ulpf_icon.ico"
    if icon_src.exists():
        shutil.copy2(icon_src, resources_dir / "ulpf_icon.ico")

    # 5. Write 1-Click Installer .command
    installer_cmd = dist_dir / "Install-ULPF-macOS.command"
    installer_cmd.write_text(MACOS_ONE_CLICK_INSTALLER, encoding="utf-8")

    # Create release tarball
    bundle_name = f"ULPF-{VERSION}-macos-universal"
    tar_out = dist_dir / f"{bundle_name}.tar.gz"
    if tar_out.exists():
        tar_out.unlink()

    with tarfile.open(tar_out, "w:gz") as tar:
        tar.add(app_dir, arcname="ULPF.app")
        tar.add(installer_cmd, arcname="Install-ULPF-macOS.command")
        if (root_dir / "README.md").exists():
            tar.add(root_dir / "README.md", arcname="README.md")
        if (root_dir / "LICENSE").exists():
            tar.add(root_dir / "LICENSE", arcname="LICENSE")
        wheels = list(dist_dir.glob(f"ulpf-{VERSION}-*.whl"))
        for w in wheels:
            tar.add(w, arcname=w.name)

    print(f"[+] macOS Application Bundle created: {app_dir}")
    print(f"[+] macOS 1-Click Installer created: {installer_cmd}")
    print(f"[+] macOS Distribution Archive created: {tar_out}")
    return app_dir

if __name__ == "__main__":
    r_dir = Path(__file__).parent.parent.parent.resolve()
    d_dir = r_dir / "dist"
    d_dir.mkdir(parents=True, exist_ok=True)
    create_macos_bundle(r_dir, d_dir)
