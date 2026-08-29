"""
Build standalone Windows executables (.exe) and MSI Installer for ULPF.

Produces:
  dist/ULPF-Launcher.exe  - Dedicated Desktop App Launcher
  dist/ulpf.exe           - Full CLI + Interactive Launcher + Dashboard
  dist/ulpf-dashboard.exe - Dedicated One-Click Web Dashboard Backend
  dist/ULPF-1.2.0-windows-x64-portable.zip - Complete portable bundle
  dist/ULPF-1.2.0-windows-x64.msi - Windows MSI Installer
"""
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

VERSION = "1.2.0"

def main():
    root_dir = Path(__file__).parent.parent.parent.resolve()
    os.chdir(root_dir)
    print(f"=== Building ULPF Windows Applications & MSI Installer v{VERSION} ===")
    print(f"Root directory: {root_dir}")

    # 1. Generate icon if needed
    icon_path = root_dir / "packaging" / "windows" / "ulpf_icon.ico"
    if not icon_path.exists():
        print("[1/5] Generating Windows application icon...")
        subprocess.run([sys.executable, str(root_dir / "packaging" / "windows" / "make_icon.py")], check=True)
    else:
        print(f"[1/5] Found Windows application icon at {icon_path.name}")

    # 2. PyInstaller build
    dist_dir = root_dir / "dist"
    print("[2/5] Compiling standalone windowed executables with PyInstaller...")
    spec_path = root_dir / "packaging" / "windows" / "ulpf.spec"
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        str(spec_path),
        "--noconfirm",
        "--clean",
    ]
    res = subprocess.run(cmd)
    if res.returncode != 0:
        print("[ERROR] PyInstaller build failed!")
        sys.exit(res.returncode)

    launcher_exe = dist_dir / "ULPF-Launcher.exe"
    ulpf_exe = dist_dir / "ulpf.exe"
    dash_exe = dist_dir / "ulpf-dashboard.exe"

    print(f"[3/5] Standalone Executables Verified:")
    print(f"      - {launcher_exe.name} ({launcher_exe.stat().st_size / (1024*1024):.2f} MB)")
    print(f"      - {ulpf_exe.name} ({ulpf_exe.stat().st_size / (1024*1024):.2f} MB)")
    print(f"      - {dash_exe.name} ({dash_exe.stat().st_size / (1024*1024):.2f} MB)")

    # 3. Create Release Portable Zip Bundle
    print("[4/5] Creating portable distribution archive...")
    bundle_name = f"ULPF-{VERSION}-windows-x64-portable"
    bundle_dir = dist_dir / bundle_name
    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)
    bundle_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(launcher_exe, bundle_dir / "ULPF-Launcher.exe")
    shutil.copy2(ulpf_exe, bundle_dir / "ulpf.exe")
    shutil.copy2(dash_exe, bundle_dir / "ulpf-dashboard.exe")
    shutil.copy2(icon_path, bundle_dir / "ulpf_icon.ico")
    if (root_dir / "README.md").exists():
        shutil.copy2(root_dir / "README.md", bundle_dir / "README.md")
    if (root_dir / "LICENSE").exists():
        shutil.copy2(root_dir / "LICENSE", bundle_dir / "LICENSE")
    if (root_dir / "sample_logs").exists():
        shutil.copytree(root_dir / "sample_logs", bundle_dir / "sample_logs", dirs_exist_ok=True)
    elif (root_dir / "ulpf" / "sample_logs").exists():
        shutil.copytree(root_dir / "ulpf" / "sample_logs", bundle_dir / "sample_logs", dirs_exist_ok=True)

    # Add quick desktop launcher batch file in portable folder
    launcher_bat = bundle_dir / "Launch_Dashboard.bat"
    launcher_bat.write_text(
        "@echo off\r\n"
        "title ULPF Operations Dashboard\r\n"
        "echo Launching ULPF Operations Dashboard...\r\n"
        "start \"\" ULPF-Launcher.exe\r\n",
        encoding="utf-8"
    )

    zip_out = dist_dir / f"{bundle_name}.zip"
    if zip_out.exists():
        zip_out.unlink()

    with zipfile.ZipFile(zip_out, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(bundle_dir):
            for f in files:
                full_p = Path(root) / f
                rel_p = full_p.relative_to(bundle_dir)
                zf.write(full_p, arcname=f"{bundle_name}/{rel_p}")

    print(f"      - Portable ZIP Bundle created: {zip_out.name} ({zip_out.stat().st_size / (1024*1024):.2f} MB)")

    # 4. Build MSI Installer
    print("[5/5] Compiling Windows MSI Installer package...")
    msi_script = root_dir / "packaging" / "windows" / "build_msi.ps1"
    msi_res = subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", str(msi_script), "-Version", VERSION])
    if msi_res.returncode != 0:
        print("[!] Note: MSI compilation returned non-zero. Check WiX logs above.")

    msi_out = dist_dir / f"ULPF-{VERSION}-windows-x64.msi"
    print(f"\n============================================================")
    print(f"  WINDOWS PACKAGING COMPLETE!")
    print(f"  Desktop App Launcher Exe:   {launcher_exe}")
    print(f"  Universal CLI Exe:          {ulpf_exe}")
    print(f"  Dashboard Backend Exe:      {dash_exe}")
    print(f"  Portable ZIP Archive:       {zip_out}")
    if msi_out.exists():
        print(f"  Official Windows MSI Setup: {msi_out} ({msi_out.stat().st_size / (1024*1024):.2f} MB)")
    print(f"============================================================\n")

if __name__ == "__main__":
    main()
