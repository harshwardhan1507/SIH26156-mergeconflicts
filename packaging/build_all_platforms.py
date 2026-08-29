"""
Cross-Platform Build & Packaging Suite for ULPF.
Builds Windows standalone executables & MSI, Linux desktop package, and macOS App bundle.
"""
import os
import shutil
import subprocess
import sys
import importlib.util
from pathlib import Path

def run_script(script_path: Path):
    res = subprocess.run([sys.executable, str(script_path)], check=True)
    return res

def main():
    root_dir = Path(__file__).parent.parent.resolve()
    os.chdir(root_dir)
    dist_dir = root_dir / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)

    print("======================================================================")
    print("       ULPF Unified Multi-Platform Packaging Suite (v1.1.0)           ")
    print("======================================================================")
    print(f"Working Directory: {root_dir}")

    # 0. Build Wheel
    print("\n[Stage 1/5] Building universal Python Wheel...")
    subprocess.run([sys.executable, "-m", "pip", "wheel", ".", "--no-deps", "-w", str(dist_dir)], check=True)

    # 1. Generate Icons
    print("\n[Stage 2/5] Generating multi-resolution application icons...")
    run_script(root_dir / "packaging" / "windows" / "make_icon.py")

    # 2. Build Windows Executables & MSI
    print("\n[Stage 3/5] Building Windows Standalone Executables & MSI Installer...")
    run_script(root_dir / "packaging" / "windows" / "build_exe.py")

    # 3. Build Linux Application Bundle
    print("\n[Stage 4/5] Building Linux Portable Bundle & Desktop App Integration...")
    run_script(root_dir / "packaging" / "linux" / "make_linux_bundle.py")

    # 4. Build macOS Application Bundle
    print("\n[Stage 5/5] Building macOS Application Bundle (ULPF.app)...")
    run_script(root_dir / "packaging" / "macos" / "make_macos_bundle.py")

    # Summary of generated packages
    print("\n======================================================================")
    print("                     ALL PLATFORM ARTIFACTS GENERATED                  ")
    print("======================================================================")
    for p in sorted(dist_dir.iterdir()):
        if p.is_file():
            size_mb = p.stat().st_size / (1024 * 1024)
            print(f"  [+] {p.name:<45} {size_mb:>8.2f} MB")
        elif p.is_dir() and p.name.endswith(".app"):
            print(f"  [+] {p.name:<45} [macOS App Bundle]")
    print("======================================================================\n")

if __name__ == "__main__":
    main()
