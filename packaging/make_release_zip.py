"""
Create complete release ZIP archive for ULPF.
"""
import os
import shutil
import zipfile
from pathlib import Path

def create_release_zip():
    scratch_dir = Path(r"C:\Users\Nitya\.gemini\antigravity\scratch")
    standalone_dir = scratch_dir / "ulpf_standalone"
    dist_dir = standalone_dir / "dist"
    staging_dir = scratch_dir / "ULPF-1.1.0-Release-Bundle"

    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True)

    # Copy files into staging
    files_to_copy = [
        ("ULPF-Launcher.exe", dist_dir / "ULPF-Launcher.exe"),
        ("ULPF-1.1.0-windows-x64.msi", dist_dir / "ULPF-1.1.0-windows-x64.msi"),
        ("ulpf.exe", dist_dir / "ulpf.exe"),
        ("ulpf-dashboard.exe", dist_dir / "ulpf-dashboard.exe"),
        ("ulpf_icon.ico", standalone_dir / "packaging" / "windows" / "ulpf_icon.ico"),
        ("README.md", standalone_dir / "README.md"),
        ("LICENSE", standalone_dir / "LICENSE"),
        ("ULPF-1.1.0-linux-x64-portable.tar.gz", dist_dir / "ULPF-1.1.0-linux-x64-portable.tar.gz"),
        ("ULPF-1.1.0-macos-universal.tar.gz", dist_dir / "ULPF-1.1.0-macos-universal.tar.gz"),
    ]

    for name, src in files_to_copy:
        if src.exists():
            shutil.copy2(src, staging_dir / name)
            print(f"[+] Added: {name}")

    # Copy sample_logs folder
    sample_logs_src = standalone_dir / "sample_logs"
    if sample_logs_src.exists():
        shutil.copytree(sample_logs_src, staging_dir / "sample_logs", dirs_exist_ok=True)
        print("[+] Added: sample_logs/")

    # Add Quick Launcher BAT
    bat_path = staging_dir / "Launch_ULPF.bat"
    bat_content = "@echo off\r\ntitle ULPF Operations Dashboard\r\necho Launching ULPF Operations Dashboard...\r\nstart \"\" ULPF-Launcher.exe\r\n"
    bat_path.write_text(bat_content, encoding="utf-8")
    print("[+] Added: Launch_ULPF.bat")

    # 1. Create Top-level Complete Release ZIP
    zip_out1 = scratch_dir / "ULPF-1.1.0-Complete-Release.zip"
    if zip_out1.exists():
        zip_out1.unlink()

    with zipfile.ZipFile(zip_out1, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(staging_dir):
            for f in files:
                full_p = Path(root) / f
                rel_p = full_p.relative_to(staging_dir)
                zf.write(full_p, arcname=f"ULPF-1.1.0/{rel_p}")

    print("\n============================================================")
    print(f"[SUCCESS] Created Release ZIP: {zip_out1}")
    print(f"Size: {zip_out1.stat().st_size / (1024*1024):.2f} MB")
    print("============================================================")

    # 2. Also update dist/ULPF-1.1.0-windows-x64-portable.zip
    zip_out2 = dist_dir / "ULPF-1.1.0-windows-x64-portable.zip"
    shutil.copy2(zip_out1, zip_out2)
    print(f"[SUCCESS] Updated: {zip_out2}")

    # 3. Clean up staging folder
    if staging_dir.exists():
        shutil.rmtree(staging_dir)

if __name__ == "__main__":
    create_release_zip()
