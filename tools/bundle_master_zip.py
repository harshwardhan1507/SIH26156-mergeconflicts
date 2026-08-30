"""
Bundle Master Release ZIP Archive with all code, standalone executables, installers, and platform packages.
"""
import os
import shutil
import zipfile
from pathlib import Path

def main():
    root_dir = Path(__file__).parent.parent.resolve()
    scratch_dir = root_dir.parent
    out_zip = scratch_dir / "ULPF-Complete-All-Platforms-Release.zip"

    staging_dir = scratch_dir / "ULPF_Master_Staging"
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Staging files from {root_dir}...")

    # 1. Copy source code and config
    items_to_copy = [
        "ulpf",
        "docs",
        "docker",
        "sample_logs",
        "packaging",
        ".github",
        "pyproject.toml",
        "requirements.txt",
        "requirements-dev.txt",
        "README.md",
        "LICENSE",
        "RELEASE_UPDATES.txt",
        "test_all.py",
        "Run_Dashboard.bat",
        "Run_Tests.bat",
        "Launch_ULPF_Dashboard.bat",
        "Create_Desktop_Shortcut.bat",
        "start_dashboard.sh",
    ]

    for item in items_to_copy:
        src = root_dir / item
        dst = staging_dir / item
        if src.is_dir():
            shutil.copytree(src, dst, dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"))
        elif src.is_file():
            shutil.copy2(src, dst)

    # 2. Copy dist folder contents (standalone binaries, installers, tarballs)
    dist_src = root_dir / "dist"
    dist_dst = staging_dir / "dist"
    dist_dst.mkdir(parents=True, exist_ok=True)

    if dist_src.exists():
        for p in dist_src.iterdir():
            if p.name.endswith(".wixpdb") or (p.is_dir() and p.name.endswith("-portable")):
                continue
            target = dist_dst / p.name
            if p.is_dir():
                shutil.copytree(p, target, dirs_exist_ok=True)
            else:
                shutil.copy2(p, target)
            print(f"  [+] Included package: {p.name}")

    # 3. Add root-level launcher
    bat_code = "@echo off\r\ntitle ULPF Operations Dashboard\r\necho Launching ULPF Operations Dashboard...\r\nif exist dist\\ULPF-Launcher.exe (\r\n    start \"\" dist\\ULPF-Launcher.exe\r\n) else (\r\n    start \"\" Launch_ULPF_Dashboard.bat\r\n)\r\n"
    (staging_dir / "Launch_Dashboard.bat").write_text(bat_code, encoding="utf-8")

    # 4. Write ZIP Archive
    print(f"[*] Compressing into master archive: {out_zip.name}...")
    if out_zip.exists():
        out_zip.unlink()

    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(staging_dir):
            for f in files:
                full_p = Path(root) / f
                rel_p = full_p.relative_to(staging_dir)
                zf.write(full_p, arcname=f"ULPF/{rel_p}")

    size_mb = out_zip.stat().st_size / (1024 * 1024)
    print("============================================================")
    print(f"  MASTER ALL-PLATFORMS RELEASE ZIP CREATED SUCCESSFULLY!   ")
    print(f"  File: {out_zip}")
    print(f"  Size: {size_mb:.2f} MB")
    print("============================================================")

    # Clean up staging
    shutil.rmtree(staging_dir)

if __name__ == "__main__":
    main()
