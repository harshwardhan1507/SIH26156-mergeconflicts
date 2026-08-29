"""
Generate Linux portable distribution archive (tar.gz) with desktop launcher, deb installer, and icons.
"""
import os
import shutil
import sys
import tarfile
from pathlib import Path
from PIL import Image

VERSION = "1.2.0"

def generate_linux_png_icons(icon_src: Path, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    png_path = out_dir / "ulpf_icon.png"
    if icon_src.exists():
        im = Image.open(icon_src)
        im.save(str(png_path), format="PNG")
    return png_path

def create_linux_bundle(root_dir: Path, dist_dir: Path) -> Path:
    bundle_name = f"ULPF-{VERSION}-linux-x64-portable"
    bundle_dir = dist_dir / bundle_name
    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)
    bundle_dir.mkdir(parents=True, exist_ok=True)

    # 1. Generate PNG icon
    icon_src = root_dir / "packaging" / "windows" / "ulpf_icon.ico"
    generate_linux_png_icons(icon_src, bundle_dir)

    # 2. Copy Linux files
    shutil.copy2(root_dir / "packaging" / "linux" / "ulpf.desktop", bundle_dir / "ulpf.desktop")
    shutil.copy2(root_dir / "packaging" / "linux" / "install_linux.sh", bundle_dir / "install_linux.sh")
    shutil.copy2(root_dir / "packaging" / "linux" / "ulpf-dashboard.service", bundle_dir / "ulpf-dashboard.service")
    shutil.copy2(root_dir / "start_dashboard.sh", bundle_dir / "launch_dashboard.sh")

    # Copy .deb if built
    deb_files = list(dist_dir.glob("ulpf_*.deb"))
    for d in deb_files:
        shutil.copy2(d, bundle_dir / d.name)

    if (root_dir / "README.md").exists():
        shutil.copy2(root_dir / "README.md", bundle_dir / "README.md")
    if (root_dir / "LICENSE").exists():
        shutil.copy2(root_dir / "LICENSE", bundle_dir / "LICENSE")
    if (root_dir / "sample_logs").exists():
        shutil.copytree(root_dir / "sample_logs", bundle_dir / "sample_logs", dirs_exist_ok=True)
    elif (root_dir / "ulpf" / "sample_logs").exists():
        shutil.copytree(root_dir / "ulpf" / "sample_logs", bundle_dir / "sample_logs", dirs_exist_ok=True)

    # Find wheel
    wheels = list(dist_dir.glob(f"ulpf-{VERSION}-*.whl"))
    for w in wheels:
        shutil.copy2(w, bundle_dir / w.name)

    tar_out = dist_dir / f"{bundle_name}.tar.gz"
    if tar_out.exists():
        tar_out.unlink()

    with tarfile.open(tar_out, "w:gz") as tar:
        tar.add(bundle_dir, arcname=bundle_name)

    print(f"[+] Linux Portable Archive created: {tar_out}")
    return tar_out

if __name__ == "__main__":
    r_dir = Path(__file__).parent.parent.parent.resolve()
    d_dir = r_dir / "dist"
    d_dir.mkdir(parents=True, exist_ok=True)
    create_linux_bundle(r_dir, d_dir)
