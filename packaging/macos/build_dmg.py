"""
Generate macOS Apple Disk Image (.dmg) containing ULPF.app, 1-click installer, and documentation.
"""
import os
import shutil
from pathlib import Path
import pycdlib

VERSION = "1.2.0"

def build_macos_dmg(root_dir: Path, dist_dir: Path) -> Path:
    app_dir = dist_dir / "ULPF.app"
    out_dmg = dist_dir / f"ULPF-{VERSION}-macos.dmg"
    installer_cmd = dist_dir / "Install-ULPF-macOS.command"
    readme_path = root_dir / "README.md"
    license_path = root_dir / "LICENSE"

    print(f"[*] Building Apple Disk Image (.dmg): {out_dmg.name}...")

    if not app_dir.exists():
        print(f"[!] ULPF.app bundle not found at {app_dir}. Building bundle first...")
        from packaging.macos.make_macos_bundle import create_macos_bundle
        create_macos_bundle(root_dir, dist_dir)

    iso = pycdlib.PyCdlib()
    iso.new(rock_ridge="1.09", joliet=3, vol_ident="ULPF Installer")

    def sanitize_iso_name(name: str) -> str:
        clean = "".join(c if c.isalnum() else "_" for c in name).upper()
        return clean[:8] or "FILE"

    dirs_created = set()
    files_added = 0

    # 1. Add all app bundle contents
    for p in sorted(app_dir.rglob("*")):
        rel = p.relative_to(app_dir.parent)
        parts = rel.parts

        # Ensure parent directories are registered in ISO
        curr_iso = ""
        curr_rr = ""
        for part in parts[:-1]:
            curr_iso += "/" + sanitize_iso_name(part)
            curr_rr += "/" + part
            if curr_rr not in dirs_created:
                iso.add_directory(curr_iso, rr_name=part, joliet_path=curr_rr)
                dirs_created.add(curr_rr)

        if p.is_dir():
            iso_p = "/" + "/".join(sanitize_iso_name(x) for x in parts)
            rr_p = "/" + "/".join(parts)
            if rr_p not in dirs_created:
                iso.add_directory(iso_p, rr_name=parts[-1], joliet_path=rr_p)
                dirs_created.add(rr_p)
        elif p.is_file():
            iso_dir = "/" + "/".join(sanitize_iso_name(x) for x in parts[:-1])
            iso_file = iso_dir + "/" + sanitize_iso_name(parts[-1]) + ";1"
            rr_name = parts[-1]
            joliet_p = "/" + "/".join(parts)
            iso.add_file(str(p), iso_file, rr_name=rr_name, joliet_path=joliet_p)
            files_added += 1

    # 2. Add 1-Click Installer
    if installer_cmd.exists():
        iso.add_file(
            str(installer_cmd),
            "/INSTALL.CMD;1",
            rr_name="Install-ULPF-macOS.command",
            joliet_path="/Install-ULPF-macOS.command",
        )
        files_added += 1

    # 3. Add Readme & License
    if readme_path.exists():
        iso.add_file(
            str(readme_path),
            "/README.TXT;1",
            rr_name="README.md",
            joliet_path="/README.md",
        )
        files_added += 1

    if license_path.exists():
        iso.add_file(
            str(license_path),
            "/LICENSE.TXT;1",
            rr_name="LICENSE",
            joliet_path="/LICENSE",
        )
        files_added += 1

    # Write output DMG
    if out_dmg.exists():
        out_dmg.unlink()

    iso.write(str(out_dmg))
    iso.close()

    size_mb = out_dmg.stat().st_size / (1024 * 1024)
    print(f"[+] Apple Disk Image (.dmg) created successfully: {out_dmg.name} ({size_mb:.2f} MB)")
    return out_dmg

if __name__ == "__main__":
    r_dir = Path(__file__).parent.parent.parent.resolve()
    d_dir = r_dir / "dist"
    d_dir.mkdir(parents=True, exist_ok=True)
    build_macos_dmg(r_dir, d_dir)
