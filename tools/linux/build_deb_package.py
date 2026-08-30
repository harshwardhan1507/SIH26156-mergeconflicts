"""
Builds standard Debian / Ubuntu .deb package for ULPF without external dpkg-deb dependencies.
"""
import io
import os
import shutil
import tarfile
import time
from pathlib import Path
from PIL import Image

def make_ar_member(name: str, data: bytes, mtime: int = 0, mode: int = 0o100644) -> bytes:
    """Create a single member entry in standard Unix ar archive format."""
    header = f"{name:<16}{mtime:<12}{0:<6}{0:<6}{oct(mode)[2:]:>8}{len(data):<10}`\n".encode("ascii")
    payload = data
    if len(payload) % 2 != 0:
        payload += b"\n"
    return header + payload

def build_deb(root_dir: Path, dist_dir: Path, version: str = "1.2.0") -> Path:
    arch = "amd64"
    pkg_name = f"ulpf_{version}_{arch}"
    out_deb = dist_dir / f"{pkg_name}.deb"

    print(f"[*] Building Debian/Ubuntu package: {out_deb.name}...")

    # 1. debian-binary
    deb_binary = b"2.0\n"

    # 2. Build control.tar.gz
    control_text = f"""Package: ulpf
Version: {version}
Section: utils
Priority: optional
Architecture: {arch}
Depends: python3 (>= 3.10), python3-pip
Maintainer: ULPF Project <info@ulpf.local>
Homepage: https://github.com/NotUrNio/ULPF
Description: Universal Log Pre-processing Framework (ULPF)
 Enterprise multi-vendor log normalization, OCSF mapping, forensic raw store,
 anomaly detection, real-time stream listener, and operations dashboard.
"""
    postinst_text = f"""#!/bin/bash
set -e

# Setup opt directory
mkdir -p /var/log/ulpf /var/lib/ulpf /etc/ulpf
chmod 755 /usr/local/bin/ulpf /usr/local/bin/ulpf-dashboard || true

# Install Python wheel if available
if [ -f /opt/ulpf/ulpf-{version}-py3-none-any.whl ]; then
    pip3 install --no-cache-dir --quiet /opt/ulpf/ulpf-{version}-py3-none-any.whl || pip install --no-cache-dir --quiet /opt/ulpf/ulpf-{version}-py3-none-any.whl || true
fi

# Update desktop and icon databases
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q /usr/share/icons/hicolor || true
fi

# Reload systemd
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

echo "============================================================"
echo "  ULPF v{version} installed successfully!"
echo "  Commands:"
echo "    - Launch CLI:       ulpf --help"
echo "    - Launch Dashboard:  ulpf-dashboard --port 8000"
echo "    - Background daemon: sudo systemctl start ulpf-dashboard"
echo "============================================================"
exit 0
"""
    prerm_text = """#!/bin/bash
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop ulpf-dashboard || true
    systemctl disable ulpf-dashboard || true
fi
exit 0
"""
    postrm_text = """#!/bin/bash
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    rm -f /usr/local/bin/ulpf /usr/local/bin/ulpf-dashboard
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database -q /usr/share/applications || true
    fi
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload || true
    fi
fi
exit 0
"""

    control_buf = io.BytesIO()
    with tarfile.open(fileobj=control_buf, mode="w:gz") as tar:
        # control
        c_bytes = control_text.encode("utf-8")
        ti = tarfile.TarInfo("./control")
        ti.size = len(c_bytes)
        ti.mode = 0o644
        ti.mtime = int(time.time())
        tar.addfile(ti, io.BytesIO(c_bytes))

        # postinst
        p_bytes = postinst_text.encode("utf-8")
        ti = tarfile.TarInfo("./postinst")
        ti.size = len(p_bytes)
        ti.mode = 0o755
        ti.mtime = int(time.time())
        tar.addfile(ti, io.BytesIO(p_bytes))

        # prerm
        pr_bytes = prerm_text.encode("utf-8")
        ti = tarfile.TarInfo("./prerm")
        ti.size = len(pr_bytes)
        ti.mode = 0o755
        ti.mtime = int(time.time())
        tar.addfile(ti, io.BytesIO(pr_bytes))

        # postrm
        prm_bytes = postrm_text.encode("utf-8")
        ti = tarfile.TarInfo("./postrm")
        ti.size = len(prm_bytes)
        ti.mode = 0o755
        ti.mtime = int(time.time())
        tar.addfile(ti, io.BytesIO(prm_bytes))

    control_tar_gz = control_buf.getvalue()

    # 3. Build data.tar.gz
    data_buf = io.BytesIO()
    with tarfile.open(fileobj=data_buf, mode="w:gz") as tar:
        # /usr/local/bin/ulpf runner script
        ulpf_runner = """#!/bin/sh
if command -v python3 >/dev/null 2>&1; then
    exec python3 -m ulpf.cli "$@"
else
    exec python -m ulpf.cli "$@"
fi
""".encode("utf-8")
        ti = tarfile.TarInfo("./usr/local/bin/ulpf")
        ti.size = len(ulpf_runner)
        ti.mode = 0o755
        ti.mtime = int(time.time())
        tar.addfile(ti, io.BytesIO(ulpf_runner))

        # /usr/local/bin/ulpf-dashboard runner script
        dash_runner = """#!/bin/sh
if command -v python3 >/dev/null 2>&1; then
    exec python3 -m ulpf.dashboard.app "$@"
else
    exec python -m ulpf.dashboard.app "$@"
fi
""".encode("utf-8")
        ti = tarfile.TarInfo("./usr/local/bin/ulpf-dashboard")
        ti.size = len(dash_runner)
        ti.mode = 0o755
        ti.mtime = int(time.time())
        tar.addfile(ti, io.BytesIO(dash_runner))

        # Desktop entry
        desk_path = root_dir / "packaging" / "linux" / "ulpf.desktop"
        if desk_path.exists():
            d_bytes = desk_path.read_bytes()
            ti = tarfile.TarInfo("./usr/share/applications/ulpf.desktop")
            ti.size = len(d_bytes)
            ti.mode = 0o644
            ti.mtime = int(time.time())
            tar.addfile(ti, io.BytesIO(d_bytes))

        # Systemd service
        serv_path = root_dir / "packaging" / "linux" / "ulpf-dashboard.service"
        if serv_path.exists():
            s_bytes = serv_path.read_bytes()
            ti = tarfile.TarInfo("./etc/systemd/system/ulpf-dashboard.service")
            ti.size = len(s_bytes)
            ti.mode = 0o644
            ti.mtime = int(time.time())
            tar.addfile(ti, io.BytesIO(s_bytes))

        # Application icon (PNG)
        icon_ico = root_dir / "packaging" / "windows" / "ulpf_icon.ico"
        if icon_ico.exists():
            im = Image.open(icon_ico)
            png_buf = io.BytesIO()
            im.save(png_buf, format="PNG")
            icon_bytes = png_buf.getvalue()
            ti = tarfile.TarInfo("./usr/share/icons/hicolor/256x256/apps/ulpf.png")
            ti.size = len(icon_bytes)
            ti.mode = 0o644
            ti.mtime = int(time.time())
            tar.addfile(ti, io.BytesIO(icon_bytes))

        # Wheel package to /opt/ulpf
        wheels = list(dist_dir.glob(f"ulpf-{version}-*.whl"))
        for w in wheels:
            w_bytes = w.read_bytes()
            ti = tarfile.TarInfo(f"./opt/ulpf/{w.name}")
            ti.size = len(w_bytes)
            ti.mode = 0o644
            ti.mtime = int(time.time())
            tar.addfile(ti, io.BytesIO(w_bytes))

    data_tar_gz = data_buf.getvalue()

    # 4. Assemble ar archive (.deb)
    now = int(time.time())
    ar_data = bytearray(b"!<arch>\n")
    ar_data.extend(make_ar_member("debian-binary", deb_binary, now, 0o100644))
    ar_data.extend(make_ar_member("control.tar.gz", control_tar_gz, now, 0o100644))
    ar_data.extend(make_ar_member("data.tar.gz", data_tar_gz, now, 0o100644))

    out_deb.write_bytes(bytes(ar_data))
    size_mb = out_deb.stat().st_size / (1024 * 1024)
    print(f"[+] Created Debian/Ubuntu Package: {out_deb.name} ({size_mb:.2f} MB)")
    return out_deb

if __name__ == "__main__":
    r_dir = Path(__file__).parent.parent.parent.resolve()
    d_dir = r_dir / "dist"
    d_dir.mkdir(parents=True, exist_ok=True)
    build_deb(r_dir, d_dir, "1.2.0")
