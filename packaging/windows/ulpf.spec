# -*- mode: python ; coding: utf-8 -*-
import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_all, collect_submodules

block_cipher = None
root_dir = Path.cwd().resolve()

# Collect hidden imports and submodules
hiddenimports = [
    "fastapi",
    "starlette",
    "starlette.middleware",
    "starlette.middleware.cors",
    "starlette.staticfiles",
    "starlette.responses",
    "uvicorn",
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespans",
    "uvicorn.lifespans.on",
    "pydantic",
    "pydantic_core",
    "jsonschema",
    "yaml",
    "dateutil",
    "dateutil.parser",
    "sqlite3",
    "webview",
    "webview.guilib",
    "webview.platforms",
    "webview.platforms.winforms",
    "webview.platforms.edgechromium",
] + collect_submodules("ulpf") + collect_submodules("webview")

datas = [
    (str(root_dir / "ulpf" / "schemas"), "ulpf/schemas"),
    (str(root_dir / "ulpf" / "config"), "ulpf/config"),
    (str(root_dir / "ulpf" / "dashboard" / "static"), "ulpf/dashboard/static"),
    (str(root_dir / "ulpf" / "sample_logs"), "ulpf/sample_logs"),
]

icon_path = str(root_dir / "packaging" / "windows" / "ulpf_icon.ico")
if not Path(icon_path).exists():
    icon_path = None

# -------------------------------------------------------------
# Target 1: ulpf.exe (CLI + Interactive Menu)
# -------------------------------------------------------------
a_cli = Analysis(
    [str(root_dir / "ulpf" / "cli.py")],
    pathex=[str(root_dir)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "scipy"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz_cli = PYZ(a_cli.pure, a_cli.zipped_data, cipher=block_cipher)

exe_cli = EXE(
    pyz_cli,
    a_cli.scripts,
    a_cli.binaries,
    a_cli.zipfiles,
    a_cli.datas,
    [],
    name="ulpf",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_path,
)

# -------------------------------------------------------------
# Target 2: ulpf-dashboard.exe (Dedicated Standalone Web App Backend)
# -------------------------------------------------------------
a_dash = Analysis(
    [str(root_dir / "ulpf" / "dashboard" / "app.py")],
    pathex=[str(root_dir)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "scipy"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz_dash = PYZ(a_dash.pure, a_dash.zipped_data, cipher=block_cipher)

exe_dash = EXE(
    pyz_dash,
    a_dash.scripts,
    a_dash.binaries,
    a_dash.zipfiles,
    a_dash.datas,
    [],
    name="ulpf-dashboard",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_path,
)

# -------------------------------------------------------------
# Target 3: ULPF-Launcher.exe (Primary Desktop Application Launcher)
# -------------------------------------------------------------
a_launcher = Analysis(
    [str(root_dir / "packaging" / "windows" / "launcher.py")],
    pathex=[str(root_dir)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "scipy"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz_launcher = PYZ(a_launcher.pure, a_launcher.zipped_data, cipher=block_cipher)

exe_launcher = EXE(
    pyz_launcher,
    a_launcher.scripts,
    a_launcher.binaries,
    a_launcher.zipfiles,
    a_launcher.datas,
    [],
    name="ULPF-Launcher",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_path,
)
