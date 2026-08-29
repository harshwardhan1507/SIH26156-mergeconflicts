"""
ULPF Native Desktop Application Launcher.
Launches the embedded FastAPI backend and presents a dedicated native desktop GUI window.
"""
import io
import os
import sys
import time
import socket
import threading
import subprocess
import webbrowser
from pathlib import Path

# Safe Null stream for GUI windowed executables (where sys.stdout/stderr are None)
class SafeStream:
    def write(self, text):
        pass
    def flush(self):
        pass
    def isatty(self):
        return False
    def fileno(self):
        raise io.UnsupportedOperation("No fileno in GUI mode")

if sys.stdout is None:
    sys.stdout = SafeStream()
if sys.stderr is None:
    sys.stderr = SafeStream()
if sys.stdin is None:
    sys.stdin = io.StringIO()

# Fix Windows high DPI scaling
if sys.platform == "win32":
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

# Ensure all parsers are auto-registered
import ulpf.parsers  # noqa: F401
from ulpf.dashboard.app import create_app, _resolve_output_dir
from ulpf.core.ingestion import FileReader
from ulpf.cli import _build_pipeline, _find_schema_dir, _find_config_dir
import uvicorn


def get_user_log_path() -> Path:
    """Get a user-writable crash/debug log path across OS platforms."""
    if sys.platform == "win32":
        app_data = os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP")
        if app_data:
            p = Path(app_data) / "ULPF"
            p.mkdir(parents=True, exist_ok=True)
            return p / "ulpf_launcher.log"
    p = Path.home() / ".ulpf"
    p.mkdir(parents=True, exist_ok=True)
    return p / "ulpf_launcher.log"


def find_available_port(host: str = "127.0.0.1", start_port: int = 8000) -> int:
    """Find the first available TCP port."""
    for p in range(start_port, start_port + 100):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex((host, p)) != 0:
                return p
    return start_port


def find_sample_logs_dir() -> Path | None:
    """Locate sample_logs directory in various packaging/source layouts."""
    candidates = [
        Path.cwd() / "sample_logs",
        Path.cwd() / "ulpf" / "sample_logs",
        Path(__file__).parent / "sample_logs",
        Path(__file__).parent / "ulpf" / "sample_logs",
        Path(__file__).parent.parent / "sample_logs",
        Path(__file__).parent.parent / "ulpf" / "sample_logs",
    ]
    # Check PyInstaller bundle directory
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        meipass = Path(sys._MEIPASS)
        candidates.insert(0, meipass / "sample_logs")
        candidates.insert(0, meipass / "ulpf" / "sample_logs")

    for c in candidates:
        if c.exists() and c.is_dir() and any(c.iterdir()):
            return c
    return None


def bootstrap_sample_data_if_needed(output_dir: Path) -> None:
    """Initialize demo events if database is empty on first launch."""
    try:
        events_file = output_dir / "events.ndjson"
        if not events_file.exists() or events_file.stat().st_size == 0:
            sample_dir = find_sample_logs_dir()
            if sample_dir and sample_dir.exists():
                output_dir.mkdir(parents=True, exist_ok=True)
                p, s, v = _build_pipeline(
                    output=output_dir,
                    schema_dir=_find_schema_dir(),
                    cfg=_find_config_dir() / "sources.yaml",
                    sink_type="ndjson",
                    enrich=True,
                )
                reader = FileReader(str(sample_dir))
                p.run(reader)
                v.close()
                for snk in s:
                    snk.close()
    except Exception as e:
        log_path = get_user_log_path()
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"[{time.ctime()}] Bootstrap notice: {e}\n")


def wait_for_server(host: str, port: int, timeout: float = 10.0) -> bool:
    """Poll until the FastAPI server is accepting connections."""
    start = time.time()
    while time.time() - start < timeout:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.1)
    return False


def launch_in_app_mode(url: str) -> bool:
    """Launch Microsoft Edge or Google Chrome in dedicated application window mode."""
    if sys.platform == "win32":
        extra_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        edge_paths = [
            os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
            os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
            os.path.expandvars(r"%LocalAppData%\Microsoft\Edge\Application\msedge.exe"),
        ]
        chrome_paths = [
            os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
        ]
        for exe in edge_paths + chrome_paths:
            if os.path.exists(exe):
                try:
                    subprocess.Popen(
                        [
                            exe,
                            f"--app={url}",
                            "--window-size=1360,860",
                            "--window-position=100,50",
                        ],
                        creationflags=extra_flags,
                    )
                    return True
                except Exception:
                    pass
    return False


def main():
    host = "127.0.0.1"
    port = find_available_port(host=host, start_port=8000)
    output_dir = _resolve_output_dir(None)

    bootstrap_sample_data_if_needed(output_dir)

    # Start FastAPI server in background thread with log_config=None to prevent isatty error
    app = create_app(output_dir=output_dir, host=host, port=port)
    config = uvicorn.Config(
        app=app,
        host=host,
        port=port,
        log_config=None,
        access_log=False,
    )
    server = uvicorn.Server(config=config)

    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()

    url = f"http://{host}:{port}"
    wait_for_server(host, port, timeout=8.0)

    # 1. Try pywebview for true native desktop window
    gui_launched = False
    try:
        import webview
        window = webview.create_window(
            title="ULPF — Operations Dashboard",
            url=url,
            width=1360,
            height=860,
            min_size=(900, 600),
            confirm_close=False,
        )
        webview.start()
        gui_launched = True
    except Exception as e:
        log_path = get_user_log_path()
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"[{time.ctime()}] PyWebView notice: {e}\n")

    # 2. Fallback: Edge/Chrome dedicated app window or browser
    if not gui_launched:
        if not launch_in_app_mode(url):
            webbrowser.open(url)
        # Keep server running permanently
        try:
            while server_thread.is_alive():
                time.sleep(0.5)
        except (KeyboardInterrupt, SystemExit):
            pass


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        crash_log = get_user_log_path()
        with open(crash_log, "a", encoding="utf-8") as f:
            f.write(f"[{time.ctime()}] Launcher Unhandled Error: {e}\n")
            import traceback
            traceback.print_exc(file=f)
