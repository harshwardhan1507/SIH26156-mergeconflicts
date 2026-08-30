"""
Dashboard server entry point: ``ulpf-dashboard``.

Owns process lifecycle concerns — port selection, background launch, PID
tracking, status, and shutdown — that have nothing to do with the framework and
so do not belong in the framework's CLI.
"""
from __future__ import annotations

import json
import logging
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path

import click
import uvicorn

from ulpf_dashboard import __version__
from ulpf_dashboard.app import create_app
from ulpf_dashboard.paths import resolve_output_dir

logger = logging.getLogger(__name__)

PID_FILENAME = "ulpf_dashboard.pid"


def _loopback(host: str) -> str:
    """Map a wildcard bind address to a connectable loopback address."""
    return "127.0.0.1" if host in ("0.0.0.0", "::", "localhost") else host  # noqa: S104


def is_running(host: str = "127.0.0.1", port: int = 8000, timeout: float = 1.0) -> bool:
    """True when a ULPF dashboard is already answering on this address."""
    url = f"http://{_loopback(host)}:{port}/api/health"
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "ULPF-Launcher"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status == 200
    except Exception:
        return False


def wait_for_server(host: str = "127.0.0.1", port: int = 8000, timeout: float = 8.0) -> bool:
    """Poll until the server answers, or the timeout expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if is_running(host, port):
            return True
        time.sleep(0.1)
    return False


def find_available_port(host: str = "127.0.0.1", start_port: int = 8000, attempts: int = 50) -> int:
    """First bindable TCP port at or after ``start_port``."""
    for candidate in range(start_port, start_port + attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind((host, candidate))
                return candidate
            except OSError:
                continue
    raise OSError(f"No free port found in {start_port}..{start_port + attempts}")


def write_pid_file(output_dir: Path, host: str, port: int) -> None:
    """Record this process's address so ``--stop`` and ``--status`` can find it."""
    try:
        (output_dir / PID_FILENAME).write_text(
            json.dumps(
                {
                    "pid": os.getpid(),
                    "host": host,
                    "port": port,
                    "version": __version__,
                    "start_time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    except OSError as exc:
        logger.debug("Could not write PID file: %s", exc)


def read_pid_file(output_dir: Path) -> dict | None:
    """Read the recorded server metadata, if any."""
    pid_file = output_dir / PID_FILENAME
    if not pid_file.exists():
        return None
    try:
        return json.loads(pid_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def remove_pid_file(output_dir: Path) -> None:
    """Remove the PID file on clean shutdown."""
    try:
        (output_dir / PID_FILENAME).unlink(missing_ok=True)
    except OSError as exc:
        logger.debug("Could not remove PID file: %s", exc)


def stop_server(output_dir: str | Path = "output", host: str = "127.0.0.1", port: int = 8000) -> bool:
    """Terminate a background dashboard recorded in the PID file."""
    resolved = resolve_output_dir(output_dir)
    info = read_pid_file(resolved)
    stopped = False

    pid = (info or {}).get("pid")
    if pid and pid != os.getpid():
        try:
            if sys.platform == "win32":
                result = subprocess.run(
                    ["taskkill", "/F", "/PID", str(pid)], capture_output=True, text=True
                )
                stopped = result.returncode == 0
            else:
                os.kill(pid, signal.SIGTERM)
                stopped = True
        except (OSError, subprocess.SubprocessError) as exc:
            logger.debug("Could not signal PID %s: %s", pid, exc)

    remove_pid_file(resolved)

    if stopped or not is_running(host, port):
        click.echo(f"[+] ULPF dashboard stopped. Port {port} is free.")
        return True
    click.echo(f"[!] No ULPF dashboard responded on port {port}.", err=True)
    return False


def server_status(output_dir: str | Path = "output", host: str = "127.0.0.1", port: int = 8000) -> None:
    """Print the current server status and headline metrics."""
    resolved = resolve_output_dir(output_dir)
    url = f"http://{_loopback(host)}:{port}"

    click.echo("=" * 60)
    click.echo("  ULPF Operations Dashboard — status")
    click.echo("=" * 60)

    if not is_running(host, port):
        click.echo("  Status:      STOPPED")
        click.echo(f"  Port:        {port} (free)")
        click.echo("=" * 60)
        return

    click.echo("  Status:      RUNNING")
    click.echo(f"  URL:         {url}")
    click.echo(f"  Output dir:  {resolved.resolve()}")
    info = read_pid_file(resolved)
    if info:
        click.echo(f"  PID:         {info.get('pid', 'n/a')}")
        click.echo(f"  Started:     {info.get('start_time', 'n/a')}")
    try:
        request = urllib.request.Request(f"{url}/api/stats", headers={"User-Agent": "ULPF-CLI"})
        with urllib.request.urlopen(request, timeout=2.0) as response:
            stats = json.loads(response.read().decode("utf-8"))
        click.echo(f"  Events:      {stats.get('total_events', 0)}")
        click.echo(f"  Dead-letter: {stats.get('dead_letter_count', 0)}")
    except Exception:
        pass
    click.echo("=" * 60)


def spawn_background(output_dir: Path, host: str, port: int, open_browser: bool) -> None:
    """Launch the dashboard in a detached background process."""
    url = f"http://{_loopback(host)}:{port}"

    if is_running(host, port):
        click.echo(f"[+] ULPF dashboard is already running at {url}")
        if open_browser:
            webbrowser.open(url)
        return

    python_exe = sys.executable
    if sys.platform == "win32":
        pythonw = Path(sys.executable).parent / "pythonw.exe"
        if pythonw.exists():
            python_exe = str(pythonw)

    command = [
        python_exe, "-m", "ulpf_dashboard.server",
        "--host", host, "--port", str(port),
        "--output-dir", str(output_dir), "--no-open-browser",
    ]
    kwargs: dict = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = 0x00000008 | 0x00000200 | 0x08000000
    else:
        kwargs["start_new_session"] = True

    process = subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        close_fds=True,
        **kwargs,
    )
    click.echo(f"[*] Starting ULPF dashboard in background (PID {process.pid})...")

    if wait_for_server(host, port):
        click.echo(f"[+] Dashboard running at {url}")
        click.echo(f"    Output directory: {output_dir.resolve()}")
        click.echo("    Stop with: ulpf-dashboard --stop")
    else:
        click.echo(f"[!] Dashboard did not answer within the timeout (PID {process.pid}).", err=True)
    if open_browser:
        webbrowser.open(url)


@click.command("ulpf-dashboard")
@click.version_option(__version__, prog_name="ulpf-dashboard")
@click.option("--output-dir", "-o", default=None,
              help="Pipeline output directory containing events.ndjson and raw_store/.")
@click.option("--host", default="127.0.0.1",
              help="Bind address. Binding beyond loopback requires ULPF_API_KEY.")
@click.option("--port", "-p", default=8000, type=int, help="Bind port.")
@click.option("--open-browser/--no-open-browser", default=True,
              help="Open the dashboard in the default browser once it is up.")
@click.option("--background", "-b", is_flag=True, help="Run persistently in the background.")
@click.option("--stop", is_flag=True, help="Stop a running background dashboard.")
@click.option("--status", is_flag=True, help="Report dashboard server status.")
@click.option("--log-level", default="info",
              type=click.Choice(["debug", "info", "warning", "error"], case_sensitive=False))
def main(
    output_dir: str | None,
    host: str,
    port: int,
    open_browser: bool,
    background: bool,
    stop: bool,
    status: bool,
    log_level: str,
) -> None:
    """Launch the ULPF Operations Dashboard."""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    if stop:
        sys.exit(0 if stop_server(output_dir or "output", host, port) else 1)
    if status:
        server_status(output_dir or "output", host, port)
        return

    resolved = resolve_output_dir(output_dir)

    if background:
        spawn_background(resolved, host, port, open_browser)
        return

    url_host = _loopback(host)
    if is_running(host, port):
        click.echo(f"[+] ULPF dashboard is already running at http://{url_host}:{port}")
        if open_browser:
            webbrowser.open(f"http://{url_host}:{port}")
        return

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((host, port))
    except OSError:
        original, port = port, find_available_port(host, port + 1)
        click.echo(f"[*] Port {original} is in use — using {port} instead.")

    url = f"http://{url_host}:{port}"
    click.echo("=" * 60)
    click.echo(f"  ULPF Operations Dashboard  {url}")
    click.echo(f"  Output directory: {resolved.resolve()}")
    click.echo("  Press Ctrl+C to stop.")
    click.echo("=" * 60)

    if open_browser:
        def _open_when_ready() -> None:
            if wait_for_server(host, port):
                webbrowser.open(url)

        threading.Thread(target=_open_when_ready, daemon=True).start()

    write_pid_file(resolved, host, port)
    try:
        uvicorn.run(
            create_app(output_dir=resolved, host=host, port=port),
            host=host,
            port=port,
            log_level=log_level.lower(),
        )
    finally:
        remove_pid_file(resolved)


if __name__ == "__main__":
    main()
