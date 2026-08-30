"""
ULPF Command Line Interface.

Usage:
  ulpf ingest --input <path> [--sink ndjson,kafka,kafka-real,parquet,cef-egress,leef-egress] [--output <dir>] [--workers N]
  ulpf listen [--port 1514] [--output <dir>]
  ulpf analyze --input output/events.ndjson [--output output/anomalies.ndjson] [--emit-features]
  ulpf lookup --event-id <uuid> [--raw-store <dir>]
  ulpf dashboard [--port 8000] [--output-dir output]
  ulpf list-parsers
"""
from __future__ import annotations

import io
import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Safe Null stream for windowed GUI or daemon modes where sys.stdout/stderr may be None
class SafeStream:
    """Safe stream wrapper preventing AttributeError/UnsupportedOperation in GUI/daemon modes."""
    def write(self, text: str) -> int:
        return len(text)
    def flush(self) -> None:
        pass
    def isatty(self) -> bool:
        return False
    def fileno(self) -> int:
        raise io.UnsupportedOperation("No fileno in GUI/headless mode")

if sys.stdout is None:
    sys.stdout = SafeStream()
if sys.stderr is None:
    sys.stderr = SafeStream()
if sys.stdin is None:
    sys.stdin = io.StringIO()

import click

# Auto-register all parsers
import ulpf.parsers  # noqa: F401  (side-effect import)

from ulpf.core.detector import FormatDetector
from ulpf.core.ingestion import FileReader, StdinReader
from ulpf.core.normalization import NormalizationEngine
from ulpf.core.pipeline import Pipeline
from ulpf.core.raw_store import FileRawStore
from ulpf.core.validation import Validator
from ulpf.core.registry import list_parser_names
from ulpf.enrichment.noop import NoOpEnrichment
from ulpf.enrichment.ip_enrichment import IPEnrichmentPlugin
from ulpf.enrichment.composite import CompositeEnrichment
from ulpf.sinks.kafka_stub import KafkaStubSink
from ulpf.sinks.ndjson_file import NDJSONFileSink

_SINK_CHOICES = ('ndjson', 'kafka', 'kafka-real', 'parquet', 'cef-egress', 'leef-egress')


def _find_schema_dir() -> Path:
    """Locate the schemas directory across package, workspace, and container paths."""
    candidates = [
        Path(__file__).parent / 'schemas',
        Path.cwd() / 'ulpf' / 'schemas',
        Path.cwd() / 'schemas',
        Path('/app/ulpf/schemas'),
        Path('/app/schemas'),
    ]
    for c in candidates:
        if c.exists() and (c / 'ues_schema.json').exists():
            return c
    return candidates[0]


def _find_config_dir() -> Path:
    """Locate the config directory across package, workspace, and container paths."""
    candidates = [
        Path(__file__).parent / 'config',
        Path.cwd() / 'ulpf' / 'config',
        Path.cwd() / 'config',
        Path('/app/ulpf/config'),
        Path('/app/config'),
    ]
    for c in candidates:
        if c.exists():
            return c
    return candidates[0]


def _make_sink(sink_name: str, output: Path):
    """Instantiate a single sink by name. See _SINK_CHOICES for valid names."""
    if sink_name == 'ndjson':
        return NDJSONFileSink(output / 'events.ndjson')
    if sink_name == 'kafka-real':
        from ulpf.sinks.kafka_producer import KafkaProducerSink
        return KafkaProducerSink(
            topic='ulpf.events',
            bootstrap_servers='localhost:9092',
            fallback_path=output / 'kafka_events.ndjson',
        )
    if sink_name == 'kafka':
        return KafkaStubSink(output / 'kafka_events.ndjson')
    if sink_name == 'parquet':
        from ulpf.sinks.parquet_sink import ParquetSink
        return ParquetSink(output / 'parquet_lake')
    if sink_name == 'cef-egress':
        from ulpf.sinks.cef_egress import CEFEgressSink
        return CEFEgressSink(output / 'egress_cef.log')
    if sink_name == 'leef-egress':
        from ulpf.sinks.leef_egress import LEEFEgressSink
        return LEEFEgressSink(output / 'egress_leef.log')
    raise click.BadParameter(f'Unknown sink {sink_name!r}. Choose from: {", ".join(_SINK_CHOICES)}')


def _build_pipeline(
    output: Path,
    schema_dir: Path,
    cfg: Path,
    sink_type: str,
    enrich: bool = True,
    raw_store_type: str = 'file',
) -> tuple[Pipeline, list, Validator]:
    """
    Build and return a configured Pipeline, sinks list, and Validator.
    sink_type may be a single name or a comma-separated list (e.g.
    'ndjson,parquet,cef-egress') to fan out every event to multiple sinks
    at once — the same normalized event, multiple SIEM/data-lake targets.
    """
    detector = FormatDetector(sources_config_path=cfg if cfg.exists() else None)
    if str(raw_store_type).lower() == 'segmented':
        from ulpf.core.segmented_raw_store import SegmentedRawStore
        raw_store = SegmentedRawStore(output / 'raw_segments')
    else:
        raw_store = FileRawStore(output / 'raw_store')
    norm_engine = NormalizationEngine(schema_dir / 'mappings')
    validator = Validator(
        schema_path=schema_dir / 'ues_schema.json',
        dead_letter_path=output / 'dead_letter.ndjson',
    )

    if enrich:
        enrichment = CompositeEnrichment([IPEnrichmentPlugin()])
    else:
        enrichment = NoOpEnrichment()

    sink_names = [s.strip() for s in sink_type.split(',') if s.strip()] or ['ndjson']
    sinks = [_make_sink(name, output) for name in sink_names]

    pipeline = Pipeline(
        detector=detector,
        raw_store=raw_store,
        normalization_engine=norm_engine,
        validator=validator,
        sinks=sinks,
        enrichment=enrichment,
    )
    return pipeline, sinks, validator


def _worker_pipeline_factory(
    output: Path, schema_dir: Path, cfg: Path, sink_type: str, enrich: bool, raw_store_type: str = 'file',
) -> Pipeline:
    """
    Module-level (hence picklable) pipeline builder for ParallelPipeline workers.
    A closure defined inside a command function cannot be pickled across
    process boundaries — this must live at module scope, and be bound to its
    arguments via functools.partial (also picklable) at the call site.
    """
    pipeline, _sinks, _validator = _build_pipeline(output, schema_dir, cfg, sink_type, enrich, raw_store_type)
    return pipeline


@click.group()
@click.option('--log-level', default='INFO',
              type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR'], case_sensitive=False),
              help='Logging verbosity.')
def main(log_level: str) -> None:
    """Universal Log Pre-processing Framework (ULPF) v1.2.0"""
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s %(levelname)-8s %(name)s: %(message)s',
    )


@main.command()
@click.option('--input', '-i', 'input_path', default='-',
              help='Input file/directory path, or "-" for stdin.')
@click.option('--sink', '-s', 'sink_type', default='ndjson',
              help='Output sink(s), comma-separated: ' + ', '.join(_SINK_CHOICES) +
                   ' (e.g. "ndjson,parquet"). kafka-real requires kafka-python.')
@click.option('--output', '-o', 'output_dir', default='output',
              help='Output directory for normalized events and raw store.')
@click.option('--raw-store', 'raw_store_type', default='file',
              type=click.Choice(['file', 'segmented'], case_sensitive=False),
              help='Raw storage engine: "file" (individual per-event forensic files) or "segmented" (high-throughput chunked storage with SQLite index).')
@click.option('--config', '-c', 'config_path', default=None,
              help='Path to sources.yaml config file.')
@click.option('--workers', '-w', 'workers', default=1, type=int,
              help='Number of parallel worker processes (>1 enables ParallelPipeline).')
@click.option('--no-enrich', 'no_enrich', is_flag=True, default=False,
              help='Disable IP enrichment (faster, for benchmarking).')
@click.option('--tenant-id', 'tenant_id', default='default',
              help='Tenant identifier attached to every ingested event.')
def ingest(
    input_path: str, sink_type: str, output_dir: str, raw_store_type: str,
    config_path: str | None, workers: int, no_enrich: bool, tenant_id: str,
) -> None:
    """Ingest raw log files/stdin and produce normalized UES events."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    for name in [s.strip() for s in sink_type.split(',') if s.strip()]:
        if name not in _SINK_CHOICES:
            raise click.BadParameter(
                f'Unknown sink {name!r}. Choose from: {", ".join(_SINK_CHOICES)}', param_hint='--sink',
            )

    schema_dir = _find_schema_dir()
    cfg = Path(config_path) if config_path else _find_config_dir() / 'sources.yaml'

    click.echo(f'Starting ingestion from {input_path!r} -> {output_dir!r} [{sink_type}] (raw_store={raw_store_type})'
               + (f' [workers={workers}]' if workers > 1 else ''))

    if workers > 1:
        import functools
        from ulpf.core.worker_pool import ParallelPipeline

        # functools.partial over a MODULE-LEVEL function is picklable across
        # process boundaries (a closure defined here would not be) — this is
        # what makes --workers actually work instead of crashing.
        factory = functools.partial(
            _worker_pipeline_factory, output, schema_dir, cfg, sink_type, not no_enrich, raw_store_type,
        )

        reader = FileReader(input_path) if input_path != '-' else StdinReader()
        parallel = ParallelPipeline(pipeline_factory=factory, num_workers=workers)
        stats = parallel.run(reader, tenant_id=tenant_id)
    else:
        pipeline, sinks, validator = _build_pipeline(
            output, schema_dir, cfg, sink_type, not no_enrich, raw_store_type,
        )
        reader = FileReader(input_path) if input_path != '-' else StdinReader()
        stats = pipeline.run(reader, tenant_id=tenant_id)
        validator.close()
        for sink in sinks:
            sink.close()

    click.echo(
        f'Done. Processed={stats["processed"]} Valid={stats["valid"]} '
        f'Invalid={stats["invalid"]} Errors={stats["errors"]}'
    )


@main.command()
@click.option('--input', '-i', 'input_path', default='output/events.ndjson',
              help='Path to NDJSON events file to analyze.')
@click.option('--output', '-o', 'output_path', default=None,
              help='Path to write anomalous events NDJSON (optional).')
@click.option('--output-dir', 'output_dir', default='output',
              help='Output directory (for baseline persistence).')
@click.option('--emit-features', 'emit_features', is_flag=True, default=False,
              help='Also write a 24-dim ML feature vector per event to '
                   '<output-dir>/features.ndjson (see ulpf.analytics.features).')
def analyze(input_path: str, output_path: str | None, output_dir: str, emit_features: bool) -> None:
    """Run statistical anomaly detection over a normalized events NDJSON file."""
    from ulpf.analytics.anomaly import AnomalyDetector

    detector = AnomalyDetector(output_dir=output_dir)
    events_file = Path(input_path)

    if not events_file.exists():
        click.echo(f'Error: events file not found: {events_file}', err=True)
        sys.exit(1)

    click.echo(f'Analyzing {events_file} for anomalies...')
    out_path = Path(output_path) if output_path else None
    result = detector.analyze_file(ndjson_path=events_file, output_path=out_path)

    click.echo(
        f'Done. Total={result["total_events"]} Anomalous={result["anomalous_events"]} '
        f'Rate={result["anomaly_rate_pct"]}%'
    )
    if out_path:
        click.echo(f'Anomalous events written to: {out_path}')

    if emit_features:
        import json as _json
        from ulpf.analytics.features import FeatureVectorExtractor

        features_path = Path(output_dir) / 'features.ndjson'
        n = 0
        with open(events_file, 'r', encoding='utf-8', errors='replace') as fin, \
             open(features_path, 'w', encoding='utf-8') as fout:
            for line in fin:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = _json.loads(line)
                except _json.JSONDecodeError:
                    continue
                vector = FeatureVectorExtractor.extract_vector(event)
                fout.write(_json.dumps({
                    'event_id': event.get('event_id'),
                    'features': vector,
                    'feature_names': FeatureVectorExtractor.get_feature_names(),
                }) + '\n')
                n += 1
        click.echo(f'Wrote {n} feature vectors to: {features_path}')


@main.command('listen')
@click.option('--host', default='0.0.0.0', help='Interface to bind the syslog listener on.')
@click.option('--port', '-p', default=1514, type=int,
              help='UDP+TCP port to listen on (use 514 if running as root/admin).')
@click.option('--output', '-o', 'output_dir', default='output',
              help='Output directory for normalized events and raw store.')
@click.option('--sink', '-s', 'sink_type', default='ndjson',
              help='Output sink(s), comma-separated: ' + ', '.join(_SINK_CHOICES))
@click.option('--config', '-c', 'config_path', default=None,
              help='Path to sources.yaml config file.')
@click.option('--no-enrich', 'no_enrich', is_flag=True, default=False,
              help='Disable IP enrichment.')
@click.option('--tenant-id', 'tenant_id', default='default',
              help='Tenant identifier attached to every ingested event.')
def listen_cmd(
    host: str, port: int, output_dir: str, sink_type: str,
    config_path: str | None, no_enrich: bool, tenant_id: str,
) -> None:
    """
    Run a live UDP+TCP syslog network listener, ingesting real perimeter
    device traffic directly into the ULPF pipeline (RFC3164/5424, CEF, LEEF,
    and anything else the registered parsers recognize).
    """
    from ulpf.collectors.syslog_listener import SyslogNetworkListener

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    schema_dir = _find_schema_dir()
    cfg = Path(config_path) if config_path else _find_config_dir() / 'sources.yaml'

    pipeline, sinks, validator = _build_pipeline(output, schema_dir, cfg, sink_type, not no_enrich)

    def on_event(line: str, source_tag: str) -> None:
        try:
            pipeline.process_event(raw_line=line, source_tag=source_tag, tenant_id=tenant_id)
        except Exception as exc:
            logging.getLogger(__name__).warning('listen: failed to process event: %s', exc)

    listener = SyslogNetworkListener(on_event=on_event, host=host, port=port)
    listener.start()

    click.echo("============================================================")
    click.echo(f"  ULPF Syslog Listener (UDP + TCP) on {host}:{port}")
    click.echo(f"  Output directory: {output.resolve()}  Sink(s): {sink_type}")
    click.echo("  Press Ctrl+C to stop.")
    click.echo("============================================================")

    import time
    try:
        last = 0
        while True:
            time.sleep(2.0)
            for sink in sinks:
                sink.flush()
            n = listener.get_stats().get('packets_received', 0)
            if n != last:
                click.echo(f"[*] {n} packets received ({pipeline._processed} processed, {pipeline._errors} errors)")
                last = n
    except KeyboardInterrupt:
        click.echo("\nStopping syslog listener...")
    finally:
        listener.stop()
        validator.close()
        for sink in sinks:
            sink.close()
        click.echo("Syslog listener stopped.")


@main.command()
@click.option('--event-id', '-e', required=True, help='UUID of the event to look up.')
@click.option('--raw-store', 'raw_store_dir', default='output/raw_store',
              help='Path to the raw store directory.')
def lookup(event_id: str, raw_store_dir: str) -> None:
    """Look up the original raw payload for a given event UUID."""
    store = FileRawStore(raw_store_dir)
    payload = store.get(event_id)
    if payload is None:
        click.echo(f'Event {event_id!r} not found in raw store.', err=True)
        sys.exit(1)
    click.echo(payload)


@main.command('list-parsers')
def list_parsers() -> None:
    """List all registered parser plugins."""
    names = list_parser_names()
    if not names:
        click.echo('No parsers registered.')
    else:
        click.echo(f'Registered parsers ({len(names)}):')
        for name in names:
            click.echo(f'  - {name}')


@main.command('monitor')
@click.option('--output', '-o', default='output', help='Output directory for captured events.')
@click.option('--interval-ms', '-i', default=250, type=int, help='Polling interval in milliseconds (default: 250ms).')
def monitor_cmd(output: str, interval_ms: int) -> None:
    """Live monitor local OS events, process executions (e.g. VALORANT, Chrome), and system logs."""
    from ulpf.collectors.live_monitor import LiveSystemMonitor
    import time

    click.echo("============================================================")
    click.echo(f"  ULPF Live OS & Process Event Monitor ({interval_ms}ms)")
    click.echo(f"  Target Output Directory: {Path(output).resolve()}")
    click.echo("  Capturing process launches, exits, and OS event logs...")
    click.echo("  Press Ctrl+C to stop.")
    click.echo("============================================================")

    mon = LiveSystemMonitor(output_dir=output, interval_ms=interval_ms)
    mon.start()
    try:
        last_captured = 0
        while True:
            time.sleep(1.0)
            stats = mon.get_stats()
            captured = stats.get("events_captured", 0)
            tracked = stats.get("tracked_processes", 0)
            diff = captured - last_captured
            last_captured = captured
            click.echo(f"[*] Live: {captured} events captured (+{diff}/s) | Tracking {tracked} active processes")
    except KeyboardInterrupt:
        click.echo("\nStopping live monitor...")
        mon.stop()
        click.echo("Live monitor stopped.")


def _find_sample_logs_dir() -> Path | None:
    """Find bundled or repository sample_logs directory."""
    candidates = [
        Path(__file__).parent / "sample_logs",
        Path(__file__).parent.parent / "sample_logs",
        Path.cwd() / "ulpf" / "sample_logs",
        Path.cwd() / "sample_logs",
    ]
    for c in candidates:
        if c.exists() and any(c.glob("*.*")):
            return c
    return None


def _spawn_background_server(output_dir: Path, host: str, port: int, open_browser: bool) -> None:
    """Launch the dashboard in a detached background process."""
    import shutil
    from ulpf.dashboard.app import _wait_for_server, _is_ulpf_running

    check_host = "127.0.0.1" if host in ("0.0.0.0", "::", "localhost") else host
    url = f"http://{check_host}:{port}"

    if _is_ulpf_running(check_host, port):
        click.echo("============================================================")
        click.echo(f"  [+] ULPF Operations Dashboard is ALREADY running at: {url}")
        click.echo(f"  Connected Output Directory: {output_dir.resolve()}")
        click.echo("============================================================")
        if open_browser:
            import webbrowser
            webbrowser.open(url)
        return

    python_exe = sys.executable
    if sys.platform == "win32":
        candidate = Path(sys.executable).parent / "pythonw.exe"
        if candidate.exists():
            python_exe = str(candidate)
        else:
            w = shutil.which("pythonw")
            if w:
                python_exe = w

    cmd = [
        python_exe,
        "-m", "ulpf.dashboard.app",
        "--port", str(port),
        "--host", host,
        "--output-dir", str(output_dir),
        "--no-open-browser",
    ]

    extra_kwargs = {}
    if sys.platform == "win32":
        DETACHED_PROCESS = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        CREATE_NO_WINDOW = 0x08000000
        extra_kwargs["creationflags"] = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
    else:
        extra_kwargs["start_new_session"] = True

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        close_fds=True,
        **extra_kwargs,
    )

    click.echo(f"[*] Starting ULPF Dashboard in background (PID {proc.pid})...")
    if _wait_for_server(check_host, port, timeout=8.0):
        click.echo("============================================================")
        click.echo(f"  [+] ULPF Operations Dashboard is RUNNING in background!")
        click.echo(f"  URL: {url}")
        click.echo(f"  Connected Output Directory: {output_dir.resolve()}")
        click.echo(f"  To stop: run 'ulpf dashboard --stop' or Stop_Dashboard.bat")
        click.echo("============================================================")
        if open_browser:
            import webbrowser
            webbrowser.open(url)
    else:
        click.echo(f"[!] Dashboard launched in background (PID {proc.pid}). Connecting...")
        if open_browser:
            import webbrowser
            webbrowser.open(url)


def _stop_dashboard_server(output_dir: str | Path, host: str, port: int) -> bool:
    """Cleanly terminate running background dashboard server."""
    import signal
    from ulpf.dashboard.app import _resolve_output_dir, _is_ulpf_running
    resolved = _resolve_output_dir(output_dir)
    pid_file = resolved / "ulpf_dashboard.pid"
    stopped = False

    if pid_file.exists():
        try:
            with open(pid_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            pid = data.get("pid")
            if pid and pid != os.getpid():
                if sys.platform == "win32":
                    res = subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, text=True)
                    if res.returncode == 0 or "SUCCESS" in res.stdout:
                        stopped = True
                else:
                    try:
                        os.kill(pid, signal.SIGTERM)
                        stopped = True
                    except OSError:
                        pass
        except Exception:
            pass
        finally:
            if pid_file.exists():
                try:
                    pid_file.unlink()
                except Exception:
                    pass

    check_host = "127.0.0.1" if host in ("0.0.0.0", "::", "localhost") else host
    if _is_ulpf_running(check_host, port):
        if sys.platform == "win32":
            try:
                ps_cmd = f"Get-NetTCPConnection -LocalPort {port} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess"
                res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True)
                for line in res.stdout.strip().splitlines():
                    p = line.strip()
                    if p.isdigit() and int(p) != os.getpid():
                        subprocess.run(["taskkill", "/F", "/PID", p], capture_output=True)
                        stopped = True
            except Exception:
                pass

    if stopped or not _is_ulpf_running(check_host, port):
        click.echo("============================================================")
        click.echo(f"  [+] ULPF Operations Dashboard server stopped.")
        click.echo(f"  Port {port} is now free.")
        click.echo("============================================================")
        return True
    else:
        click.echo(f"[!] No active ULPF dashboard server was found on port {port}.")
        return False


def _get_dashboard_status(output_dir: str | Path, host: str, port: int) -> None:
    """Print current server status and active metrics."""
    import urllib.request
    from ulpf.dashboard.app import _resolve_output_dir, _is_ulpf_running
    resolved = _resolve_output_dir(output_dir)
    check_host = "127.0.0.1" if host in ("0.0.0.0", "::", "localhost") else host
    url = f"http://{check_host}:{port}"

    running = _is_ulpf_running(check_host, port)
    pid_file = resolved / "ulpf_dashboard.pid"
    pid_info = None
    if pid_file.exists():
        try:
            with open(pid_file, "r", encoding="utf-8") as f:
                pid_info = json.load(f)
        except Exception:
            pass

    click.echo("============================================================")
    click.echo("       ULPF Operations Dashboard Status")
    click.echo("============================================================")
    if running:
        click.echo(f"  Status:         [ACTIVE / RUNNING]")
        click.echo(f"  URL:            {url}")
        click.echo(f"  Output Dir:     {resolved.resolve()}")
        if pid_info:
            click.echo(f"  Process PID:    {pid_info.get('pid', 'N/A')}")
            click.echo(f"  Started At:     {pid_info.get('start_time', 'N/A')}")
        try:
            req = urllib.request.Request(f"{url}/api/stats", headers={"User-Agent": "ULPF-CLI"})
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                stats = json.loads(resp.read().decode("utf-8"))
                click.echo(f"  Indexed Events: {stats.get('total_events', 0)}")
                click.echo(f"  Issues / DLQ:   {stats.get('dead_letter_count', 0)}")
        except Exception:
            pass
    else:
        click.echo("  Status:         [STOPPED / NOT RUNNING]")
        click.echo(f"  Port:           {port} (free)")
    click.echo("============================================================")


@main.command('dashboard')
@click.option('--output-dir', '-o', default='output', help='Path to pipeline output directory.')
@click.option('--port', '-p', default=8000, type=int, help='Port to bind the dashboard server.')
@click.option('--host', default='127.0.0.1', help='Host interface to bind.')
@click.option('--open-browser/--no-open-browser', default=True, help='Automatically open dashboard in default browser.')
@click.option('--background', '-b', '--daemon', is_flag=True, default=False, help='Run dashboard persistently in background.')
@click.option('--stop', is_flag=True, default=False, help='Stop running background dashboard server.')
@click.option('--status', is_flag=True, default=False, help='Check dashboard server status.')
def dashboard_cmd(output_dir: str, port: int, host: str, open_browser: bool, background: bool, stop: bool, status: bool) -> None:
    """Launch the interactive local web operations dashboard."""
    if stop:
        _stop_dashboard_server(output_dir, host, port)
        return
    if status:
        _get_dashboard_status(output_dir, host, port)
        return

    import threading
    import webbrowser
    import uvicorn
    from ulpf.dashboard.app import create_app, _resolve_output_dir, _is_ulpf_running, _wait_for_server, _find_available_port

    resolved = _resolve_output_dir(output_dir)

    if background:
        _spawn_background_server(resolved, host, port, open_browser)
        return

    events_file = resolved / "events.ndjson"
    if not events_file.exists() or events_file.stat().st_size == 0:
        sample_dir = _find_sample_logs_dir()
        if sample_dir:
            click.echo(f"[*] Initializing sample logs from {sample_dir} into {resolved}...")
            try:
                p, s, v = _build_pipeline(
                    output=resolved,
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
                click.echo(f"[+] Successfully loaded sample logs into {resolved}")
            except Exception as e:
                click.echo(f"[!] Note: Sample log bootstrap skipped ({e})")

    check_host = "127.0.0.1" if host in ("0.0.0.0", "::", "localhost") else host

    # 1. Check if ULPF dashboard is already running on this port
    if _is_ulpf_running(host, port):
        url = f"http://{check_host}:{port}"
        click.echo(f"============================================================")
        click.echo(f"  [+] ULPF Operations Dashboard is ALREADY running at: {url}")
        click.echo(f"  Connected Output Directory: {resolved.resolve()}")
        click.echo(f"  Opened active dashboard in your browser!")
        click.echo(f"============================================================")
        if open_browser:
            webbrowser.open(url)
        return

    # 2. Check if port is occupied by another process, switch to open port automatically
    import socket
    original_port = port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
        except OSError:
            port = _find_available_port(host, start_port=port + 1)
            click.echo(f"[*] Port {original_port} is in use. Switched to available port: {port}")

    url = f"http://{check_host}:{port}"
    click.echo(f"============================================================")
    click.echo(f"  ULPF Operations Dashboard running at: {url}")
    click.echo(f"  Connected Output Directory: {resolved.resolve()}")
    click.echo(f"  Press Ctrl+C to stop the dashboard server.")
    click.echo(f"============================================================")

    if open_browser:
        def _launch_browser():
            _wait_for_server(check_host, port, timeout=6.0)
            webbrowser.open(url)
        threading.Thread(target=_launch_browser, daemon=True).start()

    app = create_app(resolved, host=host, port=port)
    use_safe_log = (sys.stdout is None) or (not hasattr(sys.stdout, "isatty")) or (not sys.stdout.isatty())
    config = uvicorn.Config(
        app=app,
        host=host,
        port=port,
        log_config=None if use_safe_log else uvicorn.config.LOGGING_CONFIG,
        log_level="info",
    )
    server = uvicorn.Server(config=config)
    server.run()


@main.command('stop')
@click.option('--output-dir', '-o', default='output', help='Path to pipeline output directory.')
@click.option('--port', '-p', default=8000, type=int, help='Port of dashboard server.')
@click.option('--host', default='127.0.0.1', help='Host interface.')
def stop_cmd(output_dir: str, port: int, host: str) -> None:
    """Stop the running background ULPF dashboard server."""
    _stop_dashboard_server(output_dir, host, port)


@main.command('status')
@click.option('--output-dir', '-o', default='output', help='Path to pipeline output directory.')
@click.option('--port', '-p', default=8000, type=int, help='Port of dashboard server.')
@click.option('--host', default='127.0.0.1', help='Host interface.')
def status_cmd(output_dir: str, port: int, host: str) -> None:
    """Check the status of the ULPF dashboard server."""
    _get_dashboard_status(output_dir, host, port)


@main.command('benchmark')
@click.option('--events', '-n', default=10000, type=int, help='Number of log events to process.')
@click.option('--workers', '-w', default=1, type=int, help='Number of worker threads/processes.')
@click.option('--input', '-i', 'input_file', default=None, help='Custom log file to benchmark against.')
@click.option('--sink', '-s', 'sink_type', type=click.Choice(['none', 'ndjson']), default='none', help='Sink destination.')
@click.option('--raw-store', '-r', 'raw_store_mode', type=click.Choice(['none', 'file', 'segmented']), default='none', help='Raw store backend.')
@click.option('--output-dir', '-o', default='benchmark_output', help='Output directory for benchmark logs.')
def benchmark_cmd(events: int, workers: int, input_file: str | None, sink_type: str, raw_store_mode: str, output_dir: str) -> None:
    """Run a high-throughput performance benchmark measuring EPS and bandwidth."""
    from ulpf.tools.benchmark import run_benchmark, print_benchmark_report
    click.echo(f"[*] Running benchmark: {events:,} events, workers={workers}, sink={sink_type}, raw_store={raw_store_mode}...")
    res = run_benchmark(
        events_count=events,
        workers=workers,
        input_file=input_file,
        sink_type=sink_type,
        raw_store_mode=raw_store_mode,
        output_dir=output_dir,
    )
    print_benchmark_report(res)


@main.command('crosswalk')
@click.option('--input', '-i', 'input_file', required=True, help='Path to UES normalized NDJSON file or event.')
@click.option('--to', 'target_schema', type=click.Choice(['ocsf', 'ecs']), default='ocsf', help='Target taxonomy schema.')
@click.option('--output', '-o', 'output_file', default=None, help='Output path for converted records (defaults to stdout).')
def crosswalk_cmd(input_file: str, target_schema: str, output_file: str | None) -> None:
    """Translate normalized UES events into OCSF or ECS standards."""
    from ulpf.crosswalk.ocsf import to_ocsf
    from ulpf.crosswalk.ecs import to_ecs

    in_path = Path(input_file)
    if not in_path.exists():
        click.echo(f"[!] Input file not found: {input_file}", err=True)
        sys.exit(1)

    out_fh = open(output_file, "w", encoding="utf-8") if output_file else sys.stdout
    count = 0
    try:
        with open(in_path, "r", encoding="utf-8", errors="replace") as in_fh:
            for line in in_fh:
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    event = json.loads(line_str)
                    if target_schema == "ocsf":
                        converted = to_ocsf(event)
                    else:
                        converted = to_ecs(event)
                    out_fh.write(json.dumps(converted) + "\n")
                    count += 1
                except Exception as e:
                    logger.warning(f"Failed converting event line: {e}")
        if output_file:
            click.echo(f"[+] Converted {count} events into {target_schema.upper()} format at {output_file}")
    finally:
        if output_file and out_fh:
            out_fh.close()


@main.group('sources')
def sources_grp() -> None:
    """Manage built-in and declarative log sources (list, add, test, infer, toggle)."""
    pass


@sources_grp.command('list')
@click.option('--output-dir', '-o', default='output', help='Output directory storing sources registry.')
def sources_list(output_dir: str) -> None:
    """List all registered log sources and their real-time telemetry."""
    from ulpf.core.source_manager import get_source_manager
    sm = get_source_manager(output_dir)
    sources = sm.list_sources()
    click.echo(f"Registered Log Sources ({len(sources)} total):")
    click.echo(f"{'Source ID':<22} {'Type':<12} {'Vendor':<18} {'Format':<14} {'Status':<10} {'Events':>8} {'EPS':>7}")
    click.echo("-" * 96)
    for s in sources:
        status_tag = "ENABLED" if s.get("enabled") else "DISABLED"
        s_type = s.get("source_type", "plugin")
        vendor = (s.get("vendor") or "Generic")[:17]
        fmt = (s.get("input_type") or "unknown")[:13]
        ev = s.get("events_processed", 0)
        eps = s.get("current_eps", 0.0)
        click.echo(f"{s['source_id']:<22} {s_type:<12} {vendor:<18} {fmt:<14} {status_tag:<10} {ev:>8} {eps:>7.1f}")


@sources_grp.command('infer')
@click.option('--sample', '-s', required=True, help='Raw sample log record to analyze.')
@click.option('--name', '-n', default='custom_source', help='Identifier name for the source.')
@click.option('--vendor', default='CustomVendor', help='Vendor name.')
@click.option('--product', default='CustomProduct', help='Product name.')
@click.option('--output', '-o', default=None, help='File path to write inferred YAML config.')
def sources_infer(sample: str, name: str, vendor: str, product: str, output: str | None) -> None:
    """Auto-detect format and generate draft declarative YAML mapping from a sample line."""
    import yaml
    from ulpf.core.declarative import infer_declarative_mapping
    draft = infer_declarative_mapping(sample, name=name, vendor=vendor, product=product)
    yaml_str = yaml.dump(draft, sort_keys=False)
    if output:
        Path(output).write_text(yaml_str, encoding='utf-8')
        click.echo(f"[+] Inferred declarative mapping written to: {output}")
    else:
        click.echo("--- Inferred Declarative YAML Configuration ---")
        click.echo(yaml_str)


@sources_grp.command('test')
@click.option('--config', '-c', required=True, help='Path to declarative source YAML config.')
@click.option('--sample', '-s', required=True, help='Raw sample log record to parse.')
def sources_test(config: str, sample: str) -> None:
    """Test parse and normalize a raw sample against a declarative YAML configuration."""
    import yaml
    from ulpf.core.declarative import DeclarativeSourceParser, validate_declarative_config
    cfg_path = Path(config)
    if not cfg_path.exists():
        click.echo(f"[!] Config file not found: {config}", err=True)
        sys.exit(1)
    with open(cfg_path, 'r', encoding='utf-8') as f:
        cfg = yaml.safe_load(f)
    valid, errors = validate_declarative_config(cfg)
    if not valid:
        click.echo(f"[!] Schema validation failed: {errors}", err=True)
        sys.exit(1)
    parser = DeclarativeSourceParser(cfg)
    matches = parser.match(sample)
    click.echo(f"Match status: {'[MATCHED]' if matches else '[NO MATCH]'}")
    try:
        extracted = parser.extract(sample)
        click.echo("\n--- Extracted Attributes ---")
        click.echo(json.dumps(extracted, indent=2, default=str))
        normalized = parser.build_normalized_event(extracted)
        click.echo("\n--- Normalized UES v1.2.0 Structure ---")
        click.echo(json.dumps(normalized, indent=2, default=str))
    except Exception as e:
        click.echo(f"[!] Parsing error: {e}", err=True)


@sources_grp.command('add')
@click.option('--config', '-c', required=True, help='Path to declarative YAML configuration.')
@click.option('--output-dir', '-o', default='output', help='Output directory.')
def sources_add(config: str, output_dir: str) -> None:
    """Register and activate a new declarative YAML log source."""
    import yaml
    from ulpf.core.source_manager import get_source_manager
    cfg_path = Path(config)
    if not cfg_path.exists():
        click.echo(f"[!] Config file not found: {config}", err=True)
        sys.exit(1)
    with open(cfg_path, 'r', encoding='utf-8') as f:
        cfg = yaml.safe_load(f)
    sm = get_source_manager(output_dir)
    success, errors, record = sm.register_declarative_source(cfg)
    if success:
        click.echo(f"[+] Source '{record['source_id']}' ({record['name']}) successfully registered and active!")
    else:
        click.echo(f"[!] Registration failed: {errors}", err=True)
        sys.exit(1)


@sources_grp.command('enable')
@click.argument('source_id')
@click.option('--output-dir', '-o', default='output', help='Output directory.')
def sources_enable(source_id: str, output_dir: str) -> None:
    """Enable a log source."""
    from ulpf.core.source_manager import get_source_manager
    sm = get_source_manager(output_dir)
    sm.set_source_enabled(source_id, True)
    click.echo(f"[+] Source '{source_id}' enabled.")


@sources_grp.command('disable')
@click.argument('source_id')
@click.option('--output-dir', '-o', default='output', help='Output directory.')
def sources_disable(source_id: str, output_dir: str) -> None:
    """Disable a log source."""
    from ulpf.core.source_manager import get_source_manager
    sm = get_source_manager(output_dir)
    sm.set_source_enabled(source_id, False)
    click.echo(f"[+] Source '{source_id}' disabled.")


def interactive_menu() -> None:
    """Interactive console menu for double-click launch or bare invocation."""
    while True:
        click.echo("")
        click.echo("======================================================================")
        click.echo("       Universal Log Pre-processing Framework (ULPF) v1.2.0")
        click.echo("======================================================================")
        click.echo("  [1] Launch Operations Dashboard (Web UI on http://127.0.0.1:8000)")
        click.echo("  [2] Start Dashboard in Background (Persistent)")
        click.echo("  [3] Check Dashboard Server Status")
        click.echo("  [4] Stop Dashboard Server")
        click.echo("  [5] Ingest Sample Logs into output/")
        click.echo("  [6] Run Anomaly Detection on output/events.ndjson")
        click.echo("  [7] List Registered Parser Plugins")
        click.echo("  [8] Show CLI Command Help")
        click.echo("  [0] Exit")
        click.echo("======================================================================")
        try:
            choice = click.prompt("Enter choice [0-8]", default="1")
        except (KeyboardInterrupt, EOFError):
            break

        if choice == "1":
            try:
                dashboard_cmd.callback(output_dir="output", port=8000, host="127.0.0.1", open_browser=True, background=False, stop=False, status=False)
            except KeyboardInterrupt:
                click.echo("\nDashboard stopped.")
                click.pause("Press any key to return to menu...")
        elif choice == "2":
            dashboard_cmd.callback(output_dir="output", port=8000, host="127.0.0.1", open_browser=True, background=True, stop=False, status=False)
            click.pause("\nPress any key to return to menu...")
        elif choice == "3":
            _get_dashboard_status("output", "127.0.0.1", 8000)
            click.pause("\nPress any key to return to menu...")
        elif choice == "4":
            _stop_dashboard_server("output", "127.0.0.1", 8000)
            click.pause("\nPress any key to return to menu...")
        elif choice == "5":
            sample_dir = _find_sample_logs_dir()
            if sample_dir:
                try:
                    ingest.callback(
                        input_path=str(sample_dir),
                        sink_type="ndjson",
                        output_dir="output",
                        config_path=None,
                        workers=1,
                        no_enrich=False,
                    )
                except Exception as e:
                    click.echo(f"Error during ingestion: {e}")
            else:
                click.echo("Sample logs directory not found.")
            click.pause("\nPress any key to return to menu...")
        elif choice == "6":
            try:
                analyze.callback(
                    input_path="output/events.ndjson",
                    output_path="output/anomalies.ndjson",
                    output_dir="output",
                )
            except Exception as e:
                click.echo(f"Error during analysis: {e}")
            click.pause("\nPress any key to return to menu...")
        elif choice == "7":
            list_parsers.callback()
            click.pause("\nPress any key to return to menu...")
        elif choice == "8":
            with click.Context(main) as ctx:
                click.echo(main.get_help(ctx))
            click.pause("\nPress any key to return to menu...")
        elif choice in ("0", "q", "exit"):
            break


def entry_point() -> None:
    """Main entry point supporting both CLI invocation and interactive double-click."""
    if len(sys.argv) == 1 and sys.stdin and sys.stdin.isatty():
        interactive_menu()
    else:
        main()


if __name__ == '__main__':
    entry_point()
