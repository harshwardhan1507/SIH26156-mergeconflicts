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

import logging
import sys
from pathlib import Path

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
) -> tuple[Pipeline, list, Validator]:
    """
    Build and return a configured Pipeline, sinks list, and Validator.
    sink_type may be a single name or a comma-separated list (e.g.
    'ndjson,parquet,cef-egress') to fan out every event to multiple sinks
    at once — the same normalized event, multiple SIEM/data-lake targets.
    """
    detector = FormatDetector(sources_config_path=cfg if cfg.exists() else None)
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
    output: Path, schema_dir: Path, cfg: Path, sink_type: str, enrich: bool,
) -> Pipeline:
    """
    Module-level (hence picklable) pipeline builder for ParallelPipeline workers.
    A closure defined inside a command function cannot be pickled across
    process boundaries — this must live at module scope, and be bound to its
    arguments via functools.partial (also picklable) at the call site.
    """
    pipeline, _sinks, _validator = _build_pipeline(output, schema_dir, cfg, sink_type, enrich)
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
@click.option('--config', '-c', 'config_path', default=None,
              help='Path to sources.yaml config file.')
@click.option('--workers', '-w', 'workers', default=1, type=int,
              help='Number of parallel worker processes (>1 enables ParallelPipeline).')
@click.option('--no-enrich', 'no_enrich', is_flag=True, default=False,
              help='Disable IP enrichment (faster, for benchmarking).')
@click.option('--tenant-id', 'tenant_id', default='default',
              help='Tenant identifier attached to every ingested event.')
def ingest(
    input_path: str, sink_type: str, output_dir: str,
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

    click.echo(f'Starting ingestion from {input_path!r} -> {output_dir!r} [{sink_type}]'
               + (f' [workers={workers}]' if workers > 1 else ''))

    if workers > 1:
        import functools
        from ulpf.core.worker_pool import ParallelPipeline

        # functools.partial over a MODULE-LEVEL function is picklable across
        # process boundaries (a closure defined here would not be) — this is
        # what makes --workers actually work instead of crashing.
        factory = functools.partial(
            _worker_pipeline_factory, output, schema_dir, cfg, sink_type, not no_enrich,
        )

        reader = FileReader(input_path) if input_path != '-' else StdinReader()
        parallel = ParallelPipeline(pipeline_factory=factory, num_workers=workers)
        stats = parallel.run(reader, tenant_id=tenant_id)
    else:
        pipeline, sinks, validator = _build_pipeline(
            output, schema_dir, cfg, sink_type, not no_enrich,
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


@main.command('dashboard')
@click.option('--output-dir', '-o', default='output', help='Path to pipeline output directory.')
@click.option('--port', '-p', default=8000, type=int, help='Port to bind the dashboard server.')
@click.option('--host', default='127.0.0.1', help='Host interface to bind.')
@click.option('--open-browser/--no-open-browser', default=True, help='Automatically open dashboard in default browser.')
def dashboard_cmd(output_dir: str, port: int, host: str, open_browser: bool) -> None:
    """Launch the interactive local web operations dashboard."""
    import threading
    import webbrowser
    import uvicorn
    from ulpf.dashboard.app import create_app, _resolve_output_dir

    resolved = _resolve_output_dir(output_dir)
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

    url = f"http://{host}:{port}"
    click.echo(f"============================================================")
    click.echo(f"  ULPF Operations Dashboard running at: {url}")
    click.echo(f"  Connected Output Directory: {resolved.resolve()}")
    click.echo(f"  Press Ctrl+C to stop the dashboard server.")
    click.echo(f"============================================================")

    if open_browser:
        def _launch_browser():
            import time
            time.sleep(1.0)
            webbrowser.open(url)
        threading.Thread(target=_launch_browser, daemon=True).start()

    app = create_app(resolved, host=host, port=port)
    uvicorn.run(app, host=host, port=port, log_level='info')


def interactive_menu() -> None:
    """Interactive console menu for double-click launch or bare invocation."""
    while True:
        click.echo("")
        click.echo("======================================================================")
        click.echo("       Universal Log Pre-processing Framework (ULPF) v1.2.0")
        click.echo("======================================================================")
        click.echo("  [1] Launch Operations Dashboard (Web UI on http://127.0.0.1:8000)")
        click.echo("  [2] Ingest Sample Logs into output/")
        click.echo("  [3] Run Anomaly Detection on output/events.ndjson")
        click.echo("  [4] List Registered Parser Plugins")
        click.echo("  [5] Show CLI Command Help")
        click.echo("  [0] Exit")
        click.echo("======================================================================")
        try:
            choice = click.prompt("Enter choice [0-5]", default="1")
        except (KeyboardInterrupt, EOFError):
            break

        if choice == "1":
            try:
                dashboard_cmd.callback(output_dir="output", port=8000, host="127.0.0.1", open_browser=True)
            except KeyboardInterrupt:
                click.echo("\nDashboard stopped.")
                click.pause("Press any key to return to menu...")
        elif choice == "2":
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
        elif choice == "3":
            try:
                analyze.callback(
                    input_path="output/events.ndjson",
                    output_path="output/anomalies.ndjson",
                    output_dir="output",
                )
            except Exception as e:
                click.echo(f"Error during analysis: {e}")
            click.pause("\nPress any key to return to menu...")
        elif choice == "4":
            list_parsers.callback()
            click.pause("\nPress any key to return to menu...")
        elif choice == "5":
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
