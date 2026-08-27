"""
ULPF Command Line Interface.

Usage:
  ulpf ingest --input <path> [--sink ndjson|kafka|kafka-real] [--output <dir>] [--workers N]
  ulpf analyze --input output/events.ndjson [--output output/anomalies.ndjson]
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


def _build_pipeline(
    output: Path,
    schema_dir: Path,
    cfg: Path,
    sink_type: str,
    enrich: bool = True,
) -> tuple[Pipeline, list, Validator]:
    """Build and return a configured Pipeline, sinks list, and Validator."""
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

    if sink_type == 'ndjson':
        sinks = [NDJSONFileSink(output / 'events.ndjson')]
    elif sink_type == 'kafka-real':
        from ulpf.sinks.kafka_producer import KafkaProducerSink
        sinks = [KafkaProducerSink(
            topic='ulpf.events',
            bootstrap_servers='localhost:9092',
            fallback_path=output / 'kafka_events.ndjson',
        )]
    else:
        sinks = [KafkaStubSink(output / 'kafka_events.ndjson')]

    pipeline = Pipeline(
        detector=detector,
        raw_store=raw_store,
        normalization_engine=norm_engine,
        validator=validator,
        sinks=sinks,
        enrichment=enrichment,
    )
    return pipeline, sinks, validator


@click.group()
@click.option('--log-level', default='INFO',
              type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR'], case_sensitive=False),
              help='Logging verbosity.')
def main(log_level: str) -> None:
    """Universal Log Pre-processing Framework (ULPF) v1.1.0"""
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s %(levelname)-8s %(name)s: %(message)s',
    )


@main.command()
@click.option('--input', '-i', 'input_path', default='-',
              help='Input file/directory path, or "-" for stdin.')
@click.option('--sink', '-s', 'sink_type', default='ndjson',
              type=click.Choice(['ndjson', 'kafka', 'kafka-real'], case_sensitive=False),
              help='Output sink type (kafka-real requires kafka-python installed).')
@click.option('--output', '-o', 'output_dir', default='output',
              help='Output directory for normalized events and raw store.')
@click.option('--config', '-c', 'config_path', default=None,
              help='Path to sources.yaml config file.')
@click.option('--workers', '-w', 'workers', default=1, type=int,
              help='Number of parallel worker processes (>1 enables ParallelPipeline).')
@click.option('--no-enrich', 'no_enrich', is_flag=True, default=False,
              help='Disable IP enrichment (faster, for benchmarking).')
def ingest(
    input_path: str, sink_type: str, output_dir: str,
    config_path: str | None, workers: int, no_enrich: bool,
) -> None:
    """Ingest raw log files/stdin and produce normalized UES events."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    schema_dir = _find_schema_dir()
    cfg = Path(config_path) if config_path else _find_config_dir() / 'sources.yaml'

    click.echo(f'Starting ingestion from {input_path!r} -> {output_dir!r} [{sink_type}]'
               + (f' [workers={workers}]' if workers > 1 else ''))

    if workers > 1:
        from ulpf.core.worker_pool import ParallelPipeline

        def factory():
            p, _, __ = _build_pipeline(output, schema_dir, cfg, sink_type, not no_enrich)
            return p

        reader = FileReader(input_path) if input_path != '-' else StdinReader()
        parallel = ParallelPipeline(pipeline_factory=factory, num_workers=workers)
        stats = parallel.run(reader)
    else:
        pipeline, sinks, validator = _build_pipeline(
            output, schema_dir, cfg, sink_type, not no_enrich,
        )
        reader = FileReader(input_path) if input_path != '-' else StdinReader()
        stats = pipeline.run(reader)
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
def analyze(input_path: str, output_path: str | None, output_dir: str) -> None:
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


def _find_sample_logs_dir() -> Path | None:
    """Find bundled or repository sample_logs directory."""
    candidates = []
    if hasattr(sys, "_MEIPASS"):
        candidates.append(Path(sys._MEIPASS) / "ulpf" / "sample_logs")
        candidates.append(Path(sys._MEIPASS) / "sample_logs")
    candidates.extend([
        Path(__file__).parent / "sample_logs",
        Path(__file__).parent.parent / "sample_logs",
        Path.cwd() / "ulpf" / "sample_logs",
        Path.cwd() / "sample_logs",
    ])
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

    app = create_app(resolved)
    uvicorn.run(app, host=host, port=port, log_level='info')


def interactive_menu() -> None:
    """Interactive console menu for double-click launch or bare invocation."""
    while True:
        click.echo("")
        click.echo("======================================================================")
        click.echo("       Universal Log Pre-processing Framework (ULPF) v1.1.0")
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
