"""
ULPF command line interface.

Covers the framework only: ingestion, live collection, analysis, forensic
lookup, crosswalk translation, benchmarking, and source management. The web
dashboard is a separate distribution with its own ``ulpf-dashboard`` entry
point; ``ulpf dashboard`` here is a convenience shim that delegates to it if it
is installed. Nothing in this module imports the dashboard at module scope, so
the framework runs with no web stack present.
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import click

import ulpf
from ulpf import resources
from ulpf.core.ingestion import FileReader, StdinReader
from ulpf.core.registry import list_parser_names
from ulpf.runtime import RAW_STORE_NAMES, SINK_NAMES, PipelineConfig, build_session

logger = logging.getLogger(__name__)

_SINK_HELP = "Output sink(s), comma-separated: " + ", ".join(SINK_NAMES)


def _reader(input_path: str):
    """Return the reader for an input path, or stdin when the path is ``-``."""
    return StdinReader() if input_path == "-" else FileReader(input_path)


def _example_logs_dir() -> Path | None:
    """Locate bundled example logs, if this checkout or install ships them."""
    for candidate in (
        Path.cwd() / "examples" / "sample_logs",
        Path(__file__).resolve().parents[2] / "examples" / "sample_logs",
        Path("/app/sample_logs"),
    ):
        if candidate.is_dir() and any(candidate.iterdir()):
            return candidate
    return None


@click.group()
@click.version_option(ulpf.__version__, prog_name="ulpf")
@click.option("--log-level", default="INFO",
              type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
              help="Logging verbosity.")
def main(log_level: str) -> None:
    """Universal Log Pre-processing Framework (ULPF)."""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    ulpf.bootstrap()


@main.command()
@click.option("--input", "-i", "input_path", default="-",
              help='Input file or directory, or "-" for stdin.')
@click.option("--sink", "-s", "sink_type", default="ndjson", help=_SINK_HELP)
@click.option("--output", "-o", "output_dir", default="output",
              help="Output directory for normalized events and the raw store.")
@click.option("--raw-store", "raw_store_type", default="file",
              type=click.Choice(RAW_STORE_NAMES, case_sensitive=False),
              help='Raw storage engine: "file" (one forensic file per event) or '
                   '"segmented" (chunked segments with a SQLite offset index).')
@click.option("--config", "-c", "config_path", default=None, help="Path to a sources.yaml file.")
@click.option("--workers", "-w", default=1, type=int,
              help="Parallel worker processes (>1 enables the multiprocess pipeline).")
@click.option("--no-enrich", is_flag=True, default=False,
              help="Disable IP enrichment (faster; useful for benchmarking).")
@click.option("--telemetry", is_flag=True, default=False,
              help="Record per-source counters into the SQLite source registry.")
@click.option("--tenant-id", default="default", help="Tenant attached to every ingested event.")
def ingest(
    input_path: str,
    sink_type: str,
    output_dir: str,
    raw_store_type: str,
    config_path: str | None,
    workers: int,
    no_enrich: bool,
    telemetry: bool,
    tenant_id: str,
) -> None:
    """Ingest raw logs and produce normalized UES events."""
    try:
        config = PipelineConfig.from_options(
            output_dir=output_dir,
            sinks=sink_type,
            raw_store=raw_store_type,
            enrich=not no_enrich,
            sources_config=config_path,
            telemetry=telemetry,
        )
    except ValueError as exc:
        raise click.BadParameter(str(exc), param_hint="--sink") from exc

    click.echo(
        f"Ingesting {input_path!r} -> {output_dir!r} [{sink_type}] "
        f"(raw_store={raw_store_type}" + (f", workers={workers}" if workers > 1 else "") + ")"
    )

    if workers > 1:
        import functools

        from ulpf.core.worker_pool import ParallelPipeline
        from ulpf.runtime import worker_pipeline_factory

        # functools.partial over a module-level function is picklable; a closure
        # defined here would not be, and the pool would fail at dispatch.
        factory = functools.partial(worker_pipeline_factory, config)
        stats = ParallelPipeline(pipeline_factory=factory, num_workers=workers).run(
            _reader(input_path), tenant_id=tenant_id
        )
    else:
        with build_session(config=config) as session:
            stats = session.run(_reader(input_path), tenant_id=tenant_id)

    click.echo(
        f"Done. Processed={stats['processed']} Valid={stats['valid']} "
        f"Invalid={stats['invalid']} Errors={stats['errors']}"
    )
    if stats["errors"]:
        click.echo(
            f"See {Path(output_dir) / 'dead_letter.ndjson'} for the quarantined events.",
            err=True,
        )


@main.command()
@click.option("--input", "-i", "input_path", default="output/events.ndjson",
              help="Normalized events NDJSON file to analyze.")
@click.option("--output", "-o", "output_path", default=None,
              help="Where to write anomalous events (optional).")
@click.option("--output-dir", default="output", help="Directory used for baseline persistence.")
@click.option("--emit-features", is_flag=True, default=False,
              help="Also write a 24-dimension feature vector per event to features.ndjson.")
def analyze(input_path: str, output_path: str | None, output_dir: str, emit_features: bool) -> None:
    """Run statistical anomaly detection over normalized events."""
    from ulpf.analytics.anomaly import AnomalyDetector

    events_file = Path(input_path)
    if not events_file.exists():
        raise click.FileError(str(events_file), hint="events file not found")

    click.echo(f"Analyzing {events_file} for anomalies...")
    out_path = Path(output_path) if output_path else None
    result = AnomalyDetector(output_dir=output_dir).analyze_file(
        ndjson_path=events_file, output_path=out_path
    )
    click.echo(
        f"Done. Total={result['total_events']} Anomalous={result['anomalous_events']} "
        f"Rate={result['anomaly_rate_pct']}%"
    )
    if out_path:
        click.echo(f"Anomalous events written to: {out_path}")

    if emit_features:
        from ulpf.analytics.features import FeatureVectorExtractor

        features_path = Path(output_dir) / "features.ndjson"
        names = FeatureVectorExtractor.get_feature_names()
        written = 0
        with open(events_file, encoding="utf-8", errors="replace") as fin, \
             open(features_path, "w", encoding="utf-8") as fout:
            for line in fin:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                fout.write(json.dumps({
                    "event_id": event.get("event_id"),
                    "features": FeatureVectorExtractor.extract_vector(event),
                    "feature_names": names,
                }) + "\n")
                written += 1
        click.echo(f"Wrote {written} feature vectors to: {features_path}")


@main.command("listen")
@click.option("--host", default="127.0.0.1",
              help="Interface to bind. Defaults to loopback; use 0.0.0.0 only on a trusted network.")
@click.option("--port", "-p", default=1514, type=int,
              help="UDP and TCP port to listen on (514 requires root/admin).")
@click.option("--output", "-o", "output_dir", default="output", help="Output directory.")
@click.option("--sink", "-s", "sink_type", default="ndjson", help=_SINK_HELP)
@click.option("--config", "-c", "config_path", default=None, help="Path to a sources.yaml file.")
@click.option("--raw-store", "raw_store_type", default="file",
              type=click.Choice(RAW_STORE_NAMES, case_sensitive=False), help="Raw storage engine.")
@click.option("--no-enrich", is_flag=True, default=False, help="Disable IP enrichment.")
@click.option("--tenant-id", default="default", help="Tenant attached to every ingested event.")
def listen_cmd(
    host: str,
    port: int,
    output_dir: str,
    sink_type: str,
    config_path: str | None,
    raw_store_type: str,
    no_enrich: bool,
    tenant_id: str,
) -> None:
    """Receive live syslog over UDP and TCP straight into the pipeline."""
    import time

    from ulpf.collectors.syslog_listener import SyslogNetworkListener

    with build_session(
        output_dir=output_dir,
        sinks=sink_type,
        raw_store=raw_store_type,
        enrich=not no_enrich,
        sources_config=config_path,
    ) as session:

        def on_event(line: str, source_tag: str) -> None:
            try:
                session.process_event(raw_line=line, source_tag=source_tag, tenant_id=tenant_id)
            except Exception as exc:
                logger.warning("listen: failed to process event: %s", exc)

        listener = SyslogNetworkListener(on_event=on_event, host=host, port=port)
        listener.start()

        click.echo("=" * 60)
        click.echo(f"  ULPF syslog listener (UDP + TCP) on {host}:{port}")
        click.echo(f"  Output: {Path(output_dir).resolve()}  Sink(s): {sink_type}")
        click.echo("  Press Ctrl+C to stop.")
        click.echo("=" * 60)

        try:
            last = 0
            while True:
                time.sleep(2.0)
                session.flush()
                stats = listener.get_stats()
                received = stats.get("packets_received", 0)
                if received != last:
                    session_stats = session.stats()
                    click.echo(
                        f"[*] {received} packets received "
                        f"({session_stats['processed']} processed, "
                        f"{session_stats['errors']} errors, "
                        f"{stats.get('packets_dropped', 0)} dropped)"
                    )
                    last = received
        except KeyboardInterrupt:
            click.echo("\nStopping syslog listener...")
        finally:
            listener.stop()
            click.echo("Syslog listener stopped.")


@main.command()
@click.option("--event-id", "-e", required=True, help="UUID of the event to look up.")
@click.option("--raw-store", "raw_store_dir", default="output/raw_store",
              help="Path to the raw store directory.")
@click.option("--segmented", is_flag=True, default=False,
              help="Read from a segmented raw store instead of a file raw store.")
def lookup(event_id: str, raw_store_dir: str, segmented: bool) -> None:
    """Retrieve the original raw payload for an event UUID."""
    from ulpf.core.raw_store import RawStoreBase

    store: RawStoreBase
    if segmented:
        from ulpf.core.segmented_raw_store import SegmentedRawStore

        store = SegmentedRawStore(raw_store_dir)
    else:
        from ulpf.core.raw_store import FileRawStore

        store = FileRawStore(raw_store_dir)

    payload = store.get(event_id)
    store.close()
    if payload is None:
        click.echo(f"Event {event_id!r} not found in raw store.", err=True)
        sys.exit(1)
    click.echo(payload)


@main.command("list-parsers")
def list_parsers() -> None:
    """List every registered parser plugin and declarative source."""
    names = list_parser_names()
    if not names:
        click.echo("No parsers registered.")
        return
    click.echo(f"Registered parsers ({len(names)}):")
    for name in names:
        click.echo(f"  - {name}")


@main.command("monitor")
@click.option("--output", "-o", default="output", help="Output directory for captured events.")
@click.option("--interval-ms", "-i", default=250, type=int, help="Polling interval in milliseconds.")
def monitor_cmd(output: str, interval_ms: int) -> None:
    """Monitor local OS events, process executions, and network connections."""
    import time

    from ulpf.collectors.live_monitor import LiveSystemMonitor

    click.echo("=" * 60)
    click.echo(f"  ULPF live host monitor ({interval_ms}ms)")
    click.echo(f"  Output: {Path(output).resolve()}")
    click.echo("  Press Ctrl+C to stop.")
    click.echo("=" * 60)

    monitor = LiveSystemMonitor(output_dir=output, interval_ms=interval_ms)
    monitor.start()
    try:
        last = 0
        while True:
            time.sleep(1.0)
            stats = monitor.get_stats()
            captured = stats.get("events_captured", 0)
            click.echo(
                f"[*] {captured} events captured (+{captured - last}/s) | "
                f"{stats.get('tracked_processes', 0)} processes tracked"
            )
            last = captured
    except KeyboardInterrupt:
        click.echo("\nStopping live monitor...")
    finally:
        monitor.stop()


@main.command("benchmark")
@click.option("--events", "-n", default=10000, type=int, help="Number of events to process.")
@click.option("--workers", "-w", default=1, type=int, help="Worker processes.")
@click.option("--input", "-i", "input_file", default=None, help="Log file to benchmark against.")
@click.option("--sink", "-s", "sink_type", type=click.Choice(["none", "ndjson"]), default="none")
@click.option("--raw-store", "-r", "raw_store_mode",
              type=click.Choice(["none", "file", "segmented"]), default="none")
@click.option("--output-dir", "-o", default="benchmark_output", help="Benchmark output directory.")
def benchmark_cmd(
    events: int, workers: int, input_file: str | None,
    sink_type: str, raw_store_mode: str, output_dir: str,
) -> None:
    """Measure sustained throughput (events/sec) and bandwidth."""
    from ulpf.tools.benchmark import print_benchmark_report, run_benchmark

    click.echo(
        f"[*] Benchmarking {events:,} events "
        f"(workers={workers}, sink={sink_type}, raw_store={raw_store_mode})..."
    )
    print_benchmark_report(
        run_benchmark(
            events_count=events, workers=workers, input_file=input_file,
            sink_type=sink_type, raw_store_mode=raw_store_mode, output_dir=output_dir,
        )
    )


@main.command("crosswalk")
@click.option("--input", "-i", "input_file", required=True,
              help="Normalized UES NDJSON file to translate.")
@click.option("--to", "target_schema", type=click.Choice(["ocsf", "ecs"]), default="ocsf",
              help="Target taxonomy.")
@click.option("--output", "-o", "output_file", default=None,
              help="Where to write converted records (defaults to stdout).")
def crosswalk_cmd(input_file: str, target_schema: str, output_file: str | None) -> None:
    """Translate normalized UES events into OCSF or ECS."""
    from ulpf.crosswalk.ecs import to_ecs
    from ulpf.crosswalk.ocsf import to_ocsf

    in_path = Path(input_file)
    if not in_path.exists():
        raise click.FileError(input_file, hint="input file not found")

    convert = to_ocsf if target_schema == "ocsf" else to_ecs
    out_fh = open(output_file, "w", encoding="utf-8") if output_file else sys.stdout
    converted = failed = 0
    try:
        with open(in_path, encoding="utf-8", errors="replace") as in_fh:
            for line_no, line in enumerate(in_fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    out_fh.write(json.dumps(convert(json.loads(line))) + "\n")
                    converted += 1
                except Exception as exc:
                    failed += 1
                    logger.warning("Line %d: conversion failed: %s", line_no, exc)
    finally:
        if output_file:
            out_fh.close()

    if output_file:
        click.echo(f"[+] Converted {converted} events to {target_schema.upper()}: {output_file}")
    if failed:
        click.echo(f"[!] {failed} event(s) could not be converted.", err=True)


@main.group("sources")
def sources_grp() -> None:
    """Manage built-in and declarative (no-code) log sources."""


@sources_grp.command("list")
@click.option("--output-dir", "-o", default="output", help="Output directory holding the registry.")
def sources_list(output_dir: str) -> None:
    """List registered log sources with their telemetry."""
    from ulpf.core.source_manager import get_source_manager

    manager = get_source_manager(output_dir)
    sources = manager.list_sources()
    click.echo(f"Registered log sources ({len(sources)}):")
    click.echo(
        f"{'Source ID':<22} {'Type':<12} {'Vendor':<18} "
        f"{'Format':<14} {'Status':<10} {'Events':>8} {'EPS':>7}"
    )
    click.echo("-" * 96)
    for source in sources:
        click.echo(
            f"{source['source_id']:<22} {source.get('source_type', 'plugin'):<12} "
            f"{(source.get('vendor') or 'Generic')[:17]:<18} "
            f"{(source.get('input_type') or 'unknown')[:13]:<14} "
            f"{('ENABLED' if source.get('enabled') else 'DISABLED'):<10} "
            f"{source.get('events_processed', 0):>8} {source.get('current_eps', 0.0):>7.1f}"
        )


@sources_grp.command("infer")
@click.option("--sample", "-s", required=True, help="Raw sample log record to analyze.")
@click.option("--name", "-n", default="custom_source", help="Identifier for the new source.")
@click.option("--vendor", default="CustomVendor", help="Vendor name.")
@click.option("--product", default="CustomProduct", help="Product name.")
@click.option("--output", "-o", default=None, help="Write the inferred YAML here.")
def sources_infer(sample: str, name: str, vendor: str, product: str, output: str | None) -> None:
    """Infer a draft declarative YAML mapping from one sample line."""
    import yaml

    from ulpf.core.declarative import infer_declarative_mapping

    draft = yaml.dump(
        infer_declarative_mapping(sample, name=name, vendor=vendor, product=product),
        sort_keys=False,
    )
    if output:
        Path(output).write_text(draft, encoding="utf-8")
        click.echo(f"[+] Inferred declarative mapping written to: {output}")
    else:
        click.echo(draft)


@sources_grp.command("test")
@click.option("--config", "-c", required=True, help="Declarative source YAML to test.")
@click.option("--sample", "-s", required=True, help="Raw sample log record to parse.")
def sources_test(config: str, sample: str) -> None:
    """Parse and normalize a sample against a declarative configuration."""
    import yaml

    from ulpf.core.declarative import DeclarativeSourceParser, validate_declarative_config

    cfg_path = Path(config)
    if not cfg_path.exists():
        raise click.FileError(config, hint="config file not found")

    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    valid, errors = validate_declarative_config(cfg)
    if not valid:
        click.echo(f"[!] Schema validation failed: {errors}", err=True)
        sys.exit(1)

    parser = DeclarativeSourceParser(cfg)
    click.echo(f"Match status: {'[MATCHED]' if parser.match(sample) else '[NO MATCH]'}")
    try:
        extracted = parser.extract(sample)
    except Exception as exc:
        click.echo(f"[!] Parsing error: {exc}", err=True)
        sys.exit(1)

    click.echo("\n--- Extracted attributes ---")
    click.echo(json.dumps(extracted, indent=2, default=str))
    click.echo("\n--- Normalized UES structure ---")
    click.echo(json.dumps(parser.build_normalized_event(extracted), indent=2, default=str))


@sources_grp.command("add")
@click.option("--config", "-c", required=True, help="Declarative YAML configuration to register.")
@click.option("--output-dir", "-o", default="output", help="Output directory.")
def sources_add(config: str, output_dir: str) -> None:
    """Register and activate a new declarative log source."""
    import yaml

    from ulpf.core.source_manager import get_source_manager

    cfg_path = Path(config)
    if not cfg_path.exists():
        raise click.FileError(config, hint="config file not found")

    ok, errors, record = get_source_manager(output_dir).register_declarative_source(
        yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    )
    if not ok or record is None:
        click.echo(f"[!] Registration failed: {errors}", err=True)
        sys.exit(1)
    click.echo(f"[+] Source {record['source_id']!r} registered and active.")
    click.echo(f"    Stored in: {resources.user_declarative_sources_dir()}")


@sources_grp.command("enable")
@click.argument("source_id")
@click.option("--output-dir", "-o", default="output", help="Output directory.")
def sources_enable(source_id: str, output_dir: str) -> None:
    """Enable a log source."""
    from ulpf.core.source_manager import get_source_manager

    get_source_manager(output_dir).set_source_enabled(source_id, True)
    click.echo(f"[+] Source {source_id!r} enabled.")


@sources_grp.command("disable")
@click.argument("source_id")
@click.option("--output-dir", "-o", default="output", help="Output directory.")
def sources_disable(source_id: str, output_dir: str) -> None:
    """Disable a log source."""
    from ulpf.core.source_manager import get_source_manager

    get_source_manager(output_dir).set_source_enabled(source_id, False)
    click.echo(f"[+] Source {source_id!r} disabled.")


@main.command(
    "dashboard",
    context_settings={"ignore_unknown_options": True, "help_option_names": []},
    add_help_option=False,
)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def dashboard_cmd(args: tuple[str, ...]) -> None:
    """
    Launch the operations dashboard (requires the optional dashboard extra).

    The import is deferred to call time so that the framework neither depends on
    nor imports a web stack. All arguments are forwarded to ``ulpf-dashboard``.
    """
    try:
        from ulpf_dashboard.server import main as dashboard_main
    except ImportError as exc:
        click.echo(
            f"The dashboard's dependencies are not installed ({exc}).\n"
            'Install them with:  pip install "ulpf[dashboard]"',
            err=True,
        )
        sys.exit(1)
    dashboard_main.main(args=list(args), standalone_mode=True)


@main.command("info")
def info_cmd() -> None:
    """Show versions, resource locations, and registered parser counts."""
    # Report whether the dashboard can actually run, not merely whether its
    # code shipped: the extra gates dependencies, not the package itself.
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401

        from ulpf_dashboard import __version__ as dashboard_version
    except ImportError:
        dashboard_version = 'not available (pip install "ulpf[dashboard]")'

    click.echo(f"ULPF framework:   {ulpf.__version__}")
    click.echo(f"UES schema:       {ulpf.__schema_version__}")
    click.echo(f"Dashboard:        {dashboard_version}")
    click.echo(f"Registered parsers: {ulpf.parser_count()}")
    click.echo(f"Schemas:          {resources.schemas_dir()}")
    click.echo(f"User data:        {resources.user_data_dir()}")
    click.echo(f"User sources:     {resources.user_declarative_sources_dir()}")


if __name__ == "__main__":
    main()
