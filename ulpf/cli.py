"""
ULPF Command Line Interface.

Usage:
  ulpf ingest --input <path> [--sink ndjson|kafka] [--output <dir>] [--config <path>]
  ulpf lookup --event-id <uuid> [--raw-store <dir>]
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


@click.group()
@click.option('--log-level', default='INFO',
              type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR'], case_sensitive=False),
              help='Logging verbosity.')
def main(log_level: str) -> None:
    """Universal Log Pre-processing Framework (ULPF)"""
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s %(levelname)-8s %(name)s: %(message)s',
    )


@main.command()
@click.option('--input', '-i', 'input_path', default='-',
              help='Input file/directory path, or "-" for stdin.')
@click.option('--sink', '-s', 'sink_type', default='ndjson',
              type=click.Choice(['ndjson', 'kafka'], case_sensitive=False),
              help='Output sink type.')
@click.option('--output', '-o', 'output_dir', default='output',
              help='Output directory for normalized events and raw store.')
@click.option('--config', '-c', 'config_path', default=None,
              help='Path to sources.yaml config file.')
def ingest(input_path: str, sink_type: str, output_dir: str, config_path: str | None) -> None:
    """Ingest raw log files/stdin and produce normalized UES events."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    schema_dir = _find_schema_dir()
    cfg = Path(config_path) if config_path else _find_config_dir() / 'sources.yaml'

    # Build components
    detector = FormatDetector(sources_config_path=cfg if cfg.exists() else None)
    raw_store = FileRawStore(output / 'raw_store')
    norm_engine = NormalizationEngine(schema_dir / 'mappings')
    validator = Validator(
        schema_path=schema_dir / 'ues_schema.json',
        dead_letter_path=output / 'dead_letter.ndjson',
    )
    enrichment = NoOpEnrichment()

    if sink_type == 'ndjson':
        sinks = [NDJSONFileSink(output / 'events.ndjson')]
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

    # Build reader
    if input_path == '-':
        reader = StdinReader()
    else:
        reader = FileReader(input_path)

    click.echo(f'Starting ingestion from {input_path!r} -> {output_dir!r} [{sink_type}]')
    stats = pipeline.run(reader)

    validator.close()
    for sink in sinks:
        sink.close()

    click.echo(f'Done. Processed={stats["processed"]} Valid={stats["valid"]} '
               f'Invalid={stats["invalid"]} Errors={stats["errors"]}')


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
        click.echo('Registered parsers:')
        for name in names:
            click.echo(f'  - {name}')


if __name__ == '__main__':
    main()
