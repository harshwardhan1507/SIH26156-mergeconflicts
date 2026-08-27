"""
End-to-End test: raw sample_logs/ files → validated normalized output + raw lookup.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import jsonschema
import pytest

import ulpf.parsers  # noqa
from ulpf.core.detector import FormatDetector
from ulpf.core.ingestion import FileReader
from ulpf.core.normalization import NormalizationEngine
from ulpf.core.pipeline import Pipeline
from ulpf.core.raw_store import FileRawStore
from ulpf.core.validation import Validator
from ulpf.enrichment.noop import NoOpEnrichment
from ulpf.sinks.ndjson_file import NDJSONFileSink

_SAMPLE_LOGS = Path(__file__).parent.parent / 'sample_logs'
_SCHEMA_DIR = Path(__file__).parent.parent / 'schemas'


@pytest.fixture(scope='module')
def pipeline_output():
    """Run the full pipeline against sample_logs/ and return (output_dir, stats)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        raw_store_dir = tmp / 'raw_store'
        output_file = tmp / 'events.ndjson'
        dl_file = tmp / 'dead_letter.ndjson'

        detector = FormatDetector()
        raw_store = FileRawStore(raw_store_dir)
        norm_engine = NormalizationEngine(_SCHEMA_DIR / 'mappings')
        validator = Validator(_SCHEMA_DIR / 'ues_schema.json', dl_file)
        sink = NDJSONFileSink(output_file)

        pipeline = Pipeline(
            detector=detector,
            raw_store=raw_store,
            normalization_engine=norm_engine,
            validator=validator,
            sinks=[sink],
            enrichment=NoOpEnrichment(),
        )

        reader = FileReader(_SAMPLE_LOGS)
        stats = pipeline.run(reader)

        validator.close()
        sink.close()

        # Read output
        events = []
        if output_file.exists():
            with open(output_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        events.append(json.loads(line))

        dead_letter = []
        if dl_file.exists():
            with open(dl_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        dead_letter.append(json.loads(line))

        yield {
            'stats': stats,
            'events': events,
            'dead_letter': dead_letter,
            'raw_store': raw_store,
        }


def test_pipeline_processes_events(pipeline_output):
    """Pipeline must process at least one event per sample log file."""
    assert pipeline_output['stats']['processed'] > 0, 'No events were processed'


def test_all_events_have_required_fields(pipeline_output):
    """Every normalized event must have the required UES top-level fields."""
    required = {'event_id', 'ingest_timestamp', 'raw', 'source', 'event', 'lineage'}
    for ev in pipeline_output['events']:
        missing = required - ev.keys()
        assert not missing, f"Event missing fields: {missing}. Event: {ev.get('event_id')}"


def test_all_events_schema_valid(pipeline_output):
    """Every normalized event must validate against the UES JSON Schema."""
    schema_path = _SCHEMA_DIR / 'ues_schema.json'
    with open(schema_path) as f:
        schema = json.load(f)
    validator = jsonschema.Draft7Validator(schema)

    for ev in pipeline_output['events']:
        errors = list(validator.iter_errors(ev))
        assert not errors, (
            f"Event {ev.get('event_id')} schema errors: "
            + '; '.join(f'{e.json_path}: {e.message}' for e in errors)
        )


def test_raw_store_lookup(pipeline_output):
    """For every normalized event, raw_store.get(event_id) must return the original raw line."""
    raw_store = pipeline_output['raw_store']
    for ev in pipeline_output['events']:
        event_id = ev['event_id']
        raw_payload_from_event = ev['raw']['raw_payload']
        raw_payload_from_store = raw_store.get(event_id)
        assert raw_payload_from_store is not None, f'Raw not found for {event_id}'
        assert raw_payload_from_store == raw_payload_from_event, (
            f'Raw mismatch for {event_id}'
        )


def test_raw_hash_matches_payload(pipeline_output):
    """SHA256 hash in every event must match the raw payload."""
    import hashlib
    for ev in pipeline_output['events']:
        payload = ev['raw']['raw_payload']
        expected_hash = hashlib.sha256(payload.encode('utf-8', errors='surrogateescape')).hexdigest()
        assert ev['raw']['raw_hash'] == expected_hash, (
            f"Hash mismatch for event {ev.get('event_id')}"
        )


def test_lineage_present(pipeline_output):
    """Every event must carry full lineage info."""
    for ev in pipeline_output['events']:
        lineage = ev.get('lineage', {})
        assert lineage.get('parser_name'), f"Missing parser_name in lineage for {ev.get('event_id')}"
        assert lineage.get('parser_version'), f"Missing parser_version for {ev.get('event_id')}"


def test_dead_letter_format(pipeline_output):
    """Dead-letter entries (if any) must have the correct structure."""
    for dl in pipeline_output['dead_letter']:
        assert 'event_id' in dl
        assert 'errors' in dl
        assert isinstance(dl['errors'], list)


def test_parsers_from_all_source_types(pipeline_output):
    """Events from all 5 parser types must appear in output."""
    parser_names_seen = {ev['lineage']['parser_name'] for ev in pipeline_output['events']}
    expected = {'syslog_rfc5424', 'syslog_rfc3164', 'cef', 'cisco_asa', 'paloalto_csv', 'json_passthrough'}
    missing = expected - parser_names_seen
    assert not missing, f'Missing events from parsers: {missing}'
