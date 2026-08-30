"""
Tests for Multi-Tenancy Scoping, API Auth, and Dead-Letter Diagnostics.
"""
from __future__ import annotations

import json

from fastapi.testclient import TestClient

from ulpf import resources
from ulpf.core.detector import FormatDetector
from ulpf.core.normalization import NormalizationEngine
from ulpf.core.pipeline import Pipeline
from ulpf.core.raw_store import FileRawStore
from ulpf.core.validation import Validator
from ulpf.sinks.ndjson_file import NDJSONFileSink
from ulpf_dashboard.app import create_app
from ulpf_dashboard.indexer import EventIndexer


def test_tenancy_isolation_and_scoping(tmp_path):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    resources.schemas_dir()

    detector = FormatDetector()
    raw_store = FileRawStore(output_dir / "raw_store")
    norm_engine = NormalizationEngine(resources.mappings_dir())
    validator = Validator(schema_path=resources.ues_schema_path(), dead_letter_path=output_dir / "dead_letter.ndjson")
    sink = NDJSONFileSink(output_dir / "events.ndjson")

    pipeline = Pipeline(
        detector=detector,
        raw_store=raw_store,
        normalization_engine=norm_engine,
        validator=validator,
        sinks=[sink],
    )

    # Process events for two different tenants
    pipeline.process_event(
        raw_line='<134>1 2024-03-15T10:22:45Z host1 sshd 1234 - - Tenant Alpha Event',
        source_tag="syslog",
        tenant_id="tenant_alpha"
    )
    pipeline.process_event(
        raw_line='<134>1 2024-03-15T10:22:46Z host2 sshd 1234 - - Tenant Beta Event',
        source_tag="syslog",
        tenant_id="tenant_beta"
    )

    sink.close()
    validator.close()

    # Index events
    indexer = EventIndexer(output_dir=output_dir)
    count = indexer.sync_from_ndjson()
    assert count == 2

    # Query tenant_alpha
    res_alpha = indexer.query_events(tenant_id="tenant_alpha")
    assert res_alpha["total"] == 1
    assert res_alpha["events"][0]["tenant_id"] == "tenant_alpha"

    # Query tenant_beta
    res_beta = indexer.query_events(tenant_id="tenant_beta")
    assert res_beta["total"] == 1
    assert res_beta["events"][0]["tenant_id"] == "tenant_beta"


def test_dead_letter_diagnostic_completeness(tmp_path):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    dl_path = output_dir / "dead_letter.ndjson"
    resources.schemas_dir()

    validator = Validator(schema_path=resources.ues_schema_path(), dead_letter_path=dl_path)

    # Invalid event missing mandatory field 'event'
    bad_event = {
        "event_id": "00000000-0000-0000-0000-000000000099",
        "tenant_id": "test_tenant",
        "ingest_timestamp": "2024-03-15T10:22:45Z",
        "source": {"log_format": "syslog_rfc5424"},
        "raw": {"raw_payload": "corrupted", "raw_format": "unknown", "raw_hash": "c" * 64},
        "lineage": {"parser_name": "test", "parser_version": "1.0", "normalization_ruleset_version": "1.0"},
    }

    routed = validator.validate_and_route(bad_event)
    assert routed is False
    validator.close()

    # Verify dead letter file contents
    assert dl_path.exists()
    with open(dl_path, encoding="utf-8") as f:
        dl_record = json.loads(f.readline())

    assert dl_record["event_id"] == "00000000-0000-0000-0000-000000000099"
    assert dl_record["tenant_id"] == "test_tenant"
    assert dl_record["stage"] == "validation"
    assert dl_record["error_type"] == "SchemaValidationError"
    assert len(dl_record["validation_errors"]) > 0


def test_api_authentication(tmp_path, monkeypatch):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    monkeypatch.setenv("ULPF_API_KEY", "secret-key-12345")

    app = create_app(output_dir=output_dir)
    client = TestClient(app)

    # Ingest without API key -> 401
    resp = client.post("/api/ingest/line", json={"line": "test log"})
    assert resp.status_code == 401

    # Ingest with wrong API key -> 401
    resp = client.post("/api/ingest/line", json={"line": "test log"}, headers={"X-API-Key": "wrong-key"})
    assert resp.status_code == 401

    # Ingest with correct API key -> 200
    resp = client.post("/api/ingest/line", json={"line": "<134>1 2024-03-15T10:22:45Z host app - - msg"}, headers={"X-API-Key": "secret-key-12345"})
    assert resp.status_code == 200
