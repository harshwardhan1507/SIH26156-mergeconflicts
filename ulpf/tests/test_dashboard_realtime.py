"""
Unit and integration tests for real-time dashboard SSE streaming,
LiveSystemMonitor API lifecycle, and multi-client state consistency.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from ulpf.dashboard.app import create_app, STATE
from ulpf.collectors.live_monitor import LiveSystemMonitor
from ulpf.core.source_manager import SourceManager
from ulpf.dashboard.indexer import EventIndexer


@pytest.fixture
def dashboard_env(tmp_path: Path):
    output_dir = tmp_path / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    events_file = output_dir / "events.ndjson"
    events_file.write_text("", encoding="utf-8")

    app = create_app(output_dir=output_dir)
    client = TestClient(app)

    return {
        "app": app,
        "client": client,
        "output_dir": output_dir,
    }


def test_live_monitor_api_lifecycle(dashboard_env):
    client = dashboard_env["client"]

    # 1. Initial status -> stopped
    res = client.get("/api/live-monitor/status")
    assert res.status_code == 200
    data = res.json()
    assert data["running"] is False
    assert data["scan_status"] == "stopped"

    # 2. Start monitor
    res_start = client.post("/api/live-monitor/start?interval_ms=500")
    assert res_start.status_code == 200
    start_data = res_start.json()
    assert start_data["status"] == "started"
    assert start_data["running"] is True

    # 3. Connections API returns list and running state
    res_conns = client.get("/api/live-monitor/connections")
    assert res_conns.status_code == 200
    conn_data = res_conns.json()
    assert conn_data["running"] is True
    assert isinstance(conn_data["connections"], list)
    assert "stats" in conn_data

    # 4. Stop monitor
    res_stop = client.post("/api/live-monitor/stop")
    assert res_stop.status_code == 200
    stop_data = res_stop.json()
    assert stop_data["status"] == "stopped"
    assert stop_data["running"] is False


def test_source_health_update_metrics(dashboard_env):
    client = dashboard_env["client"]
    res = client.get("/api/sources")
    assert res.status_code == 200
    data = res.json()
    assert "sources" in data
    assert "metrics" in data
    assert data["metrics"]["validity_rate_pct"] >= 0


@pytest.mark.asyncio
async def test_sse_stream_event_ingestion_and_envelopes(tmp_path: Path):
    output_dir = tmp_path / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    events_file = output_dir / "events.ndjson"

    # Append a sample event
    sample_event = {
        "event_id": "test-uuid-1234",
        "schema_version": "1.2.0",
        "ingest_timestamp": "2026-08-30T12:00:00Z",
        "source": {"vendor": "Cisco", "product": "ASA", "log_format": "syslog_rfc3164"},
        "event": {"category": "network", "action": "deny", "severity_numeric": 8.0},
        "raw": {"raw_payload": "test raw", "raw_format": "cef", "raw_hash": "a" * 64},
        "lineage": {"parser_name": "cef", "parser_version": "1.0", "normalization_ruleset_version": "1.0"},
    }
    events_file.write_text(json.dumps(sample_event) + "\n", encoding="utf-8")

    app = create_app(output_dir=output_dir)

    for route in app.routes:
        if getattr(route, "path", "") == "/api/stream":
            response = await route.endpoint()
            gen = response.body_iterator
            chunk = await asyncio.wait_for(gen.__anext__(), timeout=3.0)
            assert chunk.startswith("data: ")
            payload = json.loads(chunk[6:].strip())
            assert "type" in payload
            assert "timestamp" in payload
            if payload["type"] == "event_ingested":
                assert payload["data"]["event_id"] == "test-uuid-1234"
            break


def test_multiple_clients_consistent_state(dashboard_env):
    client = dashboard_env["client"]

    # Client 1 checks sources
    r1 = client.get("/api/sources")
    # Client 2 checks stats
    r2 = client.get("/api/stats")
    # Client 3 checks monitor status
    r3 = client.get("/api/live-monitor/status")

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 200
    assert r1.json()["metrics"]["total_events"] == r2.json()["total_events"]
