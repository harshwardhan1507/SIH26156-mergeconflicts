"""
Unit and Integration Tests for ULPF Dashboard Backend & Indexer.
"""
from __future__ import annotations

import json
from pathlib import Path
from fastapi.testclient import TestClient
import pytest

from ulpf.dashboard.app import create_app
from ulpf.dashboard.indexer import EventIndexer


@pytest.fixture
def sample_output_dir(tmp_path):
    """Create a temporary output directory with mock events and dead-letter logs."""
    events_file = tmp_path / "events.ndjson"
    raw_store_dir = tmp_path / "raw_store"
    dead_letter_file = tmp_path / "dead_letter.ndjson"

    # Write 3 sample UES events
    event1 = {
        "event_id": "11111111-1111-1111-1111-111111111111",
        "ingest_timestamp": "2026-08-27T08:00:00Z",
        "source_event_timestamp": "2026-08-27T08:00:00Z",
        "raw": {"raw_payload": "raw line 1", "raw_format": "cef", "raw_hash": "a" * 64},
        "source": {"vendor": "Cisco", "product": "ASA", "device_hostname": "fw01", "log_format": "cef"},
        "event": {
            "category": "network",
            "action": "deny",
            "outcome": "failure",
            "severity_numeric": 8.0,
            "severity_original": "8",
            "event_type_vendor_specific": "106023",
        },
        "network": {
            "src_ip": "10.0.0.1",
            "src_port": 12345,
            "dst_ip": "192.168.1.1",
            "dst_port": 80,
            "protocol": "tcp",
            "bytes_in": 100,
            "bytes_out": 200,
            "direction": "inbound",
            "interface": "eth0",
        },
        "identity": {"username": "admin", "user_domain": "CORP"},
        "rule": {"rule_id": "1", "rule_name": "BLOCK_ALL", "policy_action": "deny"},
        "enrichment": None,
        "lineage": {"parser_name": "cef", "parser_version": "1.0.0", "normalization_ruleset_version": "1.0.0"},
    }

    event2 = {
        "event_id": "22222222-2222-2222-2222-222222222222",
        "ingest_timestamp": "2026-08-27T08:30:00Z",
        "source_event_timestamp": "2026-08-27T08:30:00Z",
        "raw": {"raw_payload": "raw line 2", "raw_format": "csv", "raw_hash": "b" * 64},
        "source": {"vendor": "Palo Alto Networks", "product": "PAN-OS", "device_hostname": "pa01", "log_format": "csv"},
        "event": {
            "category": "network",
            "action": "allow",
            "outcome": "success",
            "severity_numeric": 3.0,
            "severity_original": "3",
            "event_type_vendor_specific": "traffic",
        },
        "network": {
            "src_ip": "10.0.0.2",
            "src_port": 54321,
            "dst_ip": "192.168.1.2",
            "dst_port": 443,
            "protocol": "tcp",
            "bytes_in": 500,
            "bytes_out": 1000,
            "direction": "outbound",
            "interface": "eth1",
        },
        "identity": None,
        "rule": {"rule_id": "2", "rule_name": "ALLOW_WEB", "policy_action": "allow"},
        "enrichment": None,
        "lineage": {"parser_name": "paloalto_csv", "parser_version": "1.0.0", "normalization_ruleset_version": "1.0.0"},
    }

    with open(events_file, "w", encoding="utf-8") as f:
        f.write(json.dumps(event1) + "\n")
        f.write(json.dumps(event2) + "\n")

    # Store raw files in sharded structure
    p1 = raw_store_dir / "11" / "11" / "11111111-1111-1111-1111-111111111111.raw"
    p1.parent.mkdir(parents=True, exist_ok=True)
    p1.write_text("raw line 1")

    p2 = raw_store_dir / "22" / "22" / "22222222-2222-2222-2222-222222222222.raw"
    p2.parent.mkdir(parents=True, exist_ok=True)
    p2.write_text("raw line 2")

    # Dead letter
    dl_record = {
        "event_id": "99999999-9999-9999-9999-999999999999",
        "raw_payload": "corrupted syslog line",
        "errors": ["event.category is required"],
        "timestamp": "2026-08-27T08:45:00Z",
    }
    with open(dead_letter_file, "w", encoding="utf-8") as f:
        f.write(json.dumps(dl_record) + "\n")

    return tmp_path


def test_indexer_crud(sample_output_dir):
    indexer = EventIndexer(output_dir=sample_output_dir)
    count = indexer.sync_from_ndjson()
    assert count == 2

    # Query all
    res = indexer.query_events(page=1, page_size=10)
    assert res["total"] == 2
    assert len(res["events"]) == 2

    # Filter by vendor
    res_vendor = indexer.query_events(vendor="Cisco")
    assert res_vendor["total"] == 1
    assert res_vendor["events"][0]["source"]["vendor"] == "Cisco"

    # Filter by severity range
    res_sev = indexer.query_events(severity_min=7.0)
    assert res_sev["total"] == 1
    assert res_sev["events"][0]["event"]["severity_numeric"] == 8.0

    # Search free text
    res_search = indexer.query_events(search="10.0.0.2")
    assert res_search["total"] == 1
    assert res_search["events"][0]["network"]["src_ip"] == "10.0.0.2"

    # Stats
    stats = indexer.get_stats()
    assert stats["total_events"] == 2
    assert stats["dead_letter_count"] == 1
    assert stats["severity_distribution"]["high"] == 1
    assert stats["severity_distribution"]["low"] == 1

    # Dead letter
    dl = indexer.get_dead_letter_records()
    assert dl["total"] == 1
    assert dl["records"][0]["errors"][0] == "event.category is required"


def test_api_endpoints(sample_output_dir):
    app = create_app(output_dir=sample_output_dir)
    client = TestClient(app)

    # Test GET /api/stats
    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.json()
    assert data["total_events"] == 2
    assert data["dead_letter_count"] == 1

    # Test GET /api/events
    res = client.get("/api/events?page=1&page_size=10")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 2
    assert len(data["events"]) == 2

    # Test GET /api/events/{event_id}
    res = client.get("/api/events/11111111-1111-1111-1111-111111111111")
    assert res.status_code == 200
    detail = res.json()
    assert detail["event_id"] == "11111111-1111-1111-1111-111111111111"
    assert detail["raw_payload"] == "raw line 1"
    assert detail["normalized"]["source"]["vendor"] == "Cisco"

    # Test GET /api/dead-letter
    res = client.get("/api/dead-letter")
    assert res.status_code == 200
    dl_data = res.json()
    assert dl_data["total"] == 1

    # Test GET /api/parsers
    res = client.get("/api/parsers")
    assert res.status_code == 200
    parsers = res.json()["parsers"]
    assert len(parsers) >= 6

    # Test GET /api/export (CSV)
    res = client.get("/api/export?format=csv")
    assert res.status_code == 200
    assert "event_id,ingest_timestamp" in res.text

    # Test GET /api/export (JSON)
    res = client.get("/api/export?format=json")
    assert res.status_code == 200
    lines = res.text.strip().split("\n")
    assert len(lines) == 2

    # Test POST /api/reindex
    res = client.post("/api/reindex")
    assert res.status_code == 200
    assert res.json()["indexed_events"] == 2

    # Test POST /api/ingest/line
    res_line = client.post("/api/ingest/line", json={
        "line": "LEEF:1.0|Cisco|ASA|9.14|106023|src=10.0.0.99\tspt=5555\tdst=203.0.113.1\tdpt=443\tproto=TCP\tsev=8",
        "source_tag": "api_test"
    })
    assert res_line.status_code == 200
    assert res_line.json()["processed"] == 1
    assert res_line.json()["valid"] == 1

    # Test POST /api/ingest/batch
    res_batch = client.post("/api/ingest/batch", json={
        "lines": [
            "LEEF:1.0|Cisco|ASA|9.14|106023|src=10.0.0.50\tspt=1234\tdst=203.0.113.2\tdpt=80\tproto=TCP\tsev=3",
            "LEEF:1.0|Cisco|ASA|9.14|106023|src=10.0.0.51\tspt=1235\tdst=203.0.113.3\tdpt=80\tproto=TCP\tsev=3"
        ],
        "source_tag": "api_batch_test"
    })
    assert res_batch.status_code == 200
    assert res_batch.json()["processed"] == 2

    # Test POST /api/ingest/stream
    res_stream = client.post(
        "/api/ingest/stream",
        content="LEEF:1.0|Cisco|ASA|9.14|106023|src=10.0.0.52\tspt=1236\tdst=203.0.113.4\tdpt=80\tproto=TCP\tsev=3\n",
        headers={"Content-Type": "application/x-ndjson"}
    )
    assert res_stream.status_code == 200
    assert res_stream.json()["processed"] == 1

    # Test GET /api/analytics/anomalies
    res_anomalies = client.get("/api/analytics/anomalies?min_score=0.0")
    assert res_anomalies.status_code == 200
    data_anomalies = res_anomalies.json()
    assert "anomalies" in data_anomalies
    assert "total_analyzed" in data_anomalies

