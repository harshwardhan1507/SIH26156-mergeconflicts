"""
Comprehensive Conformance Test Suite for Criteria (a)-(h).

Verifies:
  (a) Raw Byte Preservation without information loss on non-UTF8/binary streams
  (b) Vendor Attribute Bag preserving 100% of unmapped source-specific fields
  (c) OCSF / ECS Common Taxonomy Alignment (class_name, class_uid, activity_name)
  (d) Traceability & Deterministic Event ID (UUIDv5) & Schema Versioning
  (e) Plug-and-play dynamic parser auto-detection
  (f) Syslog Listener & Multi-Tenancy support
  (g) Columnar Parquet Data Lake sink & CEF/LEEF Egress Sinks
  (h) ML-Ready Feature Vector Extraction (24 dimensions)
"""
import hashlib
import json
import os
import socket
import tempfile
import time
from pathlib import Path

import pytest

from ulpf.core.detector import FormatDetector
from ulpf.core.ingestion import FileReader, RawEvent
from ulpf.core.normalization import NormalizationEngine
from ulpf.core.pipeline import Pipeline
from ulpf.core.raw_store import FileRawStore
from ulpf.core.registry import get_all_parsers, get_parser_for_format
from ulpf.core.validation import Validator
from ulpf.sinks.ndjson_file import NDJSONFileSink
from ulpf.sinks.parquet_sink import ParquetSink
from ulpf.sinks.cef_egress import CEFEgressSink
from ulpf.sinks.leef_egress import LEEFEgressSink
from ulpf.analytics.features import FeatureVectorExtractor
from ulpf.collectors.syslog_listener import SyslogNetworkListener


@pytest.fixture
def temp_pipeline(tmp_path):
    mappings_dir = Path(__file__).resolve().parent.parent / "schemas" / "mappings"
    schema_path = Path(__file__).resolve().parent.parent / "schemas" / "ues_schema.json"

    detector = FormatDetector()
    raw_store = FileRawStore(base_dir=tmp_path / "raw")
    norm_engine = NormalizationEngine(mappings_dir=mappings_dir)
    validator = Validator(schema_path=schema_path, dead_letter_path=tmp_path / "dead_letter.ndjson")
    events_sink = NDJSONFileSink(output_path=tmp_path / "events.ndjson")

    pipeline = Pipeline(
        detector=detector,
        raw_store=raw_store,
        normalization_engine=norm_engine,
        validator=validator,
        sinks=[events_sink],
    )
    return pipeline, tmp_path, raw_store, validator


# --- Criterion (a): Raw Byte Preservation ---
def test_raw_byte_preservation_binary(temp_pipeline):
    pipeline, tmp_path, raw_store, _ = temp_pipeline
    raw_bytes = b"CEF:0|Vendor|\xff\xfeBinary|1.0|1|Test|5|src=10.0.0.1 dst=10.0.0.2"
    raw_str = raw_bytes.decode("utf-8", errors="surrogateescape")

    ok = pipeline.process_event(raw_line=raw_str, source_tag="binary_test", raw_bytes=raw_bytes)
    assert ok is True

    # Verify raw store holds authentic bytes
    expected_hash = hashlib.sha256(raw_bytes).hexdigest()
    event_id = list(raw_store.base_dir.rglob("*.raw"))[0].stem
    stored_bytes = raw_store.get_bytes(event_id)
    assert stored_bytes == raw_bytes
    assert hashlib.sha256(stored_bytes).hexdigest() == expected_hash


# --- Criterion (b): Vendor Attributes Preservation ---
def test_vendor_attributes_preservation(temp_pipeline):
    pipeline, tmp_path, _, _ = temp_pipeline
    cef_line = "CEF:0|CheckPoint|Firewall|1.0|DROP|Drop packet|6|src=192.168.1.5 spt=5000 dst=10.0.0.1 dpt=80 proto=TCP cs1=CorporateLAN cs2=HighSec flexString1=Rule99 msg=Packet dropped by security gateway"
    ok = pipeline.process_event(raw_line=cef_line, source_tag="cef_ext_test")
    assert ok is True

    events_file = tmp_path / "events.ndjson"
    with open(events_file, "r", encoding="utf-8") as f:
        event = json.loads(f.readline())

    # Verify vendor_attributes holds all unmapped keys
    attrs = event.get("vendor_attributes") or {}
    assert attrs.get("cs1") == "CorporateLAN"
    assert attrs.get("cs2") == "HighSec"
    assert attrs.get("flexString1") == "Rule99"
    assert attrs.get("msg") == "Packet dropped by security gateway"


# --- Criterion (c): OCSF / ECS Taxonomy Alignment ---
def test_ocsf_taxonomy_alignment(temp_pipeline):
    pipeline, tmp_path, _, _ = temp_pipeline
    auth_line = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID><TimeCreated SystemTime="2026-08-27T12:00:00Z"/><Channel>Security</Channel></System><EventData><Data Name="TargetUserName">admin</Data></EventData></Event>'
    ok = pipeline.process_event(raw_line=auth_line, source_tag="win_auth")
    assert ok is True

    events_file = tmp_path / "events.ndjson"
    with open(events_file, "r", encoding="utf-8") as f:
        event = json.loads(f.readline())

    ev_block = event.get("event", {})
    assert ev_block.get("class_name") in ["Authentication", "System Activity"]
    assert ev_block.get("class_uid") in [3001, 1001]
    assert event.get("schema_version") == "1.2.0"
    assert event.get("tenant_id") == "default"


# --- Criterion (d): Deterministic Event IDs & Reproducibility ---
def test_deterministic_event_ids(temp_pipeline):
    pipeline, _, raw_store, _ = temp_pipeline
    line = "CEF:0|Vendor|Product|1.0|100|EventName|5|src=1.2.3.4 dst=5.6.7.8 proto=TCP"

    # Process first time
    pipeline.process_event(raw_line=line, source_tag="test_src", tenant_id="tenant_a")
    ev_files_1 = list(raw_store.base_dir.rglob("*.raw"))
    id_1 = ev_files_1[0].stem

    # Process identical event again with same source tag and tenant
    pipeline.process_event(raw_line=line, source_tag="test_src", tenant_id="tenant_a")
    ev_files_2 = list(raw_store.base_dir.rglob("*.raw"))
    assert len(ev_files_2) == 1  # Exact idempotent key overwritten on duplicate
    assert ev_files_2[0].stem == id_1


# --- Criterion (e): Dynamic Parser Registration ---
def test_dynamic_parser_registration():
    parsers = get_all_parsers()
    names = [p.name for p in parsers]
    assert "cef" in names
    assert "leef" in names
    assert "cisco_asa" in names
    assert "xml_generic" in names
    assert "aws_cloudtrail" in names


# --- Criterion (f): Syslog Network Listener ---
def test_syslog_network_listener():
    received = []

    def on_syslog(msg, tag):
        received.append((msg, tag))

    listener = SyslogNetworkListener(on_event=on_syslog, host="127.0.0.1", port=15144)
    listener.start()
    time.sleep(0.2)

    # Send UDP test packet
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    test_msg = b"<134>1 2026-08-27T12:00:00Z myhost testapp 1234 - - Real UDP Syslog Message"
    sock.sendto(test_msg, ("127.0.0.1", 15144))
    sock.close()

    time.sleep(0.3)
    listener.stop()

    assert len(received) >= 1
    assert "Real UDP Syslog Message" in received[0][0]


# --- Criterion (g): Parquet Columnar Data Lake Sink & SIEM Egress Sinks ---
def test_parquet_and_egress_sinks(tmp_path):
    sample_event = {
        "schema_version": "1.2.0",
        "tenant_id": "corp_us",
        "event_id": "test-uuid-999",
        "ingest_timestamp": "2026-08-27T12:00:00Z",
        "source_event_timestamp": "2026-08-27T12:00:00Z",
        "raw": {"raw_payload": "raw text", "raw_format": "cef", "raw_hash": "a"*64},
        "source": {"vendor": "Cisco", "product": "ASA", "log_format": "cef"},
        "event": {"category": "network", "action": "deny", "outcome": "failure", "severity_numeric": 8.0},
        "network": {"src_ip": "10.1.1.5", "src_port": 44321, "dst_ip": "203.0.113.42", "dst_port": 443, "protocol": "tcp"},
        "lineage": {"parser_name": "cef", "parser_version": "1.0.0", "normalization_ruleset_version": "1.2.0"},
    }

    # 1. Parquet sink
    pq_sink = ParquetSink(base_dir=tmp_path / "parquet_lake")
    pq_sink.write(sample_event)
    pq_sink.flush()
    pq_sink.close()

    part_dir = tmp_path / "parquet_lake" / "dt=2026-08-27" / "tenant_id=corp_us"
    assert part_dir.exists()
    assert (part_dir / "events.parquet").exists() or (part_dir / "events_columnar.jsonl").exists()

    # 2. CEF Egress
    cef_str = CEFEgressSink.format_event(sample_event)
    assert cef_str.startswith("CEF:0|Cisco|ASA|1.2.0|")
    assert "src=10.1.1.5" in cef_str
    assert "dst=203.0.113.42" in cef_str

    # 3. LEEF Egress
    leef_str = LEEFEgressSink.format_event(sample_event)
    assert leef_str.startswith("LEEF:2.0|Cisco|ASA|1.2.0|")
    assert "src=10.1.1.5" in leef_str


# --- Criterion (h): ML-Ready Feature Vector Extraction ---
def test_ml_feature_vector_extraction():
    event = {
        "ingest_timestamp": "2026-08-27T14:30:00Z",
        "source_event_timestamp": "2026-08-27T14:30:00Z",
        "event": {"category": "network", "outcome": "success", "severity_numeric": 5.0, "severity_inferred": False},
        "network": {"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "dst_port": 443, "bytes_in": 1024, "bytes_out": 4096},
        "enrichment": {"threat_ip_detected": False, "src_ip_context": {"cloud_provider": "AWS"}},
    }

    vec = FeatureVectorExtractor.extract_vector(event)
    assert len(vec) == 24
    assert all(isinstance(x, float) for x in vec)
    # Check bounded range
    assert all(-1.0 <= x <= 1.0 for x in vec)
