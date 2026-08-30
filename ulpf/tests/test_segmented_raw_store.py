"""
Tests for Scalable Segmented Raw Storage Mode and Byte-Exact Forensic Recovery.
"""
from __future__ import annotations

import hashlib
import uuid
import pytest
from pathlib import Path

from ulpf.core.segmented_raw_store import SegmentedRawStore


def test_segmented_raw_store_byte_exact_recovery(tmp_path):
    store = SegmentedRawStore(base_dir=tmp_path, max_segment_size=1024 * 1024)

    test_events = [
        (str(uuid.uuid4()), "Line 1: Sample raw syslog <134>1 2024-03-15T10:22:45Z host app - - msg1"),
        (str(uuid.uuid4()), 'Line 2: JSON payload {"user": "alice", "action": "deny", "src": "10.0.0.1"}'),
        (str(uuid.uuid4()), "Line 3: Palo Alto CSV 2024-03-15,serial,TRAFFIC,allow,10.0.0.5,192.168.1.1"),
    ]

    hashes = {}
    for event_id, payload in test_events:
        digest = store.put(event_id, payload, tenant_id="tenant_alpha")
        expected_digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        assert digest == expected_digest
        hashes[event_id] = digest

    # Verify retrieval
    for event_id, original_payload in test_events:
        recovered = store.get(event_id)
        assert recovered == original_payload
        record = store.get_record(event_id)
        assert record is not None
        assert record.sha256 == hashes[event_id]
        assert record.tenant_id == "tenant_alpha"

    store.close()


def test_segmented_raw_store_chunk_rotation(tmp_path):
    # Set tiny segment size to force multiple segment file rotations
    store = SegmentedRawStore(base_dir=tmp_path, max_segment_size=100)

    event_ids = []
    for i in range(20):
        e_id = str(uuid.uuid4())
        payload = f"Log record payload with number {i} - long enough to fill segment quickly"
        store.put(e_id, payload, tenant_id="default")
        event_ids.append((e_id, payload))

    # Check all events across all segments
    for e_id, original_payload in event_ids:
        recovered = store.get(e_id)
        assert recovered == original_payload

    # Verify multiple segment files exist on disk
    segments = list(tmp_path.glob("**/*.bin"))
    assert len(segments) > 1

    store.close()
