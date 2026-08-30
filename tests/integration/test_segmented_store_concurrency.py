"""
Segmented raw store durability under concurrent writers.

The store records a byte offset into a shared segment file. Taking that offset
from a cached file size is wrong the moment a second writer appends: the bytes
land at the real end of file while the index points somewhere else, so raw
lookups silently return the wrong payload. ``ulpf ingest --workers N`` runs
exactly that shape, so it is asserted here.
"""
from __future__ import annotations

import multiprocessing as mp

from ulpf.core.segmented_raw_store import SegmentedRawStore


def _write_batch(args) -> list[tuple[str, bytes]]:
    """Append a batch of payloads from a separate process."""
    base_dir, worker_id, count = args
    store = SegmentedRawStore(base_dir)
    written = []
    for i in range(count):
        event_id = f"{worker_id:08d}-0000-0000-0000-{i:012d}"
        payload = f"worker={worker_id} seq={i} ".encode() + b"x" * (50 + i % 40)
        store.put(event_id, payload)
        written.append((event_id, payload))
    store.close()
    return written


def test_offsets_are_correct_under_single_process_writes(tmp_path):
    """Every payload must read back byte-identically."""
    store = SegmentedRawStore(tmp_path / "segments")
    expected = {}
    for i in range(200):
        event_id = f"00000000-0000-0000-0000-{i:012d}"
        payload = f"event {i} ".encode() + b"y" * (i % 100)
        store.put(event_id, payload)
        expected[event_id] = payload

    for event_id, payload in expected.items():
        assert store.get_bytes(event_id) == payload, f"payload corrupted for {event_id}"
    store.close()


def test_offsets_are_correct_under_concurrent_process_writes(tmp_path):
    """
    Payloads written by several processes into one partition must all read back
    intact — the multi-worker ingest path.
    """
    base = tmp_path / "segments"
    SegmentedRawStore(base).close()  # initialize the index before forking

    ctx = mp.get_context("spawn")
    with ctx.Pool(4) as pool:
        batches = pool.map(_write_batch, [(str(base), w, 40) for w in range(4)])

    store = SegmentedRawStore(base)
    mismatches = []
    for batch in batches:
        for event_id, payload in batch:
            actual = store.get_bytes(event_id)
            if actual != payload:
                mismatches.append((event_id, payload[:24], (actual or b"")[:24]))
    store.close()

    assert not mismatches, (
        f"{len(mismatches)} of 160 payloads read back wrong under concurrent writers; "
        f"first: {mismatches[0]}"
    )


def test_binary_payloads_survive_round_trip(tmp_path):
    """Non-UTF-8 bytes must be preserved exactly — this is a forensic store."""
    store = SegmentedRawStore(tmp_path / "segments")
    payload = bytes(range(256))
    event_id = "00000000-0000-0000-0000-00000000ffff"
    digest = store.put(event_id, payload)

    assert store.get_bytes(event_id) == payload
    assert store.get_record(event_id).sha256 == digest
    store.close()
