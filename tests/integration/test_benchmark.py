"""
Tests for Benchmark Tool Execution and Metrics Calculations.
"""
from __future__ import annotations

from ulpf.tools.benchmark import run_benchmark


def test_benchmark_execution_synthetic(tmp_path):
    res = run_benchmark(
        events_count=1000,
        workers=1,
        sink_type="none",
        raw_store_mode="none",
        output_dir=str(tmp_path),
    )

    assert res["events_processed"] == 1000
    assert res["valid_events"] == 1000
    assert res["invalid_events"] == 0
    assert res["eps"] > 0
    assert res["mb_per_sec"] > 0
    assert res["peak_memory_mb"] > 0


def test_benchmark_segmented_store(tmp_path):
    res = run_benchmark(
        events_count=500,
        workers=1,
        sink_type="ndjson",
        raw_store_mode="segmented",
        output_dir=str(tmp_path),
    )

    assert res["events_processed"] == 500
    assert res["valid_events"] == 500
    assert (tmp_path / "benchmark_events.ndjson").exists()
    assert len(list(tmp_path.glob("**/*.bin"))) > 0
