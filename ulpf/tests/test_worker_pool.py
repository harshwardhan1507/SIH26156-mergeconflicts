"""Tests for parallel worker pool."""
import pytest
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from ulpf.core.worker_pool import ParallelPipeline, DEFAULT_CHUNK_SIZE


def make_mock_reader(n_lines=10):
    """Create a simple mock reader that yields N events."""
    from ulpf.core.ingestion import RawEvent
    from datetime import datetime, timezone

    class MockReader:
        def read(self):
            for i in range(n_lines):
                yield RawEvent(
                    line=f"<134>Aug 27 08:00:0{i} host sshd[123]: Failed password for bob from 10.0.0.{i} port 22 ssh2",
                    source_tag="test",
                    ingest_timestamp=datetime.now(timezone.utc),
                )
    return MockReader()


def test_parallel_pipeline_initialization():
    factory = lambda: MagicMock()
    pp = ParallelPipeline(pipeline_factory=factory, num_workers=2, chunk_size=5)
    assert pp.num_workers == 2
    assert pp.chunk_size == 5


def test_parallel_pipeline_empty_reader():
    class EmptyReader:
        def read(self):
            return iter([])

    factory = lambda: MagicMock()
    pp = ParallelPipeline(pipeline_factory=factory, num_workers=1)
    stats = pp.run(EmptyReader())
    assert stats["processed"] == 0


def test_default_chunk_size():
    assert DEFAULT_CHUNK_SIZE > 0


def test_parallel_pipeline_auto_workers():
    import os
    factory = lambda: MagicMock()
    pp = ParallelPipeline(pipeline_factory=factory)
    assert 1 <= pp.num_workers <= 8
