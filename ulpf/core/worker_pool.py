"""
Parallel Worker Pool for high-throughput log ingestion.

Uses multiprocessing.Pool to distribute ingestion across N worker processes.
Each worker runs an independent Pipeline instance (shared-nothing architecture).
The main process collects and merges per-worker stats.

Usage via CLI:
    ulpf ingest --input /var/log/sources --output output --workers 8

Usage via Python:
    from ulpf.core.worker_pool import ParallelPipeline
    parallel = ParallelPipeline(
        pipeline_factory=my_factory_fn,
        num_workers=8,
        chunk_size=1000,
    )
    stats = parallel.run(reader)
"""
from __future__ import annotations

import logging
import multiprocessing
import os
import signal
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Maximum lines to buffer per worker chunk
DEFAULT_CHUNK_SIZE = 500


def _worker_process(
    chunk: list[tuple[str, str, str]],
    pipeline_factory: Callable,
    worker_id: int,
) -> dict[str, int]:
    """
    Worker process function. Runs in a separate process.
    
    Args:
        chunk: list of (raw_line, source_tag, ingest_timestamp_iso) tuples
        pipeline_factory: callable that returns a new Pipeline instance
        worker_id: integer worker identifier for logging
    """
    # Ignore SIGINT in workers — let main process handle it
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    logger.debug("Worker %d starting, chunk_size=%d", worker_id, len(chunk))

    pipeline = pipeline_factory()
    stats = {"processed": 0, "valid": 0, "invalid": 0, "errors": 0}

    for raw_line, source_tag, ts_iso in chunk:
        try:
            ingest_ts = datetime.fromisoformat(ts_iso)
        except Exception:
            ingest_ts = datetime.now(timezone.utc)

        ok = pipeline.process_event(
            raw_line=raw_line,
            source_tag=source_tag,
            ingest_ts=ingest_ts,
        )
        if ok:
            stats["processed"] += 1

    # Get final stats from pipeline internals
    final = pipeline.run.__func__  # we ran manually above
    # Collect from validator if accessible
    try:
        stats["valid"] = pipeline.validator.valid_count
        stats["invalid"] = pipeline.validator.invalid_count
        stats["errors"] = pipeline._errors
        # Close resources
        pipeline.validator.close()
        for sink in pipeline.sinks:
            sink.close()
    except Exception:
        pass

    logger.debug("Worker %d done: %s", worker_id, stats)
    return stats


class ParallelPipeline:
    """
    Distributes log ingestion across multiple CPU processes.
    Automatically chunks the input stream and merges stats.
    """

    def __init__(
        self,
        pipeline_factory: Callable,
        num_workers: int | None = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> None:
        self.pipeline_factory = pipeline_factory
        self.num_workers = num_workers or min(os.cpu_count() or 1, 8)
        self.chunk_size = chunk_size
        logger.info(
            "ParallelPipeline initialized: workers=%d chunk_size=%d",
            self.num_workers, self.chunk_size,
        )

    def run(self, reader) -> dict[str, int]:
        """
        Read all events from reader, chunk them, distribute across workers,
        and return merged stats.
        """
        ingest_ts_iso = datetime.now(timezone.utc).isoformat()

        # Collect all lines into chunks
        chunks: list[list[tuple[str, str, str]]] = []
        current_chunk: list[tuple[str, str, str]] = []

        for raw_event in reader.read():
            current_chunk.append((
                raw_event.line,
                raw_event.source_tag,
                raw_event.ingest_timestamp.isoformat(),
            ))
            if len(current_chunk) >= self.chunk_size:
                chunks.append(current_chunk)
                current_chunk = []

        if current_chunk:
            chunks.append(current_chunk)

        if not chunks:
            return {"processed": 0, "valid": 0, "invalid": 0, "errors": 0}

        logger.info(
            "ParallelPipeline: %d chunks, %d workers, distributing...",
            len(chunks), self.num_workers,
        )

        # Build worker args: (chunk, factory, worker_id)
        worker_args = [
            (chunk, self.pipeline_factory, idx)
            for idx, chunk in enumerate(chunks)
        ]

        # Use multiprocessing pool
        merged: dict[str, int] = {"processed": 0, "valid": 0, "invalid": 0, "errors": 0}
        try:
            with multiprocessing.Pool(processes=self.num_workers) as pool:
                results = pool.starmap(_worker_process, worker_args)
                for result in results:
                    for key in merged:
                        merged[key] += result.get(key, 0)
        except KeyboardInterrupt:
            logger.warning("ParallelPipeline interrupted by user")
        except Exception as exc:
            logger.error("ParallelPipeline error: %s", exc)
            raise

        logger.info("ParallelPipeline complete: %s", merged)
        return merged
