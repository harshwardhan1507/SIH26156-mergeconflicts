"""
Parallel Worker Pool for high-throughput log ingestion.

Uses multiprocessing.Pool to distribute ingestion across N worker processes.
Each worker runs an independent Pipeline instance (shared-nothing architecture).
The main process collects and merges per-worker stats.

IMPORTANT: `pipeline_factory` must be picklable — a closure defined inside
another function is NOT picklable and will crash the pool at dispatch time.
Use a module-level function bound via functools.partial (see ulpf.cli for
the reference implementation) or any other top-level callable.

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
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

# Maximum lines to buffer per worker chunk
DEFAULT_CHUNK_SIZE = 500

# One (raw_line, source_tag, ingest_ts_iso, raw_bytes) tuple per event
_ChunkItem = tuple[str, str, str, bytes]


def _worker_process(
    args: tuple[list[_ChunkItem], int, str],
    pipeline_factory: Callable,
) -> dict[str, int]:
    """
    Worker process entry point. Runs in a separate process.

    Args:
        args: (chunk, worker_id, tenant_id) — bundled into one tuple so this
              function has a fixed two-parameter signature and can be bound
              via functools.partial for pool.imap_unordered.
        pipeline_factory: picklable callable that returns a new Pipeline instance.
    """
    chunk, worker_id, tenant_id = args

    # Ignore SIGINT in workers — let main process handle it
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    logger.debug("Worker %d starting, chunk_size=%d", worker_id, len(chunk))

    pipeline = pipeline_factory()
    stats = {"processed": 0, "valid": 0, "invalid": 0, "errors": 0}

    for raw_line, source_tag, ts_iso, raw_bytes in chunk:
        try:
            ingest_ts = datetime.fromisoformat(ts_iso)
        except Exception:
            ingest_ts = datetime.now(UTC)

        pipeline.process_event(
            raw_line=raw_line,
            source_tag=source_tag,
            ingest_ts=ingest_ts,
            raw_bytes=raw_bytes or None,
            tenant_id=tenant_id,
        )

    try:
        stats["valid"] = pipeline.validator.valid_count
        stats["invalid"] = pipeline.validator.invalid_count
        stats["errors"] = pipeline._errors
        stats["processed"] = pipeline._processed
    except Exception as exc:
        logger.warning("Worker %d: could not collect final stats: %s", worker_id, exc)

    try:
        pipeline.validator.close()
    except Exception as exc:
        logger.warning("Worker %d: validator.close() failed: %s", worker_id, exc)
    for sink in pipeline.sinks:
        try:
            sink.close()
        except Exception as exc:
            logger.warning("Worker %d: sink %s close() failed: %s", worker_id, sink, exc)

    logger.debug("Worker %d done: %s", worker_id, stats)
    return stats


class ParallelPipeline:
    """
    Distributes log ingestion across multiple CPU processes.
    Streams the input in bounded chunks (does not buffer the entire input in
    memory) and merges per-worker stats as results arrive.
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

    def _chunks(
        self, reader: Any, tenant_id: str
    ) -> Iterator[tuple[list[_ChunkItem], int, str]]:
        """Stream (chunk, worker_id, tenant_id) tuples from the reader without
        materializing the whole input in memory at once."""
        chunk: list[_ChunkItem] = []
        worker_id = 0
        for raw_event in reader.read():
            raw_bytes = getattr(raw_event, 'raw_bytes', None) or b''
            chunk.append((
                raw_event.line,
                raw_event.source_tag,
                raw_event.ingest_timestamp.isoformat(),
                raw_bytes,
            ))
            if len(chunk) >= self.chunk_size:
                yield chunk, worker_id, tenant_id
                worker_id += 1
                chunk = []
        if chunk:
            yield chunk, worker_id, tenant_id

    def run(self, reader: Any, tenant_id: str = "default") -> dict[str, int]:
        """
        Stream events from reader in bounded chunks, distribute across
        workers as they become available, and return merged stats.
        """
        merged: dict[str, int] = {"processed": 0, "valid": 0, "invalid": 0, "errors": 0}
        chunk_iter = self._chunks(reader, tenant_id)

        # Peek to avoid spinning up a pool for an empty input.
        try:
            first = next(chunk_iter)
        except StopIteration:
            return merged

        def _all_chunks() -> Iterator[tuple[list[_ChunkItem], int, str]]:
            yield first
            yield from chunk_iter

        import functools
        bound_worker = functools.partial(_worker_process, pipeline_factory=self.pipeline_factory)

        logger.info("ParallelPipeline: streaming chunks to %d workers...", self.num_workers)

        try:
            with multiprocessing.Pool(processes=self.num_workers) as pool:
                for result in pool.imap_unordered(bound_worker, _all_chunks()):
                    for key in merged:
                        merged[key] += result.get(key, 0)
        except KeyboardInterrupt:
            logger.warning("ParallelPipeline interrupted by user")
        except Exception as exc:
            logger.error("ParallelPipeline error: %s", exc)
            raise

        logger.info("ParallelPipeline complete: %s", merged)
        return merged
