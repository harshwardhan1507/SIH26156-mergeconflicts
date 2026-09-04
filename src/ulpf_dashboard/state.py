"""
Per-application state for the dashboard.

Everything the request handlers need is held on one object attached to
``app.state``, not in a module-level dict. A module global made two apps in one
process impossible, leaked state between tests, and meant that constructing an
app mutated whatever app already existed.
"""
from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

from fastapi import Request

from ulpf.core.source_manager import SourceManager
from ulpf.runtime import PipelineSession, build_session
from ulpf_dashboard.indexer import EventIndexer

logger = logging.getLogger(__name__)


class AppState:
    """Owns the long-lived resources backing one dashboard application."""

    def __init__(self, output_dir: Path, host: str = "127.0.0.1", port: int = 7000) -> None:
        self.output_dir = output_dir
        self.host = host
        self.port = port
        self.indexer = EventIndexer(output_dir=output_dir)
        self.raw_store = build_raw_store(output_dir)
        self.source_manager = SourceManager(output_dir=output_dir)
        self.live_monitor: Any = None  # host monitor starts disabled
        self._ingest_session: PipelineSession | None = None
        self._ingest_lock = threading.Lock()

    def ingest_session(self) -> PipelineSession:
        """
        Return the shared pipeline used by the REST ingestion endpoints.

        Built once and reused. Constructing one per request meant re-parsing
        every YAML mapping, recompiling the JSON Schema, and opening a fresh
        pair of file handles for every single line ingested.
        """
        with self._ingest_lock:
            if self._ingest_session is None:
                self._ingest_session = build_session(
                    output_dir=self.output_dir, sinks="ndjson", telemetry=True
                )
            return self._ingest_session

    def close(self) -> None:
        """Release every owned resource. Safe to call more than once."""
        if self.live_monitor is not None:
            try:
                self.live_monitor.stop()
            except Exception as exc:
                logger.warning("Live monitor stop failed: %s", exc)
            self.live_monitor = None
        with self._ingest_lock:
            if self._ingest_session is not None:
                self._ingest_session.close()
                self._ingest_session = None
        for resource in (self.indexer, self.source_manager, self.raw_store):
            try:
                resource.close()
            except Exception as exc:
                logger.warning("Closing %s failed: %s", type(resource).__name__, exc)


def build_raw_store(output_dir: Path):
    """Open the forensic raw store backing event detail lookups."""
    from ulpf.core.raw_store import FileRawStore

    return FileRawStore(output_dir / "raw_store")


def get_state(request: Request) -> AppState:
    """FastAPI dependency returning the current application's state."""
    return request.app.state.ulpf
