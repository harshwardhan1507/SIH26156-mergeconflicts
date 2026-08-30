"""
Pipeline observability hook.

The pipeline reports the outcome of every event to an optional observer. This
is a callback rather than a direct :class:`~ulpf.core.source_manager.SourceManager`
dependency so that the hot path stays free of storage concerns and so that
embedders can route counters into Prometheus, StatsD, or nothing at all.
"""
from __future__ import annotations

import logging
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@runtime_checkable
class PipelineObserver(Protocol):
    """Receives the outcome of each processed event."""

    def on_event(
        self,
        parser_name: str,
        *,
        valid: bool,
        dead_lettered: bool,
        error: str | None = None,
    ) -> None:
        """Record one event outcome. Must not raise."""


class SourceTelemetryObserver:
    """
    Adapter that feeds pipeline outcomes into a :class:`SourceManager`.

    Writes are best-effort: telemetry is diagnostic, and a locked or full
    registry database must never fail an ingest that otherwise succeeded.
    """

    def __init__(self, source_manager: Any) -> None:
        self._sm = source_manager

    def on_event(
        self,
        parser_name: str,
        *,
        valid: bool,
        dead_lettered: bool,
        error: str | None = None,
    ) -> None:
        try:
            self._sm.record_event_telemetry(
                source_id=parser_name,
                is_valid=valid,
                is_dead_letter=dead_lettered,
                error_msg=error,
            )
        except Exception as exc:
            logger.debug("Telemetry write failed for %s: %s", parser_name, exc)
