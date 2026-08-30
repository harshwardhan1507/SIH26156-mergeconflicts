"""
Server-Sent Events stream.

Pushes newly ingested events plus periodic telemetry snapshots. The generator
never performs blocking work inline: file reads and SQLite aggregates are
dispatched to a worker thread so one subscriber cannot stall the event loop for
everyone else.
"""
from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from starlette.concurrency import run_in_threadpool

from ulpf_dashboard.state import AppState, get_state

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["stream"])

State = Annotated[AppState, Depends(get_state)]

#: How often new events are picked up from the NDJSON tail.
_POLL_INTERVAL = 0.25

#: How often aggregate telemetry is broadcast, in poll ticks (~2s).
_TELEMETRY_EVERY = 8

#: Cap on events emitted per tick, so a bulk ingest cannot flood one client.
_MAX_EVENTS_PER_TICK = 200


def _sse(payload: dict[str, Any]) -> str:
    """Encode one SSE ``data:`` frame."""
    return f"data: {json.dumps(payload, default=str)}\n\n"


def _read_new_events(path: Path, offset: int) -> tuple[list[dict[str, Any]], int]:
    """
    Read events appended after ``offset``.

    Byte mode throughout: the offset is compared against ``st_size``, and a
    text-mode ``tell()`` returns an opaque cookie that is only coincidentally a
    byte count.
    """
    if not path.exists():
        return [], offset
    size = path.stat().st_size
    if size < offset:
        # Rotated or truncated — resume from the new start rather than waiting
        # forever for the file to grow past a stale offset.
        logger.info("events.ndjson shrank; SSE stream resuming from offset 0")
        offset = 0
    if size == offset:
        return [], offset

    events: list[dict[str, Any]] = []
    with open(path, "rb") as fh:
        fh.seek(offset)
        for raw in fh:
            if len(events) >= _MAX_EVENTS_PER_TICK:
                break
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        offset = fh.tell()
    return events, offset


@router.get("/stream")
async def stream_events(request: Request, state: State):
    """SSE stream of newly ingested events and periodic telemetry."""
    ndjson_path = state.output_dir / "events.ndjson"

    async def generator() -> AsyncIterator[str]:
        offset = ndjson_path.stat().st_size if ndjson_path.exists() else 0
        tick = 0

        while True:
            # Stop promptly when the subscriber goes away, rather than waiting
            # for a write to fail.
            if await request.is_disconnected():
                return

            now_iso = datetime.now(UTC).isoformat()

            events, offset = await run_in_threadpool(_read_new_events, ndjson_path, offset)
            for event in events:
                yield _sse({"type": "event_ingested", "timestamp": now_iso, "data": event})

            tick += 1
            if tick >= _TELEMETRY_EVERY:
                tick = 0
                monitor = state.live_monitor
                if monitor is not None and monitor.is_running():
                    try:
                        connections = await run_in_threadpool(monitor.get_active_connections)
                        yield _sse({
                            "type": "connection_update",
                            "timestamp": now_iso,
                            "data": {
                                "connections": connections,
                                "stats": monitor.get_stats(),
                                "count": len(connections),
                            },
                        })
                    except Exception as exc:
                        logger.warning("SSE connection_update failed: %s", exc)

                try:
                    sources = await run_in_threadpool(state.source_manager.list_sources)
                    metrics = await run_in_threadpool(state.source_manager.get_pipeline_metrics)
                    yield _sse({
                        "type": "source_health_update",
                        "timestamp": now_iso,
                        "data": {"sources": sources, "metrics": metrics},
                    })
                except Exception as exc:
                    logger.warning("SSE source_health_update failed: %s", exc)

                try:
                    stats = await run_in_threadpool(state.indexer.get_stats)
                    yield _sse({"type": "metrics_update", "timestamp": now_iso, "data": stats})
                except Exception as exc:
                    logger.warning("SSE metrics_update failed: %s", exc)

            await asyncio.sleep(_POLL_INTERVAL)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
