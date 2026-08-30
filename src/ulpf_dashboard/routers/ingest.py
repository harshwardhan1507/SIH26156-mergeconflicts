"""
REST ingestion endpoints.

All three share one long-lived pipeline from :meth:`AppState.ingest_session`.
Building a pipeline per request re-read every YAML mapping, recompiled the JSON
Schema, and opened a fresh pair of file handles each time — for a single line.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ulpf_dashboard.security import require_api_key
from ulpf_dashboard.state import AppState, get_state

router = APIRouter(prefix="/api/ingest", tags=["ingest"], dependencies=[Depends(require_api_key)])

State = Annotated[AppState, Depends(get_state)]

#: Upper bound on a single batch or streamed body, so one request cannot pin an
#: unbounded amount of memory.
MAX_BATCH_LINES = 10_000
MAX_STREAM_BYTES = 32 * 1024 * 1024


class IngestLineRequest(BaseModel):
    """A single raw log line to push through the pipeline."""

    line: str = Field(min_length=1)
    source_tag: str = "api_ingest"
    tenant_id: str = "default"


class IngestBatchRequest(BaseModel):
    """A batch of raw log lines."""

    lines: list[str] = Field(default_factory=list, max_length=MAX_BATCH_LINES)
    source_tag: str = "api_ingest"
    tenant_id: str = "default"


def _run(state: AppState, lines: list[str], source_tag: str, tenant_id: str) -> dict[str, int]:
    """Push lines through the shared pipeline and resync the index."""
    session = state.ingest_session()
    before = session.stats()
    ingest_ts = datetime.now(UTC)

    for line in lines:
        if line.strip():
            session.process_event(
                raw_line=line,
                source_tag=source_tag,
                ingest_ts=ingest_ts,
                tenant_id=tenant_id,
            )

    # Flush, never close: the session outlives the request.
    session.flush()
    state.indexer.sync_from_ndjson()

    after = session.stats()
    return {key: after[key] - before[key] for key in after}


@router.post("/line")
def ingest_single_line(request: IngestLineRequest, state: State):
    """Ingest one raw log line."""
    return _run(state, [request.line], request.source_tag, request.tenant_id)


@router.post("/batch")
def ingest_batch_lines(request: IngestBatchRequest, state: State):
    """Ingest an array of raw log lines."""
    if not request.lines:
        return {"processed": 0, "valid": 0, "invalid": 0, "errors": 0}
    return _run(state, request.lines, request.source_tag, request.tenant_id)


@router.post("/stream")
async def ingest_ndjson_stream(request: Request, state: State):
    """
    Ingest a newline-delimited body — one raw log line per line.

    The body is read on the event loop (that part is genuinely async), then the
    blocking pipeline work is handed to a worker thread.
    """
    from starlette.concurrency import run_in_threadpool

    body = await request.body()
    if len(body) > MAX_STREAM_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Body exceeds the {MAX_STREAM_BYTES} byte ingest limit",
        )

    lines = [ln.decode("utf-8", errors="replace") for ln in body.splitlines() if ln.strip()]
    if not lines:
        return {"processed": 0, "valid": 0, "invalid": 0, "errors": 0, "total_lines": 0}

    stats = await run_in_threadpool(_run, state, lines, "api_stream", "default")
    return {**stats, "total_lines": len(lines)}
