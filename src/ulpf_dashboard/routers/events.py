"""
Read-only event, dead-letter, parser, and export endpoints.

These handlers are declared with ``def`` rather than ``async def`` on purpose:
they perform blocking SQLite and file I/O, and FastAPI runs sync handlers in a
worker thread. Declaring them ``async`` would run that blocking work directly on
the event loop, stalling every other request and the SSE stream along with it.
"""
from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from ulpf.crosswalk.ecs import to_ecs
from ulpf.crosswalk.ocsf import to_ocsf
from ulpf_dashboard.security import require_api_key
from ulpf_dashboard.state import AppState, get_state

router = APIRouter(prefix="/api", tags=["events"])

State = Annotated[AppState, Depends(get_state)]


@router.get("/events")
def list_events(
    state: State,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    search: str | None = None,
    vendor: str | None = None,
    category: str | None = None,
    severity_min: float | None = None,
    severity_max: float | None = None,
    outcome: str | None = None,
    action: str | None = None,
    parser_name: str | None = None,
    tenant_id: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    sort_by: str = Query("ingest_timestamp"),
    sort_order: str = Query("desc", pattern="^(?i:asc|desc)$"),
):
    """Paginated, filterable, sorted normalized UES events."""
    return state.indexer.query_events(
        page=page, page_size=page_size, search=search, vendor=vendor,
        category=category, severity_min=severity_min, severity_max=severity_max,
        outcome=outcome, action=action, parser_name=parser_name,
        tenant_id=tenant_id, start_time=start_time, end_time=end_time,
        sort_by=sort_by, sort_order=sort_order,
    )


@router.get("/events/{event_id}")
def get_event_detail(event_id: str, state: State):
    """A normalized event joined with its untouched raw payload from the raw store."""
    event = state.indexer.get_event_by_id(event_id)
    if not event:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found in index")

    raw = event.get("raw") or {}
    raw_payload = state.raw_store.get(event_id)
    if raw_payload is None:
        # The raw store is authoritative; the embedded copy is the fallback for
        # events indexed before the store existed.
        raw_payload = raw.get("raw_payload", "")

    return {
        "event_id": event_id,
        "normalized": event,
        "raw_payload": raw_payload,
        "raw_hash": raw.get("raw_hash", ""),
        "raw_format": raw.get("raw_format", "unknown"),
        "parser_name": (event.get("lineage") or {}).get("parser_name", "unknown"),
    }


@router.get("/events/{event_id}/crosswalk")
def get_event_crosswalk(
    event_id: str,
    state: State,
    format: str = Query("all", pattern="^(all|ocsf|ecs)$"),
):
    """Translate an indexed event into OCSF and/or ECS."""
    event = state.indexer.get_event_by_id(event_id)
    if not event:
        raise HTTPException(status_code=404, detail=f"Event {event_id!r} not found")
    if format == "ocsf":
        return {"ocsf": to_ocsf(event)}
    if format == "ecs":
        return {"ecs": to_ecs(event)}
    return {"ocsf": to_ocsf(event), "ecs": to_ecs(event)}


@router.get("/dead-letter")
def get_dead_letter(
    state: State,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    """Paginated dead-letter records with failure details."""
    return state.indexer.get_dead_letter_records(page=page, page_size=page_size)


@router.get("/parsers")
def get_parsers(state: State):
    """Registered parser plugins with versions and indexed event counts."""
    return {"parsers": state.indexer.get_parsers_health()}


@router.get("/stats")
def get_stats(state: State, tenant_id: str | None = None):
    """Aggregated summary statistics for metric cards and distributions."""
    return state.indexer.get_stats(tenant_id=tenant_id)


@router.get("/export")
def export_data(
    state: State,
    format: str = Query("json", pattern="^(json|csv)$"),
    search: str | None = None,
    vendor: str | None = None,
    category: str | None = None,
    outcome: str | None = None,
    tenant_id: str | None = None,
):
    """Stream filtered events as CSV or NDJSON."""
    generator = state.indexer.export_events(
        export_format=format, search=search, vendor=vendor,
        category=category, outcome=outcome, tenant_id=tenant_id,
    )
    filename = f"ulpf_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"
    return StreamingResponse(
        generator,
        media_type="text/csv" if format == "csv" else "application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/reindex", dependencies=[Depends(require_api_key)])
def trigger_reindex(state: State):
    """Drop and rebuild the SQLite index from the NDJSON source of truth."""
    return {"status": "ok", "indexed_events": state.indexer.rebuild_index()}
