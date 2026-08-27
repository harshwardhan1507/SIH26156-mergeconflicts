"""
FastAPI Application & REST Backend for ULPF Dashboard.

Serves the read-only dashboard API, static assets, and SSE event stream.
Uses the SQLite indexer for fast filtering and FileRawStore for O(1) raw lookups.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import click
import uvicorn
from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from ulpf.core.raw_store import FileRawStore
from ulpf.dashboard.indexer import EventIndexer

logger = logging.getLogger("ulpf.dashboard")

# Global state initialized on startup
STATE: dict[str, Any] = {
    "output_dir": Path("output"),
    "indexer": None,
    "raw_store": None,
    "static_dir": Path(__file__).parent / "static",
}


def _resolve_output_dir(configured_dir: str | Path | None = None) -> Path:
    """Find valid output directory, falling back to candidate paths."""
    if configured_dir:
        p = Path(configured_dir)
        if p.exists():
            return p
    candidates = [
        Path(os.environ.get("ULPF_OUTPUT_DIR", "")),
        Path("output"),
        Path("output_demo"),
        Path("output_verify"),
        Path.cwd() / "output",
        Path("/app/output"),
    ]
    for c in candidates:
        if str(c) and c.exists() and (c / "events.ndjson").exists():
            return c
    # Default fallback
    p = Path(configured_dir or "output")
    p.mkdir(parents=True, exist_ok=True)
    return p


@asynccontextmanager
async def lifespan(app: FastAPI):
    output_dir = STATE["output_dir"]
    logger.info("Initializing ULPF Dashboard backend on output_dir=%s", output_dir)
    STATE["indexer"] = EventIndexer(output_dir=output_dir)
    STATE["raw_store"] = FileRawStore(output_dir / "raw_store")

    # Initial sync
    initial_count = STATE["indexer"].sync_from_ndjson()
    logger.info("Initial sync completed: %d records indexed", initial_count)
    yield


def create_app(output_dir: str | Path | None = None) -> FastAPI:
    """Create and configure the FastAPI application instance."""
    resolved_dir = _resolve_output_dir(output_dir)
    STATE["output_dir"] = resolved_dir
    STATE["indexer"] = EventIndexer(output_dir=resolved_dir)
    STATE["raw_store"] = FileRawStore(resolved_dir / "raw_store")

    app = FastAPI(
        title="ULPF Operations Dashboard",
        description="Real-time perimeter log visualization and forensic inspection",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    static_dir = STATE["static_dir"]

    # ------------------------------------------------------------------
    # REST Endpoints
    # ------------------------------------------------------------------

    @app.get("/api/events")
    async def get_events(
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
        start_time: str | None = None,
        end_time: str | None = None,
        sort_by: str = Query("ingest_timestamp"),
        sort_order: str = Query("desc", pattern="^(asc|desc|ASC|DESC)$"),
    ):
        """Retrieve paginated, filterable, and sorted normalized UES events."""
        indexer: EventIndexer = STATE["indexer"]
        return indexer.query_events(
            page=page,
            page_size=page_size,
            search=search,
            vendor=vendor,
            category=category,
            severity_min=severity_min,
            severity_max=severity_max,
            outcome=outcome,
            action=action,
            parser_name=parser_name,
            start_time=start_time,
            end_time=end_time,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    @app.get("/api/events/{event_id}")
    async def get_event_detail(event_id: str):
        """
        Return the full normalized UES event joined with its untouched raw payload
        retrieved directly from the FileRawStore.
        """
        indexer: EventIndexer = STATE["indexer"]
        raw_store: FileRawStore = STATE["raw_store"]

        event = indexer.get_event_by_id(event_id)
        if not event:
            raise HTTPException(status_code=404, detail=f"Event {event_id} not found in index")

        raw_payload = raw_store.get(event_id)
        if raw_payload is None:
            # Fallback to embedded payload if available
            raw_payload = event.get("raw", {}).get("raw_payload", "")

        return {
            "event_id": event_id,
            "normalized": event,
            "raw_payload": raw_payload,
            "raw_hash": event.get("raw", {}).get("raw_hash", ""),
            "raw_format": event.get("raw", {}).get("raw_format", "unknown"),
            "parser_name": event.get("lineage", {}).get("parser_name", "unknown"),
        }

    @app.get("/api/dead-letter")
    async def get_dead_letter(
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
    ):
        """Return paginated dead-letter records with validation failure details."""
        indexer: EventIndexer = STATE["indexer"]
        return indexer.get_dead_letter_records(page=page, page_size=page_size)

    @app.get("/api/parsers")
    async def get_parsers():
        """List registered parser plugins with versions and indexed event counts."""
        indexer: EventIndexer = STATE["indexer"]
        return {"parsers": indexer.get_parsers_health()}

    @app.get("/api/stats")
    async def get_stats():
        """Aggregated summary statistics for metric cards and distributions."""
        indexer: EventIndexer = STATE["indexer"]
        return indexer.get_stats()

    @app.get("/api/export")
    async def export_data(
        format: str = Query("json", pattern="^(json|csv)$"),
        search: str | None = None,
        vendor: str | None = None,
        category: str | None = None,
        outcome: str | None = None,
    ):
        """Stream export of filtered events as CSV or NDJSON."""
        indexer: EventIndexer = STATE["indexer"]
        generator = indexer.export_events(
            export_format=format,
            search=search,
            vendor=vendor,
            category=category,
            outcome=outcome,
        )
        media_type = "text/csv" if format == "csv" else "application/x-ndjson"
        filename = f"ulpf_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"
        headers = {"Content-Disposition": f"attachment; filename={filename}"}
        return StreamingResponse(generator, media_type=media_type, headers=headers)

    @app.post("/api/reindex")
    async def trigger_reindex():
        """Trigger a complete index rebuild from the raw NDJSON file."""
        indexer: EventIndexer = STATE["indexer"]
        count = indexer.rebuild_index()
        return {"status": "ok", "indexed_events": count}

    @app.get("/api/stream")
    async def stream_events():
        """
        Server-Sent Events (SSE) stream pushing newly ingested events in real time.
        """
        ndjson_path = STATE["output_dir"] / "events.ndjson"

        async def event_generator():
            last_pos = ndjson_path.stat().st_size if ndjson_path.exists() else 0
            while True:
                if ndjson_path.exists():
                    current_size = ndjson_path.stat().st_size
                    if current_size > last_pos:
                        with open(ndjson_path, "r", encoding="utf-8", errors="replace") as f:
                            f.seek(last_pos)
                            for line in f:
                                line_str = line.strip()
                                if line_str:
                                    try:
                                        # Parse and sync
                                        event_data = json.loads(line_str)
                                        yield f"data: {json.dumps(event_data)}\n\n"
                                    except Exception:
                                        pass
                            last_pos = f.tell()
                await asyncio.sleep(1.5)

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    # ------------------------------------------------------------------
    # Frontend Static File Serving
    # ------------------------------------------------------------------
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

        @app.get("/")
        async def serve_index():
            index_file = static_dir / "index.html"
            if index_file.exists():
                return FileResponse(index_file)
            return Response(content="<h1>ULPF Dashboard</h1><p>index.html not found</p>", media_type="text/html")

    return app


app = create_app()


@click.command("ulpf-dashboard")
@click.option(
    "--output-dir",
    "-o",
    "output_dir",
    default=None,
    help="Path to pipeline output directory containing events.ndjson and raw_store/.",
)
@click.option("--host", "-h", default="127.0.0.1", help="Bind host address.")
@click.option("--port", "-p", default=8000, type=int, help="Bind port number.")
@click.option("--reload", is_flag=True, default=False, help="Enable auto-reload.")
def main(output_dir: str | None, host: str, port: int, reload: bool) -> None:
    """Launch the ULPF Operations Dashboard."""
    resolved = _resolve_output_dir(output_dir)
    click.echo(f"Starting ULPF Dashboard on http://{host}:{port} [output={resolved}]")
    app_instance = create_app(output_dir=resolved)
    uvicorn.run(app_instance, host=host, port=port, reload=reload)


if __name__ == "__main__":
    main()
