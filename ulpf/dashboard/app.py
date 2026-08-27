"""
FastAPI Application & REST Backend for ULPF Dashboard.

Serves the read-only dashboard API, static assets, SSE event stream,
REST ingestion endpoints, and analytics anomaly endpoint.
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
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ulpf.core.raw_store import FileRawStore
from ulpf.dashboard.indexer import EventIndexer

logger = logging.getLogger("ulpf.dashboard")


def _default_cors_origins(host: str = "127.0.0.1", port: int = 8000) -> list[str]:
    """
    CORS origins for the dashboard. Configurable via ULPF_CORS_ORIGINS
    (comma-separated). Defaults to the dashboard's own bind address — never
    a wildcard, since wildcard + credentials lets ANY site the analyst's
    browser visits forge write requests (log injection) against this API.
    """
    env_val = os.environ.get("ULPF_CORS_ORIGINS", "").strip()
    if env_val:
        return [o.strip() for o in env_val.split(",") if o.strip()]
    origins = {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}
    if host not in ("0.0.0.0", "127.0.0.1", "localhost"):
        origins.add(f"http://{host}:{port}")
    return sorted(origins)


def _require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    """
    FastAPI dependency gating state-changing endpoints (ingest, reindex,
    live host monitor). Only enforced when ULPF_API_KEY is set in the
    environment — unset means "trusted local single-user demo", matching
    how the dashboard has always been run, but any deployment reachable by
    more than one user or bound to a non-loopback address should set it.
    """
    expected = os.environ.get("ULPF_API_KEY")
    if not expected:
        return
    if not x_api_key or x_api_key != expected:
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key header")

# Pydantic models for ingestion endpoints
class IngestLineRequest(BaseModel):
    line: str
    source_tag: str = "api_ingest"

class IngestBatchRequest(BaseModel):
    lines: list[str]
    source_tag: str = "api_ingest"

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
    # Cleanup on server shutdown
    if "live_monitor" in STATE and STATE["live_monitor"] is not None:
        STATE["live_monitor"].stop()


def create_app(
    output_dir: str | Path | None = None,
    host: str = "127.0.0.1",
    port: int = 8000,
) -> FastAPI:
    """Create and configure the FastAPI application instance."""
    resolved_dir = _resolve_output_dir(output_dir)
    STATE["output_dir"] = resolved_dir
    STATE["indexer"] = EventIndexer(output_dir=resolved_dir)
    STATE["raw_store"] = FileRawStore(resolved_dir / "raw_store")
    STATE["live_monitor"] = None  # Always start with Live OS Monitor OFF by default

    app = FastAPI(
        title="ULPF Operations Dashboard",
        description="Real-time perimeter log visualization and forensic inspection",
        version="1.2.0",
        lifespan=lifespan,
    )

    origins = _default_cors_origins(host, port)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-API-Key"],
    )
    if not os.environ.get("ULPF_API_KEY"):
        logger.warning(
            "ULPF_API_KEY is not set — ingest/reindex/live-monitor endpoints are "
            "UNAUTHENTICATED. Fine for a single-user local demo; set ULPF_API_KEY "
            "before exposing this dashboard beyond localhost or to multiple users."
        )
    logger.info("CORS restricted to origins: %s", origins)

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

    @app.post("/api/reindex", dependencies=[Depends(_require_api_key)])
    async def trigger_reindex():
        """Trigger a complete index rebuild from the raw NDJSON file."""
        indexer: EventIndexer = STATE["indexer"]
        count = indexer.rebuild_index()
        return {"status": "ok", "indexed_events": count}

    # ------------------------------------------------------------------
    # REST Ingestion Endpoints
    # ------------------------------------------------------------------

    def _get_ingest_pipeline():
        """Build a fresh mini-pipeline for API ingestion (reuses output dir)."""
        import ulpf.parsers  # noqa: F401 ensure parsers registered
        from ulpf.core.detector import FormatDetector
        from ulpf.core.normalization import NormalizationEngine
        from ulpf.core.pipeline import Pipeline
        from ulpf.core.validation import Validator
        from ulpf.enrichment.ip_enrichment import IPEnrichmentPlugin
        from ulpf.enrichment.composite import CompositeEnrichment
        from ulpf.sinks.ndjson_file import NDJSONFileSink

        output_dir: Path = STATE["output_dir"]
        schema_dir = Path(__file__).parent.parent / "schemas"
        if not (schema_dir / "ues_schema.json").exists():
            schema_dir = Path.cwd() / "ulpf" / "schemas"

        detector = FormatDetector()
        raw_store = FileRawStore(output_dir / "raw_store")
        norm_engine = NormalizationEngine(schema_dir / "mappings")
        validator = Validator(
            schema_path=schema_dir / "ues_schema.json",
            dead_letter_path=output_dir / "dead_letter.ndjson",
        )
        enrichment = CompositeEnrichment([IPEnrichmentPlugin()])
        sinks = [NDJSONFileSink(output_dir / "events.ndjson")]

        pipeline = Pipeline(
            detector=detector,
            raw_store=raw_store,
            normalization_engine=norm_engine,
            validator=validator,
            sinks=sinks,
            enrichment=enrichment,
        )
        return pipeline, sinks, validator

    @app.post("/api/ingest/line", dependencies=[Depends(_require_api_key)])
    async def ingest_single_line(request: IngestLineRequest):
        """
        Ingest a single raw log line through the full ULPF pipeline.
        Returns processing result with event_id if successful.
        """
        pipeline, sinks, validator = _get_ingest_pipeline()
        ingest_ts = datetime.now(timezone.utc)
        ok = pipeline.process_event(
            raw_line=request.line,
            source_tag=request.source_tag,
            ingest_ts=ingest_ts,
        )
        for sink in sinks:
            sink.flush()
        validator.close()

        # Sync new event into indexer
        indexer: EventIndexer = STATE["indexer"]
        indexer.sync_from_ndjson()

        return {
            "processed": 1 if ok else 0,
            "valid": validator.valid_count,
            "invalid": validator.invalid_count,
            "errors": pipeline._errors,
        }

    @app.post("/api/ingest/batch", dependencies=[Depends(_require_api_key)])
    async def ingest_batch_lines(request: IngestBatchRequest):
        """
        Ingest an array of raw log lines through the full ULPF pipeline.
        Returns aggregate processing stats.
        """
        if not request.lines:
            return {"processed": 0, "valid": 0, "invalid": 0, "errors": 0}

        pipeline, sinks, validator = _get_ingest_pipeline()
        ingest_ts = datetime.now(timezone.utc)

        for line in request.lines:
            if line.strip():
                pipeline.process_event(
                    raw_line=line,
                    source_tag=request.source_tag,
                    ingest_ts=ingest_ts,
                )

        for sink in sinks:
            sink.flush()
        validator.close()

        # Sync new events into indexer
        indexer: EventIndexer = STATE["indexer"]
        indexer.sync_from_ndjson()

        return {
            "processed": pipeline._processed,
            "valid": validator.valid_count,
            "invalid": validator.invalid_count,
            "errors": pipeline._errors,
        }

    @app.post("/api/ingest/stream", dependencies=[Depends(_require_api_key)])
    async def ingest_ndjson_stream(request: Request):
        """
        Ingest a chunked NDJSON stream (one raw log line per line in request body).
        Suitable for large bulk uploads. Returns aggregate stats.
        """
        body = await request.body()
        lines = [ln.decode("utf-8", errors="replace") for ln in body.splitlines() if ln.strip()]

        if not lines:
            return {"processed": 0, "valid": 0, "invalid": 0, "errors": 0}

        pipeline, sinks, validator = _get_ingest_pipeline()
        ingest_ts = datetime.now(timezone.utc)

        for line in lines:
            if line.strip():
                pipeline.process_event(
                    raw_line=line,
                    source_tag="api_stream",
                    ingest_ts=ingest_ts,
                )

        for sink in sinks:
            sink.flush()
        validator.close()

        indexer: EventIndexer = STATE["indexer"]
        indexer.sync_from_ndjson()

        return {
            "processed": pipeline._processed,
            "valid": validator.valid_count,
            "invalid": validator.invalid_count,
            "errors": pipeline._errors,
            "total_lines": len(lines),
        }

    # ------------------------------------------------------------------
    # Analytics Endpoints
    # ------------------------------------------------------------------

    @app.get("/api/analytics/anomalies")
    async def get_anomalies(
        top_n: int = Query(20, ge=1, le=200),
        min_score: float = Query(0.3, ge=0.0, le=1.0),
    ):
        """
        Run anomaly detection over indexed events and return top anomalous events.
        Scores are computed fresh on each call using the rolling baseline.
        """
        from ulpf.analytics.anomaly import AnomalyDetector

        output_dir: Path = STATE["output_dir"]
        events_file = output_dir / "events.ndjson"

        if not events_file.exists():
            return {"anomalies": [], "total_analyzed": 0}

        detector = AnomalyDetector(output_dir=output_dir)
        anomalies = []
        total = 0

        # Two-pass: build baseline, then score
        with open(events_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    detector.update_baseline(event)
                    total += 1
                except Exception:
                    pass

        with open(events_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    annotated = detector.analyze(event)
                    analytics = annotated.get("analytics", {})
                    score = analytics.get("anomaly_score", 0.0)
                    if score >= min_score:
                        anomalies.append({
                            "event_id": annotated.get("event_id"),
                            "anomaly_score": score,
                            "anomaly_reasons": analytics.get("anomaly_reasons", []),
                            "is_anomalous": analytics.get("is_anomalous", False),
                            "ingest_timestamp": annotated.get("ingest_timestamp"),
                            "source": annotated.get("source", {}),
                            "event": annotated.get("event", {}),
                            "network": annotated.get("network", {}),
                        })
                except Exception:
                    pass

        # Sort by score desc and return top_n
        anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)
        return {
            "anomalies": anomalies[:top_n],
            "total_analyzed": total,
            "anomalies_found": len(anomalies),
        }

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
                await asyncio.sleep(0.1)

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
    # Live System Event & Process Monitor Endpoints
    # ------------------------------------------------------------------
    @app.post("/api/live-monitor/start", dependencies=[Depends(_require_api_key)])
    async def start_live_monitor(interval_ms: int = 250):
        """Start real-time OS event and process monitoring (sub-second resolution)."""
        from ulpf.collectors.live_monitor import LiveSystemMonitor

        global LIVE_MONITOR
        if "live_monitor" not in STATE or STATE["live_monitor"] is None:
            STATE["live_monitor"] = LiveSystemMonitor(
                output_dir=STATE["output_dir"],
                interval_ms=interval_ms,
            )
        monitor: LiveSystemMonitor = STATE["live_monitor"]
        if not monitor.is_running():
            monitor.start()

        return {
            "status": "started",
            "message": "Live system event and process monitor is active.",
            **monitor.get_stats(),
        }

    @app.post("/api/live-monitor/stop", dependencies=[Depends(_require_api_key)])
    async def stop_live_monitor():
        """Stop the background OS event and process monitor."""
        if "live_monitor" in STATE and STATE["live_monitor"] is not None:
            STATE["live_monitor"].stop()
            return {
                "status": "stopped",
                "message": "Live system monitor stopped.",
                **STATE["live_monitor"].get_stats(),
            }
        return {"status": "stopped", "running": False, "events_captured": 0}

    @app.get("/api/live-monitor/status")
    async def get_live_monitor_status():
        """Get current live OS monitor status and capture counts."""
        if "live_monitor" in STATE and STATE["live_monitor"] is not None:
            return STATE["live_monitor"].get_stats()
        return {
            "running": False,
            "events_captured": 0,
            "tracked_processes": 0,
            "interval_ms": 250,
            "platform": sys.platform,
        }

    @app.get("/api/live-monitor/events")
    async def get_live_monitor_events(limit: int = 100):
        """Get recent captured live host events from memory buffer (only when active)."""
        if "live_monitor" in STATE and STATE["live_monitor"] is not None:
            if STATE["live_monitor"].is_running():
                return {"events": STATE["live_monitor"].get_recent_events(limit=limit)}
        return {"events": []}

    @app.get("/api/live-monitor/connections")
    async def get_live_monitor_connections():
        """Get currently active process outbound network connections (only when monitor is active)."""
        if "live_monitor" in STATE and STATE["live_monitor"] is not None:
            if STATE["live_monitor"].is_running():
                return {"connections": STATE["live_monitor"].get_active_connections()}
        return {"connections": []}

    @app.get("/api/live-monitor/processes")
    async def get_live_monitor_processes(limit: int = 150):
        """Get snapshot of active running processes (only when monitor is active)."""
        if "live_monitor" in STATE and STATE["live_monitor"] is not None:
            if STATE["live_monitor"].is_running():
                return {"processes": STATE["live_monitor"].get_running_processes(limit=limit)}
        return {"processes": []}


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


def _find_sample_logs_dir() -> Path | None:
    """Find bundled or repository sample_logs directory."""
    candidates = [
        Path(__file__).parent.parent / "sample_logs",
        Path(__file__).parent.parent.parent / "sample_logs",
        Path.cwd() / "ulpf" / "sample_logs",
        Path.cwd() / "sample_logs",
    ]
    for c in candidates:
        if c.exists() and any(c.glob("*.*")):
            return c
    return None


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
@click.option("--open-browser/--no-open-browser", default=True, help="Automatically open browser.")
def main(output_dir: str | None, host: str, port: int, reload: bool, open_browser: bool) -> None:
    """Launch the ULPF Operations Dashboard."""
    import threading
    import webbrowser

    resolved = _resolve_output_dir(output_dir)

    # If events.ndjson is missing or empty, auto-ingest sample logs for turnkey experience
    events_file = resolved / "events.ndjson"
    if not events_file.exists() or events_file.stat().st_size == 0:
        sample_dir = _find_sample_logs_dir()
        if sample_dir:
            click.echo(f"[*] Initializing sample logs from {sample_dir} into {resolved}...")
            try:
                from ulpf.core.ingestion import FileReader
                from ulpf.cli import _build_pipeline, _find_schema_dir, _find_config_dir
                p, s, v = _build_pipeline(
                    output=resolved,
                    schema_dir=_find_schema_dir(),
                    cfg=_find_config_dir() / "sources.yaml",
                    sink_type="ndjson",
                    enrich=True,
                )
                reader = FileReader(str(sample_dir))
                p.run(reader)
                v.close()
                for snk in s:
                    snk.close()
                click.echo(f"[+] Successfully loaded sample logs into {resolved}")
            except Exception as e:
                click.echo(f"[!] Note: Sample log bootstrap skipped ({e})")

    url = f"http://{host}:{port}"
    click.echo(f"============================================================")
    click.echo(f"  ULPF Operations Dashboard running at: {url}")
    click.echo(f"  Connected Output Directory: {resolved.resolve()}")
    click.echo(f"  Press Ctrl+C to stop the dashboard server.")
    click.echo(f"============================================================")

    if open_browser:
        def _launch_browser():
            import time
            time.sleep(1.0)
            webbrowser.open(url)
        threading.Thread(target=_launch_browser, daemon=True).start()

    app_instance = create_app(output_dir=resolved, host=host, port=port)
    uvicorn.run(app_instance, host=host, port=port, reload=reload)


if __name__ == "__main__":
    main()
