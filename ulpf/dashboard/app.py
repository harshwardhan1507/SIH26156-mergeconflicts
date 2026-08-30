"""
FastAPI Application & REST Backend for ULPF Dashboard.

Serves the read-only dashboard API, static assets, SSE event stream,
REST ingestion endpoints, and analytics anomaly endpoint.
Uses the SQLite indexer for fast filtering and FileRawStore for O(1) raw lookups.
"""
from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import sys
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

# Safe Null stream for windowed GUI or daemon modes where sys.stdout/stderr may be None
class SafeStream:
    """Safe stream wrapper preventing AttributeError/UnsupportedOperation in GUI/daemon modes."""
    def write(self, text: str) -> int:
        return len(text)
    def flush(self) -> None:
        pass
    def isatty(self) -> bool:
        return False
    def fileno(self) -> int:
        raise io.UnsupportedOperation("No fileno in GUI/headless mode")

if sys.stdout is None:
    sys.stdout = SafeStream()
if sys.stderr is None:
    sys.stderr = SafeStream()
if sys.stdin is None:
    sys.stdin = io.StringIO()

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
    tenant_id: str = "default"

class IngestBatchRequest(BaseModel):
    lines: list[str]
    source_tag: str = "api_ingest"
    tenant_id: str = "default"

class DeclarativeSourceRequest(BaseModel):
    config: dict[str, Any]

class TestSourceRequest(BaseModel):
    config: dict[str, Any]
    sample_event: str
    tenant_id: str = "default"

class InferSourceRequest(BaseModel):
    sample_event: str
    name_hint: str = "custom_source"

class CrosswalkRequest(BaseModel):
    event: dict[str, Any]

# Global state initialized on startup
STATE: dict[str, Any] = {
    "output_dir": Path("output"),
    "indexer": None,
    "raw_store": None,
    "source_manager": None,
    "static_dir": Path(__file__).parent / "static",
}


def _get_user_data_dir() -> Path:
    """Get a user-writable application data directory across OS platforms."""
    if sys.platform == "win32":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data) / "ULPF" / "output"
        return Path.home() / ".ulpf" / "output"
    elif sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "ULPF" / "output"
    return Path.home() / ".local" / "share" / "ulpf" / "output"


def _resolve_output_dir(configured_dir: str | Path | None = None) -> Path:
    """Find valid output directory, falling back to candidate paths and user data dir."""
    if configured_dir:
        p = Path(configured_dir)
        try:
            p.mkdir(parents=True, exist_ok=True)
            return p
        except (PermissionError, OSError):
            pass

    env_dir = os.environ.get("ULPF_OUTPUT_DIR", "").strip()
    if env_dir:
        p = Path(env_dir)
        try:
            p.mkdir(parents=True, exist_ok=True)
            return p
        except (PermissionError, OSError):
            pass

    candidates = [
        Path("output"),
        Path("output_demo"),
        Path("output_verify"),
        Path.cwd() / "output",
        Path("/app/output"),
    ]
    for c in candidates:
        try:
            if str(c) and c.exists() and (c / "events.ndjson").exists():
                return c
        except Exception:
            pass

    # Try default relative output directory
    try:
        p = Path(configured_dir or "output")
        p.mkdir(parents=True, exist_ok=True)
        # Test write permission
        test_file = p / ".write_test"
        test_file.touch()
        test_file.unlink()
        return p
    except (PermissionError, OSError):
        # Fallback to user-writable profile directory
        user_dir = _get_user_data_dir()
        user_dir.mkdir(parents=True, exist_ok=True)
        return user_dir


def _write_pid_file(output_dir: Path, host: str, port: int) -> None:
    """Record running server metadata and PID for status and graceful stopping."""
    try:
        pid_file = output_dir / "ulpf_dashboard.pid"
        data = {
            "pid": os.getpid(),
            "host": host,
            "port": port,
            "start_time": datetime.now(timezone.utc).isoformat(),
        }
        with open(pid_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logger.debug("Could not write PID file: %s", e)


def _remove_pid_file(output_dir: Path) -> None:
    """Remove server PID file upon clean shutdown."""
    try:
        pid_file = output_dir / "ulpf_dashboard.pid"
        if pid_file.exists():
            pid_file.unlink()
    except Exception as e:
        logger.debug("Could not remove PID file: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    output_dir = STATE["output_dir"]
    host = STATE.get("host", "127.0.0.1")
    port = STATE.get("port", 8000)
    _write_pid_file(output_dir, host, port)

    logger.info("Initializing ULPF Dashboard backend on output_dir=%s", output_dir)
    from ulpf.core.source_manager import SourceManager
    STATE["indexer"] = EventIndexer(output_dir=output_dir)
    STATE["raw_store"] = FileRawStore(output_dir / "raw_store")
    STATE["source_manager"] = SourceManager(output_dir=output_dir)

    # Initial sync
    initial_count = STATE["indexer"].sync_from_ndjson()
    logger.info("Initial sync completed: %d records indexed", initial_count)
    yield
    # Cleanup on server shutdown
    if "live_monitor" in STATE and STATE["live_monitor"] is not None:
        STATE["live_monitor"].stop()
    _remove_pid_file(output_dir)


def create_app(
    output_dir: str | Path | None = None,
    host: str = "127.0.0.1",
    port: int = 8000,
) -> FastAPI:
    """Create and configure the FastAPI application instance."""
    resolved_dir = _resolve_output_dir(output_dir)
    STATE["output_dir"] = resolved_dir
    STATE["host"] = host
    STATE["port"] = port
    from ulpf.core.source_manager import SourceManager
    STATE["indexer"] = EventIndexer(output_dir=resolved_dir)
    STATE["raw_store"] = FileRawStore(resolved_dir / "raw_store")
    STATE["source_manager"] = SourceManager(output_dir=resolved_dir)
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
        action: str | None = None,
        parser_name: str | None = None,
        tenant_id: str | None = None,
    ):
        """Stream export of filtered events as CSV or formatted nested JSON."""
        indexer: EventIndexer = STATE["indexer"]
        generator = indexer.export_events(
            export_format=format,
            search=search,
            vendor=vendor,
            category=category,
            outcome=outcome,
            action=action,
            parser_name=parser_name,
            tenant_id=tenant_id,
        )
        media_type = "text/csv" if format == "csv" else "application/json"
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
    # Source Management & Observability Endpoints
    # ------------------------------------------------------------------

    @app.get("/api/sources")
    async def list_sources():
        """List all registered log sources with real-time operational telemetry."""
        sm: SourceManager = STATE["source_manager"]
        sources = sm.list_sources()
        metrics = sm.get_pipeline_metrics()
        return {
            "sources": sources,
            "metrics": metrics,
        }

    @app.post("/api/sources", dependencies=[Depends(_require_api_key)])
    async def create_declarative_source(req: DeclarativeSourceRequest):
        """Register, validate, and activate a new declarative log source."""
        sm: SourceManager = STATE["source_manager"]
        success, errors, src = sm.register_declarative_source(req.config)
        if not success:
            raise HTTPException(status_code=400, detail={"message": "Invalid source configuration", "errors": errors})
        return {"status": "ok", "source": src}

    @app.get("/api/sources/{source_id}")
    async def get_source_detail(source_id: str):
        """Get source definition and stats by source_id."""
        sm: SourceManager = STATE["source_manager"]
        src = sm.get_source(source_id)
        if not src:
            raise HTTPException(status_code=404, detail=f"Source '{source_id}' not found")
        return {"source": src}

    @app.delete("/api/sources/{source_id}", dependencies=[Depends(_require_api_key)])
    async def delete_source(source_id: str):
        """Delete a declarative source definition."""
        sm: SourceManager = STATE["source_manager"]
        success = sm.delete_source(source_id)
        if not success:
            raise HTTPException(status_code=404, detail=f"Source '{source_id}' not found or cannot be deleted")
        return {"status": "ok", "deleted": source_id}

    @app.post("/api/sources/{source_id}/enable", dependencies=[Depends(_require_api_key)])
    async def enable_source(source_id: str):
        """Enable a log source."""
        sm: SourceManager = STATE["source_manager"]
        sm.set_source_enabled(source_id, True)
        return {"status": "ok", "source_id": source_id, "enabled": True}

    @app.post("/api/sources/{source_id}/disable", dependencies=[Depends(_require_api_key)])
    async def disable_source(source_id: str):
        """Disable a log source."""
        sm: SourceManager = STATE["source_manager"]
        sm.set_source_enabled(source_id, False)
        return {"status": "ok", "source_id": source_id, "enabled": False}

    @app.post("/api/sources/infer")
    async def infer_source_mapping(req: InferSourceRequest):
        """Infer draft declarative configuration YAML from a sample log line."""
        from ulpf.core.declarative import infer_declarative_mapping
        if not req.sample_event or not req.sample_event.strip():
            raise HTTPException(status_code=400, detail="Sample event string is required")
        draft = infer_declarative_mapping(req.sample_event, req.name_hint)
        return {"draft_config": draft}

    @app.post("/api/sources/test")
    async def test_declarative_source(req: TestSourceRequest):
        """
        Test a sample raw log event against a declarative configuration.
        Returns validation result, extracted fields, normalized UES event, unmapped attributes, and SHA-256.
        """
        from ulpf.core.declarative import DeclarativeSourceParser, validate_declarative_config
        import hashlib
        import uuid

        valid, errors = validate_declarative_config(req.config)
        if not valid:
            return {
                "valid": False,
                "errors": errors,
                "warnings": [],
                "detected_format": req.config.get("log_format", "unknown"),
                "extracted_fields": {},
                "normalized_event": {},
                "vendor_attributes": {},
            }

        sample = req.sample_event.strip()
        raw_b = sample.encode("utf-8", errors="surrogateescape")
        raw_hash = hashlib.sha256(raw_b).hexdigest()
        event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"ulpf:{req.tenant_id}:{req.config.get('name')}:{raw_hash}"))

        parser = DeclarativeSourceParser(req.config)
        is_match = parser.match(sample)

        warnings = []
        if not is_match:
            warnings.append("Detection rule did not match the provided sample event.")

        try:
            extracted = parser.extract(sample)
        except Exception as e:
            return {
                "valid": False,
                "errors": [f"Extraction failed: {e}"],
                "warnings": warnings,
                "detected_format": parser.log_format,
                "extracted_fields": {},
                "normalized_event": {},
                "vendor_attributes": {},
                "raw_hash": raw_hash,
                "event_id": event_id,
            }

        try:
            normalized_core = parser.build_normalized_event(extracted)
        except Exception as e:
            return {
                "valid": False,
                "errors": [f"Normalization failed: {e}"],
                "warnings": warnings,
                "detected_format": parser.log_format,
                "extracted_fields": extracted,
                "normalized_event": {},
                "vendor_attributes": {},
                "raw_hash": raw_hash,
                "event_id": event_id,
            }

        # Build full UES dictionary
        now_iso = datetime.now(timezone.utc).isoformat()
        ues_event = {
            "schema_version": "1.2.0",
            "tenant_id": req.tenant_id,
            "event_id": event_id,
            "ingest_timestamp": now_iso,
            "source_event_timestamp": extracted.get("timestamp_dt") or now_iso,
            "raw": {
                "raw_payload": sample,
                "raw_format": parser.log_format,
                "raw_hash": raw_hash,
            },
            "source": normalized_core["source"],
            "event": normalized_core["event"],
            "network": normalized_core.get("network"),
            "identity": normalized_core.get("identity"),
            "rule": normalized_core.get("rule"),
            "vendor_attributes": normalized_core.get("vendor_attributes", {}),
            "lineage": {
                "parser_name": parser.name,
                "parser_version": parser.version,
                "normalization_ruleset_version": parser.version,
            },
        }

        # Validate with UES schema validator
        schema_path = Path(__file__).parent.parent / "schemas" / "ues_schema.json"
        from ulpf.core.validation import Validator
        val = Validator(schema_path=schema_path, dead_letter_path=Path(STATE["output_dir"]) / "temp_dl.ndjson")
        is_schema_valid, schema_errors = val.validate(ues_event)
        val.close()

        return {
            "valid": is_schema_valid and len(errors) == 0,
            "matched_detection": is_match,
            "errors": schema_errors,
            "warnings": warnings,
            "detected_format": parser.log_format,
            "extracted_fields": extracted,
            "normalized_event": ues_event,
            "vendor_attributes": normalized_core.get("vendor_attributes", {}),
            "raw_hash": raw_hash,
            "event_id": event_id,
        }

    # ------------------------------------------------------------------
    # Crosswalk Translation Endpoints
    # ------------------------------------------------------------------

    @app.post("/api/events/crosswalk")
    async def translate_event_crosswalk(req: CrosswalkRequest):
        """Translate a UES event dict to OCSF and ECS representations."""
        from ulpf.crosswalk.ocsf import to_ocsf
        from ulpf.crosswalk.ecs import to_ecs

        event = req.event
        return {
            "ocsf": to_ocsf(event),
            "ecs": to_ecs(event),
        }

    @app.get("/api/events/{event_id}/crosswalk")
    async def get_event_crosswalk(event_id: str, format: str = Query("all", pattern="^(all|ocsf|ecs)$")):
        """Fetch indexed event and return OCSF/ECS crosswalk translation."""
        from ulpf.crosswalk.ocsf import to_ocsf
        from ulpf.crosswalk.ecs import to_ecs

        indexer: EventIndexer = STATE["indexer"]
        event = indexer.get_event_by_id(event_id)
        if not event:
            raise HTTPException(status_code=404, detail=f"Event '{event_id}' not found")

        if format == "ocsf":
            return {"ocsf": to_ocsf(event)}
        elif format == "ecs":
            return {"ecs": to_ecs(event)}
        return {
            "ocsf": to_ocsf(event),
            "ecs": to_ecs(event),
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
        Server-Sent Events (SSE) stream pushing newly ingested events,
        connection telemetry, and source health metrics in real time.
        """
        ndjson_path = STATE["output_dir"] / "events.ndjson"

        async def event_generator():
            last_pos = ndjson_path.stat().st_size if ndjson_path.exists() else 0
            tick_counter = 0

            while True:
                now_iso = datetime.now(timezone.utc).isoformat()

                # 1. Stream new ingested events
                if ndjson_path.exists():
                    current_size = ndjson_path.stat().st_size
                    if current_size > last_pos:
                        with open(ndjson_path, "r", encoding="utf-8", errors="replace") as f:
                            f.seek(last_pos)
                            for line in f:
                                line_str = line.strip()
                                if line_str:
                                    try:
                                        event_data = json.loads(line_str)
                                        # Yield typed envelope
                                        envelope = {
                                            "type": "event_ingested",
                                            "timestamp": now_iso,
                                            "data": event_data,
                                        }
                                        yield f"data: {json.dumps(envelope)}\n\n"
                                    except Exception:
                                        pass
                            last_pos = f.tell()

                # 2. Periodic state broadcasts (~every 1.5s, 15 ticks of 0.1s)
                tick_counter += 1
                if tick_counter >= 15:
                    tick_counter = 0

                    # 2a. Live Connection updates if monitor is active
                    if "live_monitor" in STATE and STATE["live_monitor"] is not None:
                        monitor = STATE["live_monitor"]
                        if monitor.is_running():
                            try:
                                conns = monitor.get_active_connections()
                                stats = monitor.get_stats()
                                conn_envelope = {
                                    "type": "connection_update",
                                    "timestamp": now_iso,
                                    "data": {
                                        "connections": conns,
                                        "stats": stats,
                                        "count": len(conns),
                                    },
                                }
                                yield f"data: {json.dumps(conn_envelope)}\n\n"
                            except Exception as e:
                                logger.warning(f"SSE connection_update failed: {e}")

                    # 2b. Source health & metrics update
                    if "source_manager" in STATE and STATE["source_manager"] is not None:
                        try:
                            sm = STATE["source_manager"]
                            sources_envelope = {
                                "type": "source_health_update",
                                "timestamp": now_iso,
                                "data": {
                                    "sources": sm.list_sources(),
                                    "metrics": sm.get_pipeline_metrics(),
                                },
                            }
                            yield f"data: {json.dumps(sources_envelope)}\n\n"
                        except Exception as e:
                            logger.warning(f"SSE source_health_update failed: {e}")

                    # 2c. Overall dashboard stats update
                    if "indexer" in STATE and STATE["indexer"] is not None:
                        try:
                            idx = STATE["indexer"]
                            stats_envelope = {
                                "type": "metrics_update",
                                "timestamp": now_iso,
                                "data": idx.get_stats(),
                            }
                            yield f"data: {json.dumps(stats_envelope)}\n\n"
                        except Exception as e:
                            logger.warning(f"SSE metrics_update failed: {e}")

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
            "tracked_connections": 0,
            "interval_ms": 250,
            "platform": sys.platform,
            "permission_error": None,
            "scan_status": "stopped",
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
            monitor = STATE["live_monitor"]
            if monitor.is_running():
                return {
                    "connections": monitor.get_active_connections(),
                    "stats": monitor.get_stats(),
                    "running": True,
                    "permission_error": monitor.permission_error,
                }
        return {
            "connections": [],
            "stats": {"running": False, "tracked_connections": 0},
            "running": False,
            "permission_error": None,
        }

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


def _is_ulpf_running(host: str = "127.0.0.1", port: int = 8000) -> bool:
    """Check if an instance of ULPF dashboard is already listening and responsive."""
    import urllib.request
    check_host = "127.0.0.1" if host in ("0.0.0.0", "::", "localhost") else host
    try:
        url = f"http://{check_host}:{port}/api/stats"
        req = urllib.request.Request(url, headers={"User-Agent": "ULPF-Launcher"})
        with urllib.request.urlopen(req, timeout=1.0) as resp:
            return resp.status == 200
    except Exception:
        return False


def _wait_for_server(host: str = "127.0.0.1", port: int = 8000, timeout: float = 6.0) -> bool:
    """Poll until the FastAPI server is accepting connections."""
    import time
    start = time.time()
    check_host = "127.0.0.1" if host in ("0.0.0.0", "::", "localhost") else host
    while time.time() - start < timeout:
        if _is_ulpf_running(check_host, port):
            return True
        time.sleep(0.1)
    return False


def _find_available_port(host: str = "127.0.0.1", start_port: int = 8000, max_attempts: int = 50) -> int:
    """Find the first open TCP port starting from start_port."""
    import socket
    for p in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, p))
                return p
            except OSError:
                continue
    return start_port


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

    check_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host

    # 1. Check if ULPF dashboard is already running on this port
    if _is_ulpf_running(host, port):
        url = f"http://{check_host}:{port}"
        click.echo(f"============================================================")
        click.echo(f"  [+] ULPF Operations Dashboard is ALREADY running at: {url}")
        click.echo(f"  Connected Output Directory: {resolved.resolve()}")
        click.echo(f"  Opened active dashboard in your browser!")
        click.echo(f"============================================================")
        if open_browser:
            webbrowser.open(url)
        return

    # 2. Check if port is occupied by another process, switch to open port automatically
    import socket
    original_port = port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
        except OSError:
            port = _find_available_port(host, start_port=port + 1)
            click.echo(f"[*] Port {original_port} is in use. Switched to available port: {port}")

    url = f"http://{check_host}:{port}"
    click.echo(f"============================================================")
    click.echo(f"  ULPF Operations Dashboard running at: {url}")
    click.echo(f"  Connected Output Directory: {resolved.resolve()}")
    click.echo(f"  Press Ctrl+C to stop the dashboard server.")
    click.echo(f"============================================================")

    if open_browser:
        def _launch_browser():
            _wait_for_server(check_host, port, timeout=6.0)
            webbrowser.open(url)
        threading.Thread(target=_launch_browser, daemon=True).start()

    app_instance = create_app(output_dir=resolved, host=host, port=port)
    
    # Check if stdout/stderr are interactive or if we need safe logging
    use_safe_log = (sys.stdout is None) or (not hasattr(sys.stdout, "isatty")) or (not sys.stdout.isatty())
    config = uvicorn.Config(
        app=app_instance,
        host=host,
        port=port,
        reload=reload,
        log_config=None if use_safe_log else uvicorn.config.LOGGING_CONFIG,
        log_level="info",
    )
    server = uvicorn.Server(config=config)
    server.run()


if __name__ == "__main__":
    main()
