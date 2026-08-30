"""Log source management: listing, no-code onboarding, testing, and inference."""
from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi import Path as PathParam
from pydantic import BaseModel, Field

from ulpf import resources
from ulpf.core.declarative import DeclarativeSourceParser, validate_declarative_config
from ulpf.core.validation import Validator
from ulpf_dashboard.security import require_api_key
from ulpf_dashboard.state import AppState, get_state

router = APIRouter(prefix="/api/sources", tags=["sources"])

State = Annotated[AppState, Depends(get_state)]

#: Mirrors the ``name`` pattern in the declarative source JSON Schema. Applied
#: to path parameters so a source id can never become a path fragment.
SOURCE_ID = PathParam(pattern=r"^[a-zA-Z0-9_-]+$", max_length=128)


class DeclarativeSourceRequest(BaseModel):
    """A declarative source configuration to register."""

    config: dict[str, Any]


class TestSourceRequest(BaseModel):
    """A configuration plus a sample event to dry-run it against."""

    config: dict[str, Any]
    sample_event: str = Field(min_length=1)
    tenant_id: str = "default"


class InferSourceRequest(BaseModel):
    """A sample event from which to infer a draft configuration."""

    sample_event: str = Field(min_length=1)
    name_hint: str = "custom_source"


@router.get("")
def list_sources(state: State):
    """All registered log sources with operational telemetry."""
    return {
        "sources": state.source_manager.list_sources(),
        "metrics": state.source_manager.get_pipeline_metrics(),
    }


@router.post("", dependencies=[Depends(require_api_key)])
def create_declarative_source(req: DeclarativeSourceRequest, state: State):
    """Validate, persist, and activate a new declarative log source."""
    ok, errors, source = state.source_manager.register_declarative_source(req.config)
    if not ok:
        raise HTTPException(
            status_code=400,
            detail={"message": "Invalid source configuration", "errors": errors},
        )
    return {"status": "ok", "source": source}


@router.post("/infer")
def infer_source_mapping(req: InferSourceRequest):
    """Infer a draft declarative configuration from a sample log line."""
    from ulpf.core.declarative import infer_declarative_mapping

    return {"draft_config": infer_declarative_mapping(req.sample_event, req.name_hint)}


@router.post("/test")
def test_declarative_source(req: TestSourceRequest, state: State):
    """
    Dry-run a configuration against a sample event.

    Returns the extracted fields, the normalized UES event, schema validation
    results, and the payload hash — without registering anything.
    """
    valid, errors = validate_declarative_config(req.config)
    base = {
        "valid": False,
        "warnings": [],
        "detected_format": req.config.get("log_format", "unknown"),
        "extracted_fields": {},
        "normalized_event": {},
        "vendor_attributes": {},
    }
    if not valid:
        return {**base, "errors": errors}

    sample = req.sample_event.strip()
    raw_hash = hashlib.sha256(sample.encode("utf-8", errors="surrogateescape")).hexdigest()
    event_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"ulpf:{req.tenant_id}:{req.config.get('name')}:{raw_hash}",
        )
    )

    parser = DeclarativeSourceParser(req.config)
    matched = parser.match(sample)
    warnings = [] if matched else ["Detection rule did not match the provided sample event."]
    base = {**base, "detected_format": parser.log_format, "warnings": warnings,
            "raw_hash": raw_hash, "event_id": event_id}

    try:
        extracted = parser.extract(sample)
    except Exception as exc:
        return {**base, "errors": [f"Extraction failed: {exc}"]}

    try:
        normalized = parser.build_normalized_event(extracted)
    except Exception as exc:
        return {**base, "errors": [f"Normalization failed: {exc}"], "extracted_fields": extracted}

    now_iso = datetime.now(UTC).isoformat()
    ues_event = {
        "schema_version": "1.2.0",
        "tenant_id": req.tenant_id,
        "event_id": event_id,
        "ingest_timestamp": now_iso,
        "source_event_timestamp": extracted.get("timestamp_dt") or now_iso,
        "raw": {"raw_payload": sample, "raw_format": parser.log_format, "raw_hash": raw_hash},
        "source": normalized["source"],
        "event": normalized["event"],
        "network": normalized.get("network"),
        "identity": normalized.get("identity"),
        "rule": normalized.get("rule"),
        "vendor_attributes": normalized.get("vendor_attributes", {}),
        "lineage": {
            "parser_name": parser.name,
            "parser_version": parser.version,
            "normalization_ruleset_version": parser.version,
        },
    }

    # A dry run must not append to the operational dead-letter queue, so the
    # validator writes to a scratch path that is removed straight away.
    scratch = state.output_dir / ".source_test_dlq.ndjson"
    validator = Validator(schema_path=resources.ues_schema_path(), dead_letter_path=scratch)
    try:
        schema_valid, schema_errors = validator.validate(ues_event)
    finally:
        validator.close()
        scratch.unlink(missing_ok=True)

    return {
        **base,
        "valid": schema_valid,
        "matched_detection": matched,
        "errors": schema_errors,
        "extracted_fields": extracted,
        "normalized_event": ues_event,
        "vendor_attributes": normalized.get("vendor_attributes", {}),
    }


@router.get("/{source_id}")
def get_source_detail(state: State, source_id: str = SOURCE_ID):
    """A source's definition and statistics."""
    source = state.source_manager.get_source(source_id)
    if not source:
        raise HTTPException(status_code=404, detail=f"Source {source_id!r} not found")
    return {"source": source}


@router.delete("/{source_id}", dependencies=[Depends(require_api_key)])
def delete_source(state: State, source_id: str = SOURCE_ID):
    """Delete a declarative source definition."""
    if not state.source_manager.delete_source(source_id):
        raise HTTPException(
            status_code=404,
            detail=f"Source {source_id!r} not found or is not deletable",
        )
    return {"status": "ok", "deleted": source_id}


@router.post("/{source_id}/enable", dependencies=[Depends(require_api_key)])
def enable_source(state: State, source_id: str = SOURCE_ID):
    """Enable a log source."""
    state.source_manager.set_source_enabled(source_id, True)
    return {"status": "ok", "source_id": source_id, "enabled": True}


@router.post("/{source_id}/disable", dependencies=[Depends(require_api_key)])
def disable_source(state: State, source_id: str = SOURCE_ID):
    """Disable a log source."""
    state.source_manager.set_source_enabled(source_id, False)
    return {"status": "ok", "source_id": source_id, "enabled": False}
