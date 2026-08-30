"""
Analytics endpoints.

Anomaly scoring is a two-pass scan over the whole events file (build the
baseline, then score against it), so results are cached for a short TTL. Without
that, every dashboard poll re-read the entire file twice.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from ulpf.crosswalk.ecs import to_ecs
from ulpf.crosswalk.ocsf import to_ocsf
from ulpf_dashboard.state import AppState, get_state

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["analytics"])

State = Annotated[AppState, Depends(get_state)]

#: How long a computed anomaly ranking stays valid. Anomaly detection is a
#: full-file operation; recomputing it per poll made the endpoint O(file) per
#: request with no upper bound on concurrent cost.
_CACHE_TTL_SECONDS = 15.0

#: Cap on events scanned in one pass, so the endpoint's cost stays bounded as
#: the events file grows.
_MAX_SCAN_EVENTS = 200_000

_cache: dict[str, Any] = {}
_cache_lock = threading.Lock()


class CrosswalkRequest(BaseModel):
    """A UES event to translate into other taxonomies."""

    event: dict[str, Any]


def _iter_events(path: Path, limit: int):
    """Yield parsed events from an NDJSON file, skipping malformed lines."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        for count, line in enumerate(fh):
            if count >= limit:
                logger.warning("Anomaly scan truncated at %d events", limit)
                return
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _compute_anomalies(output_dir: Path) -> dict[str, Any]:
    """Run the two-pass anomaly scan over the events file."""
    from ulpf.analytics.anomaly import AnomalyDetector

    events_file = output_dir / "events.ndjson"
    if not events_file.exists():
        return {"anomalies": [], "total_analyzed": 0, "anomalies_found": 0}

    detector = AnomalyDetector(output_dir=output_dir)
    total = 0
    for event in _iter_events(events_file, _MAX_SCAN_EVENTS):
        detector.update_baseline(event)
        total += 1

    scored: list[dict[str, Any]] = []
    for event in _iter_events(events_file, _MAX_SCAN_EVENTS):
        annotated = detector.analyze(event)
        analytics = annotated.get("analytics")
        if not analytics:
            continue
        scored.append({
            "event_id": annotated.get("event_id"),
            "anomaly_score": analytics.get("anomaly_score", 0.0),
            "anomaly_reasons": analytics.get("anomaly_reasons", []),
            "is_anomalous": analytics.get("is_anomalous", False),
            "ingest_timestamp": annotated.get("ingest_timestamp"),
            "source": annotated.get("source", {}),
            "event": annotated.get("event", {}),
            "network": annotated.get("network") or {},
        })

    scored.sort(key=lambda item: item["anomaly_score"], reverse=True)
    return {"anomalies": scored, "total_analyzed": total, "anomalies_found": len(scored)}


@router.get("/analytics/anomalies")
def get_anomalies(
    state: State,
    top_n: int = Query(20, ge=1, le=200),
    min_score: float = Query(0.3, ge=0.0, le=1.0),
):
    """Top anomalous events, scored against a rolling baseline."""
    key = str(state.output_dir)
    now = time.monotonic()

    with _cache_lock:
        cached = _cache.get(key)
        if cached and now - cached["at"] < _CACHE_TTL_SECONDS:
            result = cached["result"]
        else:
            result = _compute_anomalies(state.output_dir)
            _cache[key] = {"at": now, "result": result}

    matching = [a for a in result["anomalies"] if a["anomaly_score"] >= min_score]
    return {
        "anomalies": matching[:top_n],
        "total_analyzed": result["total_analyzed"],
        "anomalies_found": len(matching),
    }


@router.post("/events/crosswalk")
def translate_event_crosswalk(req: CrosswalkRequest):
    """Translate an arbitrary UES event into OCSF and ECS."""
    return {"ocsf": to_ocsf(req.event), "ecs": to_ecs(req.event)}
