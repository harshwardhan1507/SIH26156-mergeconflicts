"""
Live host monitor endpoints.

The monitor inspects local processes and network connections, so every
state-changing operation requires the API key. Read endpoints return empty
results while it is stopped rather than stale data.
"""
from __future__ import annotations

import sys
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from ulpf_dashboard.security import require_api_key
from ulpf_dashboard.state import AppState, get_state

router = APIRouter(prefix="/api/live-monitor", tags=["live-monitor"])

State = Annotated[AppState, Depends(get_state)]


def _running(state: AppState):
    """Return the monitor if it is active, else None."""
    monitor = state.live_monitor
    return monitor if monitor is not None and monitor.is_running() else None


@router.post("/start", dependencies=[Depends(require_api_key)])
def start_live_monitor(state: State, interval_ms: int = Query(250, ge=50, le=10_000)):
    """Start real-time OS event and process monitoring."""
    from ulpf.collectors.live_monitor import LiveSystemMonitor

    if state.live_monitor is None:
        state.live_monitor = LiveSystemMonitor(
            output_dir=state.output_dir, interval_ms=interval_ms
        )
    if not state.live_monitor.is_running():
        state.live_monitor.start()

    return {
        "status": "started",
        "message": "Live system event and process monitor is active.",
        **state.live_monitor.get_stats(),
    }


@router.post("/stop", dependencies=[Depends(require_api_key)])
def stop_live_monitor(state: State):
    """Stop the background OS event and process monitor."""
    if state.live_monitor is None:
        return {"status": "stopped", "running": False, "events_captured": 0}
    state.live_monitor.stop()
    return {
        "status": "stopped",
        "message": "Live system monitor stopped.",
        **state.live_monitor.get_stats(),
    }


@router.get("/status")
def get_live_monitor_status(state: State):
    """Current monitor status and capture counts."""
    if state.live_monitor is not None:
        return state.live_monitor.get_stats()
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


@router.get("/events")
def get_live_monitor_events(state: State, limit: int = Query(100, ge=1, le=1000)):
    """Recently captured host events from the in-memory buffer."""
    monitor = _running(state)
    return {"events": monitor.get_recent_events(limit=limit) if monitor else []}


@router.get("/connections")
def get_live_monitor_connections(state: State):
    """Active outbound network connections per process."""
    monitor = _running(state)
    if not monitor:
        return {
            "connections": [],
            "stats": {"running": False, "tracked_connections": 0},
            "running": False,
            "permission_error": None,
        }
    return {
        "connections": monitor.get_active_connections(),
        "stats": monitor.get_stats(),
        "running": True,
        "permission_error": monitor.permission_error,
    }


@router.get("/processes")
def get_live_monitor_processes(state: State, limit: int = Query(150, ge=1, le=1000)):
    """Snapshot of running processes."""
    monitor = _running(state)
    return {"processes": monitor.get_running_processes(limit=limit) if monitor else []}
