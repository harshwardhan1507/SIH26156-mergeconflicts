"""API routers, grouped by concern."""
from __future__ import annotations

from ulpf_dashboard.routers import analytics, events, ingest, monitor, settings, sources, stream

#: Registered in order by :func:`ulpf_dashboard.app.create_app`.
ALL_ROUTERS = (
    events.router,
    ingest.router,
    sources.router,
    analytics.router,
    stream.router,
    monitor.router,
    settings.router,
)

__all__ = ["ALL_ROUTERS", "analytics", "events", "ingest", "monitor", "settings", "sources", "stream"]
