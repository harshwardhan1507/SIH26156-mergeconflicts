"""
FastAPI application factory for the ULPF Operations Dashboard.

There is no module-level ``app`` object. Building one at import time meant that
merely importing this module created directories, opened a SQLite database, and
scanned for parsers — side effects that fired even for callers that only wanted
a helper function. :func:`create_app` builds an application on request, and each
one owns its own :class:`~ulpf_dashboard.state.AppState`.
"""
from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

import ulpf
from ulpf_dashboard import __version__
from ulpf_dashboard.paths import resolve_output_dir, static_dir
from ulpf_dashboard.routers import ALL_ROUTERS
from ulpf_dashboard.security import cors_origins, warn_if_unauthenticated
from ulpf_dashboard.state import AppState

logger = logging.getLogger(__name__)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Sync the index on start-up and release every resource on shutdown."""
    state: AppState = app.state.ulpf
    indexed = state.indexer.sync_from_ndjson()
    logger.info("Initial index sync complete: %d records", indexed)
    try:
        yield
    finally:
        state.close()


def create_app(
    output_dir: str | Path | None = None,
    host: str = "127.0.0.1",
    port: int = 8000,
) -> FastAPI:
    """
    Build a configured dashboard application.

    Args:
        output_dir: Pipeline output directory to read. Resolved through
            :func:`~ulpf_dashboard.paths.resolve_output_dir`.
        host: Bind address, used for the CORS allowlist and start-up warnings.
        port: Bind port, used for the CORS allowlist.
    """
    resolved = resolve_output_dir(output_dir)
    ulpf.bootstrap()  # register built-in parsers and declarative sources

    app = FastAPI(
        title="ULPF Operations Dashboard",
        description="Real-time perimeter log visualization and forensic inspection",
        version=__version__,
        lifespan=_lifespan,
    )
    app.state.ulpf = AppState(output_dir=resolved, host=host, port=port)

    origins = cors_origins(host, port)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Content-Type", "X-API-Key"],
    )
    logger.info("CORS restricted to origins: %s", origins)
    warn_if_unauthenticated(host)

    for router in ALL_ROUTERS:
        app.include_router(router)

    @app.get("/api/health", tags=["meta"])
    def health() -> JSONResponse:
        """Liveness and version probe for orchestrators and the CLI."""
        return JSONResponse(
            {
                "status": "ok",
                "dashboard_version": __version__,
                "framework_version": ulpf.__version__,
                "schema_version": ulpf.__schema_version__,
                "output_dir": str(resolved),
                "parsers": ulpf.parser_count(),
            }
        )

    assets = static_dir()
    if assets.exists():
        app.mount("/static", StaticFiles(directory=str(assets)), name="static")

        @app.get("/", include_in_schema=False)
        def serve_index():
            """Serve the single-page dashboard frontend."""
            index_file = assets / "index.html"
            if index_file.exists():
                return FileResponse(index_file)
            return JSONResponse(
                {"detail": "Dashboard frontend assets are not installed"},
                status_code=404,
            )
    else:
        logger.warning("Static assets not found at %s — serving API only", assets)

    return app
