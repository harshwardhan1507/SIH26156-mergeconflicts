"""
Authentication and CORS policy for the dashboard API.

The dashboard exposes write endpoints (ingest, reindex, source management, host
monitor). Those are gated by an API key whenever ``ULPF_API_KEY`` is set, and
CORS is never a wildcard: wildcard origins plus a browser session would let any
site the analyst visits forge log-injection requests against this API.
"""
from __future__ import annotations

import hmac
import logging
import os

from fastapi import Header, HTTPException, status

logger = logging.getLogger(__name__)

API_KEY_ENV = "ULPF_API_KEY"
CORS_ORIGINS_ENV = "ULPF_CORS_ORIGINS"


def api_key_configured() -> bool:
    """True when an API key is configured for this process."""
    return bool(os.environ.get(API_KEY_ENV, "").strip())


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    """
    FastAPI dependency gating every state-changing endpoint.

    Enforced only when ``ULPF_API_KEY`` is set — unset means "trusted local
    single-user demo", which is how the dashboard is normally run. Any
    deployment reachable by more than one user, or bound to a non-loopback
    address, must set it; :func:`warn_if_unauthenticated` says so at start-up.
    """
    expected = os.environ.get(API_KEY_ENV, "").strip()
    if not expected:
        return
    # Constant-time compare: a naive == leaks key material through timing.
    if not x_api_key or not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid X-API-Key header",
        )


def cors_origins(host: str = "127.0.0.1", port: int = 8000) -> list[str]:
    """
    Allowed browser origins, from ``ULPF_CORS_ORIGINS`` or the bind address.

    Never returns ``*``.
    """
    configured = os.environ.get(CORS_ORIGINS_ENV, "").strip()
    if configured:
        return [o.strip() for o in configured.split(",") if o.strip()]
    origins = {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}
    if host not in ("0.0.0.0", "::", "127.0.0.1", "localhost"):  # noqa: S104
        origins.add(f"http://{host}:{port}")
    return sorted(origins)


def warn_if_unauthenticated(host: str) -> None:
    """Emit a start-up warning when write endpoints are exposed without a key."""
    if api_key_configured():
        return
    message = (
        "%s is not set — the ingest, reindex, source-management and live-monitor "
        "endpoints accept unauthenticated writes."
    )
    if host in ("0.0.0.0", "::"):  # noqa: S104 — comparison, not a bind
        logger.error(
            message + " This server is bound to ALL interfaces. Set %s before exposing it.",
            API_KEY_ENV, API_KEY_ENV,
        )
    else:
        logger.warning(
            message + " Acceptable for a single-user local demo; set %s before exposing "
            "this dashboard beyond localhost.",
            API_KEY_ENV, API_KEY_ENV,
        )
