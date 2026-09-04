"""Settings and server configuration API router."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ulpf_dashboard import __version__
from ulpf_dashboard.security import cors_origins
from ulpf_dashboard.state import AppState, get_state

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/settings", tags=["settings"])

State = Annotated[AppState, Depends(get_state)]


def load_dashboard_config(output_dir: Path) -> dict[str, Any]:
    """Load persistent dashboard settings from dashboard_config.json."""
    cfg_file = output_dir / "dashboard_config.json"
    if cfg_file.exists():
        try:
            with open(cfg_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"port": 7000, "host": "127.0.0.1", "auto_open_browser": True}


def save_dashboard_config(output_dir: Path, config: dict[str, Any]) -> None:
    """Save persistent dashboard settings to dashboard_config.json."""
    cfg_file = output_dir / "dashboard_config.json"
    try:
        with open(cfg_file, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        logger.warning("Could not save dashboard_config.json: %s", e)


class PortSettingsRequest(BaseModel):
    """Payload for updating port and browser settings."""

    port: int = Field(..., ge=1024, le=65535, description="Port between 1024 and 65535.")
    restart: bool = True
    auto_open_browser: bool | None = None


@router.get("")
def get_settings(state: State) -> dict[str, Any]:
    """Retrieve current dashboard configuration and server settings."""
    cfg = load_dashboard_config(state.output_dir)
    return {
        "current_port": state.port,
        "configured_port": cfg.get("port", state.port),
        "host": state.host,
        "auto_open_browser": cfg.get("auto_open_browser", True),
        "api_key_enabled": bool(os.environ.get("ULPF_API_KEY")),
        "cors_origins": cors_origins(state.host, state.port),
        "version": __version__,
    }


@router.post("/port")
async def update_port_settings(req: PortSettingsRequest, state: State) -> dict[str, Any]:
    """Update dashboard port setting and optionally trigger live restart on new port."""
    if req.port < 1024 or req.port > 65535:
        raise HTTPException(status_code=400, detail="Port must be an integer between 1024 and 65535.")

    cfg = load_dashboard_config(state.output_dir)
    old_port = state.port
    cfg["port"] = req.port
    if req.auto_open_browser is not None:
        cfg["auto_open_browser"] = req.auto_open_browser
    save_dashboard_config(state.output_dir, cfg)

    host = state.host
    check_host = "127.0.0.1" if host in ("0.0.0.0", "::", "localhost") else host
    redirect_url = f"http://{check_host}:{req.port}"

    if req.restart and req.port != old_port:
        async def _restart_server():
            await asyncio.sleep(0.5)
            cmd = [
                sys.executable,
                "-m",
                "ulpf_dashboard.server",
                "--background",
                "--port",
                str(req.port),
                "--host",
                str(host),
                "--output-dir",
                str(state.output_dir),
                "--no-open-browser",
            ]
            try:
                subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                )
            except Exception as exc:
                logger.error("Failed to spawn server on new port: %s", exc)

        asyncio.create_task(_restart_server())
        return {
            "status": "ok",
            "message": f"Dashboard restarting on port {req.port}. Redirecting...",
            "redirect_url": redirect_url,
            "restarted": True,
        }

    return {
        "status": "ok",
        "message": f"Port configuration saved to {req.port}.",
        "redirect_url": redirect_url,
        "restarted": False,
    }
