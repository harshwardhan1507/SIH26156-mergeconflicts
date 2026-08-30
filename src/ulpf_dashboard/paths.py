"""Output-directory resolution for the dashboard."""
from __future__ import annotations

import logging
import os
from pathlib import Path

from ulpf import resources

logger = logging.getLogger(__name__)


def resolve_output_dir(configured: str | Path | None = None) -> Path:
    """
    Resolve the pipeline output directory the dashboard should read.

    Precedence: the explicit argument, then ``ULPF_OUTPUT_DIR``, then ``./output``,
    falling back to the per-user data directory when the working directory is
    not writable (a packaged desktop build often runs from a read-only location).
    """
    for candidate in (configured, os.environ.get("ULPF_OUTPUT_DIR", "").strip() or None):
        if not candidate:
            continue
        path = Path(candidate)
        try:
            path.mkdir(parents=True, exist_ok=True)
            return path
        except OSError as exc:
            logger.warning("Output directory %s is unusable (%s); trying next candidate", path, exc)

    default = Path("output")
    try:
        default.mkdir(parents=True, exist_ok=True)
        probe = default / ".write_test"
        probe.touch()
        probe.unlink()
        return default
    except OSError:
        fallback = resources.user_data_dir() / "output"
        fallback.mkdir(parents=True, exist_ok=True)
        logger.info("Falling back to user data directory for output: %s", fallback)
        return fallback


def static_dir() -> Path:
    """Directory holding the dashboard's bundled frontend assets."""
    return Path(__file__).parent / "static"
