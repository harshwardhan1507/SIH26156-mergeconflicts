"""
ULPF Operations Dashboard — the optional web layer over the ULPF framework.

This package is a *consumer* of :mod:`ulpf`. The dependency runs one way only:
nothing in ``ulpf`` imports anything from here, so the framework installs and
runs with no web stack present. Install this layer with::

    pip install "ulpf[dashboard]"
"""
from __future__ import annotations

__version__ = "1.3.0"

__all__ = ["AppState", "__version__", "create_app"]


def __getattr__(name: str):
    # Imported lazily so that `import ulpf_dashboard` does not pull in FastAPI
    # for callers that only want the version.
    if name == "create_app":
        from ulpf_dashboard.app import create_app

        return create_app
    if name == "AppState":
        from ulpf_dashboard.state import AppState

        return AppState
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
