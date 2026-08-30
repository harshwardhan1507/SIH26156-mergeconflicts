"""
Packaged resource and data-directory resolution.

Two distinct kinds of location are resolved here, and the distinction matters:

*Package resources* (JSON/YAML shipped inside the wheel) are read-only and
located via ``importlib.resources`` — never by walking ``__file__`` upwards or
probing hardcoded container paths, both of which break for zipped/relocated
installs.

*User data* (declarative sources authored at runtime, pipeline output) is
writable and located under an OS-appropriate data directory. Writing runtime
state into the installed package directory is a packaging bug: site-packages
is frequently root-owned or mounted read-only.
"""
from __future__ import annotations

import os
import sys
from importlib import resources
from pathlib import Path

__all__ = [
    "bundled_declarative_sources_dir",
    "config_dir",
    "declarative_schema_path",
    "default_sources_config",
    "mappings_dir",
    "schemas_dir",
    "ues_schema_path",
    "user_data_dir",
    "user_declarative_sources_dir",
]


def _package_path(*parts: str) -> Path:
    """Filesystem path to a resource inside the installed ``ulpf`` package."""
    root = resources.files("ulpf")
    for part in parts:
        root = root / part
    return Path(str(root))


def schemas_dir() -> Path:
    """Directory holding the UES and declarative-source JSON schemas."""
    return _package_path("schemas")


def mappings_dir() -> Path:
    """Directory holding the per-parser YAML normalization mappings."""
    return _package_path("schemas", "mappings")


def ues_schema_path() -> Path:
    """Path to the Unified Event Schema JSON Schema document."""
    return _package_path("schemas", "ues_schema.json")


def declarative_schema_path() -> Path:
    """Path to the JSON Schema that validates declarative source configs."""
    return _package_path("schemas", "declarative_source_schema.json")


def bundled_declarative_sources_dir() -> Path:
    """Read-only directory of declarative source definitions shipped in the wheel."""
    return _package_path("schemas", "declarative_sources")


def config_dir() -> Path:
    """Directory holding packaged default configuration."""
    return _package_path("config")


def default_sources_config() -> Path:
    """Path to the packaged ``sources.yaml`` format-override configuration."""
    return _package_path("config", "sources.yaml")


def user_data_dir() -> Path:
    """
    OS-appropriate writable directory for ULPF state.

    Overridable with ``ULPF_DATA_DIR`` so operators can pin state to a mounted
    volume without relying on the platform default.
    """
    override = os.environ.get("ULPF_DATA_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA")
        return Path(base) / "ULPF" if base else Path.home() / ".ulpf"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "ULPF"
    xdg = os.environ.get("XDG_DATA_HOME", "").strip()
    return (Path(xdg) if xdg else Path.home() / ".local" / "share") / "ulpf"


def user_declarative_sources_dir() -> Path:
    """
    Writable directory where runtime-authored declarative sources are stored.

    Kept separate from :func:`bundled_declarative_sources_dir` so that adding a
    source never mutates the installed package.
    """
    override = os.environ.get("ULPF_SOURCES_DIR", "").strip()
    return Path(override).expanduser() if override else user_data_dir() / "declarative_sources"
