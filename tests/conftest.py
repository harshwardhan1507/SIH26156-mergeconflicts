"""
Shared pytest fixtures.

Tests resolve packaged data through :mod:`ulpf.resources` rather than by walking
``__file__`` upwards. Relative walks silently broke when the suite moved out of
the package, and they would not have worked against an installed wheel at all.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import ulpf
from ulpf import resources
from ulpf.core.detector import FormatDetector
from ulpf.core.normalization import NormalizationEngine

#: Repository root, used only to locate example data that is not packaged.
REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_LOGS = REPO_ROOT / "examples" / "sample_logs"


@pytest.fixture(scope="session", autouse=True)
def registered_parsers() -> int:
    """Register every built-in and declarative parser once for the whole session."""
    return ulpf.bootstrap()


@pytest.fixture(scope="session")
def schema_dir() -> Path:
    """Directory holding the packaged JSON schemas."""
    return resources.schemas_dir()


@pytest.fixture(scope="session")
def mappings_dir() -> Path:
    """Directory holding the packaged per-parser YAML mappings."""
    return resources.mappings_dir()


@pytest.fixture(scope="session")
def ues_schema_path() -> Path:
    """Path to the packaged UES JSON Schema."""
    return resources.ues_schema_path()


@pytest.fixture(scope="session")
def sample_logs_dir() -> Path:
    """Directory of example log files shipped with the repository."""
    if not SAMPLE_LOGS.is_dir():
        pytest.skip(f"example logs not found at {SAMPLE_LOGS}")
    return SAMPLE_LOGS


@pytest.fixture(scope="session")
def norm_engine() -> NormalizationEngine:
    """A normalization engine loaded with the packaged mappings."""
    return NormalizationEngine(resources.mappings_dir())


@pytest.fixture(scope="session")
def detector() -> FormatDetector:
    """A format detector with no source overrides configured."""
    return FormatDetector()


@pytest.fixture(scope="session")
def ues_schema() -> dict:
    """The parsed UES JSON Schema."""
    return json.loads(resources.ues_schema_path().read_text(encoding="utf-8"))


@pytest.fixture
def isolated_sources_dir(tmp_path, monkeypatch) -> Path:
    """
    Point declarative-source discovery at a temporary directory.

    Without this, registering a source in a test writes a YAML file into the
    user's real data directory and leaks into every later test run.
    """
    from ulpf.core import declarative

    sources = tmp_path / "declarative_sources"
    sources.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("ULPF_SOURCES_DIR", str(sources))
    monkeypatch.setattr(declarative, "_GLOBAL_DECLARATIVE_REGISTRY", None)
    yield sources
    monkeypatch.setattr(declarative, "_GLOBAL_DECLARATIVE_REGISTRY", None)
