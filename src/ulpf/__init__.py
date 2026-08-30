"""
ULPF — Universal Log Pre-processing Framework.

A vendor-agnostic pipeline that ingests heterogeneous security logs, preserves
their exact bytes for forensic traceability, and emits validated events in the
Unified Event Schema (UES).

The framework is self-contained: importing it pulls in no web server and no
optional backend. The operations dashboard is a separate distribution
(``ulpf_dashboard``, installed with ``pip install ulpf[dashboard]``) that
depends on this package, never the other way round.

Typical embedding::

    import ulpf

    ulpf.bootstrap()
    with ulpf.build_session(output_dir="output", sinks="ndjson") as session:
        stats = session.run(ulpf.FileReader("/var/log/firewall"))
"""
from __future__ import annotations

from ulpf.core.ingestion import FileReader, RawEvent, ReaderBase, StdinReader
from ulpf.core.pipeline import SCHEMA_VERSION, Pipeline
from ulpf.core.registry import list_parser_names, load_declarative_sources, parser_count
from ulpf.runtime import (
    RAW_STORE_NAMES,
    SINK_NAMES,
    PipelineConfig,
    PipelineSession,
    build_session,
)

__version__ = "1.3.0"

#: Version of the Unified Event Schema this build emits.
__schema_version__ = SCHEMA_VERSION

__all__ = [
    "RAW_STORE_NAMES",
    "SCHEMA_VERSION",
    "SINK_NAMES",
    "FileReader",
    "Pipeline",
    "PipelineConfig",
    "PipelineSession",
    "RawEvent",
    "ReaderBase",
    "StdinReader",
    "__schema_version__",
    "__version__",
    "bootstrap",
    "build_session",
    "list_parser_names",
    "parser_count",
]

_BOOTSTRAPPED = False


def bootstrap(sources_dir: str | None = None) -> int:
    """
    Register every available parser: built-in plugins and declarative sources.

    Idempotent, and safe to call from any entry point. Discovery is explicit
    rather than an import side effect so that tests and embedders control when
    the filesystem is touched.

    Returns:
        The total number of registered parsers.
    """
    global _BOOTSTRAPPED
    import ulpf.parsers  # noqa: F401  — importing registers every plugin

    if not _BOOTSTRAPPED or sources_dir is not None:
        load_declarative_sources(sources_dir)
        _BOOTSTRAPPED = True
    return parser_count()
