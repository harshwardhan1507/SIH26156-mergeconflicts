"""
Pipeline assembly — the public construction API for the ULPF framework.

This module is the single place that knows how to wire a :class:`Pipeline`
together from configuration. Both the CLI and any external embedder (including
the optional dashboard distribution) build pipelines through here, so no
consumer needs to reach into another consumer's private helpers.

A pipeline owns OS resources — an appended dead-letter file, one file handle
per sink, possibly a SQLite index. :class:`PipelineSession` makes that
ownership explicit and releases it deterministically::

    with build_session(output_dir="output") as session:
        stats = session.run(FileReader("/var/log/app"))
"""
from __future__ import annotations

import logging
from collections.abc import Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any

from ulpf import resources
from ulpf.core.detector import FormatDetector
from ulpf.core.ingestion import ReaderBase
from ulpf.core.normalization import NormalizationEngine
from ulpf.core.pipeline import Pipeline
from ulpf.core.raw_store import FileRawStore, RawStoreBase
from ulpf.core.validation import Validator
from ulpf.enrichment.base import EnrichmentPlugin
from ulpf.enrichment.composite import CompositeEnrichment
from ulpf.enrichment.ip_enrichment import IPEnrichmentPlugin
from ulpf.enrichment.noop import NoOpEnrichment
from ulpf.sinks.base import SinkBase

logger = logging.getLogger(__name__)

#: Sink identifiers accepted by :func:`build_sink` and the ``--sink`` CLI option.
SINK_NAMES: tuple[str, ...] = (
    "ndjson",
    "kafka",
    "kafka-real",
    "parquet",
    "cef-egress",
    "leef-egress",
)

#: Raw-store backends accepted by :func:`build_raw_store`.
RAW_STORE_NAMES: tuple[str, ...] = ("file", "segmented")

__all__ = [
    "RAW_STORE_NAMES",
    "SINK_NAMES",
    "PipelineConfig",
    "PipelineSession",
    "build_raw_store",
    "build_session",
    "build_sink",
]


@dataclass(slots=True)
class PipelineConfig:
    """Declarative description of a pipeline to be constructed."""

    output_dir: Path
    sinks: tuple[str, ...] = ("ndjson",)
    raw_store: str = "file"
    enrich: bool = True
    sources_config: Path | None = None
    #: Record per-source counters into the SQLite source registry. Off by
    #: default: batch ingest does not need it and it adds a write per event.
    telemetry: bool = False
    mappings_dir: Path = field(default_factory=resources.mappings_dir)
    schema_path: Path = field(default_factory=resources.ues_schema_path)

    def __post_init__(self) -> None:
        self.output_dir = Path(self.output_dir)
        unknown = [name for name in self.sinks if name not in SINK_NAMES]
        if unknown:
            raise ValueError(
                f"Unknown sink(s) {', '.join(repr(n) for n in unknown)}. "
                f"Choose from: {', '.join(SINK_NAMES)}"
            )
        if self.raw_store not in RAW_STORE_NAMES:
            raise ValueError(
                f"Unknown raw store {self.raw_store!r}. "
                f"Choose from: {', '.join(RAW_STORE_NAMES)}"
            )

    @classmethod
    def from_options(
        cls,
        output_dir: str | Path,
        sinks: str | Sequence[str] = "ndjson",
        raw_store: str = "file",
        enrich: bool = True,
        sources_config: str | Path | None = None,
        telemetry: bool = False,
    ) -> PipelineConfig:
        """Build a config from CLI-shaped options (``sinks`` may be comma-separated)."""
        if isinstance(sinks, str):
            names = tuple(s.strip() for s in sinks.split(",") if s.strip()) or ("ndjson",)
        else:
            names = tuple(sinks) or ("ndjson",)
        cfg_path = Path(sources_config) if sources_config else resources.default_sources_config()
        return cls(
            output_dir=Path(output_dir),
            sinks=names,
            raw_store=str(raw_store).lower(),
            enrich=enrich,
            telemetry=telemetry,
            sources_config=cfg_path if Path(cfg_path).exists() else None,
        )


def build_sink(name: str, output_dir: Path) -> SinkBase:
    """
    Instantiate one sink by name.

    Optional-dependency sinks are imported lazily so that a base install never
    pays for — or fails on — a backend it does not use.
    """
    if name == "ndjson":
        from ulpf.sinks.ndjson_file import NDJSONFileSink

        return NDJSONFileSink(output_dir / "events.ndjson")
    if name == "kafka":
        from ulpf.sinks.kafka_stub import KafkaStubSink

        return KafkaStubSink(output_dir / "kafka_events.ndjson")
    if name == "kafka-real":
        from ulpf.sinks.kafka_producer import KafkaProducerSink

        return KafkaProducerSink(
            topic="ulpf.events",
            bootstrap_servers="localhost:9092",
            fallback_path=output_dir / "kafka_events.ndjson",
        )
    if name == "parquet":
        from ulpf.sinks.parquet_sink import ParquetSink

        return ParquetSink(output_dir / "parquet_lake")
    if name == "cef-egress":
        from ulpf.sinks.cef_egress import CEFEgressSink

        return CEFEgressSink(output_dir / "egress_cef.log")
    if name == "leef-egress":
        from ulpf.sinks.leef_egress import LEEFEgressSink

        return LEEFEgressSink(output_dir / "egress_leef.log")
    raise ValueError(f"Unknown sink {name!r}. Choose from: {', '.join(SINK_NAMES)}")


def build_raw_store(name: str, output_dir: Path) -> RawStoreBase:
    """Instantiate the configured raw-payload store backend."""
    if str(name).lower() == "segmented":
        from ulpf.core.segmented_raw_store import SegmentedRawStore

        return SegmentedRawStore(output_dir / "raw_segments")
    return FileRawStore(output_dir / "raw_store")


def build_enrichment(enabled: bool) -> EnrichmentPlugin:
    """Return the enrichment chain, or a no-op plugin when disabled."""
    return CompositeEnrichment([IPEnrichmentPlugin()]) if enabled else NoOpEnrichment()


class PipelineSession(AbstractContextManager["PipelineSession"]):
    """
    A constructed pipeline together with the resources it owns.

    Exiting the context flushes and closes every sink and the validator's
    dead-letter handle, whether or not the run succeeded. Leaking these was the
    prior behaviour on every error path.
    """

    def __init__(
        self,
        pipeline: Pipeline,
        sinks: list[SinkBase],
        validator: Validator,
        config: PipelineConfig,
    ) -> None:
        self.pipeline = pipeline
        self.sinks = sinks
        self.validator = validator
        self.config = config
        self._closed = False

    def run(self, reader: ReaderBase, tenant_id: str = "default") -> dict[str, int]:
        """Process every event the reader yields. Returns the run's stats."""
        return self.pipeline.run(reader, tenant_id=tenant_id)

    def process_event(self, *args: Any, **kwargs: Any) -> bool:
        """Process a single raw event. See :meth:`Pipeline.process_event`."""
        return self.pipeline.process_event(*args, **kwargs)

    def flush(self) -> None:
        """Flush all sinks without closing them (for long-lived listeners)."""
        for sink in self.sinks:
            try:
                sink.flush()
            except Exception as exc:  # a broken sink must not stop the others
                logger.error("Sink %s flush failed: %s", type(sink).__name__, exc)

    def stats(self) -> dict[str, int]:
        """Current counters for this session."""
        return {
            "processed": self.pipeline.processed_count,
            "errors": self.pipeline.error_count,
            "valid": self.validator.valid_count,
            "invalid": self.validator.invalid_count,
        }

    def close(self) -> None:
        """Flush and release every owned resource. Idempotent."""
        if self._closed:
            return
        self._closed = True
        for sink in self.sinks:
            try:
                sink.close()
            except Exception as exc:
                logger.error("Sink %s close failed: %s", type(sink).__name__, exc)
        try:
            self.validator.close()
        except Exception as exc:
            logger.error("Validator close failed: %s", exc)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def build_session(
    output_dir: str | Path = "output",
    sinks: str | Sequence[str] = "ndjson",
    raw_store: str = "file",
    enrich: bool = True,
    sources_config: str | Path | None = None,
    telemetry: bool = False,
    config: PipelineConfig | None = None,
) -> PipelineSession:
    """
    Construct a ready-to-run :class:`PipelineSession`.

    Pass either the individual options or a prepared :class:`PipelineConfig`.
    The caller owns the returned session and must close it — use it as a
    context manager unless the lifetime is genuinely longer than one scope.
    """
    cfg = config or PipelineConfig.from_options(
        output_dir=output_dir,
        sinks=sinks,
        raw_store=raw_store,
        enrich=enrich,
        sources_config=sources_config,
        telemetry=telemetry,
    )
    cfg.output_dir.mkdir(parents=True, exist_ok=True)

    detector = FormatDetector(sources_config_path=cfg.sources_config)
    store = build_raw_store(cfg.raw_store, cfg.output_dir)
    norm_engine = NormalizationEngine(cfg.mappings_dir)
    validator = Validator(
        schema_path=cfg.schema_path,
        dead_letter_path=cfg.output_dir / "dead_letter.ndjson",
    )
    sink_objs = [build_sink(name, cfg.output_dir) for name in cfg.sinks]

    observer = None
    if cfg.telemetry:
        from ulpf.core.observability import SourceTelemetryObserver
        from ulpf.core.source_manager import SourceManager

        observer = SourceTelemetryObserver(SourceManager(output_dir=cfg.output_dir))

    pipeline = Pipeline(
        detector=detector,
        raw_store=store,
        normalization_engine=norm_engine,
        validator=validator,
        sinks=sink_objs,
        enrichment=build_enrichment(cfg.enrich),
        observer=observer,
    )
    return PipelineSession(pipeline, sink_objs, validator, cfg)


def worker_pipeline_factory(config: PipelineConfig) -> Pipeline:
    """
    Module-level, picklable pipeline builder for :class:`ParallelPipeline`.

    Must stay at module scope: a closure defined inside a command function
    cannot be pickled across process boundaries, which is what makes
    ``--workers`` work rather than crash at dispatch.
    """
    return build_session(config=config).pipeline
