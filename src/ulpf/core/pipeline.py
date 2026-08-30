"""
Pipeline Orchestrator.

Ties together: Reader -> Detector -> Parser -> RawStore -> Normalizer ->
Enrichment -> Validator -> Sink.

Each event is processed in isolation; a per-event exception never stops the
pipeline — the event is quarantined to the dead-letter queue with its raw
payload and hash intact, so nothing is lost and every failure is explainable.
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from ulpf.core.detector import FormatDetector
from ulpf.core.ingestion import ReaderBase
from ulpf.core.normalization import NormalizationEngine
from ulpf.core.observability import PipelineObserver
from ulpf.core.raw_store import RawStoreBase
from ulpf.core.registry import get_parser_for_format
from ulpf.core.validation import Validator
from ulpf.enrichment.base import EnrichmentPlugin
from ulpf.sinks.base import SinkBase

if TYPE_CHECKING:
    from ulpf.parsers.base import BaseParser

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1.2.0"

#: Namespace suffix for deterministic event ids. Changing this changes every
#: id the pipeline produces, so it is versioned deliberately.
_EVENT_ID_NAMESPACE = uuid.NAMESPACE_URL


class Pipeline:
    """Single-threaded event processor. Construct one per worker process."""

    def __init__(
        self,
        detector: FormatDetector,
        raw_store: RawStoreBase,
        normalization_engine: NormalizationEngine,
        validator: Validator,
        sinks: list[SinkBase],
        enrichment: EnrichmentPlugin | None = None,
        observer: PipelineObserver | None = None,
    ):
        self.detector = detector
        self.raw_store = raw_store
        self.norm_engine = normalization_engine
        self.validator = validator
        self.sinks = sinks
        self.enrichment = enrichment
        self.observer = observer
        self._processed = 0
        self._errors = 0

    def _observe(
        self, parser_name: str, *, valid: bool, dead_lettered: bool, error: str | None = None
    ) -> None:
        """Report one event outcome to the observer, if one is attached."""
        if self.observer is None:
            return
        try:
            self.observer.on_event(
                parser_name, valid=valid, dead_lettered=dead_lettered, error=error
            )
        except Exception as exc:
            logger.debug("Observer raised for %s: %s", parser_name, exc)

    @property
    def processed_count(self) -> int:
        """Events successfully written to every sink."""
        return self._processed

    @property
    def error_count(self) -> int:
        """Events that failed at any stage and were quarantined."""
        return self._errors

    # -- helpers ---------------------------------------------------------

    def _quarantine(
        self,
        *,
        event_id: str,
        ingest_ts: datetime,
        raw_line: str,
        raw_hash: str,
        raw_format: str,
        stage: str,
        error_type: str,
        error_message: str,
        source_tag: str,
        tenant_id: str,
        parser_name: str | None = None,
    ) -> None:
        """
        Write one failure record to the dead-letter queue.

        Every pre-validation failure path funnels through here so that the DLQ
        has a single, stable record shape regardless of which stage failed.
        """
        self._errors += 1
        record: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "tenant_id": tenant_id,
            "event_id": event_id,
            "ingest_timestamp": ingest_ts.isoformat(),
            "raw": {
                "raw_payload": raw_line,
                "raw_format": raw_format,
                "raw_hash": raw_hash,
            },
            "raw_payload": raw_line,
            "raw_hash": raw_hash,
            "stage": stage,
            "error_type": error_type,
            "error_message": error_message,
            "source_tag": source_tag,
            "timestamp": ingest_ts.isoformat(),
        }
        if parser_name:
            record["parser"] = parser_name
        self._observe(
            parser_name or "unknown", valid=False, dead_lettered=True, error=error_message
        )

        sink = getattr(self.validator, "dead_letter_sink", None)
        if sink is None:
            return
        try:
            sink.write(record)
        except Exception as exc:
            # The DLQ is the last line of defence; if it is itself broken the
            # event is already counted as an error and the operator needs to
            # see why, so this is logged rather than swallowed.
            logger.error("Dead-letter write failed for %s: %s", event_id, exc)

    def _resolve_parser(
        self, raw_line: str, source_tag: str
    ) -> tuple[BaseParser | None, str]:
        """Return ``(parser, format_id)`` for a raw line, or ``(None, format_id)``."""
        format_id = self.detector.detect(raw_line, source_tag)
        return get_parser_for_format(format_id), format_id

    @staticmethod
    def _build_ues_event(
        *,
        event_id: str,
        ingest_ts: datetime,
        raw_line: str,
        raw_format: str,
        raw_hash: str,
        extracted: dict[str, Any],
        normalized: dict[str, Any],
        parser_name: str,
        parser_version: str,
        tenant_id: str,
    ) -> dict[str, Any]:
        """Assemble the full UES event envelope around a normalized body."""
        return {
            "schema_version": SCHEMA_VERSION,
            "tenant_id": tenant_id,
            "event_id": event_id,
            "ingest_timestamp": ingest_ts.isoformat(),
            "source_event_timestamp": extracted.get("timestamp_dt"),
            "raw": {
                "raw_payload": raw_line,
                "raw_format": raw_format,
                "raw_hash": raw_hash,
            },
            "source": normalized["source"],
            "event": normalized["event"],
            "network": normalized.get("network"),
            "identity": normalized.get("identity"),
            "rule": normalized.get("rule"),
            "vendor_attributes": normalized.get("vendor_attributes"),
            "enrichment": normalized.get("enrichment"),
            "lineage": {
                "parser_name": parser_name,
                "parser_version": parser_version,
                "normalization_ruleset_version": normalized.get(
                    "_ruleset_version", SCHEMA_VERSION
                ),
            },
        }

    # -- main entry point ------------------------------------------------

    def process_event(
        self,
        raw_line: str,
        source_tag: str,
        ingest_ts: datetime | None = None,
        raw_bytes: bytes | None = None,
        tenant_id: str = "default",
    ) -> bool:
        """
        Process a single raw event through the full pipeline.

        Guarantees:

        1. The exact raw bytes are persisted before detection or parsing runs,
           so a parse failure still leaves a forensically complete record.
        2. The event id is a deterministic UUIDv5 over (tenant, source, hash),
           making reprocessing idempotent.
        3. Every failure lands in the dead-letter queue with traceability intact.
        """
        if ingest_ts is None:
            ingest_ts = datetime.now(UTC)

        # 1. Capture authentic raw bytes and hash them before anything else.
        if raw_bytes is None:
            raw_bytes = raw_line.encode("utf-8", errors="surrogateescape")
        raw_hash = hashlib.sha256(raw_bytes).hexdigest()

        # 2. Deterministic id so re-ingesting the same bytes is a no-op upsert.
        event_id = str(
            uuid.uuid5(_EVENT_ID_NAMESPACE, f"ulpf:{tenant_id}:{source_tag}:{raw_hash}")
        )

        # 3. Persist raw first — zero information loss even if every later stage fails.
        try:
            self.raw_store.put(event_id, raw_bytes, tenant_id=tenant_id, ingest_ts=ingest_ts)
        except Exception as exc:
            logger.error("Raw store write failed for %s: %s", event_id, exc)
            self._quarantine(
                event_id=event_id,
                ingest_ts=ingest_ts,
                raw_line=raw_line,
                raw_hash=raw_hash,
                raw_format="unknown",
                stage="raw_store",
                error_type=type(exc).__name__,
                error_message=str(exc),
                source_tag=source_tag,
                tenant_id=tenant_id,
            )
            return False

        # 4. Detect format and resolve a parser.
        parser, format_id = self._resolve_parser(raw_line, source_tag)
        if parser is None:
            logger.warning("No parser matched event from %s: %.60s", source_tag, raw_line)
            self._quarantine(
                event_id=event_id,
                ingest_ts=ingest_ts,
                raw_line=raw_line,
                raw_hash=raw_hash,
                raw_format="unknown",
                stage="detection",
                error_type="ParserNotFound",
                error_message=(
                    f"No registered or declarative parser matched format {format_id!r}"
                ),
                source_tag=source_tag,
                tenant_id=tenant_id,
            )
            return False

        # 5. Extract vendor-specific fields.
        try:
            extracted = parser.extract(raw_line)
        except Exception as exc:
            logger.warning("Parser %s extraction failed: %s", parser.name, exc)
            self._quarantine(
                event_id=event_id,
                ingest_ts=ingest_ts,
                raw_line=raw_line,
                raw_hash=raw_hash,
                raw_format=parser.log_format,
                stage="extraction",
                error_type=type(exc).__name__,
                error_message=str(exc),
                source_tag=source_tag,
                tenant_id=tenant_id,
                parser_name=parser.name,
            )
            return False

        # 6. Map into the Unified Event Schema.
        try:
            normalized = self.norm_engine.normalize(extracted, parser.name)
        except Exception as exc:
            logger.warning("Normalization failed for %s: %s", event_id, exc)
            self._quarantine(
                event_id=event_id,
                ingest_ts=ingest_ts,
                raw_line=raw_line,
                raw_hash=raw_hash,
                raw_format=parser.log_format,
                stage="normalization",
                error_type=type(exc).__name__,
                error_message=str(exc),
                source_tag=source_tag,
                tenant_id=tenant_id,
                parser_name=parser.name,
            )
            return False

        ues_event = self._build_ues_event(
            event_id=event_id,
            ingest_ts=ingest_ts,
            raw_line=raw_line,
            raw_format=extracted.get("_log_format", parser.log_format),
            raw_hash=raw_hash,
            extracted=extracted,
            normalized=normalized,
            parser_name=parser.name,
            parser_version=parser.version,
            tenant_id=tenant_id,
        )

        # 7. Enrichment is additive and best-effort: a failure must not drop
        #    an otherwise valid event.
        if self.enrichment:
            try:
                ues_event = self.enrichment.enrich(ues_event)
            except Exception as exc:
                logger.warning("Enrichment failed for %s: %s", event_id, exc)

        # 8. Schema gate. The validator routes its own failures to the DLQ.
        if not self.validator.validate_and_route(ues_event):
            self._errors += 1
            self._observe(
                parser.name, valid=False, dead_lettered=True, error="SchemaValidationError"
            )
            return False

        # 9. Fan out to every sink. A partial failure is reported as a failure
        #    so at-least-once delivery can be reconciled from the DLQ.
        sink_success = True
        for sink in self.sinks:
            try:
                sink.write(ues_event)
            except Exception as exc:
                logger.error(
                    "Sink %s write failed for %s: %s", type(sink).__name__, event_id, exc
                )
                sink_success = False
                self._errors += 1
                dl_sink = getattr(self.validator, "dead_letter_sink", None)
                if dl_sink is not None:
                    try:
                        dl_sink.write(
                            {
                                **ues_event,
                                "stage": "sink",
                                "_sink_error": str(exc),
                                "_failed_sink": type(sink).__name__,
                            }
                        )
                    except Exception as dl_exc:
                        logger.error("Dead-letter write failed for %s: %s", event_id, dl_exc)

        if not sink_success:
            self._observe(parser.name, valid=True, dead_lettered=True, error="SinkWriteError")
            return False

        self._processed += 1
        self._observe(parser.name, valid=True, dead_lettered=False)
        return True

    def run(self, reader: ReaderBase, tenant_id: str = "default") -> dict[str, int]:
        """Process every event from ``reader`` and return the run's stats."""
        for raw_event in reader.read():
            self.process_event(
                raw_line=raw_event.line,
                source_tag=raw_event.source_tag,
                ingest_ts=raw_event.ingest_timestamp,
                raw_bytes=getattr(raw_event, "raw_bytes", None),
                tenant_id=tenant_id,
            )

        for sink in self.sinks:
            try:
                sink.flush()
            except Exception as exc:
                logger.error("Sink %s flush failed: %s", type(sink).__name__, exc)

        return {
            "processed": self._processed,
            "errors": self._errors,
            "valid": self.validator.valid_count,
            "invalid": self.validator.invalid_count,
        }
