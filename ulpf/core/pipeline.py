"""
Pipeline Orchestrator.

Ties together: Reader -> Detector -> Parser -> RawStore -> Normalizer ->
Enrichment -> Validator -> Sink.

Each event is processed in isolation; a per-event exception does NOT
stop the pipeline — it is written to dead-letter instead.
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ulpf.core.ingestion import ReaderBase
from ulpf.core.detector import FormatDetector
from ulpf.core.registry import get_parser_for_format, get_all_parsers
from ulpf.core.raw_store import RawStoreBase
from ulpf.core.normalization import NormalizationEngine
from ulpf.core.validation import Validator
from ulpf.enrichment.base import EnrichmentPlugin
from ulpf.sinks.base import SinkBase

logger = logging.getLogger(__name__)


class Pipeline:
    def __init__(
        self,
        detector: FormatDetector,
        raw_store: RawStoreBase,
        normalization_engine: NormalizationEngine,
        validator: Validator,
        sinks: list[SinkBase],
        enrichment: EnrichmentPlugin | None = None,
    ):
        self.detector = detector
        self.raw_store = raw_store
        self.norm_engine = normalization_engine
        self.validator = validator
        self.sinks = sinks
        self.enrichment = enrichment
        self._processed = 0
        self._errors = 0

    def _build_ues_event(
        self,
        event_id: str,
        ingest_ts: datetime,
        raw_line: str,
        raw_format: str,
        raw_hash: str,
        extracted: dict[str, Any],
        normalized: dict[str, Any],
        parser_name: str,
        parser_version: str,
        tenant_id: str = "default",
    ) -> dict[str, Any]:
        """Assemble the full UES event dict."""
        source_ts = extracted.get('timestamp_dt')

        return {
            'schema_version': '1.2.0',
            'tenant_id': tenant_id,
            'event_id': event_id,
            'ingest_timestamp': ingest_ts.isoformat(),
            'source_event_timestamp': source_ts,
            'raw': {
                'raw_payload': raw_line,
                'raw_format': raw_format,
                'raw_hash': raw_hash,
            },
            'source': normalized['source'],
            'event': normalized['event'],
            'network': normalized.get('network'),
            'identity': normalized.get('identity'),
            'rule': normalized.get('rule'),
            'vendor_attributes': normalized.get('vendor_attributes'),
            'enrichment': normalized.get('enrichment'),
            'lineage': {
                'parser_name': parser_name,
                'parser_version': parser_version,
                'normalization_ruleset_version': normalized.get('_ruleset_version', '1.2.0'),
            },
        }

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
        1. Exact raw bytes are persisted to RawStore immediately (before detection/parsing).
        2. Deterministic UUIDv5 event ID based on namespace, tenant, source, and raw hash.
        3. Parse failures are routed to dead-letter with raw store traceability intact.
        4. Strict at-least-once sink delivery.
        """
        if ingest_ts is None:
            ingest_ts = datetime.now(timezone.utc)

        # 1. Capture authentic raw bytes & compute SHA-256 immediately
        if raw_bytes is None:
            raw_bytes = raw_line.encode('utf-8', errors='surrogateescape')
        raw_hash = hashlib.sha256(raw_bytes).hexdigest()

        # 2. Deterministic UUIDv5 event ID for idempotent processing
        event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"ulpf:{tenant_id}:{source_tag}:{raw_hash}"))

        # 3. Store raw event immediately (zero information loss even on parse errors)
        try:
            self.raw_store.put(event_id, raw_bytes, tenant_id=tenant_id, ingest_ts=ingest_ts)
        except TypeError:
            self.raw_store.put(event_id, raw_bytes)

        # 4. Detect format
        format_id = self.detector.detect(raw_line, source_tag)

        # 5. Get parser
        parser = get_parser_for_format(format_id)
        if parser is None:
            # Try all registered parsers dynamically
            for p in get_all_parsers():
                if p.match(raw_line):
                    parser = p
                    format_id = p.name
                    break

        if parser is None:
            logger.warning('No parser found for event: %s...', raw_line[:60])
            self._errors += 1
            dead_letter_record = {
                'schema_version': '1.2.0',
                'tenant_id': tenant_id,
                'event_id': event_id,
                'ingest_timestamp': ingest_ts.isoformat(),
                'raw': {
                    'raw_payload': raw_line,
                    'raw_format': 'unknown',
                    'raw_hash': raw_hash,
                },
                'raw_payload': raw_line,
                'raw_hash': raw_hash,
                'stage': 'detection',
                'error_type': 'ParserNotFound',
                'error_message': 'No registered or declarative parser matched event format',
                'error': 'No parser matched format',
                'source_tag': source_tag,
                'timestamp': ingest_ts.isoformat(),
            }
            if hasattr(self.validator, 'dead_letter_sink') and self.validator.dead_letter_sink:
                try:
                    self.validator.dead_letter_sink.write(dead_letter_record)
                except Exception:
                    pass
            return False

        # 6. Extract
        try:
            extracted = parser.extract(raw_line)
        except Exception as exc:
            logger.warning('Parser %s extraction failed: %s', parser.name, exc)
            self._errors += 1
            dead_letter_record = {
                'schema_version': '1.2.0',
                'tenant_id': tenant_id,
                'event_id': event_id,
                'ingest_timestamp': ingest_ts.isoformat(),
                'raw': {
                    'raw_payload': raw_line,
                    'raw_format': parser.log_format,
                    'raw_hash': raw_hash,
                },
                'raw_payload': raw_line,
                'raw_hash': raw_hash,
                'stage': 'extraction',
                'error_type': type(exc).__name__,
                'error_message': str(exc),
                'error': f'Extraction failed: {exc}',
                'parser': parser.name,
                'source_tag': source_tag,
                'timestamp': ingest_ts.isoformat(),
            }
            if hasattr(self.validator, 'dead_letter_sink') and self.validator.dead_letter_sink:
                try:
                    self.validator.dead_letter_sink.write(dead_letter_record)
                except Exception:
                    pass
            return False

        # 7. Normalize
        try:
            normalized = self.norm_engine.normalize(extracted, parser.name)
        except Exception as exc:
            logger.warning('Normalization failed for %s: %s', event_id, exc)
            self._errors += 1
            dead_letter_record = {
                'schema_version': '1.2.0',
                'tenant_id': tenant_id,
                'event_id': event_id,
                'ingest_timestamp': ingest_ts.isoformat(),
                'raw_payload': raw_line,
                'raw_hash': raw_hash,
                'stage': 'normalization',
                'error_type': type(exc).__name__,
                'error_message': str(exc),
                'parser': parser.name,
                'source_tag': source_tag,
                'timestamp': ingest_ts.isoformat(),
            }
            if hasattr(self.validator, 'dead_letter_sink') and self.validator.dead_letter_sink:
                try:
                    self.validator.dead_letter_sink.write(dead_letter_record)
                except Exception:
                    pass
            return False

        # 8. Build full UES event
        raw_format = extracted.get('_log_format', parser.log_format)

        ues_event = self._build_ues_event(
            event_id=event_id,
            ingest_ts=ingest_ts,
            raw_line=raw_line,
            raw_format=raw_format,
            raw_hash=raw_hash,
            extracted=extracted,
            normalized=normalized,
            parser_name=parser.name,
            parser_version=parser.version,
            tenant_id=tenant_id,
        )

        # 9. Enrichment (optional)
        if self.enrichment:
            try:
                ues_event = self.enrichment.enrich(ues_event)
            except Exception as exc:
                logger.warning('Enrichment failed for %s: %s', event_id, exc)

        # 10. Validate
        is_valid = self.validator.validate_and_route(ues_event)
        if not is_valid:
            self._errors += 1
            return False

        # 11. Write to sinks (strict at-least-once error tracking)
        sink_success = True
        for sink in self.sinks:
            try:
                sink.write(ues_event)
            except Exception as exc:
                logger.error('Sink %s write failed for %s: %s', sink.__class__.__name__, event_id, exc)
                sink_success = False
                self._errors += 1
                if hasattr(self.validator, 'dead_letter_sink') and self.validator.dead_letter_sink:
                    try:
                        self.validator.dead_letter_sink.write({
                            **ues_event,
                            '_sink_error': str(exc),
                            '_failed_sink': sink.__class__.__name__,
                        })
                    except Exception:
                        pass

        if not sink_success:
            return False

        self._processed += 1
        return True

    def run(self, reader: ReaderBase, tenant_id: str = "default") -> dict[str, int]:
        """Run the pipeline over all events from reader. Returns stats dict."""
        for raw_event in reader.read():
            self.process_event(
                raw_line=raw_event.line,
                source_tag=raw_event.source_tag,
                ingest_ts=raw_event.ingest_timestamp,
                raw_bytes=getattr(raw_event, 'raw_bytes', None),
                tenant_id=tenant_id,
            )

        for sink in self.sinks:
            try:
                sink.flush()
            except Exception as exc:
                logger.error('Sink flush failed: %s', exc)

        return {
            'processed': self._processed,
            'errors': self._errors,
            'valid': self.validator.valid_count,
            'invalid': self.validator.invalid_count,
        }
