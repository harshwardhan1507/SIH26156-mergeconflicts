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
    ) -> dict[str, Any]:
        """Assemble the full UES event dict."""
        source_ts = extracted.get('timestamp_dt')

        return {
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
            'enrichment': normalized.get('enrichment'),
            'lineage': {
                'parser_name': parser_name,
                'parser_version': parser_version,
                'normalization_ruleset_version': normalized.get('_ruleset_version', '0.0.0'),
            },
        }

    def process_event(self, raw_line: str, source_tag: str, ingest_ts: datetime | None = None) -> bool:
        """
        Process a single raw event through the full pipeline.
        Returns True if successfully written to a sink, False otherwise.
        """
        if ingest_ts is None:
            ingest_ts = datetime.now(timezone.utc)
        event_id = str(uuid.uuid4())

        # 1. Detect format
        format_id = self.detector.detect(raw_line, source_tag)

        # 2. Get parser
        parser = get_parser_for_format(format_id)
        if parser is None:
            # Try all parsers in registration order
            for p in get_all_parsers():
                if p.match(raw_line):
                    parser = p
                    format_id = p.name
                    break

        if parser is None:
            logger.warning('No parser found for event: %s...', raw_line[:60])
            self._errors += 1
            return False

        # 3. Extract
        try:
            extracted = parser.extract(raw_line)
        except Exception as exc:
            logger.warning('Parser %s extraction failed: %s', parser.name, exc)
            self._errors += 1
            return False

        # 4. Store raw event (get sha256)
        raw_hash = self.raw_store.put(event_id, raw_line)

        # 5. Normalize
        try:
            normalized = self.norm_engine.normalize(extracted, parser.name)
        except Exception as exc:
            logger.warning('Normalization failed for %s: %s', event_id, exc)
            self._errors += 1
            return False

        # 6. Build full UES event
        raw_format = extracted.get('_log_format', format_id)
        # Map log_format to schema enum values
        format_enum_map = {
            'syslog_rfc5424': 'syslog_rfc5424',
            'syslog_rfc3164': 'syslog_rfc3164',
            'cef': 'cef',
            'leef': 'leef',
            'json': 'json',
            'csv': 'csv',
            'kv': 'kv',
            'xml': 'xml',
            'xml_generic': 'xml',
            'aws_cloudtrail': 'json',
            'azure_monitor': 'json',
            'gcp_audit': 'json',
        }
        raw_format_enum = format_enum_map.get(raw_format, 'unknown')

        ues_event = self._build_ues_event(
            event_id=event_id,
            ingest_ts=ingest_ts,
            raw_line=raw_line,
            raw_format=raw_format_enum,
            raw_hash=raw_hash,
            extracted=extracted,
            normalized=normalized,
            parser_name=parser.name,
            parser_version=parser.version,
        )

        # 7. Enrichment (optional)
        if self.enrichment:
            try:
                ues_event = self.enrichment.enrich(ues_event)
            except Exception as exc:
                logger.warning('Enrichment failed for %s: %s', event_id, exc)

        # 8. Validate
        is_valid = self.validator.validate_and_route(ues_event)
        if not is_valid:
            self._errors += 1
            return False

        # 9. Write to sinks
        for sink in self.sinks:
            try:
                sink.write(ues_event)
            except Exception as exc:
                logger.error('Sink %s write failed for %s: %s', sink.__class__.__name__, event_id, exc)

        self._processed += 1
        return True

    def run(self, reader: ReaderBase) -> dict[str, int]:
        """Run the pipeline over all events from reader. Returns stats dict."""
        for raw_event in reader.read():
            self.process_event(
                raw_line=raw_event.line,
                source_tag=raw_event.source_tag,
                ingest_ts=raw_event.ingest_timestamp,
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
