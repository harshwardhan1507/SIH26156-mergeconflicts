"""
UES Validation Gate.

Validates every normalized event against the UES JSON Schema.
Invalid events are written to a dead-letter NDJSON file.
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator

logger = logging.getLogger(__name__)


class _DeadLetterSink:
    """
    Thin writer that lets other pipeline stages (parser/detector failures,
    sink write failures) route arbitrary records into the same dead-letter
    file the Validator uses for schema failures — one quarantine queue.
    """

    def __init__(self, fh: Any) -> None:
        self._fh = fh

    def write(self, record: dict[str, Any]) -> None:
        self._fh.write(json.dumps(record, default=str) + '\n')


class Validator:
    def __init__(self, schema_path: str | Path, dead_letter_path: str | Path):
        self.schema_path = Path(schema_path)
        self.dead_letter_path = Path(dead_letter_path)
        self.dead_letter_path.parent.mkdir(parents=True, exist_ok=True)

        with open(self.schema_path, encoding='utf-8') as fh:
            schema = json.load(fh)
        self._validator = Draft7Validator(schema)
        self._dl_fh = open(self.dead_letter_path, 'a', encoding='utf-8', buffering=1)
        # Exposed so Pipeline can route pre-validation failures (parser not
        # found, extraction error, sink write error) to the same queue.
        self.dead_letter_sink = _DeadLetterSink(self._dl_fh)
        self._valid_count = 0
        self._invalid_count = 0

    def validate(self, event: dict[str, Any]) -> tuple[bool, list[str]]:
        """Returns (is_valid, list_of_error_messages)."""
        errors = [
            f'{e.json_path}: {e.message}'
            for e in sorted(self._validator.iter_errors(event), key=lambda e: list(e.path))
        ]
        return len(errors) == 0, errors

    def validate_and_route(self, event: dict[str, Any]) -> bool:
        """
        Validate event. Returns True if valid, False if sent to dead-letter.
        Writes invalid events to the dead-letter file.
        """
        is_valid, errors = self.validate(event)
        if is_valid:
            self._valid_count += 1
            return True
        else:
            self._invalid_count += 1
            dl_record = {
                'schema_version': event.get('schema_version', '1.2.0'),
                'tenant_id': event.get('tenant_id', 'default'),
                'event_id': event.get('event_id', 'unknown'),
                'raw_payload': event.get('raw', {}).get('raw_payload', ''),
                'raw_hash': event.get('raw', {}).get('raw_hash', ''),
                'raw_format': event.get('raw', {}).get('raw_format', 'unknown'),
                'stage': 'validation',
                'error_type': 'SchemaValidationError',
                'error_message': '; '.join(errors) if errors else 'Failed schema validation',
                'validation_errors': errors,
                'timestamp': datetime.now(tz=UTC).isoformat(),
            }
            self._dl_fh.write(json.dumps(dl_record, default=str) + '\n')
            logger.warning('Event %s failed validation: %s', event.get('event_id'), errors)
            return False

    def close(self) -> None:
        self._dl_fh.close()

    @property
    def valid_count(self) -> int:
        return self._valid_count

    @property
    def invalid_count(self) -> int:
        return self._invalid_count
