"""
Generic JSON Passthrough Parser.

For sources that already emit structured JSON but with vendor-specific field names.
The parser extracts the JSON fields as-is; the normalization engine maps them
via the json_passthrough.yaml mapping.

Example:
  {"ts":"2024-03-15T10:22:45Z","host":"vpn-gw01","event":"vpn_connect","user":"alice","src":"203.0.113.5","dst":"10.0.0.1","proto":"udp","bytes_in":1234,"bytes_out":5678,"result":"success"}
"""
from __future__ import annotations

import json
from typing import Any

from ulpf.parsers.base import BaseParser, ParseError
from ulpf.core.registry import register_parser


@register_parser
class JSONPassthroughParser(BaseParser):
    name = 'json_passthrough'
    version = '1.0.0'
    log_format = 'json'

    def match(self, raw_line: str) -> bool:
        stripped = raw_line.strip()
        if not stripped.startswith('{'):
            return False
        try:
            json.loads(stripped)
            return True
        except json.JSONDecodeError:
            return False

    def extract(self, raw_line: str) -> dict[str, Any]:
        stripped = raw_line.strip()
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as e:
            raise ParseError(f'JSON parse error: {e}') from e

        if not isinstance(data, dict):
            raise ParseError(f'Expected JSON object, got {type(data).__name__}')

        fields: dict[str, Any] = {
            '_raw': raw_line,
            '_log_format': self.log_format,
        }

        # Flatten the JSON (one level deep — top-level keys only)
        # Nested objects are kept as-is but stored in _raw (zero information loss)
        for k, v in data.items():
            fields[k] = v

        # Try common timestamp field names
        for ts_field in ('ts', 'timestamp', 'time', '@timestamp', 'event_time', 'datetime'):
            if ts_field in fields:
                dt = self.parse_timestamp(str(fields[ts_field]))
                fields['timestamp_dt'] = dt.isoformat() if dt else None
                break
        else:
            fields['timestamp_dt'] = None

        # Validate IPs if present
        for ip_field in ('src', 'dst', 'src_ip', 'dst_ip', 'source_ip', 'dest_ip'):
            if ip_field in fields:
                validated = self.validate_ip(str(fields[ip_field]))
                if validated:
                    fields[ip_field] = validated

        # Determine severity
        sev = fields.get('severity', fields.get('level', fields.get('priority', None)))
        if isinstance(sev, int):
            fields['severity_ues'] = max(0, min(10, sev))
        else:
            fields['severity_ues'] = 5  # default informational

        return fields
