"""
Format Detector.

Heuristic-based classifier that determines which parser format_id
should handle a given raw line.

Detection priority order (highest to lowest):
  1. Manual override from sources.yaml (keyed by source_tag prefix/exact match)
  2. Cisco ASA (contains %ASA-)
  3. CEF (starts with CEF: optionally after syslog header)
  4. RFC 5424 (<DIGITS>1 SP)
  5. RFC 3164 (<DIGITS> + month-name timestamp)
  6. PAN CSV (TRAFFIC in col[2], >=30 columns)
  7. JSON ({...})
  8. LEEF (LEEF: prefix — recognized but no parser yet, returns 'leef')
  9. Key-Value (key=value pairs)
 10. unknown
"""
from __future__ import annotations

import json
import re
import csv
import io
from pathlib import Path

import yaml


_ASA_RE = re.compile(r'%ASA-\d-\d+')
_CEF_RE = re.compile(r'(?:^|<\d+>\S+\s+\S+\s+\S+\s+)CEF:\d')
_RFC5424_RE = re.compile(r'^<\d+>1\s')
_RFC3164_RE = re.compile(r'^<\d+>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s')
_RFC3164_ALT_RE = re.compile(r'^<\d+>\d{4}-')
_LEEF_RE = re.compile(r'^LEEF:[0-9.]+\|')
_KV_RE = re.compile(r'\b\w+=\S+')


class FormatDetector:
    """
    Classifies raw log lines into format_id strings that match parser names.
    """

    def __init__(self, sources_config_path: str | Path | None = None):
        self._overrides: dict[str, str] = {}  # source_tag_prefix -> format_id
        if sources_config_path:
            self._load_overrides(Path(sources_config_path))

    def _load_overrides(self, path: Path) -> None:
        if not path.exists():
            return
        with open(path, 'r', encoding='utf-8') as fh:
            config = yaml.safe_load(fh) or {}
        for entry in config.get('sources', []):
            tag = entry.get('source_tag', '')
            fmt = entry.get('format', '')
            if tag and fmt:
                self._overrides[tag] = fmt

    def detect(self, raw_line: str, source_tag: str = '') -> str:
        """Return the format_id string for raw_line."""
        # 1. Manual override
        for prefix, fmt in self._overrides.items():
            if source_tag.startswith(prefix) or source_tag == prefix:
                return fmt

        stripped = raw_line.strip()

        # 2. Cisco ASA (before RFC3164 check since it IS RFC3164 wrapped)
        if _ASA_RE.search(stripped):
            return 'cisco_asa'

        # 3. CEF
        if _CEF_RE.search(stripped):
            return 'cef'

        # 4. RFC 5424
        if _RFC5424_RE.match(stripped):
            return 'syslog_rfc5424'

        # 5. RFC 3164 (BSDsyslog with month name or ISO-date variant)
        if _RFC3164_RE.match(stripped) or _RFC3164_ALT_RE.match(stripped):
            return 'syslog_rfc3164'

        # 6. PAN CSV — TRAFFIC in col 2, enough columns
        if ',' in stripped and 'TRAFFIC' in stripped:
            try:
                rows = list(csv.reader(io.StringIO(stripped)))
                if rows and len(rows[0]) >= 30 and rows[0][2].strip().upper() == 'TRAFFIC':
                    return 'paloalto_csv'
            except Exception:
                pass

        # 7. JSON object
        if stripped.startswith('{'):
            try:
                json.loads(stripped)
                return 'json_passthrough'
            except json.JSONDecodeError:
                pass

        # 8. LEEF (recognized, no parser yet)
        if _LEEF_RE.match(stripped):
            return 'leef'

        # 9. Key-value
        if _KV_RE.search(stripped):
            return 'kv'

        return 'unknown'
