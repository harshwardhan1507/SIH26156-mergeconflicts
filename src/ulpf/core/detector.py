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

import csv
import io
import json
import re
from pathlib import Path

import yaml

from ulpf.core.registry import get_all_parsers

_ASA_RE = re.compile(r'%ASA-\d-\d+')
# Match CEF:/LEEF: markers either at the very start of the line, or immediately
# after ANY syslog envelope (RFC3164, RFC5424, or vendor variants with a
# different number of header tokens) — i.e. right after whitespace.
_CEF_RE = re.compile(r'(?:^|\s)CEF:\d')
_LEEF_RE = re.compile(r'(?:^|\s)LEEF:[0-9.]+\|')
_RFC5424_RE = re.compile(r'^<\d+>1\s')
_RFC3164_RE = re.compile(r'^<\d+>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s')
_RFC3164_ALT_RE = re.compile(r'^<\d+>\d{4}-')
_KV_RE = re.compile(r'\b\w+=\S+')


class FormatDetector:
    """
    Classifies raw log lines into format_id strings that match parser names.
    Supports dynamic parser self-registration with intelligent priority ordering.
    """

    def __init__(self, sources_config_path: str | Path | None = None):
        self._overrides: dict[str, str] = {}  # source_tag_prefix -> format_id
        if sources_config_path:
            self._load_overrides(Path(sources_config_path))

    def _load_overrides(self, path: Path) -> None:
        if not path.exists():
            return
        with open(path, encoding='utf-8') as fh:
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

        # 2. Priority matchers for encapsulated / structured formats
        # Cisco ASA (%ASA- mnemonic inside syslog envelope)
        if _ASA_RE.search(stripped):
            return 'cisco_asa'

        # CEF (ArcSight, with or without syslog envelope)
        if _CEF_RE.search(stripped):
            return 'cef'

        # LEEF (IBM QRadar, with or without syslog envelope)
        if _LEEF_RE.search(stripped):
            return 'leef'

        # RFC 5424 structured syslog
        if _RFC5424_RE.match(stripped):
            return 'syslog_rfc5424'

        # Windows / Generic XML
        if stripped.startswith('<?xml') or re.match(r'^\s*<[a-zA-Z_]', stripped):
            return 'xml_generic'

        # JSON formats (CloudTrail, Azure, GCP, Generic)
        if stripped.startswith('{'):
            try:
                obj = json.loads(stripped)
                if 'eventVersion' in obj and 'eventSource' in obj and str(obj.get('eventSource', '')).endswith('.amazonaws.com'):
                    return 'aws_cloudtrail'
                if 'protoPayload' in obj and ('logName' in obj or 'insertId' in obj) and str(obj.get('protoPayload', {}).get('@type', '')).startswith('type.googleapis.com/google.cloud.audit'):
                    return 'gcp_audit'
                if 'operationName' in obj and 'resourceId' in obj and ('resultType' in obj or 'category' in obj):
                    return 'azure_monitor'
                return 'json_passthrough'
            except json.JSONDecodeError:
                pass

        # PAN CSV
        if ',' in stripped and 'TRAFFIC' in stripped:
            try:
                rows = list(csv.reader(io.StringIO(stripped)))
                if rows and len(rows[0]) >= 30 and rows[0][2].strip().upper() == 'TRAFFIC':
                    return 'paloalto_csv'
            except Exception:
                pass

        # RFC 3164 BSD syslog
        if _RFC3164_RE.match(stripped) or _RFC3164_ALT_RE.match(stripped):
            return 'syslog_rfc3164'

        # 3. Dynamic evaluation of declarative no-code sources
        try:
            from ulpf.core.declarative import get_declarative_registry
            for decl_parser in get_declarative_registry().list_sources():
                if decl_parser.enabled and decl_parser.match(raw_line):
                    return decl_parser.name
        except Exception:
            pass

        # 4. Dynamic evaluation of all registered Python plugin parsers
        for parser in get_all_parsers():
            try:
                if parser.match(raw_line):
                    return parser.name
            except Exception:
                pass

        # 5. Key-value fallback
        if _KV_RE.search(stripped):
            return 'kv'

        return 'unknown'
