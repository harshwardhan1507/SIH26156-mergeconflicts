"""
RFC 3164 / BSD Syslog Parser.

Format:
  <PRIVAL>TIMESTAMP HOSTNAME TAG[PID]: MSG
  or <PRIVAL>TIMESTAMP HOSTNAME MSG

Example:
  <38>Aug 15 12:34:56 proxy01 squid[2048]: TCP_MISS/200 4321 GET http://example.com/ - DIRECT/93.184.216.34 text/html
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from ulpf.parsers.base import BaseParser, ParseError
from ulpf.core.registry import register_parser

_RFC3164_RE = re.compile(
    r'^<(?P<priority>\d+)>'
    r'(?P<timestamp>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|'
    r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<tag>\S+?)(?:\[(?P<pid>\d+)\])?:\s*'
    r'(?P<message>.*)$',
    re.DOTALL,
)

_SYSLOG_SEVERITY_MAP = {0: 10, 1: 9, 2: 8, 3: 7, 4: 6, 5: 5, 6: 3, 7: 1}
_SYSLOG_SEVERITY_NAMES = {
    0: 'emergency', 1: 'alert', 2: 'critical', 3: 'error',
    4: 'warning', 5: 'notice', 6: 'informational', 7: 'debug',
}


@register_parser
class SyslogRFC3164Parser(BaseParser):
    name = 'syslog_rfc3164'
    version = '1.0.0'
    log_format = 'syslog_rfc3164'

    def match(self, raw_line: str) -> bool:
        stripped = raw_line.strip()
        # RFC 3164: starts with <DIGITS> but NOT <DIGITS>1 SP (which is RFC5424)
        if not re.match(r'^<\d+>', stripped):
            return False
        # Exclude RFC5424 (version=1 immediately after PRI)
        if re.match(r'^<\d+>1\s', stripped):
            return False
        # Exclude Cisco ASA (handled by dedicated parser)
        if '%ASA-' in stripped:
            return False
        return True

    def extract(self, raw_line: str) -> dict[str, Any]:
        stripped = raw_line.strip()
        m = _RFC3164_RE.match(stripped)
        if not m:
            raise ParseError(f'Not a valid RFC3164 syslog line: {raw_line[:80]!r}')

        pri = int(m.group('priority'))
        facility = pri >> 3
        sev_num = pri & 0x07

        # Inject current year if timestamp has no year (BSD syslog)
        ts_raw = m.group('timestamp')
        if ts_raw and not re.match(r'\d{4}', ts_raw):
            ts_raw = f"{datetime.now(tz=timezone.utc).year} {ts_raw}"

        ts = self.parse_timestamp(ts_raw)

        fields: dict[str, Any] = {
            '_raw': raw_line,
            '_log_format': self.log_format,
            'priority': pri,
            'facility': facility,
            'syslog_severity': sev_num,
            'syslog_severity_name': _SYSLOG_SEVERITY_NAMES.get(sev_num, 'unknown'),
            'timestamp_raw': m.group('timestamp'),
            'timestamp_dt': ts.isoformat() if ts else None,
            'hostname': m.group('hostname'),
            'tag': m.group('tag'),
            'pid': m.group('pid'),
            'message': m.group('message').strip() if m.group('message') else None,
            'severity_ues': _SYSLOG_SEVERITY_MAP.get(sev_num, 5),
        }
        return fields
