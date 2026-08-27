"""
RFC 5424 Syslog Parser.

Format:
  <PRIVAL>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG

Example:
  <134>1 2024-03-15T10:22:45.123456+00:00 fw01.corp.example.com sshd 1234 ID47 [exampleSDID@32473 iut="3" eventSource="Application"] User login accepted
"""
from __future__ import annotations

import re
from typing import Any

from ulpf.parsers.base import BaseParser, ParseError
from ulpf.core.registry import register_parser

# RFC 5424 regex: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APPNAME SP PROCID SP MSGID SP SD MSG
_RFC5424_RE = re.compile(
    r'^<(?P<priority>\d+)>(?P<version>\d+)\s+'
    r'(?P<timestamp>\S+)\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<appname>\S+)\s+'
    r'(?P<procid>\S+)\s+'
    r'(?P<msgid>\S+)\s+'
    r'(?P<structured_data>(?:\[.*?\])+|-)\s*'
    r'(?P<message>.*)$',
    re.DOTALL,
)

_SD_ELEMENT_RE = re.compile(r'\[(?P<sdid>[\w@.-]+)(?P<params>(?:\s+[\w.-]+="[^"]*")*?)\]')
_SD_PARAM_RE = re.compile(r'([\w.-]+)="([^"]*)"')


def _parse_structured_data(sd_str: str) -> dict[str, Any]:
    """Parse STRUCTURED-DATA into a flat dict prefixed by SD-ID."""
    result: dict[str, Any] = {}
    if sd_str == '-':
        return result
    for m in _SD_ELEMENT_RE.finditer(sd_str):
        sdid = m.group('sdid')
        for pk, pv in _SD_PARAM_RE.findall(m.group('params')):
            result[f'sd_{sdid}_{pk}'] = pv
    return result


def _pri_to_facility_severity(pri: int) -> tuple[int, int]:
    """Split RFC 5424 PRI into (facility, severity)."""
    return pri >> 3, pri & 0x07


_SYSLOG_SEVERITY_MAP = {0: 10, 1: 9, 2: 8, 3: 7, 4: 6, 5: 5, 6: 3, 7: 1}
_SYSLOG_SEVERITY_NAMES = {
    0: 'emergency', 1: 'alert', 2: 'critical', 3: 'error',
    4: 'warning', 5: 'notice', 6: 'informational', 7: 'debug',
}


@register_parser
class SyslogRFC5424Parser(BaseParser):
    name = 'syslog_rfc5424'
    version = '1.0.0'
    log_format = 'syslog_rfc5424'

    def match(self, raw_line: str) -> bool:
        stripped = raw_line.strip()
        # Must start with <DIGITS> followed by a single-digit version number
        return bool(re.match(r'^<\d+>1\s', stripped))

    def extract(self, raw_line: str) -> dict[str, Any]:
        stripped = raw_line.strip()
        m = _RFC5424_RE.match(stripped)
        if not m:
            raise ParseError(f'Not a valid RFC5424 syslog line: {raw_line[:80]!r}')

        pri = int(m.group('priority'))
        facility, sev_num = _pri_to_facility_severity(pri)

        fields: dict[str, Any] = {
            '_raw': raw_line,
            '_log_format': self.log_format,
            'priority': pri,
            'facility': facility,
            'syslog_severity': sev_num,
            'syslog_severity_name': _SYSLOG_SEVERITY_NAMES.get(sev_num, 'unknown'),
            'version': self.safe_int(m.group('version')),
            'timestamp_raw': m.group('timestamp') if m.group('timestamp') != '-' else None,
            'hostname': m.group('hostname') if m.group('hostname') != '-' else None,
            'appname': m.group('appname') if m.group('appname') != '-' else None,
            'procid': m.group('procid') if m.group('procid') != '-' else None,
            'msgid': m.group('msgid') if m.group('msgid') != '-' else None,
            'message': m.group('message').strip() if m.group('message') else None,
            'severity_ues': _SYSLOG_SEVERITY_MAP.get(sev_num, 5),
        }

        # Parse structured data
        sd_fields = _parse_structured_data(m.group('structured_data'))
        fields.update(sd_fields)

        # Parse timestamp
        ts = self.parse_timestamp(fields['timestamp_raw'])
        fields['timestamp_dt'] = ts.isoformat() if ts else None

        return fields
