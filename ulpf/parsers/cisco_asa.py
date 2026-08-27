"""
Cisco ASA Syslog Parser.

Cisco ASA wraps %ASA-severity-mnemonic messages inside an RFC 3164 syslog envelope.

Examples:
  <166>Aug 15 14:22:10 asa01.corp.example.com %ASA-6-106100: access-list OUTSIDE_IN permitted tcp OUTSIDE/10.0.0.5(44123) -> INSIDE/192.168.1.100(443) hit-cnt 1
  <162>Aug 15 14:23:01 asa01.corp.example.com %ASA-2-106016: Deny IP spoof from (10.0.0.99) to 192.168.1.50 on interface OUTSIDE
  <165>Aug 15 14:25:44 asa01.corp.example.com %ASA-5-304001: 192.168.1.5 Accessed URL 203.0.113.10:/index.html
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from ulpf.parsers.base import BaseParser, ParseError
from ulpf.core.registry import register_parser

_RFC3164_PREFIX_RE = re.compile(
    r'^<(?P<priority>\d+)>'
    r'(?P<timestamp>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<body>.*)$',
    re.DOTALL,
)

_ASA_MSG_RE = re.compile(
    r'^%ASA-(?P<sev_num>\d)-(?P<mnemonic>\d+):\s*(?P<message>.*)$',
    re.DOTALL,
)

# Try to extract src/dst IP:port from common ASA message patterns
# Handles: "permitted tcp OUTSIDE/10.0.0.5(port) -> INSIDE/192.168.1.1(port)"
# Also handles: "from (10.0.0.99) to ..." and "Deny IP spoof from (IP)"
_ASA_CONN_RE = re.compile(
    r'(?:from|permitted|denied)'           # action keyword
    r'\s+(?:\w+\s+)?'                      # optional protocol token (e.g. "tcp ")
    r'(?:[\w-]+/)?'                        # optional interface name + slash
    r'\(?(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})\)?'   # src IP (optional parens)
    r'(?:\((?P<src_port>\d+)\))?'          # optional src port in parens
    r'(?:\s*->\s*'                          # arrow separator
    r'(?:[\w-]+/)?'                        # optional dst interface + slash
    r'(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})'  # dst IP
    r'(?:\((?P<dst_port>\d+)\))?)?',       # optional dst port in parens
    re.IGNORECASE,
)

_ASA_ACL_RE = re.compile(
    r'access-list\s+(?P<acl_name>\S+)\s+(?P<action>permitted|denied)\s+(?P<proto>\w+)',
    re.IGNORECASE,
)

_ASA_SEVERITY_MAP = {
    '0': 10, '1': 9, '2': 8, '3': 7, '4': 6, '5': 5, '6': 3, '7': 1
}
_ASA_SEVERITY_NAMES = {
    '0': 'emergency', '1': 'alert', '2': 'critical', '3': 'error',
    '4': 'warning', '5': 'notification', '6': 'informational', '7': 'debug',
}


@register_parser
class CiscoASAParser(BaseParser):
    name = 'cisco_asa'
    version = '1.0.0'
    log_format = 'syslog_rfc3164'

    def match(self, raw_line: str) -> bool:
        return '%ASA-' in raw_line

    def extract(self, raw_line: str) -> dict[str, Any]:
        stripped = raw_line.strip()

        # Parse outer RFC3164 envelope
        env_m = _RFC3164_PREFIX_RE.match(stripped)
        if not env_m:
            raise ParseError(f'Cannot parse Cisco ASA envelope: {raw_line[:80]!r}')

        pri = int(env_m.group('priority'))
        facility = pri >> 3

        ts_raw = env_m.group('timestamp')
        if ts_raw and not re.match(r'\d{4}', ts_raw):
            ts_raw = f"{datetime.now(tz=timezone.utc).year} {ts_raw}"
        ts = self.parse_timestamp(ts_raw)

        body = env_m.group('body').strip()

        # Parse %ASA-sev-mnemonic
        asa_m = _ASA_MSG_RE.match(body)
        if not asa_m:
            raise ParseError(f'Cannot parse ASA message body: {body[:80]!r}')

        sev_str = asa_m.group('sev_num')
        mnemonic = asa_m.group('mnemonic')
        message = asa_m.group('message').strip()

        fields: dict[str, Any] = {
            '_raw': raw_line,
            '_log_format': self.log_format,
            'vendor': 'Cisco',
            'product': 'ASA',
            'hostname': env_m.group('hostname'),
            'priority': pri,
            'facility': facility,
            'asa_severity': sev_str,
            'asa_severity_name': _ASA_SEVERITY_NAMES.get(sev_str, 'unknown'),
            'severity_ues': _ASA_SEVERITY_MAP.get(sev_str, 5),
            'asa_mnemonic': mnemonic,
            'timestamp_raw': env_m.group('timestamp'),
            'timestamp_dt': ts.isoformat() if ts else None,
            'message': message,
        }

        # Try to extract ACL info
        acl_m = _ASA_ACL_RE.search(message)
        if acl_m:
            fields['acl_name'] = acl_m.group('acl_name')
            fields['acl_action'] = acl_m.group('action').lower()
            fields['proto'] = acl_m.group('proto').lower()

        # Try to extract connection 5-tuple
        conn_m = _ASA_CONN_RE.search(message)
        if conn_m:
            fields['src_ip'] = self.validate_ip(conn_m.group('src_ip'))
            fields['src_port'] = self.safe_port(conn_m.group('src_port'))
            fields['dst_ip'] = self.validate_ip(conn_m.group('dst_ip'))
            fields['dst_port'] = self.safe_port(conn_m.group('dst_port'))

        return fields
