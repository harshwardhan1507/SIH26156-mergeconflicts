"""
LEEF (Log Event Extended Format) Parser -- IBM QRadar.

Supports LEEF version 1.0 and 2.0.

LEEF 1.0 format:
  LEEF:1.0|Vendor|Product|Version|EventID|key=value\tkey=value...

LEEF 2.0 format (with optional delimiter specification):
  LEEF:2.0|Vendor|Product|Version|EventID|{delimiter}|key=value{delim}key=value...
"""
from __future__ import annotations

import re
from typing import Any

from ulpf.core.registry import register_parser
from ulpf.parsers.base import BaseParser, ParseError

_LEEF_HEADER_RE = re.compile(
    r'^LEEF:(?P<leef_version>[12]\.0)\|'
    r'(?P<vendor>[^|]*)\|'
    r'(?P<product>[^|]*)\|'
    r'(?P<product_version>[^|]*)\|'
    r'(?P<event_id>[^|]*)'
    r'(?:\|(?P<delimiter>[^|a-zA-Z0-9\s]))?'
    r'\|(?P<attributes>.*)$',
    re.DOTALL,
)

_LEEF_KEY_MAP = {
    'src': 'src_ip', 'dst': 'dst_ip',
    'spt': 'src_port', 'dpt': 'dst_port',
    'proto': 'protocol', 'usrName': 'username',
    'devTime': 'timestamp_raw', 'cat': 'category_raw',
    'sev': 'severity_raw', 'msg': 'message',
    'srcBytes': 'bytes_in', 'dstBytes': 'bytes_out',
    'action': 'action', 'outcome': 'outcome',
    'url': 'url', 'resource': 'resource',
    'domain': 'domain', 'role': 'role',
}

_LEEF_SEV_MAP = {
    '0': 1, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5,
    '6': 6, '7': 7, '8': 8, '9': 9, '10': 10,
    'low': 2, 'medium': 5, 'high': 8, 'critical': 10, 'unknown': 3,
}


def _parse_leef_attributes(attr_str: str, delimiter: str = '\t') -> dict[str, str]:
    result: dict[str, str] = {}
    if not attr_str.strip():
        return result
    pairs = attr_str.split(delimiter)
    for pair in pairs:
        pair = pair.strip()
        if '=' in pair:
            k, _, v = pair.partition('=')
            result[k.strip()] = v.strip()
    return result


# Strip optional syslog header before LEEF: — header token count varies by
# vendor/RFC (3164 vs 5424), so match generically up to the marker itself.
_SYSLOG_PREFIX_RE = re.compile(r'^(?:<\d+>.*?\s)?(?P<leef>LEEF:[0-9.]+\|.*)$', re.DOTALL)


@register_parser
class LEEFParser(BaseParser):
    """IBM QRadar LEEF 1.0 and 2.0 log format parser."""
    name = 'leef'
    version = '1.0.0'
    log_format = 'leef'

    def match(self, raw_line: str) -> bool:
        s = raw_line.strip()
        m = _SYSLOG_PREFIX_RE.match(s)
        if not m:
            return False
        leef_part = m.group('leef')
        return leef_part.startswith('LEEF:1.0|') or leef_part.startswith('LEEF:2.0|')

    def extract(self, raw_line: str) -> dict[str, Any]:
        stripped = raw_line.strip()
        pm = _SYSLOG_PREFIX_RE.match(stripped)
        leef_str = pm.group('leef') if pm else stripped

        m = _LEEF_HEADER_RE.match(leef_str)
        if not m:
            raise ParseError(f'Not a valid LEEF line: {raw_line[:80]!r}')

        leef_version = m.group('leef_version')
        raw_delimiter = m.group('delimiter')
        attributes_str = m.group('attributes') or ''
        delimiter = raw_delimiter if (leef_version == '2.0' and raw_delimiter) else '\t'
        raw_attrs = _parse_leef_attributes(attributes_str, delimiter)

        fields: dict[str, Any] = {
            '_raw': raw_line,
            '_log_format': self.log_format,
            'leef_version': leef_version,
            'vendor': m.group('vendor') or None,
            'product': m.group('product') or None,
            'product_version': m.group('product_version') or None,
            'event_id': m.group('event_id') or None,
        }

        for raw_key, raw_val in raw_attrs.items():
            mapped_key = _LEEF_KEY_MAP.get(raw_key, raw_key)
            fields[mapped_key] = raw_val

        fields['src_ip'] = self.validate_ip(fields.get('src_ip'))
        fields['dst_ip'] = self.validate_ip(fields.get('dst_ip'))
        fields['src_port'] = self.safe_port(fields.get('src_port'))
        fields['dst_port'] = self.safe_port(fields.get('dst_port'))
        fields['bytes_in'] = self.safe_int(fields.get('bytes_in'))
        fields['bytes_out'] = self.safe_int(fields.get('bytes_out'))
        ts = self.parse_timestamp(fields.get('timestamp_raw'))
        fields['timestamp_dt'] = ts.isoformat() if ts else None
        sev_raw = str(fields.get('severity_raw', '5')).lower().strip()
        fields['severity_numeric'] = _LEEF_SEV_MAP.get(sev_raw, 5)
        if 'protocol' in fields:
            fields['protocol'] = str(fields['protocol']).lower()

        return fields
