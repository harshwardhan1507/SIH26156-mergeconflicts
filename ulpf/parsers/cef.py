"""
Common Event Format (CEF) Parser.

Format:
  CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

Optionally prefixed by a syslog header.

Example:
  CEF:0|Cisco|ASA|9.14|106023|Deny TCP (no connection)|5|src=10.1.1.5 spt=44321 dst=203.0.113.42 dpt=443 proto=TCP
"""
from __future__ import annotations

import re
from typing import Any

from ulpf.parsers.base import BaseParser, ParseError
from ulpf.core.registry import register_parser

# Strip optional syslog header before CEF:
_SYSLOG_PREFIX_RE = re.compile(r'^(?:<\d+>\S+\s+\S+\s+\S+\s+)?(?P<cef>CEF:.*)$', re.DOTALL)

# Split CEF header pipe-delimited (first 8 fields)
_CEF_HEADER_RE = re.compile(
    r'^CEF:(?P<version>\d+)\|'
    r'(?P<device_vendor>[^|]*)\|'
    r'(?P<device_product>[^|]*)\|'
    r'(?P<device_version>[^|]*)\|'
    r'(?P<signature_id>[^|]*)\|'
    r'(?P<name>[^|]*)\|'
    r'(?P<severity>[^|]*)\|'
    r'(?P<extension>.*)$',
    re.DOTALL,
)

_CEF_SEV_TO_UES = {
    0: 1, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8, 9: 9, 10: 10
}


def _parse_extension(ext: str) -> dict[str, str]:
    """
    Parse CEF extension key=value pairs.
    Handles escaped equals and spaces in values.
    """
    result: dict[str, str] = {}
    # Match key=value, value may contain spaces but ends before next key=
    pattern = re.compile(r'(\w+)=((?:[^\\=]|\\.)*)(?=(?:\s+\w+=|$))')
    for m in pattern.finditer(ext):
        result[m.group(1)] = m.group(2).strip()
    return result


@register_parser
class CEFParser(BaseParser):
    name = 'cef'
    version = '1.0.0'
    log_format = 'cef'

    def match(self, raw_line: str) -> bool:
        stripped = raw_line.strip()
        # May have a syslog prefix before CEF:
        m = _SYSLOG_PREFIX_RE.match(stripped)
        return m is not None and m.group('cef').startswith('CEF:')

    def extract(self, raw_line: str) -> dict[str, Any]:
        stripped = raw_line.strip()

        # Strip syslog prefix if present
        syslog_prefix = None
        pm = _SYSLOG_PREFIX_RE.match(stripped)
        if pm:
            cef_str = pm.group('cef')
        else:
            cef_str = stripped

        m = _CEF_HEADER_RE.match(cef_str)
        if not m:
            raise ParseError(f'Not a valid CEF line: {raw_line[:80]!r}')

        sev_raw = m.group('severity').strip()
        try:
            sev_int = int(sev_raw)
        except ValueError:
            sev_int = 5
        sev_ues = _CEF_SEV_TO_UES.get(sev_int, 5)

        ext = _parse_extension(m.group('extension') or '')

        fields: dict[str, Any] = {
            '_raw': raw_line,
            '_log_format': self.log_format,
            'cef_version': self.safe_int(m.group('version')),
            'DeviceVendor': m.group('device_vendor').strip(),
            'DeviceProduct': m.group('device_product').strip(),
            'DeviceVersion': m.group('device_version').strip(),
            'SignatureID': m.group('signature_id').strip(),
            'Name': m.group('name').strip(),
            'Severity': sev_raw,
            'severity_ues': sev_ues,
        }

        # Merge extension fields
        fields.update(ext)

        # Parse known timestamp fields
        for ts_field in ('rt', 'start', 'end', 'deviceReceiptTime'):
            if ts_field in ext:
                dt = self.parse_timestamp(ext[ts_field])
                fields[f'{ts_field}_dt'] = dt.isoformat() if dt else None
                break
        else:
            fields['rt_dt'] = None

        # Validate IPs
        for ip_field in ('src', 'dst', 'dvc'):
            if ip_field in fields:
                fields[ip_field] = self.validate_ip(fields[ip_field]) or fields[ip_field]

        return fields
