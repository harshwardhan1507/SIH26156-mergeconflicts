"""
Palo Alto Networks Traffic Log CSV Parser.

PAN-OS traffic logs exported in CSV format have a fixed column order.
This parser handles the first ~35 columns that are most analytically useful.

Example:
  2024-03-15T10:22:45.000+00:00,corp-pa,TRAFFIC,start,2024/03/15 10:22:45,2024/03/15 10:22:50,vsys1,10.1.0.5,198.51.100.20,10.1.0.5,198.51.100.20,allow-internet,username1,,,0,,,TCP,inside,outside,Gi0/1,Gi0/2,allow-internet,2024/03/15 10:22:51,12345,1,443,58432,0,0,0x401a,tcp,allow,1024,2048,3072,10,2024/03/15 10:22:50,5,any,0,2345678,0x0,US,US,0,5,4
"""
from __future__ import annotations

import csv
import io
from typing import Any

from ulpf.core.registry import register_parser
from ulpf.parsers.base import BaseParser, ParseError

# PAN-OS traffic log column names (positions 0-35, key fields)
_PAN_COLUMNS = [
    'receive_time',        # 0
    'serial',              # 1
    'type',                # 2 — must be 'TRAFFIC'
    'threat_content_type', # 3
    'config_version',      # 4
    'generate_time',       # 5
    'src_ip',              # 6
    'dst_ip',              # 7
    'natsrc',              # 8
    'natdst',              # 9
    'rule',                # 10
    'src_user',            # 11
    'dst_user',            # 12
    'app',                 # 13 (application)
    'vsys',                # 14
    'src_zone',            # 15
    'dst_zone',            # 16
    'inbound_if',          # 17
    'outbound_if',         # 18
    'log_action',          # 19
    'session_end_reason',  # 20
    'sessionid',           # 21
    'repeatcnt',           # 22
    'src_port',            # 23
    'dst_port',            # 24
    'natsport',            # 25
    'natdport',            # 26
    'flags',               # 27
    'proto',               # 28
    'action',              # 29
    'bytes',               # 30
    'bytes_sent',          # 31
    'bytes_received',      # 32
    'packets',             # 33
    'start',               # 34
    'elapsed',             # 35
]


@register_parser
class PaloAltoCSVParser(BaseParser):
    name = 'paloalto_csv'
    version = '1.0.0'
    log_format = 'csv'

    def match(self, raw_line: str) -> bool:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith('#'):
            return False
        try:
            rows = list(csv.reader(io.StringIO(stripped)))
            if not rows:
                return False
            cols = rows[0]
            # PAN traffic logs have TRAFFIC in position 2
            return len(cols) >= 30 and cols[2].strip().upper() == 'TRAFFIC'
        except Exception:
            return False

    def extract(self, raw_line: str) -> dict[str, Any]:
        stripped = raw_line.strip()
        try:
            rows = list(csv.reader(io.StringIO(stripped)))
        except Exception as e:
            raise ParseError(f'CSV parse failed: {e}') from e

        if not rows:
            raise ParseError('Empty CSV line')

        cols = rows[0]
        if len(cols) < 30:
            raise ParseError(f'Expected >=30 columns, got {len(cols)}')

        if cols[2].strip().upper() != 'TRAFFIC':
            raise ParseError(f'Not a TRAFFIC log, type={cols[2]!r}')

        # Map column positions
        named: dict[str, str] = {}
        for i, col_name in enumerate(_PAN_COLUMNS):
            if i < len(cols):
                named[col_name] = cols[i].strip()

        # Store extra columns
        extra = {f'col_{i}': v.strip() for i, v in enumerate(cols) if i >= len(_PAN_COLUMNS)}

        # Parse action → UES mapping
        action_raw = named.get('action', '').lower()
        action_ues = {
            'allow': 'allow',
            'deny': 'deny',
            'drop': 'deny',
            'reset-both': 'deny',
            'reset-client': 'deny',
            'reset-server': 'deny',
        }.get(action_raw, action_raw)

        ts = self.parse_timestamp(named.get('receive_time'))

        fields: dict[str, Any] = {
            '_raw': raw_line,
            '_log_format': self.log_format,
            'vendor': 'Palo Alto Networks',
            'product': 'PAN-OS',
            'device_serial': named.get('serial'),
            'timestamp_raw': named.get('receive_time'),
            'timestamp_dt': ts.isoformat() if ts else None,
            'src_ip': self.validate_ip(named.get('src_ip')),
            'dst_ip': self.validate_ip(named.get('dst_ip')),
            'src_port': self.safe_port(named.get('src_port')),
            'dst_port': self.safe_port(named.get('dst_port')),
            'proto': named.get('proto', '').lower() or None,
            'bytes_sent': self.safe_int(named.get('bytes_sent')),
            'bytes_received': self.safe_int(named.get('bytes_received')),
            'action_raw': action_raw,
            'action_ues': action_ues,
            'rule': named.get('rule'),
            'src_user': named.get('src_user') or None,
            'app': named.get('app') or None,
            'src_zone': named.get('src_zone') or None,
            'dst_zone': named.get('dst_zone') or None,
            'inbound_if': named.get('inbound_if') or None,
            'outbound_if': named.get('outbound_if') or None,
            'sessionid': named.get('sessionid'),
            'severity_ues': 3,  # Traffic logs are informational
            '_vendor_extra': extra,
        }

        return fields
