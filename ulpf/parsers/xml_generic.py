"""
Generic XML and Windows Event Log (EVTX/XML) Parser.

Handles two formats:
1. Windows Event Log XML (Security, System, Application channels):
   <Event xmlns="..."><System><EventID>4624</EventID>...</System><EventData>...</EventData></Event>

2. Generic flat XML: any XML where attributes/child text are extracted as key=value fields.

Windows EventID -> UES category/severity mapping included.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

from ulpf.parsers.base import BaseParser, ParseError
from ulpf.core.registry import register_parser

# Windows EventID -> (category, severity_numeric, description)
_WIN_EVENT_MAP: dict[int, tuple[str, int, str]] = {
    # Authentication
    4624: ('authentication', 3, 'An account was successfully logged on'),
    4625: ('authentication', 7, 'An account failed to log on'),
    4634: ('authentication', 3, 'An account was logged off'),
    4647: ('authentication', 3, 'User initiated logoff'),
    4648: ('authentication', 6, 'Logon using explicit credentials'),
    4649: ('authentication', 8, 'A replay attack was detected'),
    4675: ('authentication', 5, 'SIDs were filtered'),
    4768: ('authentication', 3, 'Kerberos TGT was requested'),
    4769: ('authentication', 3, 'Kerberos service ticket was requested'),
    4771: ('authentication', 7, 'Kerberos pre-authentication failed'),
    4776: ('authentication', 5, 'NTLM authentication attempted'),
    # Account management
    4720: ('authentication', 7, 'A user account was created'),
    4722: ('authentication', 5, 'A user account was enabled'),
    4723: ('authentication', 6, 'An attempt was made to change a password'),
    4724: ('authentication', 7, 'Password reset attempted'),
    4725: ('authentication', 7, 'A user account was disabled'),
    4726: ('authentication', 8, 'A user account was deleted'),
    4728: ('policy', 7, 'Member added to security-enabled global group'),
    4732: ('policy', 7, 'Member added to security-enabled local group'),
    4738: ('authentication', 6, 'A user account was changed'),
    # Policy change
    4670: ('policy', 7, 'Permissions on an object were changed'),
    4698: ('policy', 8, 'A scheduled task was created'),
    4699: ('policy', 9, 'A scheduled task was deleted'),
    4702: ('policy', 7, 'A scheduled task was updated'),
    4703: ('policy', 6, 'A user right was adjusted'),
    4704: ('policy', 7, 'A user right was assigned'),
    4705: ('policy', 7, 'A user right was removed'),
    # System
    4616: ('system', 4, 'System time was changed'),
    4657: ('system', 6, 'A registry value was modified'),
    4688: ('system', 4, 'A new process was created'),
    4689: ('system', 3, 'A process has exited'),
    4697: ('system', 9, 'A service was installed in the system'),
    7045: ('system', 9, 'New service installed'),
    # Network
    5140: ('network', 5, 'A network share object was accessed'),
    5145: ('network', 5, 'A network share object was checked'),
    5156: ('network', 3, 'Windows Filtering Platform connection permitted'),
    5157: ('network', 5, 'Windows Filtering Platform connection blocked'),
    # Threat
    1102: ('threat', 9, 'The audit log was cleared'),
    4713: ('threat', 8, 'Kerberos policy was changed'),
    4765: ('threat', 8, 'SID History was added to an account'),
    4766: ('threat', 8, 'Attempt to add SID History to an account failed'),
}


def _strip_ns(tag: str) -> str:
    """Strip XML namespace from a tag like {uri}LocalName -> LocalName."""
    if tag.startswith('{'):
        return tag.split('}', 1)[1]
    return tag


def _xml_to_dict(element: ET.Element, prefix: str = '') -> dict[str, Any]:
    """Recursively flatten XML element into a flat dict."""
    result: dict[str, Any] = {}
    tag = _strip_ns(element.tag)
    full_key = f'{prefix}.{tag}' if prefix else tag

    # Element attributes
    for attr_key, attr_val in element.attrib.items():
        result[f'{full_key}.{_strip_ns(attr_key)}'] = attr_val

    # Text content
    text = (element.text or '').strip()
    if text:
        result[full_key] = text

    # Children
    for child in element:
        child_dict = _xml_to_dict(child, full_key)
        result.update(child_dict)

    return result


def _extract_windows_event(root: ET.Element) -> dict[str, Any]:
    """Extract fields from a Windows Event Log XML event."""
    fields: dict[str, Any] = {}
    ns = {'w': 'http://schemas.microsoft.com/win/2004/08/events/event'}

    system = root.find('w:System', ns)
    if system is None:
        system = root.find('System')
    event_data = root.find('w:EventData', ns)
    if event_data is None:
        event_data = root.find('EventData')

    if system is not None:
        for child in system:
            key = _strip_ns(child.tag)
            text = (child.text or '').strip()
            attrib = child.attrib
            if text:
                fields[key] = text
            for ak, av in attrib.items():
                fields[f'{key}.{_strip_ns(ak)}'] = av

    # Try to parse EventID
    event_id_str = fields.get('EventID') or fields.get('EventID.#text', '')
    try:
        event_id = int(str(event_id_str).strip())
        fields['windows_event_id'] = event_id
    except (ValueError, TypeError):
        event_id = None

    # EventData key=value pairs
    if event_data is not None:
        for data_el in event_data:
            name = data_el.get('Name') or _strip_ns(data_el.tag)
            text = (data_el.text or '').strip()
            if name and text:
                fields[f'EventData.{name}'] = text

    return fields, event_id


@register_parser
class XMLGenericParser(BaseParser):
    """Generic XML and Windows Event Log parser."""

    name = 'xml_generic'
    version = '1.0.0'
    log_format = 'xml'

    # Match lines that look like XML
    _XML_START_RE = re.compile(r'^\s*<(?:Event|event|log|record|entry|\?xml)', re.IGNORECASE)

    def match(self, raw_line: str) -> bool:
        stripped = raw_line.strip()
        return bool(self._XML_START_RE.match(stripped)) or stripped.startswith('<?xml')

    def extract(self, raw_line: str) -> dict[str, Any]:
        stripped = raw_line.strip()
        try:
            root = ET.fromstring(stripped)
        except ET.ParseError as exc:
            raise ParseError(f'XML parse error: {exc}') from exc

        fields: dict[str, Any] = {
            '_raw': raw_line,
            '_log_format': self.log_format,
        }

        root_tag = _strip_ns(root.tag)
        is_windows_event = root_tag.lower() in ('event',)
        event_id = None

        if is_windows_event:
            extracted, event_id = _extract_windows_event(root)
            fields.update(extracted)
            fields['is_windows_event_log'] = True
        else:
            # Generic XML flattening
            flat = _xml_to_dict(root)
            fields.update(flat)
            fields['is_windows_event_log'] = False

        # Map known Windows EventIDs
        if event_id and event_id in _WIN_EVENT_MAP:
            cat, sev, desc = _WIN_EVENT_MAP[event_id]
            fields['category'] = cat
            fields['severity_numeric'] = sev
            fields['event_description'] = desc
        else:
            fields['category'] = 'system'
            fields['severity_numeric'] = 3

        # Extract common fields from EventData
        fields['src_ip'] = self.validate_ip(
            fields.get('EventData.IpAddress') or
            fields.get('EventData.SourceAddress') or
            fields.get('EventData.CallerIPAddress')
        )
        fields['username'] = (
            fields.get('EventData.SubjectUserName') or
            fields.get('EventData.TargetUserName') or
            fields.get('EventData.AccountName')
        )
        fields['hostname'] = (
            fields.get('Computer') or
            fields.get('EventData.WorkstationName')
        )
        fields['timestamp_raw'] = (
            fields.get('TimeCreated.SystemTime') or
            fields.get('TimeCreated')
        )
        ts = self.parse_timestamp(fields.get('timestamp_raw'))
        fields['timestamp_dt'] = ts.isoformat() if ts else None
        fields['message'] = (
            fields.get('event_description') or
            fields.get('EventData.Message') or
            f"Windows Event ID {event_id or 'unknown'}"
        )

        return fields
