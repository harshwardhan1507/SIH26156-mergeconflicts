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
from pathlib import PureWindowsPath
from typing import Any

from ulpf.core.registry import register_parser
from ulpf.parsers.base import BaseParser, ParseError

# Windows EventID -> (category, severity_numeric, action, description)
_WIN_EVENT_MAP: dict[int, tuple[str, int, str, str]] = {
    # Authentication
    4624: ('authentication', 3, 'logon_success', 'An account was successfully logged on'),
    4625: ('authentication', 7, 'logon_failure', 'An account failed to log on'),
    4634: ('authentication', 3, 'logoff', 'An account was logged off'),
    4647: ('authentication', 3, 'logoff', 'User initiated logoff'),
    4648: ('authentication', 6, 'logon_explicit', 'Logon using explicit credentials'),
    4649: ('authentication', 8, 'replay_attack', 'A replay attack was detected'),
    4675: ('authentication', 5, 'sid_filter', 'SIDs were filtered'),
    4768: ('authentication', 3, 'kerberos_tgt', 'Kerberos TGT was requested'),
    4769: ('authentication', 3, 'kerberos_service', 'Kerberos service ticket was requested'),
    4771: ('authentication', 7, 'kerberos_fail', 'Kerberos pre-authentication failed'),
    4776: ('authentication', 5, 'ntlm_auth', 'NTLM authentication attempted'),
    # Account management
    4720: ('authentication', 7, 'user_created', 'A user account was created'),
    4722: ('authentication', 5, 'user_enabled', 'A user account was enabled'),
    4723: ('authentication', 6, 'password_change', 'An attempt was made to change a password'),
    4724: ('authentication', 7, 'password_reset', 'Password reset attempted'),
    4725: ('authentication', 7, 'user_disabled', 'A user account was disabled'),
    4726: ('authentication', 8, 'user_deleted', 'A user account was deleted'),
    4728: ('policy', 7, 'group_member_add', 'Member added to security-enabled global group'),
    4732: ('policy', 7, 'group_member_add', 'Member added to security-enabled local group'),
    4738: ('authentication', 6, 'user_modified', 'A user account was changed'),
    # Policy change
    4670: ('policy', 7, 'permission_change', 'Permissions on an object were changed'),
    4698: ('policy', 8, 'task_created', 'A scheduled task was created'),
    4699: ('policy', 9, 'task_deleted', 'A scheduled task was deleted'),
    4702: ('policy', 7, 'task_updated', 'A scheduled task was updated'),
    4703: ('policy', 6, 'right_adjusted', 'A user right was adjusted'),
    4704: ('policy', 7, 'right_assigned', 'A user right was assigned'),
    4705: ('policy', 7, 'right_removed', 'A user right was removed'),
    # System & Process Execution
    4616: ('system', 4, 'time_changed', 'System time was changed'),
    4657: ('system', 6, 'registry_modified', 'A registry value was modified'),
    4688: ('system', 4, 'process_start', 'A new process was created'),
    4689: ('system', 3, 'process_stop', 'A process has exited'),
    4697: ('system', 9, 'service_install', 'A service was installed in the system'),
    7045: ('system', 9, 'service_install', 'New service installed'),
    16384: ('system', 4, 'service_spp', 'Software Protection service update'),
    15: ('system', 4, 'security_product_state', 'Security Center state update'),
    # Network
    5140: ('network', 5, 'share_access', 'A network share object was accessed'),
    5145: ('network', 5, 'share_check', 'A network share object was checked'),
    5156: ('network', 3, 'connection_permit', 'Windows Filtering Platform connection permitted'),
    5157: ('network', 5, 'connection_block', 'Windows Filtering Platform connection blocked'),
    # Threat
    1102: ('threat', 9, 'audit_cleared', 'The audit log was cleared'),
    4713: ('threat', 8, 'policy_changed', 'Kerberos policy was changed'),
    4765: ('threat', 8, 'sid_history_add', 'SID History was added to an account'),
    4766: ('threat', 8, 'sid_history_fail', 'Attempt to add SID History to an account failed'),
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


def _extract_windows_event(root: ET.Element) -> tuple[dict[str, Any], int | None]:
    """
    Extract structured fields from standard Windows Event XML (<Event>).
    """
    fields: dict[str, Any] = {}
    event_id: int | None = None

    for child in root:
        ctag = _strip_ns(child.tag)
        if ctag == 'System':
            for sys_elem in child:
                stag = _strip_ns(sys_elem.tag)
                if stag == 'EventID':
                    try:
                        event_id = int((sys_elem.text or '').strip())
                        fields['windows_event_id'] = event_id
                    except ValueError:
                        pass
                elif stag == 'TimeCreated':
                    fields['TimeCreated.SystemTime'] = sys_elem.attrib.get('SystemTime')
                elif stag == 'Provider':
                    fields['Provider.Name'] = sys_elem.attrib.get('Name')
                    fields['Provider.Guid'] = sys_elem.attrib.get('Guid')
                elif stag == 'Computer':
                    fields['Computer'] = (sys_elem.text or '').strip()
                elif stag == 'Channel':
                    fields['Channel'] = (sys_elem.text or '').strip()
                elif stag == 'Level':
                    fields['Level'] = (sys_elem.text or '').strip()
        elif ctag == 'EventData':
            for data_elem in child:
                dtag = _strip_ns(data_elem.tag)
                if dtag == 'Data':
                    name = data_elem.attrib.get('Name')
                    val = (data_elem.text or '').strip()
                    if name:
                        fields[f'EventData.{name}'] = val
                    else:
                        fields.setdefault('EventData.DataList', []).append(val)

    return fields, event_id


#: Matches an XML document type declaration anywhere in the record.
_DOCTYPE_RE = re.compile(r"<!DOCTYPE", re.IGNORECASE)


@register_parser
class XMLGenericParser(BaseParser):
    name = 'xml_generic'
    version = '1.1.0'
    log_format = 'xml'

    @staticmethod
    def _parse(text: str) -> ET.Element:
        """
        Parse XML with document type definitions refused.

        Log records never legitimately carry an internal DTD subset, and
        accepting one enables entity-expansion amplification: a few hundred
        bytes of nested entity definitions expand into hundreds of kilobytes
        before any limit applies. CPython's expat does cap the amplification
        factor, but that backstop varies by runtime and expat build, so the
        vector is removed here rather than relied upon. External entities are
        already refused by ElementTree, which is what blocks file disclosure.
        """
        if _DOCTYPE_RE.search(text):
            raise ParseError("XML document type definitions are not accepted")
        return ET.fromstring(text)  # noqa: S314 — DTDs rejected above

    def match(self, raw_line: str) -> bool:
        stripped = raw_line.strip()
        if not (stripped.startswith('<?xml') or stripped.startswith('<')):
            return False
        # Do not match syslog PRI tags like <134>1
        if re.match(r'^<\d+>', stripped):
            return False
        try:
            self._parse(stripped)
            return True
        except (ET.ParseError, ParseError):
            return False

    def extract(self, raw_line: str) -> dict[str, Any]:
        stripped = raw_line.strip()
        try:
            root = self._parse(stripped)
        except ET.ParseError as e:
            raise ParseError(f"XML parse error: {e}") from e

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
            fields['vendor'] = 'Microsoft'
            fields['product'] = 'Windows'
        else:
            # Generic XML flattening
            flat = _xml_to_dict(root)
            fields.update(flat)
            fields['is_windows_event_log'] = False
            fields['vendor'] = fields.get('vendor') or 'Generic XML'
            fields['product'] = fields.get('product') or 'XML'

        # Extract process path and process name
        raw_proc_path = fields.get('EventData.NewProcessName') or fields.get('EventData.ProcessName')
        if raw_proc_path:
            fields['process_name'] = PureWindowsPath(str(raw_proc_path)).name
            fields['process_path'] = raw_proc_path

        # Map known Windows EventIDs
        if event_id and event_id in _WIN_EVENT_MAP:
            cat, sev, act, desc = _WIN_EVENT_MAP[event_id]
            fields['category'] = cat
            fields['severity_numeric'] = sev
            fields['action'] = fields.get('EventData.Action') or act
            if fields.get('process_name'):
                fields['event_description'] = f"Process: {fields['process_name']} ({fields['action']})"
            else:
                fields['event_description'] = desc
        else:
            fields['category'] = 'system'
            fields['severity_numeric'] = 3
            fields['action'] = fields.get('EventData.Action') or 'system_event'
            fields['event_description'] = f"Windows Event ID {event_id or 'unknown'}"

        # Extract common fields from EventData
        fields['src_ip'] = self.validate_ip(
            fields.get('EventData.IpAddress') or
            fields.get('EventData.SourceAddress') or
            fields.get('EventData.CallerIPAddress')
        )
        fields['src_port'] = self.safe_port(
            fields.get('EventData.SourcePort') or
            fields.get('EventData.IpPort')
        )
        fields['dst_ip'] = self.validate_ip(
            fields.get('EventData.DestAddress') or
            fields.get('EventData.DestinationAddress') or
            fields.get('EventData.DestinationIpAddress') or
            fields.get('EventData.TargetAddress')
        )
        fields['dst_port'] = self.safe_port(
            fields.get('EventData.DestPort') or
            fields.get('EventData.DestinationPort') or
            fields.get('EventData.TargetPort')
        )
        raw_proto = str(fields.get('EventData.ProtocolName') or fields.get('EventData.Protocol') or '').strip().lower()
        if raw_proto in ('6', 'tcp'):
            fields['protocol'] = 'tcp'
        elif raw_proto in ('17', 'udp'):
            fields['protocol'] = 'udp'
        elif raw_proto:
            fields['protocol'] = raw_proto
        else:
            fields['protocol'] = None

        fields['direction'] = fields.get('EventData.Direction') or ('outbound' if fields.get('dst_ip') else None)
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
