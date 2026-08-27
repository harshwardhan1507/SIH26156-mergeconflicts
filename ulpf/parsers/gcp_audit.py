"""
Google Cloud Platform (GCP) Audit Log JSON Parser.

Handles GCP Cloud Audit Logs in structured JSON format (protoPayload envelope).

Example:
{
  "logName": "projects/my-project/logs/cloudaudit.googleapis.com%2Factivity",
  "severity": "NOTICE",
  "timestamp": "2026-08-27T08:00:00.000000Z",
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "methodName": "storage.objects.get",
    "resourceName": "projects/_/buckets/my-bucket/objects/data.csv",
    "authenticationInfo": {"principalEmail": "alice@example.com"},
    "requestMetadata": {"callerIp": "203.0.113.5", "callerSuppliedUserAgent": "gsutil/..."},
    "status": {"code": 0, "message": "OK"},
    "authorizationInfo": [{"permission": "storage.objects.get", "granted": true}]
  }
}
"""
from __future__ import annotations

import json
from typing import Any

from ulpf.parsers.base import BaseParser, ParseError
from ulpf.core.registry import register_parser

# GCP severity -> UES severity_numeric
_GCP_SEVERITY_MAP = {
    'DEFAULT': 3, 'DEBUG': 1, 'INFO': 3, 'NOTICE': 4,
    'WARNING': 6, 'ERROR': 7, 'CRITICAL': 9, 'ALERT': 9, 'EMERGENCY': 10,
}

# GCP status code -> UES outcome
def _status_to_outcome(status: dict) -> str:
    code = status.get('code', 0)
    if code == 0:
        return 'success'
    elif code in (1, 3, 5, 6, 7, 9, 13):
        return 'failure'
    elif code == 16:  # UNAUTHENTICATED
        return 'failure'
    elif code == 7:  # PERMISSION_DENIED
        return 'failure'
    return 'unknown'

# GCP method prefix -> UES category
_GCP_METHOD_CATEGORY = {
    'storage.': 'network',
    'compute.': 'network',
    'iam.': 'authentication',
    'admin.': 'policy',
    'cloudresourcemanager.': 'policy',
    'container.': 'system',
    'sqladmin.': 'system',
    'logging.': 'system',
    'cloudkms.': 'policy',
    'secretmanager.': 'policy',
}

def _method_to_category(method_name: str) -> str:
    method_lower = method_name.lower()
    for prefix, cat in _GCP_METHOD_CATEGORY.items():
        if method_lower.startswith(prefix):
            return cat
    if any(kw in method_lower for kw in ('login', 'auth', 'signin', 'token')):
        return 'authentication'
    return 'network'


@register_parser
class GCPAuditParser(BaseParser):
    """Google Cloud Platform Audit Log JSON parser."""

    name = 'gcp_audit'
    version = '1.0.0'
    log_format = 'json'

    def match(self, raw_line: str) -> bool:
        s = raw_line.strip()
        if not s.startswith('{'):
            return False
        try:
            obj = json.loads(s)
            return (
                'protoPayload' in obj and
                (
                    'logName' in obj or 'insertId' in obj
                ) and
                obj.get('protoPayload', {}).get('@type', '').startswith('type.googleapis.com/google.cloud.audit')
            )
        except (json.JSONDecodeError, AttributeError):
            return False

    def extract(self, raw_line: str) -> dict[str, Any]:
        try:
            obj = json.loads(raw_line.strip())
        except json.JSONDecodeError as exc:
            raise ParseError(f'Invalid JSON: {exc}') from exc

        proto = obj.get('protoPayload', {}) or {}
        auth_info = proto.get('authenticationInfo', {}) or {}
        req_meta = proto.get('requestMetadata', {}) or {}
        status = proto.get('status', {}) or {}
        authz_info = proto.get('authorizationInfo', []) or []

        method_name = proto.get('methodName', '')
        resource_name = proto.get('resourceName', '')
        principal_email = auth_info.get('principalEmail', '')
        caller_ip_raw = req_meta.get('callerIp', '')

        # Parse log name for project/service
        log_name = obj.get('logName', '')
        project_id = None
        log_type = None
        if 'projects/' in log_name:
            parts = log_name.split('/')
            try:
                project_id = parts[parts.index('projects') + 1]
            except (ValueError, IndexError):
                pass
        if 'logs/' in log_name:
            log_type = log_name.split('logs/')[-1].split('%2F')[-1]

        # Category
        category = _method_to_category(method_name)

        # Outcome
        outcome = _status_to_outcome(status)

        # Severity
        gcp_severity = obj.get('severity', 'NOTICE')
        severity_numeric = _GCP_SEVERITY_MAP.get(gcp_severity, 4)
        # Bump severity on denial
        if status.get('code') in (7, 16):
            severity_numeric = max(severity_numeric, 8)

        # Authorization result
        granted = True
        for az in authz_info:
            if not az.get('granted', True):
                granted = False
                break

        # Action: last part of methodName (e.g., "storage.objects.get" -> "get")
        action = method_name.split('.')[-1] if method_name else 'unknown'

        src_ip = self.validate_ip(caller_ip_raw.split(':')[0] if caller_ip_raw else '')

        raw_ts = obj.get('timestamp')
        ts = self.parse_timestamp(raw_ts)

        fields: dict[str, Any] = {
            '_raw': raw_line,
            '_log_format': self.log_format,
            'vendor': 'Google',
            'product': 'Google Cloud Platform',
            'timestamp_raw': raw_ts,
            'timestamp_dt': ts.isoformat() if ts else None,
            'method_name': method_name,
            'action': action,
            'resource_name': resource_name,
            'principal_email': principal_email,
            'username': principal_email,
            'src_ip': src_ip,
            'caller_ip_raw': caller_ip_raw,
            'user_agent': req_meta.get('callerSuppliedUserAgent'),
            'status_code': status.get('code'),
            'status_message': status.get('message'),
            'gcp_severity': gcp_severity,
            'severity_numeric': severity_numeric,
            'category': category,
            'outcome': outcome,
            'authorization_granted': granted,
            'project_id': project_id,
            'log_name': log_name,
            'log_type': log_type,
            'insert_id': obj.get('insertId'),
            'service_name': proto.get('serviceName'),
            'message': f'GCP {method_name} [{gcp_severity}]{" DENIED" if not granted else ""}',
        }

        return fields
