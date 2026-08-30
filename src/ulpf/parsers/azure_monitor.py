"""
Azure Monitor / Activity Log JSON Parser.

Recognizes Azure Monitor log schema with operationName, resourceId, and resultType.

Example:
{
  "time": "2026-08-27T08:00:00.0000000Z",
  "resourceId": "/subscriptions/xxx/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/web01",
  "operationName": "Microsoft.Compute/virtualMachines/write",
  "category": "Administrative",
  "resultType": "Success",
  "resultSignature": "200",
  "callerIpAddress": "198.51.100.10",
  "identity": {"authorization": {"action": "Microsoft.Compute/virtualMachines/write"}, "claims": {"name": "alice@contoso.com"}},
  "properties": {...}
}
"""
from __future__ import annotations

import json
from typing import Any

from ulpf.core.registry import register_parser
from ulpf.parsers.base import BaseParser, ParseError

# Azure category -> UES category
_AZURE_CATEGORY_MAP = {
    'Administrative': 'policy',
    'Security': 'threat',
    'ServiceHealth': 'system',
    'Alert': 'threat',
    'Recommendation': 'policy',
    'Policy': 'policy',
    'Autoscale': 'system',
    'ResourceHealth': 'system',
    'SignIn': 'authentication',
    'AuditLogs': 'authentication',
    'NonInteractiveUserSignInLogs': 'authentication',
    'ServicePrincipalSignInLogs': 'authentication',
    'ManagedIdentitySignInLogs': 'authentication',
}

# Azure resultType -> UES outcome
_AZURE_RESULT_MAP = {
    'Success': 'success',
    'Succeeded': 'success',
    'Start': 'unknown',
    'Accept': 'success',
    'Failed': 'failure',
    'Failure': 'failure',
    'Canceled': 'failure',
    'Rejected': 'failure',
}

# Azure operation verbs -> UES severity hints
_AZURE_SEVERITY_VERBS = {
    'delete': 8, 'remove': 7, 'disable': 7, 'deny': 8,
    'write': 5, 'create': 5, 'update': 5, 'modify': 5,
    'read': 3, 'list': 2, 'get': 2,
}


def _parse_resource_id(resource_id: str) -> dict[str, str]:
    """Extract subscription, resource group, provider, resource type and name from Azure resourceId."""
    parts = [p for p in resource_id.split('/') if p]
    result: dict[str, str] = {}
    try:
        if len(parts) >= 2 and parts[0].lower() == 'subscriptions':
            result['subscription_id'] = parts[1]
        if len(parts) >= 4 and parts[2].lower() == 'resourcegroups':
            result['resource_group'] = parts[3]
        if len(parts) >= 6 and parts[4].lower() == 'providers':
            result['provider'] = parts[5]
            if len(parts) >= 8:
                result['resource_type'] = parts[6]
                result['resource_name'] = parts[7]
    except IndexError:
        pass
    return result


def _severity_from_operation(operation_name: str, result_type: str) -> int:
    if 'failed' in result_type.lower() or 'failure' in result_type.lower():
        return 7
    op_lower = operation_name.lower()
    for verb, sev in _AZURE_SEVERITY_VERBS.items():
        if op_lower.endswith(f'/{verb}') or op_lower.endswith(verb):
            return sev
    return 4


@register_parser
class AzureMonitorParser(BaseParser):
    """Azure Monitor / Activity Log / Diagnostic Log JSON parser."""

    name = 'azure_monitor'
    version = '1.0.0'
    log_format = 'json'

    def match(self, raw_line: str) -> bool:
        s = raw_line.strip()
        if not s.startswith('{'):
            return False
        try:
            obj = json.loads(s)
            return (
                'operationName' in obj and
                'resourceId' in obj and
                (
                    'resultType' in obj or 'category' in obj or
                    'callerIpAddress' in obj or 'time' in obj
                )
            )
        except (json.JSONDecodeError, AttributeError):
            return False

    def extract(self, raw_line: str) -> dict[str, Any]:
        try:
            obj = json.loads(raw_line.strip())
        except json.JSONDecodeError as exc:
            raise ParseError(f'Invalid JSON: {exc}') from exc

        operation_name = obj.get('operationName', '')
        resource_id = obj.get('resourceId', '')
        result_type = obj.get('resultType', '')
        az_category = obj.get('category', '')
        identity = obj.get('identity', {}) or {}
        properties = obj.get('properties', {}) or {}
        claims = identity.get('claims', {}) or {}

        # Category
        category = _AZURE_CATEGORY_MAP.get(az_category, 'policy')

        # Outcome
        outcome = _AZURE_RESULT_MAP.get(result_type, 'unknown')

        # Severity
        severity_numeric = _severity_from_operation(operation_name, result_type)

        # User
        username = (
            claims.get('name') or claims.get('upn') or
            claims.get('unique_name') or obj.get('callerDisplayName') or
            identity.get('caller')
        )

        # IPs
        src_ip = self.validate_ip(obj.get('callerIpAddress', '').split(':')[0])

        # Resource parsing
        resource_parts = _parse_resource_id(resource_id)

        # Action: last segment of operationName
        action = operation_name.split('/')[-1] if operation_name else 'unknown'

        raw_ts = obj.get('time') or obj.get('timestamp')
        ts = self.parse_timestamp(raw_ts)

        fields: dict[str, Any] = {
            '_raw': raw_line,
            '_log_format': self.log_format,
            'vendor': 'Microsoft',
            'product': 'Azure Monitor',
            'timestamp_raw': raw_ts,
            'timestamp_dt': ts.isoformat() if ts else None,
            'operation_name': operation_name,
            'action': action,
            'resource_id': resource_id,
            'az_category': az_category,
            'result_type': result_type,
            'result_signature': obj.get('resultSignature'),
            'result_description': obj.get('resultDescription'),
            'src_ip': src_ip,
            'username': username,
            'category': category,
            'outcome': outcome,
            'severity_numeric': severity_numeric,
            'message': f'Azure {operation_name} [{result_type}]',
            'correlation_id': obj.get('correlationId'),
            'operation_id': obj.get('operationId'),
            'tenant_id': claims.get('tid'),
            **resource_parts,
        }

        # Azure carries most of its operational detail (statusCode,
        # serviceRequestId, clientIpAddress, ...) inside `properties`. These
        # were read and discarded, so they never reached vendor_attributes and
        # the losslessness contract did not hold for this source. Flatten them
        # under a prefix so they survive without colliding with mapped fields.
        for key, value in properties.items():
            fields.setdefault(f'properties.{key}', value)

        return fields
