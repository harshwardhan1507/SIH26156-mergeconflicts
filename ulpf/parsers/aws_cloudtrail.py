"""
AWS CloudTrail JSON Parser.

Recognizes CloudTrail single-event JSON records and CloudTrail log file Records arrays.

CloudTrail single event example:
{
  "eventVersion": "1.08",
  "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::...", "userName": "alice"},
  "eventTime": "2026-08-27T08:00:00Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "GetObject",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.10",
  "requestParameters": {...},
  "errorCode": "AccessDenied",
  "errorMessage": "..."
}
"""
from __future__ import annotations

import json
from typing import Any

from ulpf.parsers.base import BaseParser, ParseError
from ulpf.core.registry import register_parser

# CloudTrail eventName prefix -> UES category
_CT_CATEGORY_MAP = {
    'Get': 'network', 'List': 'network', 'Describe': 'network',
    'Create': 'policy', 'Update': 'policy', 'Modify': 'policy',
    'Put': 'policy', 'Set': 'policy', 'Attach': 'policy', 'Add': 'policy',
    'Delete': 'policy', 'Remove': 'policy', 'Detach': 'policy',
    'Assume': 'authentication', 'Login': 'authentication', 'Logout': 'authentication',
    'Auth': 'authentication', 'Console': 'authentication',
    'Start': 'system', 'Stop': 'system', 'Terminate': 'system', 'Reboot': 'system',
    'Run': 'system', 'Launch': 'system',
}

# CloudTrail errorCode -> UES outcome
_CT_ERROR_OUTCOME = {
    None: 'success',
    '': 'success',
    'AccessDenied': 'failure',
    'UnauthorizedAccess': 'failure',
    'AuthFailure': 'failure',
    'InvalidClientTokenId': 'failure',
    'NoSuchBucket': 'failure',
    'NoSuchKey': 'failure',
    'ThrottlingException': 'failure',
}

# CloudTrail service -> vendor product
_CT_SERVICE_MAP = {
    's3.amazonaws.com': ('Amazon Web Services', 'S3'),
    'ec2.amazonaws.com': ('Amazon Web Services', 'EC2'),
    'iam.amazonaws.com': ('Amazon Web Services', 'IAM'),
    'rds.amazonaws.com': ('Amazon Web Services', 'RDS'),
    'lambda.amazonaws.com': ('Amazon Web Services', 'Lambda'),
    'sts.amazonaws.com': ('Amazon Web Services', 'STS'),
    'cloudtrail.amazonaws.com': ('Amazon Web Services', 'CloudTrail'),
    'kms.amazonaws.com': ('Amazon Web Services', 'KMS'),
    'secretsmanager.amazonaws.com': ('Amazon Web Services', 'Secrets Manager'),
    'guardduty.amazonaws.com': ('Amazon Web Services', 'GuardDuty'),
}


def _infer_category(event_name: str) -> str:
    for prefix, cat in _CT_CATEGORY_MAP.items():
        if event_name.startswith(prefix):
            return cat
    return 'network'


def _infer_severity(error_code: str | None, event_name: str, category: str) -> int:
    if error_code in ('AccessDenied', 'UnauthorizedAccess', 'AuthFailure'):
        return 8
    if error_code:
        return 6
    if category == 'policy' and any(k in event_name for k in ('Delete', 'Remove', 'Detach')):
        return 7
    if category == 'authentication':
        return 4
    return 3


@register_parser
class AWSCloudTrailParser(BaseParser):
    """AWS CloudTrail JSON event parser."""

    name = 'aws_cloudtrail'
    version = '1.0.0'
    log_format = 'json'

    def match(self, raw_line: str) -> bool:
        s = raw_line.strip()
        if not s.startswith('{'):
            return False
        try:
            obj = json.loads(s)
            return (
                'eventVersion' in obj and
                'eventSource' in obj and
                'eventName' in obj and
                obj.get('eventSource', '').endswith('.amazonaws.com')
            )
        except (json.JSONDecodeError, AttributeError):
            return False

    def extract(self, raw_line: str) -> dict[str, Any]:
        try:
            obj = json.loads(raw_line.strip())
        except json.JSONDecodeError as exc:
            raise ParseError(f'Invalid JSON: {exc}') from exc

        if 'eventVersion' not in obj:
            raise ParseError('Not a CloudTrail event (missing eventVersion)')

        event_source = obj.get('eventSource', '')
        event_name = obj.get('eventName', '')
        error_code = obj.get('errorCode') or None
        user_identity = obj.get('userIdentity', {}) or {}
        request_params = obj.get('requestParameters') or {}
        response_elements = obj.get('responseElements') or {}

        # Vendor/product from service
        vendor, product = _CT_SERVICE_MAP.get(event_source, ('Amazon Web Services', event_source))

        # Category
        category = _infer_category(event_name)

        # Severity
        severity_numeric = _infer_severity(error_code, event_name, category)

        # Outcome
        outcome = _CT_ERROR_OUTCOME.get(error_code, 'failure' if error_code else 'success')

        # Username
        username = (
            user_identity.get('userName') or
            user_identity.get('userId') or
            user_identity.get('sessionContext', {}).get('sessionIssuer', {}).get('userName')
        )

        # Source IP
        src_ip_raw = obj.get('sourceIPAddress', '')
        src_ip = self.validate_ip(src_ip_raw)
        if src_ip is None and not src_ip_raw.endswith('.amazonaws.com'):
            src_ip = None

        ts = self.parse_timestamp(obj.get('eventTime'))

        fields: dict[str, Any] = {
            '_raw': raw_line,
            '_log_format': self.log_format,
            'vendor': vendor,
            'product': product,
            'event_version': obj.get('eventVersion'),
            'event_name': event_name,
            'event_source': event_source,
            'event_type': obj.get('eventType'),
            'aws_region': obj.get('awsRegion'),
            'timestamp_raw': obj.get('eventTime'),
            'timestamp_dt': ts.isoformat() if ts else None,
            'src_ip': src_ip,
            'src_ip_raw': src_ip_raw,
            'username': username,
            'user_identity_type': user_identity.get('type'),
            'user_arn': user_identity.get('arn'),
            'account_id': user_identity.get('accountId'),
            'error_code': error_code,
            'error_message': obj.get('errorMessage'),
            'request_id': obj.get('requestID'),
            'event_id': obj.get('eventID'),
            'read_only': obj.get('readOnly'),
            'category': category,
            'severity_numeric': severity_numeric,
            'outcome': outcome,
            'action': event_name,
            'message': f'AWS {event_name} on {event_source}' + (f' [ERROR: {error_code}]' if error_code else ''),
            '_request_params': json.dumps(request_params),
            '_response_elements': json.dumps(response_elements),
        }

        return fields
