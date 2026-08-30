"""Tests for AWS CloudTrail JSON parser."""
import json

from ulpf.parsers.aws_cloudtrail import AWSCloudTrailParser

PARSER = AWSCloudTrailParser()

CT_EVENT = json.dumps({
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "AssumedRole",
        "arn": "arn:aws:sts::123456789012:assumed-role/admin/alice",
        "userName": "alice",
        "accountId": "123456789012"
    },
    "eventTime": "2026-08-27T08:00:00Z",
    "eventSource": "s3.amazonaws.com",
    "eventName": "GetObject",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "203.0.113.10",
    "requestID": "REQ-001",
    "eventID": "EVT-001",
    "readOnly": True,
    "requestParameters": {"bucketName": "my-bucket", "key": "data.csv"},
    "responseElements": None
})

CT_EVENT_DENIED = json.dumps({
    "eventVersion": "1.08",
    "userIdentity": {"type": "IAMUser", "userName": "bob", "accountId": "123456789012"},
    "eventTime": "2026-08-27T08:01:00Z",
    "eventSource": "iam.amazonaws.com",
    "eventName": "DeleteUser",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "192.168.1.5",
    "errorCode": "AccessDenied",
    "errorMessage": "User is not authorized",
    "requestID": "REQ-002",
    "eventID": "EVT-002",
    "readOnly": False,
})

CT_NON_AWS = json.dumps({"key": "value", "other": "data"})


def test_match_cloudtrail():
    assert PARSER.match(CT_EVENT)


def test_no_match_generic_json():
    assert not PARSER.match(CT_NON_AWS)
    assert not PARSER.match("{}")
    assert not PARSER.match("not json")


def test_extract_basic():
    result = PARSER.extract(CT_EVENT)
    assert result["vendor"] == "Amazon Web Services"
    assert result["product"] == "S3"
    assert result["event_name"] == "GetObject"
    assert result["event_source"] == "s3.amazonaws.com"
    assert result["aws_region"] == "us-east-1"
    assert result["src_ip"] == "203.0.113.10"
    assert result["username"] == "alice"
    assert result["outcome"] == "success"
    assert result["category"] == "network"


def test_extract_denied():
    result = PARSER.extract(CT_EVENT_DENIED)
    assert result["error_code"] == "AccessDenied"
    assert result["outcome"] == "failure"
    assert result["severity_numeric"] >= 7
    assert result["username"] == "bob"


def test_timestamp_parsed():
    result = PARSER.extract(CT_EVENT)
    assert result["timestamp_dt"] is not None


def test_log_format():
    result = PARSER.extract(CT_EVENT)
    assert result["_log_format"] == "json"
