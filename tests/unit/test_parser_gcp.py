"""Tests for GCP Audit Log JSON parser."""
import json

from ulpf.parsers.gcp_audit import GCPAuditParser

PARSER = GCPAuditParser()

GCP_EVENT = json.dumps({
    "logName": "projects/my-project/logs/cloudaudit.googleapis.com%2Factivity",
    "severity": "NOTICE",
    "timestamp": "2026-08-27T08:00:00.000000Z",
    "insertId": "insert-001",
    "protoPayload": {
        "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "methodName": "storage.objects.get",
        "resourceName": "projects/_/buckets/my-bucket/objects/data.csv",
        "serviceName": "storage.googleapis.com",
        "authenticationInfo": {"principalEmail": "alice@example.com"},
        "requestMetadata": {
            "callerIp": "203.0.113.5",
            "callerSuppliedUserAgent": "gsutil/5.0"
        },
        "status": {"code": 0, "message": "OK"},
        "authorizationInfo": [{"permission": "storage.objects.get", "granted": True}]
    }
})

GCP_DENIED = json.dumps({
    "logName": "projects/my-project/logs/cloudaudit.googleapis.com%2Factivity",
    "severity": "WARNING",
    "timestamp": "2026-08-27T08:01:00.000000Z",
    "insertId": "insert-002",
    "protoPayload": {
        "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "methodName": "iam.roles.delete",
        "resourceName": "projects/my-project/roles/customRole",
        "authenticationInfo": {"principalEmail": "attacker@evil.com"},
        "requestMetadata": {"callerIp": "185.220.100.5"},
        "status": {"code": 7, "message": "PERMISSION_DENIED"},
        "authorizationInfo": [{"permission": "iam.roles.delete", "granted": False}]
    }
})

GCP_NON = json.dumps({"key": "value", "data": "something else"})


def test_match_gcp():
    assert PARSER.match(GCP_EVENT)


def test_no_match():
    assert not PARSER.match(GCP_NON)
    assert not PARSER.match("{}")
    assert not PARSER.match("plain text")


def test_extract_basic():
    result = PARSER.extract(GCP_EVENT)
    assert result["vendor"] == "Google"
    assert result["product"] == "Google Cloud Platform"
    assert result["method_name"] == "storage.objects.get"
    assert result["principal_email"] == "alice@example.com"
    assert result["username"] == "alice@example.com"
    assert result["outcome"] == "success"
    assert result["category"] == "network"
    assert result["src_ip"] == "203.0.113.5"
    assert result["authorization_granted"] is True


def test_extract_denied():
    result = PARSER.extract(GCP_DENIED)
    assert result["authorization_granted"] is False
    assert result["outcome"] == "failure"
    assert result["severity_numeric"] >= 7


def test_project_id_parsed():
    result = PARSER.extract(GCP_EVENT)
    assert result["project_id"] == "my-project"


def test_action_field():
    result = PARSER.extract(GCP_EVENT)
    assert result["action"] == "get"


def test_timestamp():
    result = PARSER.extract(GCP_EVENT)
    assert result["timestamp_dt"] is not None
