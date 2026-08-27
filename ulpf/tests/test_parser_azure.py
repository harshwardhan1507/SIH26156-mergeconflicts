"""Tests for Azure Monitor JSON parser."""
import json
import pytest
from ulpf.parsers.azure_monitor import AzureMonitorParser

PARSER = AzureMonitorParser()

AZURE_EVENT = json.dumps({
    "time": "2026-08-27T08:00:00.0000000Z",
    "resourceId": "/subscriptions/sub-001/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/web01",
    "operationName": "Microsoft.Compute/virtualMachines/write",
    "category": "Administrative",
    "resultType": "Success",
    "resultSignature": "200",
    "callerIpAddress": "198.51.100.10",
    "identity": {
        "authorization": {"action": "Microsoft.Compute/virtualMachines/write"},
        "claims": {"name": "alice@contoso.com", "tid": "tenant-001"}
    },
    "properties": {}
})

AZURE_FAILED = json.dumps({
    "time": "2026-08-27T08:01:00.0000000Z",
    "resourceId": "/subscriptions/sub-001/resourceGroups/prod/providers/Microsoft.Storage/storageAccounts/mystore",
    "operationName": "Microsoft.Storage/storageAccounts/delete",
    "category": "Administrative",
    "resultType": "Failed",
    "callerIpAddress": "10.0.0.5",
    "identity": {"claims": {"name": "bob@contoso.com"}},
})


def test_match_azure():
    assert PARSER.match(AZURE_EVENT)


def test_no_match():
    assert not PARSER.match("{}")
    assert not PARSER.match('{"key": "value"}')
    assert not PARSER.match("plain text")


def test_extract_basic():
    result = PARSER.extract(AZURE_EVENT)
    assert result["vendor"] == "Microsoft"
    assert result["product"] == "Azure Monitor"
    assert result["operation_name"] == "Microsoft.Compute/virtualMachines/write"
    assert result["outcome"] == "success"
    assert result["category"] == "policy"
    assert result["username"] == "alice@contoso.com"
    assert result["subscription_id"] == "sub-001"
    assert result["resource_group"] == "prod"


def test_extract_failed():
    result = PARSER.extract(AZURE_FAILED)
    assert result["outcome"] == "failure"
    assert result["severity_numeric"] >= 6


def test_src_ip():
    result = PARSER.extract(AZURE_EVENT)
    assert result["src_ip"] == "198.51.100.10"


def test_timestamp():
    result = PARSER.extract(AZURE_EVENT)
    assert result["timestamp_dt"] is not None
