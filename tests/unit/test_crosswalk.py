"""
Tests for OCSF and ECS Crosswalk Standards Translation Layer.
"""
from __future__ import annotations

from ulpf.crosswalk.ecs import to_ecs
from ulpf.crosswalk.ocsf import to_ocsf


def test_ocsf_network_activity_crosswalk():
    ues_event = {
        "event_id": "00000000-0000-0000-0000-000000000001",
        "ingest_timestamp": "2024-03-15T10:22:45.000000+00:00",
        "source": {
            "vendor": "Palo Alto Networks",
            "product": "PAN-OS",
            "device_hostname": "fw-edge01",
            "log_format": "csv",
        },
        "event": {
            "category": "network",
            "action": "allow",
            "outcome": "success",
            "severity_numeric": 3.0,
        },
        "network": {
            "src_ip": "10.0.0.5",
            "src_port": 54321,
            "dst_ip": "198.51.100.20",
            "dst_port": 443,
            "protocol": "tcp",
            "bytes_in": 1024,
            "bytes_out": 2048,
        },
        "identity": {
            "username": "alice",
        },
        "vendor_attributes": {
            "custom_rule_id": "ALLOW_INTERNET"
        },
        "raw": {
            "raw_payload": "raw palo alto log",
            "raw_hash": "a" * 64,
        }
    }

    ocsf = to_ocsf(ues_event)
    assert ocsf["class_uid"] == 4001
    assert ocsf["category_name"] == "Network Activity"
    assert ocsf["src_endpoint"]["ip"] == "10.0.0.5"
    assert ocsf["src_endpoint"]["port"] == 54321
    assert ocsf["dst_endpoint"]["ip"] == "198.51.100.20"
    assert ocsf["dst_endpoint"]["port"] == 443
    assert ocsf["user"]["name"] == "alice"
    assert ocsf["unmapped"]["custom_rule_id"] == "ALLOW_INTERNET"


def test_ocsf_authentication_crosswalk():
    ues_event = {
        "event_id": "00000000-0000-0000-0000-000000000002",
        "ingest_timestamp": "2024-03-15T10:22:45.000000+00:00",
        "event": {
            "category": "authentication",
            "action": "login",
            "outcome": "failure",
            "severity_numeric": 7.0,
        },
        "identity": {
            "username": "admin",
            "user_domain": "CORP",
        },
        "network": {
            "src_ip": "203.0.113.88",
        }
    }

    ocsf = to_ocsf(ues_event)
    assert ocsf["class_uid"] == 3001
    assert ocsf["class_name"] == "Authentication"
    assert ocsf["category_name"] == "Identity & Access Management"
    assert ocsf["user"]["name"] == "admin"
    assert ocsf["user"]["domain"] == "CORP"
    assert ocsf["status"] == "Failure"
    assert ocsf["severity_id"] == 4  # High


def test_ecs_crosswalk():
    ues_event = {
        "event_id": "00000000-0000-0000-0000-000000000003",
        "ingest_timestamp": "2024-03-15T10:22:45.000000+00:00",
        "source": {
            "vendor": "Cisco",
            "product": "ASA",
            "device_hostname": "asa01.corp",
            "log_format": "syslog_rfc3164",
        },
        "event": {
            "category": "threat",
            "action": "deny",
            "outcome": "failure",
            "severity_numeric": 8.0,
        },
        "network": {
            "src_ip": "10.1.1.5",
            "src_port": 44123,
            "dst_ip": "192.168.1.100",
            "dst_port": 443,
            "protocol": "tcp",
        },
        "identity": {
            "username": "threat_actor",
        },
        "raw": {
            "raw_payload": "<162>Aug 15 14:23:01 asa01.corp.example.com %ASA-2-106016: Deny IP spoof",
            "raw_hash": "b" * 64,
        }
    }

    ecs = to_ecs(ues_event)
    assert ecs["ecs"]["version"] == "8.11.0"
    assert ecs["event"]["id"] == "00000000-0000-0000-0000-000000000003"
    assert ecs["event"]["category"] == ["threat"]
    assert ecs["event"]["action"] == "deny"
    assert ecs["source"]["ip"] == "10.1.1.5"
    assert ecs["source"]["port"] == 44123
    assert ecs["destination"]["ip"] == "192.168.1.100"
    assert ecs["destination"]["port"] == 443
    assert ecs["network"]["transport"] == "tcp"
    assert ecs["user"]["name"] == "threat_actor"
    assert ecs["observer"]["vendor"] == "Cisco"
    assert ecs["observer"]["product"] == "ASA"
