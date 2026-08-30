"""
Tests for Declarative Generic Parser and No-Code Source Onboarding Engine.
"""
from __future__ import annotations

import json

from ulpf.core.declarative import (
    DeclarativeSourceParser,
    DeclarativeSourceRegistry,
    infer_declarative_mapping,
    validate_declarative_config,
)


def test_declarative_key_value_extraction():
    config = {
        "name": "test_kv_fw",
        "vendor": "TestVendor",
        "product": "TestFW",
        "version": "1.0.0",
        "enabled": True,
        "log_format": "test_kv",
        "detection": {
            "contains": ["srcip=", "dstip="],
            "contains_mode": "all",
        },
        "parser": {
            "type": "key_value",
            "pair_delimiter": " ",
            "kv_delimiter": "=",
            "strip_quotes": True,
        },
        "fields": {
            "timestamp": "time",
            "types": {
                "srcport": "port",
                "dstport": "port",
                "bytes_in": "int",
            }
        },
        "normalize": {
            "source.vendor": "TestVendor",
            "source.product": "TestFW",
            "event.category": "network",
            "event.action": "action",
            "event.outcome": "action",
            "event.severity_numeric": 4.0,
            "network.src_ip": "srcip",
            "network.dst_ip": "dstip",
            "network.src_port": "srcport",
            "network.dst_port": "dstport",
            "network.bytes_in": "bytes_in",
            "identity.username": "user",
            "retain_unmapped": True,
        }
    }

    parser = DeclarativeSourceParser(config)
    raw = 'time="2024-03-15T10:22:45Z" srcip=192.168.1.100 dstip=10.0.0.1 srcport=54321 dstport=443 action=allow user=alice bytes_in=1024 custom_flag=0x44'
    assert parser.match(raw) is True

    extracted = parser.extract(raw)
    assert extracted["srcip"] == "192.168.1.100"
    assert extracted["dstip"] == "10.0.0.1"
    assert extracted["srcport"] == 54321
    assert extracted["dstport"] == 443
    assert extracted["bytes_in"] == 1024
    assert extracted["user"] == "alice"

    normalized = parser.build_normalized_event(extracted)
    assert normalized["source"]["vendor"] == "TestVendor"
    assert normalized["event"]["category"] == "network"
    assert normalized["event"]["action"] == "allow"
    assert normalized["event"]["outcome"] == "success"
    assert normalized["network"]["src_ip"] == "192.168.1.100"
    assert normalized["network"]["dst_port"] == 443
    assert normalized["identity"]["username"] == "alice"
    assert normalized["vendor_attributes"]["custom_flag"] == "0x44"


def test_declarative_csv_extraction():
    config = {
        "name": "test_csv_proxy",
        "vendor": "ProxyCorp",
        "product": "WebProxy",
        "parser": {
            "type": "csv",
            "delimiter": ",",
            "columns": ["timestamp", "client_ip", "server_ip", "port", "user", "action", "status_code"],
        },
        "fields": {
            "timestamp": "timestamp",
            "types": {
                "port": "port",
                "status_code": "int",
            }
        },
        "normalize": {
            "event.category": "network",
            "event.action": "action",
            "network.src_ip": "client_ip",
            "network.dst_ip": "server_ip",
            "network.dst_port": "port",
            "identity.username": "user",
        }
    }

    parser = DeclarativeSourceParser(config)
    raw = "2024-03-15T10:22:45Z,192.168.1.55,198.51.100.20,443,bob,CONNECT,200"
    extracted = parser.extract(raw)
    assert extracted["client_ip"] == "192.168.1.55"
    assert extracted["port"] == 443
    assert extracted["status_code"] == 200

    normalized = parser.build_normalized_event(extracted)
    assert normalized["network"]["src_ip"] == "192.168.1.55"
    assert normalized["identity"]["username"] == "bob"


def test_declarative_json_nested_paths():
    config = {
        "name": "test_json_auth",
        "vendor": "AuthVendor",
        "product": "SSOService",
        "parser": {
            "type": "json",
            "json_paths": {
                "user_name": "actor.profile.username",
                "client_ip": "actor.connection.ip",
                "rule_id": "policy.matched_rules[0]",
            }
        },
        "normalize": {
            "event.category": "authentication",
            "event.action": "event_name",
            "event.outcome": "status",
            "network.src_ip": "client_ip",
            "identity.username": "user_name",
            "rule.rule_id": "rule_id",
        }
    }

    parser = DeclarativeSourceParser(config)
    raw = json.dumps({
        "event_name": "user_login",
        "status": "success",
        "actor": {
            "profile": {"username": "admin_svc"},
            "connection": {"ip": "203.0.113.77"}
        },
        "policy": {
            "matched_rules": ["RULE_MFA_01", "RULE_PASS"]
        }
    })

    extracted = parser.extract(raw)
    assert extracted["user_name"] == "admin_svc"
    assert extracted["client_ip"] == "203.0.113.77"
    assert extracted["rule_id"] == "RULE_MFA_01"

    normalized = parser.build_normalized_event(extracted)
    assert normalized["identity"]["username"] == "admin_svc"
    assert normalized["network"]["src_ip"] == "203.0.113.77"
    assert normalized["rule"]["rule_id"] == "RULE_MFA_01"


def test_declarative_regex_extraction():
    config = {
        "name": "test_regex_bank",
        "vendor": "BankApp",
        "product": "CoreEngine",
        "detection": {
            "prefix": "[BANK-LOG]"
        },
        "parser": {
            "type": "regex",
            "pattern": r"^\[BANK-LOG\]\s+USER=(?P<user>\S+)\s+IP=(?P<ip>\S+)\s+AMOUNT=(?P<amount>\S+)"
        },
        "fields": {
            "types": {
                "amount": "float"
            }
        },
        "normalize": {
            "identity.username": "user",
            "network.src_ip": "ip",
        }
    }

    parser = DeclarativeSourceParser(config)
    raw = "[BANK-LOG] USER=alice_tx IP=192.168.1.99 AMOUNT=2500.50"
    assert parser.match(raw) is True
    extracted = parser.extract(raw)
    assert extracted["user"] == "alice_tx"
    assert extracted["ip"] == "192.168.1.99"
    assert extracted["amount"] == 2500.50


def test_declarative_config_validation():
    # Valid config
    valid_cfg = {
        "name": "valid_source",
        "vendor": "Vendor",
        "product": "Product",
        "parser": {
            "type": "key_value"
        }
    }
    is_valid, errors = validate_declarative_config(valid_cfg)
    assert is_valid is True
    assert len(errors) == 0

    # Invalid regex pattern
    invalid_regex_cfg = {
        "name": "invalid_regex",
        "vendor": "Vendor",
        "product": "Product",
        "parser": {
            "type": "regex",
            "pattern": "[unclosed bracket"
        }
    }
    is_valid, errors = validate_declarative_config(invalid_regex_cfg)
    assert is_valid is False
    assert any("Invalid regex pattern" in e for e in errors)


def test_declarative_registry_dynamic_loading(tmp_path):
    registry = DeclarativeSourceRegistry(sources_dir=tmp_path)
    config = {
        "name": "dynamic_source",
        "vendor": "DynVendor",
        "product": "DynProd",
        "parser": {
            "type": "key_value"
        },
        "normalize": {
            "event.category": "network"
        }
    }

    success, _errors, parser = registry.add_source(config)
    assert success is True
    assert parser is not None
    assert (tmp_path / "dynamic_source.yaml").exists()

    # Re-scan from disk
    new_reg = DeclarativeSourceRegistry(sources_dir=tmp_path)
    loaded = new_reg.scan_and_register()
    assert loaded == 1
    src = new_reg.get_source("dynamic_source")
    assert src is not None
    assert src.vendor == "DynVendor"


def test_infer_declarative_mapping():
    sample_kv = 'devtime="2024-03-15T10:22:45Z" srcip=192.168.1.55 dstip=10.0.0.1 srcport=54321 action=deny user=alice'
    inferred = infer_declarative_mapping(sample_kv, "firewall_inferred")
    assert inferred["parser"]["type"] == "key_value"
    assert inferred["normalize"]["network.src_ip"] == "srcip"
    assert inferred["normalize"]["identity.username"] == "user"

    sample_json = json.dumps({"timestamp": "2024-03-15T10:22:45Z", "src_ip": "10.0.0.5", "username": "bob", "action": "login"})
    inferred_json = infer_declarative_mapping(sample_json, "auth_inferred")
    assert inferred_json["parser"]["type"] == "json"
    assert inferred_json["normalize"]["network.src_ip"] == "src_ip"
