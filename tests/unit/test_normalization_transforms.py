"""
Unit tests for Normalization Transformation Functions (_upper, _lower, _strip, _first, _split, _default, _literal).
"""
from __future__ import annotations

from ulpf.core.normalization import NormalizationEngine, _get_field


def test_normalization_transform_literal():
    extracted = {"foo": "bar"}
    assert _get_field(extracted, "_literal:my_constant") == "my_constant"


def test_normalization_transform_upper_lower_strip():
    extracted = {
        "raw_user": "  Alice_Admin  ",
        "proto_mixed": "Tcp_Session",
    }
    assert _get_field(extracted, "_upper:proto_mixed") == "TCP_SESSION"
    assert _get_field(extracted, "_lower:proto_mixed") == "tcp_session"
    assert _get_field(extracted, "_strip:raw_user") == "Alice_Admin"


def test_normalization_transform_first_coalesce():
    extracted1 = {"client_ip": "10.0.0.1", "src": ""}
    extracted2 = {"src": "192.168.1.1", "client_ip": None}
    extracted3 = {"other": "value"}

    spec = "_first:client_ip,src,remote_host"
    assert _get_field(extracted1, spec) == "10.0.0.1"
    assert _get_field(extracted2, spec) == "192.168.1.1"
    assert _get_field(extracted3, spec) is None


def test_normalization_transform_split():
    extracted = {
        "socket_pair": "10.0.0.5:8080",
        "csv_tuple": "admin,CORP,HR",
    }
    assert _get_field(extracted, "_split:socket_pair,:,0") == "10.0.0.5"
    assert _get_field(extracted, "_split:socket_pair,:,1") == "8080"
    assert _get_field(extracted, "_split:csv_tuple,,,1") == "CORP"


def test_normalization_transform_default_fallback():
    extracted1 = {"status": "success"}
    extracted2 = {"status": ""}
    extracted3 = {}

    spec = "_default:status,unknown"
    assert _get_field(extracted1, spec) == "success"
    assert _get_field(extracted2, spec) == "unknown"
    assert _get_field(extracted3, spec) == "unknown"


def test_engine_normalization_with_transforms(tmp_path):
    # Create test mapping YAML with custom transforms
    mapping_yaml = """
ruleset_version: "1.0.0"
source:
  vendor: "_literal:CustomSec"
  product: "_upper:app_name"
  device_hostname: "_strip:raw_host"
  source_ip: "_first:src_ip,client_ip,remote_addr"
  log_format: "custom_transform_fmt"
event:
  category: "_default:cat,network"
  action: "_lower:act_raw"
  outcome: "_outcome_from_action"
  severity_numeric: 5.0
  severity_original: null
  event_type_vendor_specific: null
network:
  src_ip: "_first:src_ip,client_ip"
  src_port: "_split:src_socket,:,1"
  dst_ip: null
  dst_port: null
  protocol: null
  bytes_in: null
  bytes_out: null
  direction: null
  interface: null
identity:
  username: "_first:user_name,account_id"
  user_domain: null
rule:
  rule_id: null
  rule_name: null
  policy_action: null
"""
    map_dir = tmp_path / "mappings"
    map_dir.mkdir()
    (map_dir / "custom_test.yaml").write_text(mapping_yaml, encoding="utf-8")

    engine = NormalizationEngine(mappings_dir=map_dir)

    sample_extracted = {
        "_raw": "raw log line",
        "_log_format": "custom_test",
        "app_name": "firewall_core",
        "raw_host": "  fw-dc1.corp.net  ",
        "client_ip": "10.20.30.40",
        "src_socket": "10.20.30.40:54321",
        "act_raw": "PERMITTED",
        "user_name": "alice_sec",
        "unmapped_flag": "0xDEADBEEF",
    }

    norm = engine.normalize(sample_extracted, "custom_test")

    assert norm["source"]["vendor"] == "CustomSec"
    assert norm["source"]["product"] == "FIREWALL_CORE"
    assert norm["source"]["device_hostname"] == "fw-dc1.corp.net"
    assert norm["source"]["source_ip"] == "10.20.30.40"
    assert norm["event"]["category"] == "network"
    assert norm["event"]["action"] == "permitted"
    assert norm["event"]["outcome"] == "success"
    assert norm["network"]["src_ip"] == "10.20.30.40"
    assert norm["network"]["src_port"] == 54321
    assert norm["identity"]["username"] == "alice_sec"
    assert norm["vendor_attributes"]["unmapped_flag"] == "0xDEADBEEF"
