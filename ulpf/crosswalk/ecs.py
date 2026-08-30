"""
ECS (Elastic Common Schema) Crosswalk Module.

Translates UES v1.2.0 normalized events into Elastic Common Schema (ECS v8.11.0)
compliant dictionaries.

Documented Scope:
- Core fieldsets: @timestamp, ecs.version, event.*, observer.*, source.*, destination.*,
  network.*, user.*, rule.*, labels.*, original event preservation.
"""
from __future__ import annotations

from typing import Any


def to_ecs(ues_event: dict[str, Any]) -> dict[str, Any]:
    """
    Convert a UES v1.2.0 normalized event dict into an ECS standard representation.
    """
    ts = ues_event.get("source_event_timestamp") or ues_event.get("ingest_timestamp")

    src_info = ues_event.get("source", {})
    ev_info = ues_event.get("event", {})
    net_info = ues_event.get("network") or {}
    ident_info = ues_event.get("identity") or {}
    rule_info = ues_event.get("rule") or {}
    raw_info = ues_event.get("raw") or {}
    lineage_info = ues_event.get("lineage") or {}

    sev_num = ev_info.get("severity_numeric")
    ecs_severity = int(sev_num * 10) if sev_num is not None else 50

    ecs_record: dict[str, Any] = {
        "@timestamp": ts,
        "ecs": {
            "version": "8.11.0",
        },
        "event": {
            "id": ues_event.get("event_id"),
            "kind": "event",
            "category": [ev_info.get("category", "network")],
            "action": ev_info.get("action"),
            "outcome": ev_info.get("outcome") or "unknown",
            "severity": ecs_severity,
            "original": raw_info.get("raw_payload"),
            "hash": {
                "sha256": raw_info.get("raw_hash"),
            },
            "ingested": ues_event.get("ingest_timestamp"),
        },
        "observer": {
            "vendor": src_info.get("vendor"),
            "product": src_info.get("product"),
            "hostname": src_info.get("device_hostname"),
            "ip": src_info.get("source_ip"),
            "type": src_info.get("log_format"),
            "version": lineage_info.get("parser_version"),
        },
        "labels": {
            "tenant_id": ues_event.get("tenant_id", "default"),
            "parser_name": lineage_info.get("parser_name"),
            "ruleset_version": lineage_info.get("normalization_ruleset_version"),
        },
    }

    # Add network fields
    if net_info:
        if net_info.get("src_ip") or net_info.get("src_port"):
            ecs_record["source"] = {
                "ip": net_info.get("src_ip"),
                "port": net_info.get("src_port"),
                "bytes": net_info.get("bytes_out"),
            }
        if net_info.get("dst_ip") or net_info.get("dst_port"):
            ecs_record["destination"] = {
                "ip": net_info.get("dst_ip"),
                "port": net_info.get("dst_port"),
                "bytes": net_info.get("bytes_in"),
            }
        if net_info.get("protocol") or net_info.get("direction"):
            ecs_record["network"] = {
                "transport": net_info.get("protocol"),
                "direction": net_info.get("direction"),
                "bytes": (net_info.get("bytes_in") or 0) + (net_info.get("bytes_out") or 0) or None,
            }

    # Add identity/user fields
    if ident_info.get("username") or ident_info.get("user_domain"):
        ecs_record["user"] = {
            "name": ident_info.get("username"),
            "domain": ident_info.get("user_domain"),
        }

    # Add rule/policy fields
    if rule_info.get("rule_id") or rule_info.get("rule_name"):
        ecs_record["rule"] = {
            "id": rule_info.get("rule_id"),
            "name": rule_info.get("rule_name"),
            "description": rule_info.get("policy_action"),
        }

    # Retain vendor attributes in custom labels
    if ues_event.get("vendor_attributes"):
        for k, v in ues_event["vendor_attributes"].items():
            safe_k = "".join(c if c.isalnum() or c == "_" else "_" for c in str(k))
            ecs_record["labels"][f"vendor_{safe_k}"] = str(v)

    # Attach threat enrichment tags
    threat_tags = ues_event.get("enrichment", {}).get("threat_intel_tags")
    if threat_tags:
        ecs_record["tags"] = threat_tags

    return ecs_record
