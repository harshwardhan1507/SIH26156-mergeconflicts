"""
OCSF Crosswalk Module.

Translates UES v1.2.0 normalized events into Open Cybersecurity Schema Framework (OCSF v1.1.0/v1.2.0)
compliant dictionaries.

Documented Scope:
- Classes: Network Activity (4001), Authentication (3001), Security Finding (2001),
  System Activity (1001), Policy Activity (5001), Database Activity (6004).
- Severity mapping: UES 0.0-10.0 scale mapped to OCSF 0-6 severity_id values.
- Retains authentic raw payload in metadata.raw_data and hash in metadata.raw_hash.
"""
from __future__ import annotations

from typing import Any

_OCSF_CATEGORY_CLASS_MAP = {
    "network": {
        "class_uid": 4001,
        "class_name": "Network Activity",
        "category_uid": 4,
        "category_name": "Network Activity",
    },
    "authentication": {
        "class_uid": 3001,
        "class_name": "Authentication",
        "category_uid": 3,
        "category_name": "Identity & Access Management",
    },
    "threat": {
        "class_uid": 2001,
        "class_name": "Security Finding",
        "category_uid": 2,
        "category_name": "Findings",
    },
    "system": {
        "class_uid": 1001,
        "class_name": "System Activity",
        "category_uid": 1,
        "category_name": "System Activity",
    },
    "policy": {
        "class_uid": 5001,
        "class_name": "Policy Activity",
        "category_uid": 5,
        "category_name": "Governance & Policy",
    },
    "database": {
        "class_uid": 6004,
        "class_name": "Database Activity",
        "category_uid": 6,
        "category_name": "Application Activity",
    },
    "unknown": {
        "class_uid": 1,
        "class_name": "Base Event",
        "category_uid": 0,
        "category_name": "Other",
    },
}

_OCSF_STATUS_MAP = {
    "success": ("Success", 1),
    "failure": ("Failure", 2),
    "unknown": ("Unknown", 0),
}


def _severity_to_ocsf(sev_numeric: float | None) -> tuple[str, int]:
    """Map UES 0-10 severity to OCSF (Severity Name, severity_id)."""
    if sev_numeric is None:
        return "Unknown", 0
    if sev_numeric >= 9.0:
        return "Critical", 5
    elif sev_numeric >= 7.0:
        return "High", 4
    elif sev_numeric >= 5.0:
        return "Medium", 3
    elif sev_numeric >= 3.0:
        return "Low", 2
    elif sev_numeric > 0.0:
        return "Informational", 1
    return "Unknown", 0


def to_ocsf(ues_event: dict[str, Any]) -> dict[str, Any]:
    """
    Convert a UES v1.2.0 normalized event dict into an OCSF standard representation.
    """
    category = ues_event.get("event", {}).get("category", "unknown")
    cls_info = _OCSF_CATEGORY_CLASS_MAP.get(category, _OCSF_CATEGORY_CLASS_MAP["unknown"])

    sev_num = ues_event.get("event", {}).get("severity_numeric")
    sev_name, sev_id = _severity_to_ocsf(sev_num)

    outcome = ues_event.get("event", {}).get("outcome") or "unknown"
    status_str, status_id = _OCSF_STATUS_MAP.get(outcome.lower(), ("Unknown", 0))

    src_info = ues_event.get("source", {})
    net_info = ues_event.get("network") or {}
    ident_info = ues_event.get("identity") or {}
    rule_info = ues_event.get("rule") or {}
    raw_info = ues_event.get("raw") or {}
    lineage_info = ues_event.get("lineage") or {}

    ocsf_record: dict[str, Any] = {
        "metadata": {
            "version": "1.1.0",
            "uid": ues_event.get("event_id"),
            "tenant_uid": ues_event.get("tenant_id", "default"),
            "processed_time": ues_event.get("ingest_timestamp"),
            "product": {
                "vendor_name": src_info.get("vendor"),
                "name": src_info.get("product"),
                "version": lineage_info.get("parser_version"),
            },
            "profiles": ["host", "security_control"],
            "raw_data": raw_info.get("raw_payload"),
            "raw_hash": raw_info.get("raw_hash"),
        },
        "time": ues_event.get("source_event_timestamp") or ues_event.get("ingest_timestamp"),
        "class_uid": cls_info["class_uid"],
        "class_name": cls_info["class_name"],
        "category_uid": cls_info["category_uid"],
        "category_name": cls_info["category_name"],
        "severity_id": sev_id,
        "severity": sev_name,
        "status_id": status_id,
        "status": status_str,
        "activity_name": ues_event.get("event", {}).get("action") or "Unknown",
        "device": {
            "hostname": src_info.get("device_hostname"),
            "ip": src_info.get("source_ip"),
            "type": src_info.get("log_format"),
        },
    }

    # Add network endpoint objects if network data present
    if net_info.get("src_ip") or net_info.get("dst_ip"):
        ocsf_record["src_endpoint"] = {
            "ip": net_info.get("src_ip"),
            "port": net_info.get("src_port"),
            "interface_name": net_info.get("interface"),
        }
        ocsf_record["dst_endpoint"] = {
            "ip": net_info.get("dst_ip"),
            "port": net_info.get("dst_port"),
        }
        if net_info.get("protocol"):
            ocsf_record["connection_info"] = {
                "protocol_name": net_info.get("protocol"),
                "direction": net_info.get("direction"),
            }
        if net_info.get("bytes_in") is not None or net_info.get("bytes_out") is not None:
            ocsf_record["traffic"] = {
                "bytes_in": net_info.get("bytes_in"),
                "bytes_out": net_info.get("bytes_out"),
            }

    # Add actor/user info
    if ident_info.get("username"):
        user_obj = {
            "name": ident_info.get("username"),
            "domain": ident_info.get("user_domain"),
        }
        ocsf_record["user"] = user_obj
        ocsf_record["actor"] = {
            "user": user_obj
        }

    # Add rule/policy info
    if rule_info.get("rule_id") or rule_info.get("rule_name"):
        ocsf_record["policy"] = {
            "uid": rule_info.get("rule_id"),
            "name": rule_info.get("rule_name"),
            "action": rule_info.get("policy_action"),
        }

    # Retain vendor attributes & enrichments
    if ues_event.get("vendor_attributes"):
        ocsf_record["unmapped"] = ues_event.get("vendor_attributes")
    if ues_event.get("enrichment"):
        ocsf_record["enrichments"] = ues_event.get("enrichment")

    return ocsf_record
