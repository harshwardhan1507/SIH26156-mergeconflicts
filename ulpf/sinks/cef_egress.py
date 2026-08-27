"""
ArcSight CEF Egress Sink.

Serializes normalized UES events back to standard RFC-compliant ArcSight CEF
syslog format for forwarding to legacy SIEM receivers, SOC collectors, and forwarders.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ulpf.sinks.base import SinkBase


class CEFEgressSink(SinkBase):
    """Writes UES events as standard CEF formatted strings to disk or stream."""

    def __init__(self, output_path: str | Path):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.output_path, "a", encoding="utf-8")

    @staticmethod
    def format_event(event: dict[str, Any]) -> str:
        """Convert UES event dict to standard CEF string."""
        src = event.get("source") or {}
        ev = event.get("event") or {}
        net = event.get("network") or {}
        ident = event.get("identity") or {}
        rule = event.get("rule") or {}

        vendor = src.get("vendor") or "ULPF"
        product = src.get("product") or "UnifiedLog"
        version = event.get("schema_version") or "1.2.0"
        sig_id = str(ev.get("event_type_vendor_specific") or ev.get("activity_id") or "EVENT_0")
        name = str(ev.get("activity_name") or ev.get("action") or ev.get("category") or "Generic Event")
        sev = int(round(float(ev.get("severity_numeric") or 5)))

        ext_parts = []
        if net.get("src_ip"): ext_parts.append(f"src={net['src_ip']}")
        if net.get("src_port"): ext_parts.append(f"spt={net['src_port']}")
        if net.get("dst_ip"): ext_parts.append(f"dst={net['dst_ip']}")
        if net.get("dst_port"): ext_parts.append(f"dpt={net['dst_port']}")
        if net.get("protocol"): ext_parts.append(f"proto={net['protocol']}")
        if net.get("bytes_in"): ext_parts.append(f"in={net['bytes_in']}")
        if net.get("bytes_out"): ext_parts.append(f"out={net['bytes_out']}")
        if ident.get("username"): ext_parts.append(f"suser={ident['username']}")
        if rule.get("policy_action"): ext_parts.append(f"act={rule['policy_action']}")
        if event.get("event_id"): ext_parts.append(f"externalId={event['event_id']}")
        if event.get("source_event_timestamp"): ext_parts.append(f"rt={event['source_event_timestamp']}")

        ext_str = " ".join(ext_parts)
        return f"CEF:0|{vendor}|{product}|{version}|{sig_id}|{name}|{sev}|{ext_str}"

    def write(self, event: dict[str, Any]) -> None:
        line = self.format_event(event)
        self._fh.write(line + "\n")

    def flush(self) -> None:
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()
