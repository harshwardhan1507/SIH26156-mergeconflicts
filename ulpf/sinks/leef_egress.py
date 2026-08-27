"""
IBM QRadar LEEF Egress Sink.

Serializes normalized UES events back to standard IBM QRadar LEEF 2.0 format.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ulpf.sinks.base import SinkBase


class LEEFEgressSink(SinkBase):
    """Writes UES events as standard LEEF 2.0 formatted strings."""

    def __init__(self, output_path: str | Path):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.output_path, "a", encoding="utf-8")

    @staticmethod
    def format_event(event: dict[str, Any]) -> str:
        """Convert UES event dict to standard LEEF 2.0 string."""
        src = event.get("source") or {}
        ev = event.get("event") or {}
        net = event.get("network") or {}
        ident = event.get("identity") or {}

        vendor = src.get("vendor") or "ULPF"
        product = src.get("product") or "UnifiedLog"
        version = event.get("schema_version") or "1.2.0"
        event_id = str(ev.get("event_type_vendor_specific") or ev.get("activity_name") or "LEEF_EVENT")

        attrs = []
        if net.get("src_ip"): attrs.append(f"src={net['src_ip']}")
        if net.get("src_port"): attrs.append(f"spt={net['src_port']}")
        if net.get("dst_ip"): attrs.append(f"dst={net['dst_ip']}")
        if net.get("dst_port"): attrs.append(f"dpt={net['dst_port']}")
        if net.get("protocol"): attrs.append(f"proto={net['protocol']}")
        if ident.get("username"): attrs.append(f"usrName={ident['username']}")
        if ev.get("severity_numeric") is not None:
            attrs.append(f"sev={int(round(float(ev['severity_numeric'])))}")
        if ev.get("action"): attrs.append(f"action={ev['action']}")
        if ev.get("outcome"): attrs.append(f"outcome={ev['outcome']}")
        if event.get("source_event_timestamp"): attrs.append(f"devTime={event['source_event_timestamp']}")

        attr_str = "\t".join(attrs)
        return f"LEEF:2.0|{vendor}|{product}|{version}|{event_id}|\t|{attr_str}"

    def write(self, event: dict[str, Any]) -> None:
        line = self.format_event(event)
        self._fh.write(line + "\n")

    def flush(self) -> None:
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()
