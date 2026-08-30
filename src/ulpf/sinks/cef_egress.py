"""
ArcSight CEF Egress Sink.

Serializes normalized UES events back into ArcSight CEF for forwarding to
legacy SIEM receivers, SOC collectors, and syslog forwarders.

Escaping is not cosmetic here. CEF delimits header fields with ``|`` and
extension pairs with ``=``; those characters routinely appear in real log data
(hostnames, rule names, usernames). Emitting them unescaped lets a crafted
source log inject extra fields — or an entire extra event — into whatever SIEM
consumes this stream. Per the ArcSight specification, header fields escape
``\\`` and ``|``; extension values escape ``\\``, ``=``, and newlines.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ulpf.sinks.base import SinkBase


def _escape_header(value: Any) -> str:
    """Escape a CEF header field: backslash and the ``|`` field delimiter."""
    return str(value).replace("\\", "\\\\").replace("|", "\\|")


def _escape_extension(value: Any) -> str:
    """Escape a CEF extension value: backslash, ``=``, and embedded newlines."""
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\r\n", "\\n")
        .replace("\n", "\\n")
        .replace("\r", "\\n")
    )


class CEFEgressSink(SinkBase):
    """Writes UES events as CEF-formatted lines."""

    #: UES field path -> CEF extension key, in emission order.
    _EXTENSION_MAP: tuple[tuple[str, str, str], ...] = (
        ("network", "src_ip", "src"),
        ("network", "src_port", "spt"),
        ("network", "dst_ip", "dst"),
        ("network", "dst_port", "dpt"),
        ("network", "protocol", "proto"),
        ("network", "bytes_in", "in"),
        ("network", "bytes_out", "out"),
        ("identity", "username", "suser"),
        ("rule", "policy_action", "act"),
    )

    def __init__(self, output_path: str | Path):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.output_path, "a", encoding="utf-8")
        self._count = 0

    @staticmethod
    def format_event(event: dict[str, Any]) -> str:
        """Convert a UES event dict into a CEF:0 record."""
        src = event.get("source") or {}
        ev = event.get("event") or {}

        vendor = _escape_header(src.get("vendor") or "ULPF")
        product = _escape_header(src.get("product") or "UnifiedLog")
        version = _escape_header(event.get("schema_version") or "1.2.0")
        sig_id = _escape_header(
            ev.get("event_type_vendor_specific") or ev.get("activity_id") or "EVENT_0"
        )
        name = _escape_header(
            ev.get("activity_name") or ev.get("action") or ev.get("category") or "Generic Event"
        )
        try:
            sev = round(float(ev.get("severity_numeric") or 5))
        except (TypeError, ValueError):
            sev = 5
        sev = max(0, min(10, sev))

        ext_parts: list[str] = []
        for block_name, field, cef_key in CEFEgressSink._EXTENSION_MAP:
            block = event.get(block_name) or {}
            value = block.get(field)
            if value is not None and value != "":
                ext_parts.append(f"{cef_key}={_escape_extension(value)}")
        if event.get("event_id"):
            ext_parts.append(f"externalId={_escape_extension(event['event_id'])}")
        if event.get("source_event_timestamp"):
            ext_parts.append(f"rt={_escape_extension(event['source_event_timestamp'])}")

        return f"CEF:0|{vendor}|{product}|{version}|{sig_id}|{name}|{sev}|{' '.join(ext_parts)}"

    def write(self, event: dict[str, Any]) -> None:
        self._fh.write(self.format_event(event) + "\n")
        self._count += 1

    def flush(self) -> None:
        self._fh.flush()

    def close(self) -> None:
        self._fh.flush()
        self._fh.close()

    @property
    def events_written(self) -> int:
        return self._count
