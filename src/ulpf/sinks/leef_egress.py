"""
IBM QRadar LEEF Egress Sink.

Serializes normalized UES events into IBM QRadar LEEF 2.0.

LEEF 2.0 delimits header fields with ``|`` and attribute pairs with a
configurable delimiter (tab here, declared in the header). Both characters
occur in real log data, so they are escaped rather than emitted raw — an
unescaped tab in a username would otherwise split one event into two
attributes in the receiving SIEM.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ulpf.sinks.base import SinkBase

#: Attribute delimiter, declared in the LEEF 2.0 header as ``x09``.
_ATTR_DELIM = "\t"


def _escape_header(value: Any) -> str:
    """Escape a LEEF header field: backslash and the ``|`` delimiter."""
    return str(value).replace("\\", "\\\\").replace("|", "\\|")


def _escape_attr(value: Any) -> str:
    """Escape a LEEF attribute value: backslash, delimiter, and newlines."""
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace(_ATTR_DELIM, "\\t")
        .replace("\r\n", "\\n")
        .replace("\n", "\\n")
        .replace("\r", "\\n")
    )


class LEEFEgressSink(SinkBase):
    """Writes UES events as LEEF 2.0 formatted lines."""

    def __init__(self, output_path: str | Path):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.output_path, "a", encoding="utf-8")
        self._count = 0

    @staticmethod
    def format_event(event: dict[str, Any]) -> str:
        """Convert a UES event dict into a LEEF:2.0 record."""
        src = event.get("source") or {}
        ev = event.get("event") or {}
        net = event.get("network") or {}
        ident = event.get("identity") or {}

        vendor = _escape_header(src.get("vendor") or "ULPF")
        product = _escape_header(src.get("product") or "UnifiedLog")
        version = _escape_header(event.get("schema_version") or "1.2.0")
        event_id = _escape_header(
            ev.get("event_type_vendor_specific") or ev.get("activity_name") or "LEEF_EVENT"
        )

        attrs: list[str] = []

        def add(key: str, value: Any) -> None:
            if value is not None and value != "":
                attrs.append(f"{key}={_escape_attr(value)}")

        add("src", net.get("src_ip"))
        add("spt", net.get("src_port"))
        add("dst", net.get("dst_ip"))
        add("dpt", net.get("dst_port"))
        add("proto", net.get("protocol"))
        add("usrName", ident.get("username"))
        if ev.get("severity_numeric") is not None:
            try:
                add("sev", max(0, min(10, round(float(ev["severity_numeric"])))))
            except (TypeError, ValueError):
                pass
        add("action", ev.get("action"))
        add("outcome", ev.get("outcome"))
        add("devTime", event.get("source_event_timestamp"))

        # The header's trailing field declares the attribute delimiter (x09).
        return (
            f"LEEF:2.0|{vendor}|{product}|{version}|{event_id}|x09|"
            + _ATTR_DELIM.join(attrs)
        )

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
