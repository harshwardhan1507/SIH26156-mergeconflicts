"""
Egress sink escaping.

CEF and LEEF are delimiter-separated formats whose delimiters occur naturally in
log data. Emitting them unescaped lets a crafted source record inject extra
fields — or a whole extra event — into the SIEM consuming the stream, which is
the entire audience for these sinks.
"""
from __future__ import annotations

import pytest

from ulpf.sinks.cef_egress import CEFEgressSink
from ulpf.sinks.leef_egress import LEEFEgressSink


def _split_cef_header(line: str) -> list[str]:
    """
    Split a CEF record on unescaped pipes only.

    A naive ``line.split("|")`` also splits on an escaped pipe, which would
    report correct escaping as a failure.
    """
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == "|":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    fields.append("".join(current))
    return fields


def _event(**overrides):
    """A minimal UES event with hostile values in operator-controlled fields."""
    event = {
        "schema_version": "1.2.0",
        "event_id": "11111111-1111-1111-1111-111111111111",
        "source": {"vendor": "Acme", "product": "Firewall"},
        "event": {"category": "network", "action": "allow", "severity_numeric": 5},
        "network": {"src_ip": "10.0.0.1", "dst_port": 443},
        "identity": {"username": "alice"},
        "rule": {},
    }
    for key, value in overrides.items():
        block, _, field = key.partition(".")
        event[block][field] = value
    return event


def test_cef_escapes_pipe_in_header_fields():
    """A vendor name containing '|' must not create extra CEF header fields."""
    line = CEFEgressSink.format_event(_event(**{"source.vendor": "Ac|me|Corp"}))
    fields = _split_cef_header(line)
    # CEF:0, vendor, product, version, signature, name, severity, extension.
    assert len(fields) == 8, f"escaping failed, record split into {len(fields)} fields: {line}"
    assert fields[1] == r"Ac\|me\|Corp"
    assert fields[2] == "Firewall"


def test_cef_escapes_equals_and_newlines_in_extension_values():
    """An '=' or newline in a value must not forge additional extension pairs."""
    line = CEFEgressSink.format_event(
        _event(**{"identity.username": "alice suser=admin\nCEF:0|Evil|"})
    )
    assert "\n" not in line, "a newline in a value split the record into two"
    assert r"\=" in line


def test_cef_severity_is_clamped_to_the_valid_range():
    """CEF severity is 0-10; out-of-range input must be clamped, not emitted raw."""
    high = _split_cef_header(CEFEgressSink.format_event(_event(**{"event.severity_numeric": 99})))
    assert high[6] == "10"
    low = _split_cef_header(CEFEgressSink.format_event(_event(**{"event.severity_numeric": -5})))
    assert low[6] == "0"


def test_cef_tolerates_non_numeric_severity():
    """A malformed severity must degrade to the default, not raise."""
    fields = _split_cef_header(
        CEFEgressSink.format_event(_event(**{"event.severity_numeric": "high"}))
    )
    assert fields[6] == "5"


def test_leef_escapes_tab_in_attribute_values():
    """A tab in a value must not split one attribute into two."""
    line = LEEFEgressSink.format_event(
        _event(**{"identity.username": "alice\tsev=10\tdst=evil.example"})
    )
    body = line.split("|", 6)[-1]
    keys = [pair.split("=")[0] for pair in body.split("\t") if "=" in pair]
    assert keys.count("sev") <= 1, f"tab injection created a duplicate attribute: {line}"
    assert r"\t" in line


def test_leef_escapes_pipe_in_header_fields():
    """A '|' in the product name must not create extra LEEF header fields."""
    line = LEEFEgressSink.format_event(_event(**{"source.product": "Fire|wall"}))
    fields = _split_cef_header(line)  # same unescaped-delimiter rule as CEF
    assert fields[0:2] == ["LEEF:2.0", "Acme"]
    assert fields[2] == r"Fire\|wall"


@pytest.mark.parametrize("sink_cls", [CEFEgressSink, LEEFEgressSink])
def test_null_fields_are_omitted_rather_than_emitted_empty(sink_cls):
    """Absent values must be left out, not written as empty attributes."""
    event = _event()
    event["network"] = {"src_ip": "10.0.0.1"}
    line = sink_cls.format_event(event)
    assert "dst=" not in line
    assert "dpt=" not in line
