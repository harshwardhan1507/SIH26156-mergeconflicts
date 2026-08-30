"""
Tests for Event Framing Layer and Max-Bytes Quarantine Protection.
"""
from __future__ import annotations

from ulpf.core.framing import (
    JSONStreamFramer,
    LineFramer,
    MultilineRegexFramer,
    SyslogOctetFramer,
)


def test_line_framer():
    stream = [b"line1\nline2\r\nline3\n"]
    framer = LineFramer()
    results = list(framer.frame(stream))
    assert [r.raw_text for r in results] == ["line1", "line2", "line3"]
    assert all(not r.is_oversized for r in results)


def test_multiline_regex_framer_stacktraces():
    log_data = [
        b"2024-03-15 10:00:00 [INFO] Server started\n",
        b"2024-03-15 10:00:01 [ERROR] NullPointerException\n",
        b"    at com.example.Service.handle(Service.java:42)\n",
        b"    at com.example.Engine.run(Engine.java:100)\n",
        b"2024-03-15 10:00:02 [INFO] Heartbeat OK\n",
    ]
    framer = MultilineRegexFramer(
        start_pattern=r"^\d{4}-\d{2}-\d{2}",
        max_bytes=10000,
    )
    results = list(framer.frame(log_data))
    assert len(results) == 3
    assert "Server started" in results[0].raw_text
    assert "NullPointerException" in results[1].raw_text
    assert "at com.example.Service.handle" in results[1].raw_text
    assert "Heartbeat OK" in results[2].raw_text


def test_json_stream_framer():
    json_data = [b'{"id": 1, "msg": "hello"} {"id": 2, "nested": {"val": true}} {"id": 3}']
    framer = JSONStreamFramer()
    results = list(framer.frame(json_data))
    assert len(results) == 3
    assert '{"id": 1, "msg": "hello"}' in results[0].raw_text
    assert '"val": true' in results[1].raw_text
    assert '{"id": 3}' in results[2].raw_text


def test_syslog_octet_framer():
    msg1 = "<134>1 2024-03-15T10:22:45Z msg1"
    msg2 = "<134>1 2024-03-15T10:22:46Z msg2"
    syslog_data = [f"{len(msg1)} {msg1} {len(msg2)} {msg2}".encode()]
    framer = SyslogOctetFramer()
    results = list(framer.frame(syslog_data))
    assert len(results) == 2
    assert results[0].raw_text == msg1
    assert results[1].raw_text == msg2


def test_oversized_event_handling():
    huge_data = [b"A" * 5000 + b"\n"]
    # Max bytes is set to 1024
    framer = LineFramer(max_bytes=1024)
    results = list(framer.frame(huge_data))
    assert len(results) == 1
    assert results[0].is_oversized is True
    assert "exceeds max_bytes" in results[0].error
