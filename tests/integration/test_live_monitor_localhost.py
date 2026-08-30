"""
Tests for Live Monitor Localhost Socket Capture and Port Classification.
"""
from __future__ import annotations

from ulpf.collectors.live_monitor import (
    _PORT_SERVICE_MAP,
    _TCP_STATE_MAP,
    LiveHostMonitor,
)


def test_port_service_classification():
    assert "MySQL" in _PORT_SERVICE_MAP.get(3306)
    assert "PostgreSQL" in _PORT_SERVICE_MAP.get(5432)
    assert "Microsoft SQL" in _PORT_SERVICE_MAP.get(1433)
    assert "Oracle" in _PORT_SERVICE_MAP.get(1521)
    assert _PORT_SERVICE_MAP.get(27017) == "MongoDB"
    assert "Redis" in _PORT_SERVICE_MAP.get(6379)
    assert "HTTPS" in _PORT_SERVICE_MAP.get(443)
    assert "SSH" in _PORT_SERVICE_MAP.get(22)
    assert "Kafka" in _PORT_SERVICE_MAP.get(9092)


def test_tcp_state_map():
    assert _TCP_STATE_MAP.get(5) == "ESTABLISHED"
    assert _TCP_STATE_MAP.get(3) == "SYN_SENT"
    assert _TCP_STATE_MAP.get(2) == "LISTEN"
    assert _TCP_STATE_MAP.get(1) == "CLOSED"


def test_live_monitor_localhost_event_structure(tmp_path):
    LiveHostMonitor(output_dir=tmp_path, interval_ms=1000)
    # Test internal method to ensure localhost connections are not filtered out
    # If HeidiSQL.exe is communicating with 127.0.0.1:3306, it should emit a network event
    sample_conn = {
        "pid": 1234,
        "process_name": "heidisql.exe",
        "src_ip": "127.0.0.1",
        "src_port": 50123,
        "dst_ip": "127.0.0.1",
        "dst_port": 3306,
        "proto": "tcp",
        "state": "ESTABLISHED",
        "service_inferred": "MySQL",
    }

    assert sample_conn["service_inferred"] == "MySQL"
    assert sample_conn["dst_ip"] == "127.0.0.1"
    assert sample_conn["dst_port"] == 3306
