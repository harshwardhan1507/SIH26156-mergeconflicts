"""
Unit and integration tests for Live System Monitor & Process Collector.
"""
from __future__ import annotations

import datetime
import time
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from ulpf.collectors.live_monitor import LiveSystemMonitor
from ulpf.dashboard.app import create_app


def test_monitor_initialization(tmp_path):
    mon = LiveSystemMonitor(output_dir=tmp_path, interval_ms=100)
    assert not mon.is_running()
    assert mon.interval_sec == 0.1
    stats = mon.get_stats()
    assert stats["running"] is False
    assert stats["events_captured"] == 0
    assert stats["interval_ms"] == 100


def test_scan_processes():
    mon = LiveSystemMonitor()
    procs = mon._scan_processes()
    assert isinstance(procs, dict)
    assert len(procs) > 0
    # Check process entry structure
    first_pid = next(iter(procs))
    entry = procs[first_pid]
    assert "pid" in entry
    assert "name" in entry


def test_build_process_event_xml():
    mon = LiveSystemMonitor()
    now = datetime.datetime.now(datetime.timezone.utc)
    proc_info = {
        "pid": 9999,
        "name": "VALORANT.exe",
        "path": "C:\\Riot Games\\VALORANT\\live\\VALORANT.exe",
        "ppid": 1000,
    }
    xml_str = mon._build_process_event_xml(4688, proc_info, "process_start", now)
    assert "<EventID>4688</EventID>" in xml_str
    assert "VALORANT.exe" in xml_str
    assert "SubjectUserName" in xml_str


def test_build_network_connection_xml():
    mon = LiveSystemMonitor()
    now = datetime.datetime.now(datetime.timezone.utc)
    conn_info = {
        "pid": 9999,
        "src_ip": "192.168.1.5",
        "src_port": 54321,
        "dst_ip": "104.18.41.99",
        "dst_port": 443,
        "proto": "tcp",
    }
    proc_info = {
        "pid": 9999,
        "name": "VALORANT.exe",
        "path": "C:\\Riot Games\\VALORANT\\live\\VALORANT.exe",
    }
    xml_str = mon._build_network_connection_xml(conn_info, proc_info, now)
    assert "<EventID>5156</EventID>" in xml_str
    assert "192.168.1.5" in xml_str
    assert "104.18.41.99" in xml_str
    assert "VALORANT.exe" in xml_str
    assert "443" in xml_str


def test_monitor_dispatch_to_pipeline(tmp_path):
    dispatched = []

    def dummy_callback(raw_line, source_tag, ts):
        dispatched.append((raw_line, source_tag))

    mon = LiveSystemMonitor(output_dir=tmp_path, pipeline_callback=dummy_callback)
    now = datetime.datetime.now(datetime.timezone.utc)
    xml_str = mon._build_process_event_xml(4688, {"pid": 1234, "name": "test.exe"}, "process_start", now)
    mon._dispatch_event(xml_str, "test_source", now)

    assert len(dispatched) == 1
    assert "test.exe" in dispatched[0][0]
    assert dispatched[0][1] == "test_source"
    assert mon.events_captured == 1


def test_monitor_lifecycle(tmp_path):
    mon = LiveSystemMonitor(output_dir=tmp_path, interval_ms=50)
    mon.start()
    assert mon.is_running() is True
    time.sleep(0.15)
    stats = mon.get_stats()
    assert stats["running"] is True
    assert stats["tracked_processes"] > 0
    mon.stop()
    assert mon.is_running() is False


def test_dashboard_live_monitor_api(tmp_path):
    app = create_app(output_dir=tmp_path)
    client = TestClient(app)

    # Initial status
    res = client.get("/api/live-monitor/status")
    assert res.status_code == 200
    data = res.json()
    assert "running" in data

    # Start live monitor
    res_start = client.post("/api/live-monitor/start?interval_ms=100")
    assert res_start.status_code == 200
    start_data = res_start.json()
    assert start_data["status"] == "started"
    assert start_data["running"] is True

    # Status while running
    res_status = client.get("/api/live-monitor/status")
    assert res_status.status_code == 200
    assert res_status.json()["running"] is True

    # Stop live monitor
    res_stop = client.post("/api/live-monitor/stop")
    assert res_stop.status_code == 200
    stop_data = res_stop.json()
    assert stop_data["status"] == "stopped"
    assert stop_data["running"] is False

    # Check dedicated host data endpoints
    res_events = client.get("/api/live-monitor/events")
    assert res_events.status_code == 200
    assert "events" in res_events.json()

    res_conns = client.get("/api/live-monitor/connections")
    assert res_conns.status_code == 200
    assert "connections" in res_conns.json()

    res_procs = client.get("/api/live-monitor/processes")
    assert res_procs.status_code == 200
    assert "processes" in res_procs.json()
