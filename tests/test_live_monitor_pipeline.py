import datetime
import json
import time
from pathlib import Path
from ulpf.collectors.live_monitor import LiveSystemMonitor

def test_live_monitor_writes_and_flushes_pipeline(tmp_path: Path):
    monitor = LiveSystemMonitor(
        output_dir=tmp_path,
        interval_ms=100,
        write_to_main_pipeline=True
    )
    
    # Simulate dispatched events
    now = datetime.datetime.now(datetime.UTC)
    now_iso = now.isoformat()
    raw_xml = (
        f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        f"<System><EventID>4688</EventID><TimeCreated SystemTime='{now_iso}'/></System>"
        f"<EventData><Data Name='NewProcessName'>C:\\Windows\\System32\\cmd.exe</Data>"
        f"<Data Name='Action'>process_create</Data></EventData></Event>"
    )
    
    monitor._dispatch_event(raw_xml, "win_evt_security", now)
    # The monitor should ensure session exists and flush on stop() or auto-flush
    monitor.stop()

    events_file = tmp_path / "events.ndjson"
    assert events_file.exists()
    assert events_file.stat().st_size > 0
    lines = [line for line in events_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) >= 1
    event = json.loads(lines[0])
    assert event["schema_version"] == "1.2.0"
    source = event.get("source") or {}
    assert source.get("vendor") in ("Microsoft (Windows)", "Host System", "Microsoft", "Windows") or "event" in event
