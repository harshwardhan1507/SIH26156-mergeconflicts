# Real-Time Host Event Streaming Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stream authentic host machine events (Windows Event Logs, running process creations/exits, and active network sockets) directly into the normalized UES pipeline and SQLite index so the Event Grid displays live real-time host data instead of static demo logs.

**Architecture:** Purge existing demo data from `output/`. Enhance `LiveSystemMonitor` with automated periodic session flushing and integrate it into FastAPI's lifespan lifecycle in `ulpf_dashboard/app.py` with `write_to_main_pipeline=True`. As real system events occur, they are normalized into UES format, appended to `output/events.ndjson`, indexed into SQLite `dashboard_index.db`, and broadcast via SSE to the browser Event Grid.

**Tech Stack:** Python 3.11+, FastAPI, Uvicorn, SQLite (WAL mode), Windows ToolHelp / IP Helper API (`ctypes`), `wevtutil`, SSE (Server-Sent Events), Vanilla JS virtual scroller.

## Global Constraints
- Target platform: Windows (with POSIX fallback for socket scanning).
- Pipeline schema conformance: Universal Event Schema (UES) v1.2.0.
- Raw payload integrity: Untouched raw XML / event payloads preserved in `output/raw_store/` with SHA-256 hashes.
- Clean isolation: No demo data mixed with live data.

---

### Task 1: Demo Data Wipe & Launcher Demo Fallback Removal

**Files:**
- Modify: `tools/windows/launcher.py:96-120`
- Script: `scripts/Launch_ULPF_Dashboard.bat`

**Interfaces:**
- Consumes: Filesystem output directory paths.
- Produces: Clean `output/` directory with no demo `events.ndjson` or demo `dashboard_index.db`.

- [ ] **Step 1: Write a test verifying that launcher does not seed sample demo data into empty output**

```python
# tests/test_clean_output.py
from pathlib import Path
from tools.windows.launcher import bootstrap_sample_data_if_needed

def test_bootstrap_sample_data_is_noop(tmp_path: Path):
    events_file = tmp_path / "events.ndjson"
    bootstrap_sample_data_if_needed(tmp_path)
    assert not events_file.exists() or events_file.stat().st_size == 0
```

- [ ] **Step 2: Run test to verify current behavior**

Run: `py -m pytest tests/test_clean_output.py -v`

- [ ] **Step 3: Update `tools/windows/launcher.py` to disable demo data injection and wipe stale output**

In `tools/windows/launcher.py`:
Change `bootstrap_sample_data_if_needed` to be a no-op or remove it so no demo events are loaded into `output/`.

- [ ] **Step 4: Stop running background dashboard processes and purge `output/` directory**

Run powershell command to terminate any lingering `pythonw` processes on ports 7000/8000 and delete `output/events.ndjson`, `output/dashboard_index.db`, `output/dead_letter.ndjson`, `output/raw_store`.

- [ ] **Step 5: Run test to verify it passes**

Run: `py -m pytest tests/test_clean_output.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add tools/windows/launcher.py tests/test_clean_output.py
git commit -m "fix(launcher): disable automatic demo data injection on empty index"
```

---

### Task 2: Live Host Telemetry Pipeline Ingestion & Auto-Flush

**Files:**
- Modify: `src/ulpf/collectors/live_monitor.py:120-145, 500-535`
- Test: `tests/test_live_monitor_pipeline.py`

**Interfaces:**
- Consumes: `LiveSystemMonitor(write_to_main_pipeline=True, interval_ms=...)`
- Produces: Valid UES normalized events written to `output/events.ndjson` with regular disk flushes.

- [ ] **Step 1: Write failing test for live monitor pipeline writing and flushing**

```python
# tests/test_live_monitor_pipeline.py
import json
import time
from pathlib import Path
from ulpf.collectors.live_monitor import LiveSystemMonitor

def test_live_monitor_writes_to_main_pipeline(tmp_path: Path):
    monitor = LiveSystemMonitor(
        output_dir=tmp_path,
        interval_ms=100,
        write_to_main_pipeline=True
    )
    # Simulate a single live event dispatch
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ")
    raw_xml = f"<Event><System><EventID>4688</EventID><TimeCreated SystemTime='{now}'/></System><EventData><Data Name='NewProcessName'>test_proc.exe</Data><Data Name='Action'>process_create</Data></EventData></Event>"
    import datetime
    monitor._dispatch_event(raw_xml, "test_host", datetime.datetime.now(datetime.UTC))
    
    # Flush session
    if monitor._session:
        monitor._session.flush()

    events_file = tmp_path / "events.ndjson"
    assert events_file.exists()
    assert events_file.stat().st_size > 0
    lines = events_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 1
    event = json.loads(lines[0])
    assert event["schema_version"] == "1.2.0"
    assert event["vendor"] in ("Microsoft (Windows)", "Host System", "Microsoft")
```

- [ ] **Step 2: Run test to verify behavior**

Run: `py -m pytest tests/test_live_monitor_pipeline.py -v`

- [ ] **Step 3: Implement periodic session flushing in `LiveSystemMonitor`**

In `src/ulpf/collectors/live_monitor.py`:
- In `_dispatch_event`: after `process_event(...)`, keep track of dispatched event count and call `self._session.flush()` every 5 events or on loop tick so `events.ndjson` is persisted without delay.
- In `stop()`: call `self._session.flush()` and `self._session.close()` to ensure all buffered events are written to disk.

- [ ] **Step 4: Run test to verify it passes**

Run: `py -m pytest tests/test_live_monitor_pipeline.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/ulpf/collectors/live_monitor.py tests/test_live_monitor_pipeline.py
git commit -m "feat(collector): add automated pipeline session flushing for live host monitor"
```

---

### Task 3: Dashboard Lifespan Auto-Start of Live Host Monitor

**Files:**
- Modify: `src/ulpf_dashboard/app.py:30-45`
- Modify: `src/ulpf_dashboard/server.py:220-250`
- Test: `tests/test_dashboard_live_startup.py`

**Interfaces:**
- Consumes: `create_app(output_dir=..., live_monitor=True)`
- Produces: Background host monitoring active on application startup, emitting live host telemetry directly into `events.ndjson`.

- [ ] **Step 1: Write test for dashboard lifespan starting live monitor**

```python
# tests/test_dashboard_live_startup.py
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from ulpf_dashboard.app import create_app

def test_dashboard_starts_live_monitor_in_lifespan(tmp_path: Path):
    app = create_app(output_dir=tmp_path, live_monitor=True)
    with TestClient(app) as client:
        res = client.get("/api/live-monitor/status")
        assert res.status_code == 200
        data = res.json()
        assert data["running"] is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `py -m pytest tests/test_dashboard_live_startup.py -v`
Expected: FAIL (or live_monitor not running by default)

- [ ] **Step 3: Modify `create_app` in `src/ulpf_dashboard/app.py`**

- Accept `enable_live_monitor: bool = True` in `create_app`.
- In `_lifespan`:
  ```python
  if app.state.enable_live_monitor:
      from ulpf.collectors.live_monitor import LiveSystemMonitor
      state.live_monitor = LiveSystemMonitor(
          output_dir=state.output_dir,
          interval_ms=500,
          write_to_main_pipeline=True
      )
      state.live_monitor.start()
  ```
- In shutdown:
  ```python
  if state.live_monitor is not None and state.live_monitor.is_running():
      state.live_monitor.stop()
  ```

- [ ] **Step 4: Update `server.py` to forward CLI option `--no-live-monitor` if desired**

- [ ] **Step 5: Run test to verify it passes**

Run: `py -m pytest tests/test_dashboard_live_startup.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/ulpf_dashboard/app.py src/ulpf_dashboard/server.py tests/test_dashboard_live_startup.py
git commit -m "feat(dashboard): auto-start live host telemetry streaming on startup"
```

---

### Task 4: End-to-End System Verification & Launch

**Files:**
- Execute: `scripts/Launch_ULPF_Dashboard.bat` / `ulpf.cli dashboard`
- Test: Full integration test suite

- [ ] **Step 1: Run the full automated test suite**

Run: `py -m pytest tests/ -v`
Expected: All tests pass

- [ ] **Step 2: Clean output directory and launch dashboard**

Run:
`Stop_Dashboard.bat` (or kill any running python dashboard PIDs)
Verify `output/` has no old demo files.
Launch: `py -m ulpf_dashboard.server --port 7000 --output-dir output`

- [ ] **Step 3: Verify real events ingested into Event Grid**

Query: `http://127.0.0.1:7000/api/events?page=1&page_size=10`
Verify:
1. `total > 0`
2. All events have real host metadata (real device hostname, real process names like `python.exe`, real IPs/ports).
3. SSE `/api/stream` actively pushes new events as processes launch or network connections change.

- [ ] **Step 4: Commit any final integration adjustments**

```bash
git add -A
git commit -m "chore: verify real-time host telemetry in event grid"
```
