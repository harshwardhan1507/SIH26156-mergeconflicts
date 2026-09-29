# Design Specification: Real-Time Host Event Streaming to ULPF Event Grid

- **Author**: Antigravity & Engineering Team
- **Date**: 2026-09-29
- **Status**: Approved
- **Scope**: Replaces static demo/sample events on the ULPF dashboard with live, continuous host telemetry (Windows Event Logs, active socket connections, process execution monitoring) feeding directly into the normalized pipeline and SQLite index.

---

## 1. Problem Statement & Motivation

Previously, the ULPF operations dashboard was seeded with synthetic/demo logs from `examples/sample_logs/` (such as sample Cisco ASA, Azure Monitor, and AWS CloudTrail logs) for demonstration and testing purposes. 

To validate and demonstrate the platform under authentic conditions, the dashboard must display genuine, real-time security events captured from the local host system (Windows processes, network socket connections, and Windows System/Application Event Logs), while completely wiping existing demo logs.

---

## 2. Architecture & Data Flow

```
                      +------------------------------------------+
                      |               Host System                |
                      |  - Windows Event Logs (App & System)     |
                      |  - Process Launches / Exits (4688/4689)  |
                      |  - Active Sockets / TCP Conns (5156)     |
                      +--------------------+---------------------+
                                           | (XML / Sub-second Polling)
                                           v
+----------------------------------------------------------------------------------+
| ulpf.collectors.live_monitor.LiveSystemMonitor                                   |
| (write_to_main_pipeline=True, interval_ms=500, auto-flush session)               |
+------------------------------------------+---------------------------------------+
                                           |
                                           v
+----------------------------------------------------------------------------------+
| ULPF Normalization Engine (XMLGenericParser -> UES Schema v1.2.0)                |
| - Generates deterministic UUIDs, timestamps, vendor (Microsoft/Host), category   |
| - Preserves full raw XML/payload in raw_store/                                    |
+------------------------------------------+---------------------------------------+
                                           |
                                           v
                        +------------------+------------------+
                        |                                     |
                        v                                     v
              output/events.ndjson               output/raw_store/
                        |
                        v
        +---------------+---------------+
        |                               |
        v                               v
SQLite Indexer (dashboard_index.db)  FastAPI SSE Stream (/api/stream)
        |                               |
        v                               v
REST API (/api/events, /api/stats)    Browser UI (Virtual Table Event Grid)
```

---

## 3. Detailed Component Changes

### 3.1 Live Host Telemetry Ingestion (`src/ulpf/collectors/live_monitor.py`)
- Configure `LiveSystemMonitor` so `write_to_main_pipeline=True` can be enabled on startup.
- Implement an automated periodic buffer flush (`session.flush()`) inside the monitor dispatch cycle every ~1 second or 10 events, ensuring newly collected events are promptly committed to disk in `output/events.ndjson`.
- Maintain thread-safety across the collector loop and the pipeline session.

### 3.2 Dashboard Lifecycle & Auto-Start (`src/ulpf_dashboard/app.py` & `server.py`)
- Inside `create_app`'s async lifespan context manager:
  - Initialize and start `state.live_monitor = LiveSystemMonitor(output_dir=resolved, interval_ms=500, write_to_main_pipeline=True)` upon server launch.
  - On shutdown, call `state.live_monitor.stop()` to cleanly terminate the background worker thread and flush all pending buffers.
- Provide a clean CLI toggle (`--no-live-monitor`) if an analyst ever desires a passive mode without background telemetry.

### 3.3 Demo Data Wipe & Clean Output Isolation
- Terminate any running stale dashboard processes across ports 7000 and 8000.
- Wipe existing demo data in `output/` (`events.ndjson`, `dead_letter.ndjson`, `dashboard_index.db`, and contents of `raw_store/`).
- Remove any automatic fallback in launchers (`tools/windows/launcher.py`) that seeds demo data when the database is empty.

### 3.4 SSE Stream & Frontend Grid Coordination (`src/ulpf_dashboard/routers/stream.py` & `app.js`)
- The SSE endpoint `/api/stream` detects incremental file appends to `output/events.ndjson` and broadcasts `event_ingested` messages.
- The virtual scroller in `app.js` inserts incoming real events at the top of the Event Grid, updating metrics (Total Events, Velocity, Top Sources) seamlessly.

---

## 4. Error Handling & Guardrails

1. **Privilege & Permission Handling**: On systems where `wevtutil.exe` or raw socket query requires administrative access, any `AccessDenied` exception is caught gracefully; the collector falls back to polling unprivileged sockets and active user-level process listings without interrupting server execution.
2. **Rate Limiting & Memory Safety**: The collector throttles connection notifications using event deduplication so redundant socket polls do not produce duplicate entries or overwhelm SQLite indexing.
3. **Graceful Shutdown**: All file handles and background monitor threads are closed when receiving `SIGINT`, `SIGTERM`, or via `Stop_Dashboard.bat`.

---

## 5. Verification Plan

1. **Clean State Check**: Verify `output/events.ndjson` and `output/dashboard_index.db` are completely purged of demo records.
2. **Collector Execution**: Run the dashboard and verify in logs that `LiveSystemMonitor` starts with `write_to_main_pipeline=True`.
3. **Pipeline Ingestion**: Inspect `output/events.ndjson` to ensure newly captured records reflect real machine hostname, current username, and active Windows processes/connections.
4. **API Verification**: Query `/api/events` and `/api/stats` to verify indexed event count increases as live processes/network events occur.
5. **UI Confirmation**: Open `http://127.0.0.1:7000` in the browser and confirm that the Event Grid dynamically renders real host events with full raw payload traceability.
