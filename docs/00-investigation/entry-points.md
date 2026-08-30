# Application Entry Points

This document provides a factual trace of all execution entry points in the ULPF repository, detailing the starting files, entry functions, parameters, and downstream subsystems invoked.

---

## 1. CLI Entry Points

### 1.1 Root CLI (`ulpf` console script)
* **File**: `ulpf/cli.py`
* **Entry Point**: `main()` (`@click.group()`, line 147) and `entry_point()` (line 564)
* **Registered Script**: `pyproject.toml:21` (`ulpf = "ulpf.cli:main"`)
* **Purpose**: Primary command-line interface for the framework supporting subcommands and an interactive console menu if launched without arguments in a TTY.
* **Command Map & Downstream Invocations**:

| Command | Entry Function | Options / Arguments | What It Invokes Next |
|---|---|---|---|
| `ulpf ingest` | `ingest()` (`ulpf/cli.py:159`) | `--input` (`-i`), `--sink` (`-s`), `--output` (`-o`), `--config` (`-c`), `--workers` (`-w`), `--no-enrich`, `--tenant-id` | Instantiates `FileReader` or `StdinReader` (`core.ingestion`), builds `Pipeline` (`core.pipeline`) via `_build_pipeline()`, or spawns `ParallelPipeline` (`core.worker_pool`) when `--workers > 1`. Flushes sinks and closes validator. |
| `ulpf listen` | `listen_cmd()` (`ulpf/cli.py:283`) | `--host`, `--port` (`-p`), `--output` (`-o`), `--sink` (`-s`), `--config` (`-c`), `--no-enrich`, `--tenant-id` | Instantiates `_build_pipeline()`, starts `SyslogNetworkListener` (`collectors.syslog_listener`) on background daemon threads, dispatches incoming UDP/TCP packets to `pipeline.process_event()`. |
| `ulpf analyze` | `analyze()` (`ulpf/cli.py:225`) | `--input` (`-i`), `--output` (`-o`), `--output-dir`, `--emit-features` | Instantiates `AnomalyDetector` (`analytics.anomaly`), reads NDJSON via `analyze_file()`, updates/evaluates rolling baseline (`analytics.baseline`), and optionally extracts 24-dim vectors via `FeatureVectorExtractor` (`analytics.features`). |
| `ulpf lookup` | `lookup()` (`ulpf/cli.py:351`) | `--event-id` (`-e`), `--raw-store` | Instantiates `FileRawStore` (`core.raw_store`), calls `store.get(event_id)`, outputs exact raw text to stdout. |
| `ulpf list-parsers` | `list_parsers()` (`ulpf/cli.py:365`) | None | Calls `list_parser_names()` (`core.registry`) and prints all registered parser names to stdout. |
| `ulpf monitor` | `monitor_cmd()` (`ulpf/cli.py:377`) | `--output` (`-o`), `--interval-ms` (`-i`) | Instantiates `LiveSystemMonitor` (`collectors.live_monitor`), starts background ToolHelp32/iphlpapi polling thread, records process/network socket events. |
| `ulpf dashboard` | `dashboard_cmd()` (`ulpf/cli.py:424`) | `--output-dir` (`-o`), `--port` (`-p`), `--host`, `--open-browser/--no-open-browser` | Bootstraps sample logs if needed, verifies port availability via `_find_available_port()`, starts `create_app()` (`dashboard.app`) via `uvicorn.run()`, opens browser thread. |

---

## 2. Dashboard Server Entry Points

### 2.1 Dashboard App Launcher (`ulpf-dashboard`)
* **File**: `ulpf/dashboard/app.py`
* **Entry Point**: `main()` (line 693)
* **Registered Script**: `pyproject.toml:22` (`ulpf-dashboard = "ulpf.dashboard.app:main"`)
* **Purpose**: Dedicated entry point to run the FastAPI dashboard server directly.
* **Execution Flow**:
  1. Resolves output directory via `_resolve_output_dir()`.
  2. Checks if an instance is already responsive via `_is_ulpf_running()`.
  3. Verifies port availability or falls back via `_find_available_port()`.
  4. Optionally bootstraps sample logs via `_build_pipeline()` if `events.ndjson` is missing.
  5. Launches a daemon thread to open the browser (`webbrowser.open`).
  6. Calls `create_app(output_dir, host, port)` and runs with `uvicorn.run()`.

### 2.2 ASGI Application Factory
* **File**: `ulpf/dashboard/app.py`
* **Entry Point**: `create_app(output_dir, host, port)` (line 159)
* **Purpose**: Constructs the `FastAPI` application instance with CORS middleware, state configuration, routes, and static asset mounts.
* **Subsystems Initialized**:
  - `EventIndexer` (`ulpf/dashboard/indexer.py`): SQLite index manager.
  - `FileRawStore` (`ulpf/core/raw_store.py`): Raw store reader for UUID queries.
  - Static file routes for UI (`/static`, `/`).

---

## 3. Native & GUI Launchers

### 3.1 Windows Packaged Launcher
* **File**: `packaging/windows/launcher.py`
* **Entry Point**: `main()` (line 119)
* **Purpose**: Custom launcher used when packaged with PyInstaller in windowed (`noconsole`) mode on Windows.
* **Execution Flow**:
  - Replaces `sys.stdout` and `sys.stderr` with `SafeStream` (in-memory buffer + log file) to prevent `NoneType` / `isatty()` crashes under `pythonw.exe`.
  - Parses `--port` / `--output-dir` arguments.
  - Resolves output path with permission fallback.
  - Bootstraps sample logs if empty.
  - Negotiates open ports and launches `uvicorn.run(log_config=None)`.

### 3.2 1-Click Batch & Shell Launchers
* **`Launch_ULPF_Dashboard.bat` / `Run_Dashboard.bat`**: Detects `python.exe` / `py.exe` and executes `%PYTHON_EXE% -m ulpf.cli dashboard --port 8000 --output-dir output`.
* **`start_dashboard.sh`**: Unix shell wrapper executing `python3 -m ulpf.cli dashboard "$@"`.
* **`Run_Tests.bat`**: Windows batch wrapper executing `python test_all.py`.

---

## 4. Test Suite Entry Points

### 4.1 Standalone Master Verification Runner
* **File**: `test_all.py`
* **Entry Point**: `main()` (line 111)
* **Execution Flow**:
  1. Checks if dashboard is running at `http://127.0.0.1:8000`; starts background subprocess if offline (`ensure_server_running()`).
  2. Executes HTTP requests against `/api/stats`, `/api/parsers`, `/api/ingest/line`, `/api/events`, `/api/analytics/anomalies`, `/api/export`, `/api/live-monitor/*`.
  3. Runs `pytest ulpf/tests/` as a subprocess.
  4. Runs explicit programmatic checks for Criteria (a) through (h) (raw byte exactness, vendor attribute preservation, OCSF taxonomy, UUIDv5 traceability, dynamic plugin discovery, syslog listener socket, Parquet sink, 24-dim feature vector).

### 4.2 Pytest Test Runner
* **Target Directory**: `ulpf/tests/`
* **Entry Point**: `pytest` invocation
* **Test Modules**: 21 test files (`test_parser_*.py`, `test_detector.py`, `test_e2e.py`, `test_dashboard.py`, `test_criteria_conformance.py`, `test_worker_pool.py`, `test_enrichment_ip.py`, `test_analytics_anomaly.py`, `test_live_monitor.py`).

---

## 5. Container Entry Points

### 5.1 Dockerfile
* **File**: `docker/Dockerfile`
* **Entrypoint**: `ENTRYPOINT ["ulpf"]` (line 49)
* **Default Command**: `CMD ["ingest", "--input", "/app/sample_logs", "--output", "/app/output"]` (line 50)

### 5.2 Docker Compose Services
* **File**: `docker/docker-compose.yml`
* **Service `ulpf`**: Runs `ulpf ingest --input /app/sample_logs --output /app/output --log-level INFO` with `network_mode: none`.
* **Service `dashboard`**: Runs `ulpf-dashboard --output-dir /app/output --host 0.0.0.0 --port 8000` with port mapping `8000:8000`.
