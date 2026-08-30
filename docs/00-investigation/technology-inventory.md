# Technology Inventory

This document establishes the verified technology matrix based strictly on codebase imports, configuration files, and package dependencies.

---

## 1. Programming Languages

| Language | Scope / Usage in Repository | Verified Evidence | Status |
|---|---|---|---|
| **Python** (>=3.11) | Core pipeline, parsers, collectors, analytics, REST backend, CLI, and packaging scripts | `pyproject.toml:9`, all `.py` files | CONFIRMED |
| **JavaScript** (ES6+ Vanilla) | Frontend operations dashboard SPA (DOM manipulation, SSE consumer, Chart rendering, modal inspector) | `ulpf/dashboard/static/app.js` | CONFIRMED |
| **HTML5 / CSS3** | Frontend operations dashboard layouts, styling, themes (dark/light, professional view) | `ulpf/dashboard/static/index.html`, `style.css` | CONFIRMED |
| **Windows Batch (`.bat`)** | Local launcher scripts, test execution wrapper | `Run_Tests.bat`, `Launch_ULPF_Dashboard.bat`, `Run_Dashboard.bat` | CONFIRMED |
| **Bash (`.sh`)** | Packaging and execution shell scripts for Linux / macOS | `packaging/linux/build_deb.sh`, `start_dashboard.sh` | CONFIRMED |
| **PowerShell (`.ps1`)** | Windows packaging scripts | `packaging/windows/build_exe.ps1`, `build_msi.ps1` | CONFIRMED |
| **C / Native APIs (via ctypes)** | Win32 ToolHelp32 process snapshots (`CreateToolhelp32Snapshot`) and IP Helper socket tables (`GetExtendedTcpTable`) | `ulpf/collectors/live_monitor.py:34-74` | CONFIRMED |

---

## 2. Frameworks and Core Libraries

| Category | Component / Library | Stated Version / Requirement | Verified Code Usage | Status |
|---|---|---|---|---|
| **Web Framework** | `FastAPI` | `>=0.110.0` (`pyproject.toml:16`) | REST routes, query params, dependency injection, SSE (`ulpf/dashboard/app.py:22-26`) | CONFIRMED |
| **ASGI Server** | `uvicorn` | `>=0.28.0` (`pyproject.toml:17`) | Dashboard server runner (`ulpf/dashboard/app.py:498, 774`) | CONFIRMED |
| **CLI Framework** | `click` | `>=8.1` (`pyproject.toml:13`) | CLI command groups, options, interactive console menu (`ulpf/cli.py:18, 147-520`) | CONFIRMED |
| **Data Validation** | `pydantic` | `>=2.0` (`pyproject.toml:11`) | API request models `IngestLineRequest`, `IngestBatchRequest` (`ulpf/dashboard/app.py:26, 65-72`) | CONFIRMED |
| **Schema Validation** | `jsonschema` | `>=4.17` (`pyproject.toml:12`) | Draft-7 validator `Draft7Validator` (`ulpf/core/validation.py:15-16`) | CONFIRMED |
| **Configuration Parsing**| `PyYAML` (`yaml`)| `>=6.0` (`pyproject.toml:14`) | Schema mappings and source overrides loader (`ulpf/core/normalization.py:17`, `detector.py:27`) | CONFIRMED |
| **Date / Time Parsing** | `python-dateutil` | `>=2.8` (`pyproject.toml:15`) | Timestamp parsing fallback across parsers (`ulpf/parsers/base.py:25`) | CONFIRMED |

---

## 3. Databases, Caches, and Storage Systems

| Technology | Implementation in Code | Role / Responsibility | Status |
|---|---|---|---|
| **SQLite3** | `sqlite3` (Python standard library) | Disposable search and aggregation index (`dashboard_index.db`) backing dashboard API queries (`ulpf/dashboard/indexer.py:15, 25-66`) | CONFIRMED |
| **File-based Raw Store** | `FileRawStore` (`ulpf/core/raw_store.py:34-92`) | Sharded local filesystem store (`<base_dir>/<aa>/<bb>/<event_id>.raw`) for byte-exact raw payloads | CONFIRMED |
| **Newline-Delimited JSON (NDJSON)** | Direct file I/O (`json.dumps` + `\n`) | Primary persistent event stream (`events.ndjson`) and quarantine queue (`dead_letter.ndjson`) | CONFIRMED |
| **Apache Parquet (Optional)** | `pyarrow.parquet` (`pyarrow>=14.0` optional in `pyproject.toml:29`) | Columnar data lake output partitioned by date and tenant (`ulpf/sinks/parquet_sink.py:20-25`). Falls back to partitioned NDJSON when `pyarrow` is absent. | CONFIRMED |
| **Redis / Memcached** | None found | Not present in codebase. | ABSENT |
| **Elasticsearch / OpenSearch** | None found | Not present in codebase. | ABSENT |

---

## 4. Queues, Streams, and Messaging

| Technology | Implementation in Code | Role / Responsibility | Status |
|---|---|---|---|
| **Apache Kafka (Optional)** | `kafka-python` (`kafka-python>=2.0` optional in `pyproject.toml:32`) | `KafkaProducerSink` (`ulpf/sinks/kafka_producer.py:32-42`). Falls back to local file `kafka_events.ndjson` if library or cluster is unavailable. | CONFIRMED |
| **Server-Sent Events (SSE)** | `StreamingResponse(event_generator(), media_type="text/event-stream")` | Real-time live log feed to browser dashboard (`ulpf/dashboard/app.py:525-559`) | CONFIRMED |
| **Syslog UDP/TCP Socket** | `socket.socket` (`socket.SOCK_DGRAM`, `socket.SOCK_STREAM`) | Live perimeter syslog ingestion server (`ulpf/collectors/syslog_listener.py:44-64`) | CONFIRMED |
| **RabbitMQ / NATS / ZeroMQ** | None found | Not present in codebase. | ABSENT |

---

## 5. Containerization and Infrastructure

| Technology | Configuration File | Implementation Details | Status |
|---|---|---|---|
| **Docker** | `docker/Dockerfile` | Multi-stage build based on `python:3.11-slim`. Stage 1 compiles wheelhouse; Stage 2 installs wheels offline with no network. | CONFIRMED |
| **Docker Compose** | `docker/docker-compose.yml` | Defines `ulpf-pipeline` (runs with `network_mode: none`) and `ulpf-dashboard` (port `8000:8000`). | CONFIRMED |
| **Kubernetes (Helm / K8s manifests)** | None found | No Kubernetes YAML manifests or Helm charts present. | ABSENT |
| **Cloud Infrastructure (Terraform / CloudFormation)** | None found | No infrastructure-as-code files present in repo. | ABSENT |

---

## 6. Development and Testing Tooling

| Tool / Library | Version / Requirement | Location | Status |
|---|---|---|---|
| **pytest** | `>=7.4` | `pyproject.toml:25`, `requirements-dev.txt:4` | CONFIRMED |
| **pytest-cov** | `>=4.0` | `pyproject.toml:25`, `requirements-dev.txt:5` | CONFIRMED |
| **httpx** | `>=0.27.0` | `pyproject.toml:25`, `requirements-dev.txt:6` | CONFIRMED |
| **PyInstaller** | Stated in scripts | `packaging/windows/build_exe.py` | CONFIRMED |
| **WiX Toolset v3** | Stated in `.wxs` and `.ps1` | `packaging/windows/ulpf.wxs`, `build_msi.ps1` | CONFIRMED |
| **hdiutil / pkgbuild** | macOS system binaries | `packaging/macos/build_dmg.py`, `build_pkg.sh` | CONFIRMED |
| **dpkg-deb** | Linux system binary | `packaging/linux/build_deb.sh` | CONFIRMED |
