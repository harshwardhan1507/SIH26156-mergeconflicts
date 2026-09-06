<p align="center">
  <img src="docs/ulpf-banner.svg" width="560" alt="ULPF Banner" />
</p>

<p align="center">
  <a href="https://github.com/NotUrNio/ULPF"><img src="https://img.shields.io/badge/tests-256%20passed-10b981?logo=pytest&logoColor=white" alt="tests" /></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white" alt="python" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="license" /></a>
  <a href="deploy/docker/Dockerfile"><img src="https://img.shields.io/badge/docker-air--gapped%20ready-0f766e?logo=docker&logoColor=white" alt="docker" /></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/FastAPI-005571?logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/SQLite-003B57?logo=sqlite&logoColor=white" alt="SQLite" />
  <img src="https://img.shields.io/badge/Apache_Kafka-231F20?logo=apachekafka&logoColor=white" alt="Apache Kafka" />
  <img src="https://img.shields.io/badge/Apache_Parquet-56B4E9?logo=apacheparquet&logoColor=white" alt="Apache Parquet" />
  <img src="https://img.shields.io/badge/OCSF-v1.1.0-blue" alt="OCSF" />
  <img src="https://img.shields.io/badge/ECS-v8.11.0-orange" alt="ECS" />
</p>

Takes raw logs from firewalls, IDS/IPS, VPN gateways, cloud audit logs, database systems, operating systems, and proxies — any vendor, any format — and turns them into one consistent, lossless JSON schema (UES v1.2.0) with crosswalk translation to **OCSF v1.1.0** and **ECS v8.11.0**. Supports **11 built-in code parsers** + **dynamic Declarative No-Code Onboarding** (YAML, CSV, JSON, Key-Value, Regex, Delimited) with live sample inference.

Every raw event's authentic bytes are hashed and persisted **before** detection/parsing runs into shard-backed or segmented storage, and linked back to its normalized form by a deterministic UUID — guaranteeing 100% forensic traceability.

---

## Why ULPF

- **Zero information loss & Segmented Raw Storage** — raw bytes are hashed and written to disk *before* detection or parsing. Supports file-sharded mode or high-throughput append-only segmented chunk storage (`raw/YYYY/MM/DD/tenant/segment-000001.bin`) with $O(1)$ random seek. Anything unmapped by a parser's YAML lands in `vendor_attributes`.
- **No-Code Declarative Onboarding & Live Inference** — onboard custom proprietary log formats with zero Python code via YAML configs (`src/ulpf/schemas/declarative_sources/`). Features built-in schema validation and sample string auto-inference (`infer_declarative_mapping`).
- **Event Framing Layer & Max-Bytes Quarantine** — handles stream framing across Line delimiters, Multiline Stacktrace regexes (`^\d{4}-\d{2}-\d{2}`), JSON byte streams, and RFC 5425/6587 Syslog octet counting with oversized event quarantine.
- **OCSF & ECS Crosswalk Standards Translation** — translates UES normalized events into Open Cybersecurity Schema Framework (OCSF v1.1.0, classes 4001, 3001, 2001, 1001, 5001, 6004) and Elastic Common Schema (ECS v8.11.0).
- **11 out-of-the-box log parsers** — Syslog RFC 5424/3164, CEF (ArcSight/Fortinet/Snort/CheckPoint), LEEF 1.0/2.0 (IBM QRadar), Windows Event Log / Generic XML, Cisco ASA, Palo Alto Networks CSV, AWS CloudTrail, Azure Monitor, GCP Cloud Audit, and JSON Passthrough.
- **True plug-and-play parsers** — drop a new parser file into `parsers/` or YAML into `schemas/declarative_sources/` and it self-registers dynamically.
- **Live syslog ingestion & Localhost Monitor** — `ulpf listen` runs a UDP+TCP syslog receiver, and the built-in host monitor captures localhost database (MySQL port 3306, Redis, Postgres) & network connections with zero leakage across Windows, Linux, and macOS.
- **Horizontal multi-process scaling & Benchmarking** — `ulpf ingest --workers N` streams chunked events across a worker pool; `ulpf benchmark` provides rigorous EPS & memory profiling.
- **Multi-sink fan-out** — `--sink ndjson,parquet,cef-egress,leef-egress` writes normalized events to a data lake and legacy SIEM receivers concurrently.
- **Offline IP & threat enrichment** — pure Python, air-gap safe classification for RFC 1918 private ranges, cloud ASN recognition (AWS, Azure, GCP, Cloudflare), and embedded threat intel feeds.
- **Statistical anomaly detection engine** — pure Python Z-score deviation (>3σ), IQR byte-volume outlier detection, frequency burst detection, and 24-dim ML feature vectors (`ulpf analyze --emit-features`).
- **Optional operations dashboard, cleanly separated** — the `ulpf_dashboard` distribution (FastAPI, SQLite indexer, SSE streaming, onboarding wizard, forensic inspector) depends on the framework, never the reverse. `pip install ulpf` gives you a pipeline with no web server in it; `pip install "ulpf[dashboard]"` adds the UI.
- **256 tests, green on Linux/macOS/Windows across Python 3.11-3.13** — unit, declarative onboarding, framing, segmented-store concurrency, crosswalk, egress escaping, architectural boundary, and end-to-end integration tests, plus `ruff` and `mypy` in CI.

---

## Architecture

![ULPF architecture diagram](docs/architecture-diagram.svg)

---

## Screenshots

| Default View (Overview) | Professional View (SOC Operations) |
|---|---|
| ![Default View](docs/screenshots/dashboard-default.png) | ![Professional View](docs/screenshots/dashboard-professional.png) |

| Traceability Forensic Split Inspector | Live Host & Process Monitor |
|---|---|
| ![Traceability Inspector](docs/screenshots/dashboard-inspector.png) | ![Live Host Monitor](docs/screenshots/dashboard-livehost.png) |

---

## Supported Log Formats

| Format / Source | Parser Plugin | Supported Features |
|---|---|---|
| **Syslog RFC 5424** | `syslog_rfc5424.py` | Priority, facility, severity, ID47 structured data |
| **Syslog RFC 3164** | `syslog_rfc3164.py` | BSD syslog, automatic year injection, process PID |
| **CEF (Common Event Format)** | `cef.py` | ArcSight, Fortinet, Snort, CheckPoint, extension key-values |
| **LEEF 1.0 & 2.0** | `leef.py` | IBM QRadar format, custom delimiters (`^`), standard attributes |
| **Windows / Generic XML** | `xml_generic.py` | Windows EventLog 4624/4625/etc., generic XML tag flattening |
| **Cisco ASA** | `cisco_asa.py` | `%ASA-` mnemonic parsing, ACL rule names, 5-tuple extraction |
| **Palo Alto Networks CSV** | `paloalto_csv.py` | PAN-OS 35+ column traffic log mapping, action normalization |
| **AWS CloudTrail** | `aws_cloudtrail.py` | S3, EC2, IAM, STS JSON events, error code outcome mapping |
| **Azure Monitor** | `azure_monitor.py` | Activity logs, resource ID parsing, caller IP & identity claims |
| **GCP Cloud Audit** | `gcp_audit.py` | `protoPayload` audit logs, method names, authorization status |
| **Generic JSON** | `json_passthrough.py` | Arbitrary structured JSON logs with automatic field mapping |

---

## Requirements

- Python 3.11+ (tested on 3.11, 3.12, 3.13)
- pip 23+

**Framework** (`pip install ulpf`) — `pyyaml`, `jsonschema`, `click`, `python-dateutil`, `pydantic`. No web server.

**Optional extras**

| Extra | Install | Adds |
|---|---|---|
| `dashboard` | `pip install "ulpf[dashboard]"` | FastAPI + uvicorn operations dashboard |
| `parquet` | `pip install "ulpf[parquet]"` | Real columnar Parquet output (falls back to partitioned NDJSON) |
| `kafka` | `pip install "ulpf[kafka]"` | Live Kafka streaming (falls back to local NDJSON) |
| `dev` | `pip install -e ".[dev]"` | Test, lint, and type-check tooling |

---

## Install

```bash
git clone https://github.com/NotUrNio/ULPF.git
cd ULPF

# Framework only — no web stack is installed
pip install -e .

# Framework plus the operations dashboard
pip install -e ".[dashboard]"

# Everything, including test and lint tooling
pip install -e ".[dev]"
```

Verify installed parsers:

```bash
ulpf list-parsers
```

### Offline install (air-gapped environment)

```bash
# On an internet-connected machine (requirements.txt is runtime-only —
# dev/test tooling lives in requirements-dev.txt and is not needed in
# an air-gapped deployment):
# Framework only (smallest air-gapped footprint):
pip wheel . -w ./wheelhouse

# Or framework + dashboard:
pip wheel ".[dashboard]" -w ./wheelhouse

# Copy wheelhouse/ to the air-gapped machine, then:
pip install --no-index --find-links ./wheelhouse ulpf
```

---

## Usage

### Ingest Logs

```bash
# Ingest all sample logs into NDJSON + Raw Store
ulpf ingest --input examples/sample_logs/ --output output/

# Ingest single file
ulpf ingest --input examples/sample_logs/cisco_asa.log --output output/

# Ingest from stdin (pipe)
cat /var/log/syslog | ulpf ingest --input - --output output/

# Ingest with 4 parallel worker processes (streams chunks, doesn't buffer the whole input)
ulpf ingest --input /var/log/sources/ --output output/ --workers 4

# Ingest directly to Kafka topic (with auto local fallback)
ulpf ingest --input examples/sample_logs/ --output output/ --sink kafka-real

# Fan out to multiple sinks in one run: NDJSON + Parquet data lake + legacy CEF/LEEF egress
ulpf ingest --input examples/sample_logs/ --output output/ --sink ndjson,parquet,cef-egress,leef-egress

# Tag events from a specific tenant/business unit
ulpf ingest --input /var/log/tenant-a/ --output output/ --tenant-id tenant-a
```

### Live Syslog Ingestion

```bash
# Real UDP+TCP syslog receiver feeding straight into the pipeline
ulpf listen --port 1514 --output output/
```

### Statistical Anomaly Analysis

```bash
# Run statistical anomaly detection over normalized events
ulpf analyze --input output/events.ndjson --output output/anomalies.ndjson

# Also emit a 24-dim ML feature vector per event (output/features.ndjson)
ulpf analyze --input output/events.ndjson --emit-features
```

### Forensic Raw Store Lookup

```bash
# Retrieve original raw payload and verify SHA-256 hash by event UUID
ulpf lookup --event-id d0f0b096-9b96-43ff-ac78-e4bce3caa108
```

### Launch Web Dashboard

```bash
# Default port is 7000:
ulpf dashboard --output-dir output/
# Navigate to http://127.0.0.1:7000

# Put any custom port of your choice (e.g., 3000, 5000, 8000, 8080, 9000):
ulpf dashboard --port 8080 --output-dir output/
# Navigate to http://127.0.0.1:8080

# Or with the dedicated dashboard runner using the -p short flag:
ulpf-dashboard -p 8080 --output-dir output/

# Require an API key on write endpoints (ingest/reindex/live-monitor) and
# restrict CORS to a specific origin, e.g. when exposing beyond localhost:
ULPF_API_KEY=change-me ULPF_CORS_ORIGINS=http://localhost:8080 ulpf dashboard --port 8080
```

#### Custom Port Selection & Configuration

The port is completely up to you! You can put and run the dashboard on any custom port of your choice:
- **CLI Flag (`--port` / `-p`)**: Run with any custom port you want by passing `--port <PORT>` or `-p <PORT>` (for example: `ulpf dashboard --port 8080`, `ulpf-dashboard -p 3000`, or `ulpf dashboard --port 9000`).
- **Web UI Settings Modal**: In the dashboard interface, open the **Settings** modal, enter any custom port, and click save. It automatically persists your custom port preference to `dashboard_config.json` via `/api/settings` across restarts.
- **Automatic Conflict Detection & Fallback**: If the custom port you selected is already occupied by another application or service on your system, ULPF will automatically scan and bind to the next available free port so the dashboard always starts smoothly without crashing.

By default (no `ULPF_API_KEY` set) the dashboard is a trusted single-user
local tool — CORS is still restricted to its own origin (never a wildcard),
but write endpoints are open. Set `ULPF_API_KEY` for any deployment reachable
by more than one person or bound to a non-loopback address.

---

## REST API Ingestion & Endpoints

| Method | Endpoint | Description | Auth |
|---|---|---|---|
| `POST` | `/api/ingest/line` | Ingest single raw line: `{"line": "..."}` | `X-API-Key` if `ULPF_API_KEY` set |
| `POST` | `/api/ingest/batch` | Ingest array of lines: `{"lines": [...]}` | `X-API-Key` if `ULPF_API_KEY` set |
| `POST` | `/api/ingest/stream` | Stream chunked NDJSON body | `X-API-Key` if `ULPF_API_KEY` set |
| `POST` | `/api/reindex` | Rebuild the SQLite index from `events.ndjson` | `X-API-Key` if `ULPF_API_KEY` set |
| `GET` | `/api/events` | Paginated, sorted, filtered UES events | open |
| `GET` | `/api/events/{event_id}` | Event detail + untouched raw payload from RawStore | open |
| `GET` | `/api/stats` | Aggregate metrics (totals, categories, vendors, severities) | open |
| `GET` | `/api/parsers` | Parser plugin registry health and event counts | open |
| `GET` | `/api/dead-letter` | Quarantine queue with validation failure reasons | open |
| `GET` | `/api/analytics/anomalies`| Top anomalous events with scores and reasoning | open |
| `GET` | `/api/export` | Stream CSV or NDJSON data dump | open |
| `GET` | `/api/stream` | Server-Sent Events (SSE) real-time event feed | open |
| `POST` | `/api/live-monitor/start`, `/stop` | Host process/socket telemetry capture | `X-API-Key` if `ULPF_API_KEY` set |

---

## Adding a New Parser Plugin

Creating a new parser requires **zero modifications to core code**:

1. **Create `ulpf/parsers/my_device.py`:**
```python
from ulpf.parsers.base import BaseParser
from ulpf.core.registry import register_parser

@register_parser
class MyDeviceParser(BaseParser):
    name = "my_device"
    version = "1.0.0"
    log_format = "syslog_rfc3164"

    def match(self, raw_line: str) -> bool:
        return "MY_TAG" in raw_line

    def extract(self, raw_line: str) -> dict:
        ts = self.parse_timestamp("...")
        return {
            "_raw": raw_line,
            "_log_format": self.log_format,
            "timestamp_dt": ts.isoformat() if ts else None,
            "src_ip": self.validate_ip("..."),
            "src_port": self.safe_port("..."),
            "severity_ues": 5,
        }
```

2. **Create `ulpf/schemas/mappings/my_device.yaml`:**
```yaml
ruleset_version: "1.0.0"
source:
  vendor: _literal:MyVendor
  product: _literal:MyProduct
  device_hostname: hostname
  source_ip: null
  log_format: syslog_rfc3164
event:
  category: _category_default:network
  action: action
  outcome: _outcome_from_action
  severity_numeric: severity_ues
  severity_original: null
  event_type_vendor_specific: null
network:
  src_ip: src_ip
  src_port: src_port
  dst_ip: null
  dst_port: null
  protocol: null
  bytes_in: null
  bytes_out: null
  direction: null
  interface: null
identity:
  username: null
  user_domain: null
rule:
  rule_id: null
  rule_name: null
  policy_action: null
```

3. **Verify:**
```bash
ulpf list-parsers  # my_device appears automatically
```

---

## Tests

```bash
# Full suite (unit, integration, dashboard, architectural boundaries)
pytest

# One layer at a time
pytest tests/unit
pytest tests/integration
pytest tests/dashboard

# With coverage
pytest --cov --cov-report=term-missing

# Lint and type-check, as CI runs them
ruff check src tests
mypy

# Operator smoke test against a running deployment (not part of the suite)
python tests/system_verification.py
```

---

## Docker Deployment

```bash
# Batch pipeline, fully air-gapped (network_mode: none)
docker compose -f deploy/docker/docker-compose.yml up ulpf

# Dashboard. ULPF_API_KEY is required — the write endpoints are
# unauthenticated without it.
ULPF_API_KEY="$(openssl rand -hex 24)" \
  docker compose -f deploy/docker/docker-compose.yml up dashboard
```

---

## License

[MIT](LICENSE) © 2026 ULPF Project
