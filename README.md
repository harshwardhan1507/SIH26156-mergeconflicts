# ULPF — Universal Log Pre-processing Framework

[![tests](https://img.shields.io/badge/tests-124%20passed-10b981?logo=pytest&logoColor=white)](https://github.com/NotUrNio/ULPF)
[![python](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![docker](https://img.shields.io/badge/docker-air--gapped%20ready-0f766e?logo=docker&logoColor=white)](docker/Dockerfile)

Takes raw logs from firewalls, IDS/IPS, VPN gateways, cloud audit logs, operating systems, and proxies — any vendor, any format — and turns them into one consistent, lossless JSON schema for SIEM, data lakes, and security analytics. Supports **11 formats out of the box** (Syslog RFC 3164/5424, CEF, LEEF 1.0/2.0, Windows/Generic XML, Cisco ASA, Palo Alto CSV, AWS CloudTrail, Azure Monitor, GCP Audit, generic JSON), with a self-registering plugin system built to add more without touching a line of existing code.

Every raw event is kept, untouched, on disk and linked back to its normalized form by UUID — so nothing is ever lost for forensic or compliance review. Features offline IP & threat intelligence enrichment, a statistical anomaly detection engine, multi-process parallel scaling, real Kafka streaming sink, and a high-performance web dashboard.

---

## Why ULPF

- **Zero information loss** — the exact original log line is always retrievable by the event's UUID, hashed with SHA-256 for cryptographic forensic integrity.
- **11 Out-of-the-box log parsers** — Syslog RFC 5424/3164, CEF (ArcSight), LEEF 1.0/2.0 (IBM QRadar), Windows Event Log / Generic XML, Cisco ASA, Palo Alto Networks CSV, AWS CloudTrail, Azure Monitor, GCP Cloud Audit, and JSON Passthrough.
- **True plug-and-play parsers** — drop a new parser file into `parsers/` and it self-registers via `pkgutil` dynamic discovery. Zero edits to core pipeline code.
- **Offline IP & threat enrichment** — pure Python, air-gap safe classification for RFC 1918 private ranges, loopback, link-local, cloud provider ASN recognition (AWS, Azure, GCP, Cloudflare, Akamai, Fastly), and embedded threat intel CIDRs.
- **Statistical anomaly detection engine** — pure Python Z-score deviation (>3σ), IQR byte-volume outlier detection, frequency burst detection (>3× baseline rate), rare category detection (<1%), and authentication failure chain tracking.
- **Horizontal multi-process scaling** — `--workers N` worker pool (`multiprocessing.Pool`) for high-throughput enterprise scale.
- **Production & streaming sinks** — analytics-ready NDJSON File Sink and production `KafkaProducerSink` with automatic local fallback.
- **REST API ingestion & analytics** — `POST /api/ingest/line`, `POST /api/ingest/batch`, `POST /api/ingest/stream`, and `GET /api/analytics/anomalies`.
- **Built-in operations dashboard** — FastAPI backend with SQLite indexer, SSE live streaming, dark/light themes, default/professional views, and forensic Traceability Split Inspector.
- **Air-gapped by design** — zero external runtime calls, no CDN dependencies, local offline wheels install.
- **124 tests, all green** — unit, parser-level, anomaly engine, worker pool, REST API, and end-to-end integration tests.

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

- Python 3.11+
- pip 23+
- Dependencies: `pyyaml`, `jsonschema`, `click`, `python-dateutil`, `pydantic`, `fastapi`, `uvicorn`
- Optional: `kafka-python` (for live Kafka streaming)

---

## Install

```bash
git clone https://github.com/NotUrNio/ULPF.git
cd ULPF
pip install -e .[dev]
```

Verify installed parsers:

```bash
ulpf list-parsers
```

### Offline install (air-gapped environment)

```bash
# On an internet-connected machine:
pip download -r requirements.txt -d ./wheelhouse
pip wheel . --no-deps -w ./wheelhouse

# Copy wheelhouse/ to the air-gapped machine, then:
pip install --no-index --find-links ./wheelhouse -r requirements.txt
pip install --no-index --find-links ./wheelhouse ulpf
```

---

## Usage

### Ingest Logs

```bash
# Ingest all sample logs into NDJSON + Raw Store
ulpf ingest --input ulpf/sample_logs/ --output output/

# Ingest single file
ulpf ingest --input ulpf/sample_logs/cisco_asa.log --output output/

# Ingest from stdin (pipe)
cat /var/log/syslog | ulpf ingest --input - --output output/

# Ingest with 4 parallel worker processes
ulpf ingest --input /var/log/sources/ --output output/ --workers 4

# Ingest directly to Kafka topic (with auto local fallback)
ulpf ingest --input ulpf/sample_logs/ --output output/ --sink kafka-real
```

### Statistical Anomaly Analysis

```bash
# Run statistical anomaly detection over normalized events
ulpf analyze --input output/events.ndjson --output output/anomalies.ndjson
```

### Forensic Raw Store Lookup

```bash
# Retrieve original raw payload and verify SHA-256 hash by event UUID
ulpf lookup --event-id d0f0b096-9b96-43ff-ac78-e4bce3caa108
```

### Launch Web Dashboard

```bash
ulpf dashboard --port 8000 --output-dir output/
# Navigate to http://127.0.0.1:8000
```

---

## REST API Ingestion & Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/ingest/line` | Ingest single raw line: `{"line": "..."}` |
| `POST` | `/api/ingest/batch` | Ingest array of lines: `{"lines": [...]}` |
| `POST` | `/api/ingest/stream` | Stream chunked NDJSON body |
| `GET` | `/api/events` | Paginated, sorted, filtered UES events |
| `GET` | `/api/events/{event_id}` | Event detail + untouched raw payload from RawStore |
| `GET` | `/api/stats` | Aggregate metrics (totals, categories, vendors, severities) |
| `GET` | `/api/parsers` | Parser plugin registry health and event counts |
| `GET` | `/api/dead-letter` | Quarantine queue with validation failure reasons |
| `GET` | `/api/analytics/anomalies`| Top anomalous events with scores and reasoning |
| `GET` | `/api/export` | Stream CSV or NDJSON data dump |
| `GET` | `/api/stream` | Server-Sent Events (SSE) real-time event feed |

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
# Run Master System Verification (Tests VPN, Cloud, MySQL, Windows, Live Host, SHA-256)
python test_all.py

# Run all 124 unit and integration tests via Pytest
pytest ulpf/tests/ -v

# Run with test coverage
pytest ulpf/tests/ -v --cov=ulpf --cov-report=term-missing
```

---

## Docker Deployment

```bash
# Build air-gapped image
docker compose -f docker/docker-compose.yml build

# Run pipeline + dashboard
docker compose -f docker/docker-compose.yml up
```

---

## License

[MIT](LICENSE) © 2026 NotUrNio
