# ULPF — Universal Log Pre-processing Framework

[![tests](https://img.shields.io/badge/tests-53%20passed-10b981?logo=pytest&logoColor=white)](https://github.com/NotUrNio/ULPF)
[![python](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![docker](https://img.shields.io/badge/docker-air--gapped%20ready-0f766e?logo=docker&logoColor=white)](docker/Dockerfile)

Takes raw logs from firewalls, IDS/IPS, VPN gateways, and proxies — any
vendor, any format — and turns them into one consistent, lossless JSON
schema for SIEM, data lake, and ML pipelines. Supports syslog (RFC 3164 and
5424), CEF, Cisco ASA, Palo Alto CSV, and generic JSON out of the box, with
a plugin system built to add more without touching a line of existing code.

Every raw event is kept, untouched, on disk and linked back to its
normalized form by UUID — so nothing is ever lost for forensic or compliance
review. No external API calls, no telemetry, fully deployable air-gapped.

## Why ULPF

- **Zero information loss** — the exact original log line is always
  retrievable by the event's UUID, hashed with sha256 for integrity checks.
- **True plug-and-play parsers** — drop a new parser file into `parsers/`
  and it self-registers via `pkgutil` discovery. No edits to core pipeline
  code, no edits to any other file, ever.
- **One normalized schema** — every source, regardless of vendor or format,
  lands in the same Universal Event Schema, ready for correlation and ML.
- **Built-in operations dashboard** — browse events, inspect raw/dead-letter
  data, and monitor parser health, with independent Color Themes (Light/Dark)
  and independent View Modes (Default/Professional) for SOC analysts.
- **Air-gapped by design** — zero network calls anywhere in the default code
  path, multi-stage Docker build that installs from local wheels only.
- **53 tests, all green** — parser-level, end-to-end, and dashboard tests.

## Architecture

![ULPF architecture diagram](docs/architecture-diagram.svg)

## Screenshots

| Default View (Overview) | Professional View (SOC Operations) |
|---|---|
| ![Default View](docs/screenshots/dashboard-default.png) | ![Professional View](docs/screenshots/dashboard-professional.png) |

| Traceability Forensic Split Inspector |
|---|
| ![Traceability Inspector](docs/screenshots/dashboard-inspector.png) |

---

## Requirements

- Python 3.11+
- pip 23+
- Dependencies: `pyyaml`, `jsonschema`, `click`, `python-dateutil`, `pydantic`

---

## Install

```bash
git clone <repo-url>
cd ulpf
pip install -e .[dev]
```

Check it works:

```bash
ulpf list-parsers
```

### Offline install (no internet on target machine)

On a machine that has internet:

```bash
pip download -r requirements.txt -d ./wheelhouse
pip wheel . --no-deps -w ./wheelhouse
```

Copy `wheelhouse/` to the target machine, then:

```bash
pip install --no-index --find-links ./wheelhouse -r requirements.txt
pip install --no-index --find-links ./wheelhouse ulpf
```

---

## Running the pipeline

Against the included sample logs:

```bash
ulpf ingest --input ulpf/sample_logs/ --output output/
```

```
Starting ingestion from 'ulpf/sample_logs/' -> 'output/' [ndjson]
Done. Processed=28 Valid=28 Invalid=0 Errors=0
```

Single file:

```bash
ulpf ingest --input ulpf/sample_logs/cisco_asa.log --output output/
```

From stdin:

```bash
cat /var/log/syslog | ulpf ingest --input - --output output/
```

Kafka stub sink (writes Kafka-envelope records to a local file instead of a broker):

```bash
ulpf ingest --input ulpf/sample_logs/ --output output/ --sink kafka
```

Look up the original raw line for any event by its UUID:

```bash
ulpf lookup --event-id d0f0b096-9b96-43ff-ac78-e4bce3caa108
```

---

## Output

```
output/
  events.ndjson         one normalized JSON event per line
  dead_letter.ndjson    events that failed schema validation, with error details
  raw_store/
    <aa>/<bb>/<uuid>.raw  original log line, one file per event
```

---

## CLI

```
ulpf [--log-level debug|info|warning|error] COMMAND

  ingest        read logs, write normalized events
  lookup        print the original raw line for a given event UUID
  list-parsers  show registered parsers

ulpf ingest
  -i, --input   file or directory path, or "-" for stdin
  -s, --sink    ndjson (default) or kafka
  -o, --output  output directory (default: output)
  -c, --config  path to sources.yaml

ulpf lookup
  -e, --event-id   UUID  [required]
  --raw-store      path to raw_store dir (default: output/raw_store)
```

---

## Adding a new parser

Two files. Nothing in `core/` changes, and nothing else in `parsers/` needs
editing either — `ulpf/parsers/__init__.py` auto-discovers every module in
the package via `pkgutil.iter_modules` at import time.

**1. Create `ulpf/parsers/my_vendor.py`:**

```python
from ulpf.parsers.base import BaseParser
from ulpf.core.registry import register_parser

@register_parser
class MyVendorParser(BaseParser):
    name       = 'my_vendor'       # unique key in the registry
    version    = '1.0.0'
    log_format = 'syslog_rfc3164'  # raw_format enum value

    def match(self, raw_line: str) -> bool:
        return 'MY_VENDOR_TAG' in raw_line

    def extract(self, raw_line: str) -> dict:
        # parse what you need, use the helpers below
        ts = self.parse_timestamp('...')
        return {
            '_raw': raw_line,
            '_log_format': self.log_format,
            'timestamp_dt': ts.isoformat() if ts else None,
            'hostname': '...',
            'src_ip': self.validate_ip('...'),
            'src_port': self.safe_port('...'),
            'severity_ues': 5,
        }
        # helpers: parse_timestamp, validate_ip, safe_int, safe_port
```

**2. Create `ulpf/schemas/mappings/my_vendor.yaml`:**

```yaml
ruleset_version: "1.0.0"
source:
  vendor: null
  product: null
  device_hostname: hostname   # key from extract() dict
  source_ip: null
  log_format: syslog_rfc3164
event:
  category: _category_default:network
  action: null
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

YAML value rules:
- plain string = key name from `extract()` output
- `null` = set to `None`
- `_category_default:X` = infer category from message text, fall back to X
- `_outcome_from_action` = map allow/permit -> success, deny/drop -> failure
- `_direction_from_zones` = use `src_zone`/`dst_zone` to set inbound/outbound/internal

**3. Verify:**

```bash
ulpf list-parsers   # my_vendor should appear
ulpf ingest --input path/to/logs/ --output output/
```

**5. Write a test** in `ulpf/tests/test_parser_my_vendor.py`:

```python
from ulpf.parsers.my_vendor import MyVendorParser

def test_match():
    assert MyVendorParser().match('... MY_VENDOR_TAG ...')

def test_extract():
    fields = MyVendorParser().extract('... MY_VENDOR_TAG ...')
    assert fields['hostname'] == 'expected'
    assert 0 <= fields['severity_ues'] <= 10
```

---

## Tests

```bash
pytest ulpf/tests/ -v

# with coverage
pytest ulpf/tests/ -v --cov=ulpf/core --cov=ulpf/parsers --cov=ulpf/sinks --cov-report=term-missing

# one file
pytest ulpf/tests/test_parser_cisco_asa.py -v

# end-to-end only
pytest ulpf/tests/test_e2e.py -v
```

Currently: 51 passed, 0 failed.

The E2E test runs the full pipeline against `sample_logs/`, checks every event
against the JSON Schema, verifies raw-store lookup for each UUID, and confirms
all 6 parsers produced output.

---

## Docker

```bash
# build
docker compose -f docker/docker-compose.yml build

# run
docker compose -f docker/docker-compose.yml up
```

The Dockerfile has two stages. Stage 1 downloads all wheels (including the ulpf
wheel itself). Stage 2 installs from those wheels with `--no-index`, so the
runtime container needs no network. `docker-compose.yml` sets `network_mode: none`.

Output goes to `docker/output/` via volume mount.

Manual:

```bash
docker run --network none -v $(pwd)/output:/app/output ulpf:latest \
    ingest --input /app/sample_logs --output /app/output
```

---

## Layout

```
ulpf/
  pyproject.toml
  requirements.txt
  README.md
  docker/
    Dockerfile
    docker-compose.yml
  ulpf/
    cli.py
    config/sources.yaml       format overrides per source path
    core/
      ingestion.py            FileReader, StdinReader, ReaderBase
      detector.py             FormatDetector
      registry.py             @register_parser, PARSER_REGISTRY
      normalization.py        NormalizationEngine (reads YAML mappings)
      validation.py           Validator + dead-letter writer
      raw_store.py            FileRawStore, RawStoreBase
      pipeline.py             Pipeline (orchestrates all stages)
    parsers/
      base.py                 BaseParser ABC
      syslog_rfc5424.py
      syslog_rfc3164.py
      cef.py
      cisco_asa.py
      paloalto_csv.py
      json_passthrough.py
    sinks/
      base.py                 SinkBase ABC
      ndjson_file.py
      kafka_stub.py
    enrichment/
      base.py                 EnrichmentPlugin ABC
      noop.py
    schemas/
      ues_schema.json         JSON Schema Draft 7
      mappings/               one .yaml per parser
    sample_logs/              28 synthetic log lines across 6 formats
    tests/                    51 tests
```
