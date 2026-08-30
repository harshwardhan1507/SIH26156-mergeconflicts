# Important Components and Symbols

This document catalogs the core classes, functions, schemas, and services across the ULPF framework with exact file references and observed responsibilities from code.

---

## 1. Core Pipeline and Ingestion

### `RawEvent` (`ulpf/core/ingestion.py:21-36`)
* **Type**: `@dataclass`
* **Fields**: `line: str`, `source_tag: str`, `raw_bytes: bytes`, `ingest_timestamp: datetime`
* **Observed Responsibility**: Immutable unit of raw ingestion. In `__post_init__`, ensures binary bytes (`raw_bytes`) and string representation (`line`) are synchronized using `errors='surrogateescape'` to prevent lossy character replacement.

### `ReaderBase`, `FileReader`, `StdinReader` (`ulpf/core/ingestion.py:38-110`)
* **Type**: Abstract base class and concrete implementations
* **Observed Responsibility**:
  - `FileReader`: Reads files in binary mode (`'rb'`), strips trailing `\r\n`, decodes with `surrogateescape`, and yields `RawEvent` instances. Handles single files or directories recursively.
  - `StdinReader`: Streams binary/text from `sys.stdin` line by line without buffer overflow.

### `FormatDetector` (`ulpf/core/detector.py:45-137`)
* **Type**: Class
* **Observed Responsibility**: Classifies raw log lines into format strings (`format_id`) matching registered parsers.
* **Algorithm Hierarchy**:
  1. Manual override lookup from `sources.yaml` based on `source_tag` prefix/equality.
  2. Regex matchers: Cisco ASA (`%ASA-\d-\d+`), CEF (`(?:^|\s)CEF:\d`), LEEF (`(?:^|\s)LEEF:[0-9.]+\|`), RFC 5424 (`^<\d+>1\s`), Generic/Windows XML (`^<\?xml` or `^\s*<[a-zA-Z_]`).
  3. JSON structure inspection: Parses top-level JSON and checks signatures for AWS CloudTrail (`eventSource.endswith('.amazonaws.com')`), GCP Audit (`protoPayload.@type`), Azure Monitor (`operationName` + `resourceId`), or generic JSON.
  4. CSV structure inspection: Checks for PAN-OS 30+ column format with `TRAFFIC` in column 2.
  5. RFC 3164 Syslog matchers (`^<\d+>(?:Jan|Feb...)` or `^<\d+>\d{4}-`).
  6. Dynamic evaluation: Iterates through all registered parsers via `get_all_parsers()` calling `parser.match(raw_line)`.
  7. Key-value fallback (`\b\w+=\S+`) or `'unknown'`.

### `FileRawStore` (`ulpf/core/raw_store.py:34-92`)
* **Type**: Concrete subclass of `RawStoreBase`
* **Observed Responsibility**:
  - Validates `event_id` as a strict UUID using `uuid.UUID()` before path interpolation to prevent path-traversal attacks.
  - Shards storage into two levels of 2-character hex directories (`base_dir / shard[:2] / shard[2:4] / f'{safe_id}.raw'`).
  - `put(event_id, raw_payload)` writes exact raw bytes to disk and returns SHA-256 hex digest.
  - `get(event_id)` and `get_bytes(event_id)` retrieve stored payloads or return `None` if missing.

### `NormalizationEngine` (`ulpf/core/normalization.py:132-338`)
* **Type**: Class
* **Observed Responsibility**: Loads per-parser declarative YAML mapping definitions from `ulpf/schemas/mappings/` and maps extracted dictionary fields into structured UES dictionaries.
* **Transform Functions**:
  - `_infer_category()`: Categorizes events into `network`, `authentication`, `threat`, `system`, `policy`, `api`, `database`, `unknown`.
  - `_resolve_outcome()`: Normalizes action/outcome tokens (`allow`, `permit`, `accept` -> `success`; `deny`, `drop`, `reject`, `reset`, `fail` -> `failure`).
  - `_resolve_direction()`: Resolves `inbound`, `outbound`, `internal`, `unknown` from zone names.
  - `_OCSF_CLASS_MAP` & `_OCSF_ACTIVITY_MAP`: Crosswalks categories and action verbs to OCSF class/activity names and numeric UIDs.
  - **Vendor Attributes Preservation**: Iterates over all keys in the extracted dict; any key not explicitly mapped to a UES field and not starting with `_` is placed into `vendor_attributes` dictionary (lines 323-326).

### `Validator` (`ulpf/core/validation.py:35-90`)
* **Type**: Class
* **Observed Responsibility**:
  - Compiles `ues_schema.json` using `Draft7Validator`.
  - `validate(event)` returns boolean status and list of JSONPath validation error strings.
  - `validate_and_route(event)` writes invalid events directly to `dead_letter.ndjson` and increments invalid counters.
  - Exposes `dead_letter_sink` so pre-validation errors (e.g. extraction failures, sink write errors) are recorded in the same quarantine queue.

### `Pipeline` (`ulpf/core/pipeline.py:31-269`)
* **Type**: Class (Central Orchestrator)
* **Observed Responsibility**:
  - `process_event()` executes the end-to-end single-event workflow:
    1. Computes SHA-256 over authentic `raw_bytes`.
    2. Derives deterministic UUIDv5 `event_id` from `ulpf:{tenant_id}:{source_tag}:{raw_hash}`.
    3. Persists raw bytes in `RawStore` *before* detection or parsing.
    4. Detects format via `FormatDetector`.
    5. Resolves parser from `registry` (or fallback search).
    6. Calls `parser.extract(raw_line)`.
    7. Normalizes via `NormalizationEngine`.
    8. Assembles UES event dictionary (`_build_ues_event`).
    9. Enriches via `EnrichmentPlugin` (if configured).
    10. Validates via `Validator`.
    11. Writes to each sink in `sinks` list with at-least-once error routing to dead-letter.
  - `run(reader)` loops over `reader.read()`, calls `process_event()`, flushes sinks, and returns stats.

### `ParallelPipeline` (`ulpf/core/worker_pool.py:102-179`)
* **Type**: Class
* **Observed Responsibility**: Streams bounded chunks (default 500 events) from `reader` into a `multiprocessing.Pool` using `pool.imap_unordered`. Dispatches to picklable module-level `_worker_process()` bound via `functools.partial`, avoiding complete in-memory buffering.

---

## 2. Parser Plugins and Registry

### `register_parser` & `get_all_parsers` (`ulpf/core/registry.py:19-38`)
* **Observed Responsibility**: Maintains global dictionary `_REGISTRY: dict[str, type[BaseParser]]`. Decorator `@register_parser` registers classes. `ulpf/parsers/__init__.py` uses `pkgutil.iter_modules(__path__)` to auto-import all parser files on startup.

### `BaseParser` (`ulpf/parsers/base.py:32-150`)
* **Type**: Abstract base class
* **Abstract Methods**: `match(raw_line: str) -> bool`, `extract(raw_line: str) -> dict[str, Any]`
* **Helper Methods**:
  - `parse_timestamp()`: Handles Unix epoch integers (seconds, ms, microseconds) and calendar string timestamps via `dateutil`.
  - `validate_ip()`: Validates IPv4/IPv6 addresses via `ipaddress`.
  - `safe_int()`, `safe_float()`, `safe_port()`: Validates and coerces numerical fields.
  - `strip_quotes()`: Cleans quoted string literals.

### Parser Plugin Suite (11 Implementations)
1. `CEFParser` (`ulpf/parsers/cef.py`): Parses standard/syslog-wrapped CEF header pipes (8 fields) and key-value extensions.
2. `LEEFParser` (`ulpf/parsers/leef.py`): Parses LEEF 1.0 and 2.0 headers, custom delimiters (`\t`, `^`), and attribute pairs.
3. `SyslogRFC3164Parser` (`ulpf/parsers/syslog_rfc3164.py`): BSD syslog parser; injects current year for year-less timestamps; extracts priority, facility, severity, hostname, tag, PID.
4. `SyslogRFC5424Parser` (`ulpf/parsers/syslog_rfc5424.py`): Structured syslog parser; extracts structured data blocks `[SDID@... key="val"]`.
5. `CiscoASAParser` (`ulpf/parsers/cisco_asa.py`): Cisco ASA syslog parser; extracts `%ASA-` severity and mnemonic, ACL rules, and connection 5-tuples.
6. `PaloAltoCSVParser` (`ulpf/parsers/paloalto_csv.py`): PAN-OS traffic CSV parser; maps 35+ positional columns.
7. `AWSCloudTrailParser` (`ulpf/parsers/aws_cloudtrail.py`): CloudTrail JSON parser; maps AWS service names, actions, user identities, and error codes.
8. `AzureMonitorParser` (`ulpf/parsers/azure_monitor.py`): Azure Activity / Diagnostic log parser; parses Azure `resourceId` path components and result types.
9. `GCPAuditParser` (`ulpf/parsers/gcp_audit.py`): GCP Audit JSON parser; extracts `protoPayload` method, authorization status, and project IDs.
10. `XMLGenericParser` (`ulpf/parsers/xml_generic.py`): Handles Windows Security EventLog XML (EventIDs 4624, 4625, 4688, 4689, 5156, 1102, etc.) and generic XML tag flattening.
11. `JSONPassthroughParser` (`ulpf/parsers/json_passthrough.py`): Generic single-level JSON flattener for structured JSON log streams.

---

## 3. Real-Time Collectors

### `SyslogNetworkListener` (`ulpf/collectors/syslog_listener.py:18-131`)
* **Type**: Class
* **Observed Responsibility**:
  - Binds concurrent UDP socket (`socket.SOCK_DGRAM`) and TCP socket (`socket.SOCK_STREAM`) on specified port (default 1514).
  - Runs separate background daemon threads (`_udp_worker`, `_tcp_worker`) handling incoming connections and decoding UTF-8 lines with `surrogateescape`.
  - Dispatches lines to `on_event(line, source_tag)` callback.

### `LiveSystemMonitor` (`ulpf/collectors/live_monitor.py:77-563`)
* **Type**: Class
* **Observed Responsibility**:
  - High-frequency background poller (default 250ms).
  - On Windows: Uses Win32 C APIs (`CreateToolhelp32Snapshot`, `Process32First/Next`, `QueryFullProcessImageNameW`) for process tracking, `GetExtendedTcpTable` from `iphlpapi` for active TCP/UDP socket tracking (5-tuples), and `wevtutil` for Windows event log polling.
  - On Unix: Falls back to `ps -eo pid,ppid,comm`.
  - Synthesizes Windows Security XML events (EventID 4688 for process start, 4689 for process exit, 5156 for network connection).
  - Maintains isolated in-memory circular buffer (`event_history: deque(maxlen=250)`).

---

## 4. Analytics and Machine Learning Components

### `RollingStats` (`ulpf/analytics/baseline.py:27-104`)
* **Type**: Class
* **Observed Responsibility**: Implements Welford's online algorithm for computing rolling mean, variance, and standard deviation over a sliding window (`deque(maxlen=1000)`). Computes Z-scores and IQR outlier boundaries.

### `BaselineProfiler` (`ulpf/analytics/baseline.py:105-218`)
* **Type**: Class
* **Observed Responsibility**: Tracks per-source-IP severity baselines, per-source-IP byte volume baselines, global category distributions, and per-IP event timestamps for burst detection. Persists baseline state to `output/analytics_baseline.json`.

### `AnomalyDetector` (`ulpf/analytics/anomaly.py:43-218`)
* **Type**: Class
* **Observed Responsibility**:
  - Scores events against rolling baselines across 6 dimensions:
    1. Severity Z-Score (>3σ = 0.35 weight, 2-3σ = 0.20 weight)
    2. Bytes IQR Outlier (0.25 weight)
    3. Event Burst Detection (>3x baseline rate = 0.30 weight)
    4. Rare Category (<1% historical distribution = 0.15 weight)
    5. Threat Intel IP Match (0.40 weight)
    6. Auth Failure Chain (>=5 consecutive failures = 0.30 weight)
  - Produces `anomaly_score` in [0.0, 1.0], human-readable `anomaly_reasons`, and calculated `risk_score`. Annotates event without mutating existing core blocks.

### `FeatureVectorExtractor` (`ulpf/analytics/features.py:15-104`)
* **Type**: Class
* **Observed Responsibility**: Transforms a UES event dict into a dense 24-dimensional floating-point feature vector normalized to `[-1.0, 1.0]`:
  - 4 temporal cyclical features (`hour_sin`, `hour_cos`, `dow_sin`, `dow_cos`)
  - 2 severity features (`severity_norm`, `severity_inferred`)
  - 2 log-scaled network volume features (`log_bytes_in`, `log_bytes_out`)
  - 3 port category one-hot features (`well_known`, `registered`, `dynamic`)
  - 3 outcome one-hot features (`success`, `failure`, `unknown`)
  - 2 threat/cloud indicator features (`threat_detected`, `cloud_origin`)
  - 8 category one-hot features (`network`, `authentication`, `threat`, `system`, `policy`, `api`, `database`, `unknown`)

---

## 5. Storage and Egress Sinks

### `NDJSONFileSink` (`ulpf/sinks/ndjson_file.py:13-39`)
* **Observed Responsibility**: Writes JSON strings followed by `\n` to a specified file with buffered writes.

### `ParquetSink` (`ulpf/sinks/parquet_sink.py:28-134`)
* **Observed Responsibility**: Flattens nested UES dictionaries into tabular records and writes to date/tenant partitioned directories (`dt=YYYY-MM-DD/tenant_id=<tenant>/events.parquet`). Uses `pyarrow.parquet` with Snappy compression if installed; falls back to partitioned NDJSON (`events_columnar.jsonl`) otherwise.

### `KafkaProducerSink` (`ulpf/sinks/kafka_producer.py:42-155`)
* **Observed Responsibility**: Connects to Apache Kafka cluster using `kafka.KafkaProducer` with idempotence and gzip compression. Serializes records keyed by `event_id`. Falls back to local file `kafka_events.ndjson` if library or cluster is unavailable.

### `CEFEgressSink` (`ulpf/sinks/cef_egress.py:15-64`) & `LEEFEgressSink` (`ulpf/sinks/leef_egress.py:14-60`)
* **Observed Responsibility**: Serializes normalized UES events back into standard ArcSight CEF:0 syslog format or IBM QRadar LEEF:2.0 format for transmission to legacy SIEM receivers.

---

## 6. Dashboard and Indexing

### `EventIndexer` (`ulpf/dashboard/indexer.py:69-594`)
* **Type**: Class
* **Observed Responsibility**:
  - Manages SQLite database `dashboard_index.db` with table `events_index` and 8 B-Tree indexes.
  - `sync_from_ndjson()`: Reads `events.ndjson` incrementally tracking file byte offset in `index_meta` table.
  - `query_events()`: Executes multi-field parameterized SQL queries with pagination, sorting, and full-text search across 13 fields.
  - `get_stats()`: Computes aggregated statistics (total counts, categories, top 3 vendors, severity breakdown, 1h/24h velocities).
  - `export_events()`: Streams query results in CSV or NDJSON format.

### `FastAPI Backend` (`ulpf/dashboard/app.py:159-649`)
* **Observed Responsibility**:
  - Configures REST routes: `/api/events`, `/api/events/{event_id}`, `/api/dead-letter`, `/api/parsers`, `/api/stats`, `/api/export`, `/api/reindex`, `/api/ingest/line`, `/api/ingest/batch`, `/api/ingest/stream`, `/api/analytics/anomalies`, `/api/stream` (SSE), `/api/live-monitor/*`.
  - Enforces origin-restricted CORS via `_default_cors_origins()`.
  - Enforces `X-API-Key` on state-changing endpoints if `ULPF_API_KEY` is set.
