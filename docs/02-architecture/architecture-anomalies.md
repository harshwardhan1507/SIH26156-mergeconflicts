# Architectural Anomalies

This document records **factual architectural anomalies, disconnects, fallback behaviors, and discrepancies** discovered during the Phase 1 runtime architecture reconstruction. In accordance with Phase 1 instructions, no architectural redesigns or code modifications are proposed in this document.

---

## 1. Pipeline Disconnects & Unconnected Paths

### 1.1 Live System Monitor Ring-Buffer Isolation
* **Location**: `ulpf/collectors/live_monitor.py:88-89`, `ulpf/dashboard/app.py:169`
* **Observation**: `LiveSystemMonitor` defaults to `write_to_main_pipeline = False`. Captured process execution and network socket events are appended exclusively to an in-memory `deque(maxlen=250)` (`self.event_history`). Unless `pipeline_callback` is explicitly passed and configured, live host events bypass the `Pipeline`, `FileRawStore`, `NormalizationEngine`, `events.ndjson`, and `dashboard_index.db`.
* **Impact**: Events viewed in the Live Monitor UI tab do not appear in the main historical events table or statistics cards unless a dual-write bridge is explicitly triggered.

### 1.2 Analytics Pipeline Asynchronous Separation
* **Location**: `ulpf/core/pipeline.py:91-245`, `ulpf/analytics/anomaly.py:43-67`
* **Observation**: `AnomalyDetector` is not invoked inline during `Pipeline.process_event()`. Anomaly scoring and baseline updates occur as a separate batch process via `ulpf analyze` or on-demand via the `/api/analytics/anomalies` REST endpoint.
* **Impact**: Events stored in `events.ndjson` during ingestion initially have `analytics: null` (or omitted) until an external analysis pass executes.

---

## 2. Fallback Behaviors & Graceful Degradation

### 2.1 Kafka Sink Local File Fallback
* **Location**: `ulpf/sinks/kafka_producer.py:69-104`
* **Observation**: If the `kafka-python` library is not installed, or if the Kafka broker is unreachable during startup, `KafkaProducerSink` automatically redirects all writes to a local append-only file (`output/kafka_events.ndjson`).
* **Impact**: The sink succeeds without throwing an exception, but events reside locally on disk rather than on a remote message queue.

### 2.2 Parquet Columnar NDJSON Fallback
* **Location**: `ulpf/sinks/parquet_sink.py:114-129`
* **Observation**: If `pyarrow` is not installed (e.g. in minimal air-gap environments), `ParquetSink` partitions events into date/tenant directory structures (`dt=YYYY-MM-DD/tenant_id=<tenant>/`) but writes them as newline-delimited JSON (`events_columnar.jsonl`) instead of binary Snappy-compressed `.parquet` files.
* **Impact**: Partitioning is preserved, but files are non-binary and lack Apache Parquet metadata.

### 2.3 Format Detection Key-Value Fallback
* **Location**: `ulpf/core/detector.py:133-134`
* **Observation**: When all explicit regex, JSON, and dynamic parser checks fail, `FormatDetector` checks for `\b\w+=\S+`. If matched, it returns format ID `'kv'`.
* **Impact**: There is currently no registered parser with `name = "kv"` in the repository (unless a generic key-value plugin is added), so this format ID defaults to the dead-letter queue with `error: "No parser matched format"`.

---

## 3. Duplicated Processing & Interface Idiosyncrasies

### 3.1 Dual Kafka Sinks in CLI Options
* **Location**: `ulpf/cli.py:73-82` (`_make_sink`)
* **Observation**: The CLI supports two distinct sink names for Kafka:
  - `--sink kafka`: Instantiates `KafkaStubSink` (which always writes to `output/kafka_events.ndjson`).
  - `--sink kafka-real`: Instantiates `KafkaProducerSink` (which connects to `localhost:9092` with fallback to `output/kafka_events.ndjson`).
* **Impact**: Redundant sink abstractions for Kafka simulation versus live connection.

### 3.2 Dual Syslog Parsers (RFC 3164 vs RFC 5424 vs Embedded Cisco ASA)
* **Location**: `ulpf/parsers/syslog_rfc3164.py`, `ulpf/parsers/syslog_rfc5424.py`, `ulpf/parsers/cisco_asa.py`
* **Observation**: Cisco ASA logs frequently arrive wrapped inside standard RFC 3164 or RFC 5424 syslog headers. To prevent generic syslog parsers from consuming the line before Cisco ASA field extraction occurs, `FormatDetector` explicitly prioritizes `%ASA-` regex checks before standard syslog regexes.
* **Impact**: Parsing correctness depends strictly on the ordering of heuristic checks in `FormatDetector.detect()`.

### 3.3 IP Enrichment Severity Preservation Constraint
* **Location**: `ulpf/enrichment/ip_enrichment.py:199-204`
* **Observation**: `IPEnrichmentPlugin` matches public IPs against threat intelligence CIDR blocks and flags `threat_ip_detected = True`, but deliberately leaves `event.severity_numeric` unmodified (e.g. at default 5.0).
* **Impact**: High-threat IP detections do not elevate the numeric severity score in the core UES record; severity boosting only occurs if `AnomalyDetector` processes the event later.
