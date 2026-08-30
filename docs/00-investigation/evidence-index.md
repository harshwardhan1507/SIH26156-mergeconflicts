# Master Evidence Index

This ledger records all foundational claims about the ULPF repository, the specific code/configuration evidence supporting them, and their verified ground truth status.

## Evidence Hierarchy
1. **Level 1**: Concrete source code implementation
2. **Level 2**: Test suite verification & execution
3. **Level 3**: Configuration & schema files
4. **Level 4**: Build & container configuration
5. **Level 5**: Documentation / README (Claim only)
6. **Level 6**: Filename / directory naming (Indicator only)

---

## Evidence Ledger

| ID | Claim | Exact File Reference | Symbol / Line | Evidence Level | Status | Notes / Nuance |
|---|---|---|---|---|---|---|
| **E-001** | Python 3.11+ is the mandatory runtime version | `pyproject.toml` | line 9 (`requires-python = ">=3.11"`) | Level 3 (Config) | **CONFIRMED** | Uses modern type union syntax (`X \| Y`), dataclass enhancements, and datetime features. |
| **E-002** | 11 log format parsers are implemented and self-registering | `ulpf/parsers/__init__.py`, `ulpf/core/registry.py` | `__init__.py:18-22`, `registry.py:19-23` | Level 1 (Code) | **CONFIRMED** | `pkgutil.iter_modules()` imports all modules in `ulpf/parsers/` dynamically; each parser is decorated with `@register_parser`. |
| **E-003** | Exact raw bytes are persisted before format detection or parsing | `ulpf/core/pipeline.py`, `ulpf/core/raw_store.py` | `pipeline.py:111-120`, `raw_store.py:65-74` | Level 1 (Code) | **CONFIRMED** | `raw_bytes` are stored in `FileRawStore` at step 3 of `process_event()`, prior to format classification. |
| **E-004** | SHA-256 hash is computed over authentic raw bytes | `ulpf/core/pipeline.py`, `ulpf/core/raw_store.py` | `pipeline.py:113`, `raw_store.py:70` | Level 1 (Code) | **CONFIRMED** | Uses `hashlib.sha256(raw_bytes).hexdigest()` over exact bytes preserved with `surrogateescape`. |
| **E-005** | Deterministic UUIDv5 event IDs enable idempotent reprocessing | `ulpf/core/pipeline.py` | `pipeline.py:116` | Level 1 (Code) | **CONFIRMED** | `uuid.uuid5(uuid.NAMESPACE_URL, f"ulpf:{tenant_id}:{source_tag}:{raw_hash}")` produces identical UUID for identical tenant, source, and payload. |
| **E-006** | Raw store implements path-traversal protection | `ulpf/core/raw_store.py` | `raw_store.py:46-56` | Level 1 (Code) | **CONFIRMED** | Rejects non-UUID `event_id` strings (raising `InvalidEventIdError`) before filesystem interpolation. |
| **E-007** | Unmapped vendor attributes are preserved in normalized events | `ulpf/core/normalization.py` | `normalization.py:323-326` | Level 1 (Code) | **PARTIALLY CONFIRMED** | Top-level unmapped keys in extracted dict are placed into `vendor_attributes`. Deeply nested non-extracted trees remain in `raw_payload`. |
| **E-008** | Real UDP+TCP network Syslog listener is implemented | `ulpf/collectors/syslog_listener.py` | `syslog_listener.py:44-64` | Level 1 (Code) | **CONFIRMED** | Sockets are bound to `host:port` on daemon threads; incoming lines dispatch to pipeline. |
| **E-009** | Horizontal multi-process scaling streams bounded chunks | `ulpf/core/worker_pool.py` | `worker_pool.py:102-179` | Level 1 (Code) | **CONFIRMED** | `ParallelPipeline` batches into chunks of 500 events and dispatches across `multiprocessing.Pool` using picklable `functools.partial` factory. |
| **E-010** | Multi-sink fan-out distributes single normalized event to multiple outputs | `ulpf/cli.py`, `ulpf/core/pipeline.py` | `cli.py:120-131`, `pipeline.py:223-241` | Level 1 (Code) | **CONFIRMED** | `--sink ndjson,parquet,cef-egress,leef-egress` writes the event sequentially to all instantiated sinks. |
| **E-011** | Columnar Parquet data lake sink with automatic fallback | `ulpf/sinks/parquet_sink.py` | `parquet_sink.py:20-25, 114-129` | Level 1 (Code) | **CONFIRMED** | Uses `pyarrow` if available to write Snappy-compressed Parquet partitioned by date and tenant; falls back to partitioned NDJSON when `pyarrow` is missing. |
| **E-012** | Production Kafka sink with automatic local fallback | `ulpf/sinks/kafka_producer.py` | `kafka_producer.py:32-40, 99-104` | Level 1 (Code) | **CONFIRMED** | Connects via `kafka-python` when available; falls back to appending to local `kafka_events.ndjson` if library or cluster is unavailable. |
| **E-013** | Reverse egress serializers for ArcSight CEF and IBM QRadar LEEF | `ulpf/sinks/cef_egress.py`, `ulpf/sinks/leef_egress.py` | `cef_egress.py:23-54`, `leef_egress.py:22-50` | Level 1 (Code) | **CONFIRMED** | Formats structured UES events back into standard CEF:0 and LEEF:2.0 string representations. |
| **E-014** | Offline IP and Threat Intelligence classification (zero external network calls) | `ulpf/enrichment/ip_enrichment.py` | `ip_enrichment.py:26-104` | Level 1 (Code) | **CONFIRMED** | Uses embedded static Python CIDR tables for RFC 1918, Cloud provider ASNs, and threat CIDRs via `ipaddress` module. |
| **E-015** | Statistical anomaly detection engine (Z-score, IQR, burst rate, rare category, auth chains) | `ulpf/analytics/anomaly.py`, `ulpf/analytics/baseline.py` | `anomaly.py:43-218`, `baseline.py:27-218` | Level 1 (Code) | **CONFIRMED** | Pure Python math (Welford algorithm) computing rolling baseline stats, Z-score deviation, byte IQR outliers, frequency burst rate, rare categories, and auth failure chains. |
| **E-016** | 24-dimensional normalized ML feature vector extraction | `ulpf/analytics/features.py` | `features.py:15-104` | Level 1 (Code) | **CONFIRMED** | Extracts 24 numeric floats in `[-1.0, 1.0]` spanning cyclical time, severity, volume, port classification, outcome, threat/cloud flags, and category one-hots. |
| **E-017** | Sub-second Live OS and Process/Network socket collector | `ulpf/collectors/live_monitor.py` | `live_monitor.py:34-74, 136-230` | Level 1 (Code) | **CONFIRMED** | Direct Win32 C bindings (`CreateToolhelp32Snapshot`, `iphlpapi.GetExtendedTcpTable`) with isolated in-memory buffer. |
| **E-018** | Disposable SQLite indexer with full-text search and aggregation | `ulpf/dashboard/indexer.py` | `indexer.py:25-66, 230-366` | Level 1 (Code) | **CONFIRMED** | SQLite index (`dashboard_index.db`) synchronizes incrementally from `events.ndjson` with 8 B-Tree indexes. |
| **E-019** | REST API with Server-Sent Events (SSE) and restricted CORS | `ulpf/dashboard/app.py` | `app.py:34-63, 178-193, 525-559` | Level 1 (Code) | **CONFIRMED** | FastAPI backend with restricted CORS origins, optional `X-API-Key` gating, and `/api/stream` SSE generator. |
| **E-020** | Air-gapped Docker multi-stage build and isolated container mode | `docker/Dockerfile`, `docker/docker-compose.yml` | `Dockerfile:31-35`, `docker-compose.yml:9` | Level 4 (Container) | **CONFIRMED** | Runtime image installs only from local wheels; pipeline service runs with `network_mode: none`. |
| **E-021** | Billion-events/day throughput capability | `docs/ARCHITECTURE.md` | `ARCHITECTURE.md:84` | Level 5 (Docs) | **UNKNOWN / LIMITATION** | Not supported. Single-event JSON schema validation and per-event raw file writes are explicitly documented as architectural limitations for ultra-high volumes. |
| **E-022** | Full OCSF specification compliance | `ulpf/core/normalization.py`, `docs/ARCHITECTURE.md` | `normalization.py:102-130`, `ARCHITECTURE.md:85` | Level 1 (Code) | **PARTIALLY CONFIRMED** | Code provides a crosswalk mapping categories to OCSF Class and Activity (`class_name`, `class_uid`, `activity_name`, `activity_id`), not full schema conformance. |
