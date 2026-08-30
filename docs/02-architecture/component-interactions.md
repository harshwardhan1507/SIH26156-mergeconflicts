# Component Interactions and Interfaces

This document defines the **component interaction matrix**, invocation contracts, interface signatures, and coupling relationships across all subsystems in the Universal Log Parsing Framework (ULPF).

---

## 1. Comprehensive Component Interaction Matrix

| Component | Calls | Called By | Input | Output | Architectural Responsibility |
|---|---|---|---|---|---|
| **`FileReader`** (`ulpf/core/ingestion.py`) | OS Filesystem (`open`, `glob`) | `Pipeline.run()`, `ParallelPipeline.run()`, `ulpf.cli:ingest()` | `path: Path`, `recursive: bool`, `extensions: tuple` | `Iterator[RawEvent]` | Streams log files from disk preserving binary bytes via `surrogateescape`. |
| **`StdinReader`** (`ulpf/core/ingestion.py`) | `sys.stdin.buffer` | `Pipeline.run()`, `ulpf.cli:ingest()` | `sys.stdin` stream | `Iterator[RawEvent]` | Streams newline-delimited events from standard input. |
| **`SyslogNetworkListener`** (`ulpf/collectors/syslog_listener.py`) | `socket` API, `on_event` callback | `ulpf.cli:listen_cmd()` | UDP datagrams / TCP socket streams | Invokes `on_event(line, source_tag)` | Listens on UDP/TCP ports (e.g. 1514) on background daemon threads. |
| **`LiveSystemMonitor`** (`ulpf/collectors/live_monitor.py`) | `ctypes` (Win32 ToolHelp32/iphlpapi) or `subprocess` (`ps`, `wevtutil`) | `ulpf.cli:monitor_cmd()`, FastAPI live-monitor routes | Polling timer (default 250ms) | Synthetic Windows Security XML strings | Captures real-time local OS process executions and socket connections. |
| **`FileRawStore`** (`ulpf/core/raw_store.py`) | OS Filesystem (`write_bytes`, `read_bytes`) | `Pipeline.process_event()`, `ulpf.cli:lookup()`, FastAPI `/api/events/{id}` | `event_id: str`, `raw_payload: bytes` | SHA-256 digest string (`put`), raw string/bytes (`get`) | High-fidelity, 2-tier sharded disk storage for untouched raw log payloads. Blocks path traversal. |
| **`FormatDetector`** (`ulpf/core/detector.py`) | `get_all_parsers()`, `sources.yaml` | `Pipeline.process_event()` | `raw_line: str`, `source_tag: str` | `format_id: str` (e.g. `'cisco_asa'`, `'unknown'`) | Multi-stage heuristic classification mapping raw log lines to parser names. |
| **`ParserRegistry`** (`ulpf/core/registry.py`) | None | `FormatDetector`, `Pipeline.process_event()`, `ulpf.cli:list_parsers()` | Parser classes via `@register_parser` decorator | Parser instances or class references | Maintains global dictionary of auto-discovered parser plugins. |
| **`BaseParser` Subclasses** (`ulpf/parsers/*.py`) | `dateutil.parser`, `ipaddress`, regex | `Pipeline.process_event()` | `raw_line: str` | `extracted: dict[str, Any]` | Regex/CSV/JSON/XML extraction into structured dictionaries. |
| **`NormalizationEngine`** (`ulpf/core/normalization.py`) | `yaml.safe_load`, `ulpf/schemas/mappings/*.yaml` | `Pipeline.process_event()` | `extracted: dict[str, Any]`, `parser_name: str` | `normalized: dict[str, Any]` | Declarative transformation of extracted fields into UES canonical structure. Preserves unmapped keys in `vendor_attributes`. |
| **`IPEnrichmentPlugin`** (`ulpf/enrichment/ip_enrichment.py`) | `ipaddress` | `Pipeline.process_event()` | `ues_event: dict[str, Any]` | `ues_event: dict[str, Any]` (mutated) | Air-gapped classification of private/public IPs, threat intelligence CIDRs, and cloud providers. |
| **`Validator`** (`ulpf/core/validation.py`) | `Draft7Validator`, `_DeadLetterSink` | `Pipeline.process_event()` | `ues_event: dict[str, Any]` | `bool` (`True` if valid, `False` if quarantined) | Validates normalized events against `ues_schema.json`. Quarantines invalid events to `dead_letter.ndjson`. |
| **`Pipeline`** (`ulpf/core/pipeline.py`) | `RawStore`, `Detector`, `Registry`, `Parser`, `Normalizer`, `Enrichment`, `Validator`, `Sinks` | `FileReader.read()`, `SyslogNetworkListener`, `FastAPI /api/ingest` | `raw_line: str`, `source_tag: str`, `raw_bytes: bytes` | `bool` (success/failure) | Central single-event orchestrator ensuring strict ordering, lossless capture, and at-least-once sink delivery. |
| **`ParallelPipeline`** (`ulpf/core/worker_pool.py`) | `multiprocessing.Pool`, `_worker_process()` | `ulpf.cli:ingest(workers > 1)` | `ReaderBase`, `num_workers: int`, `chunk_size: int` | Aggregated stats dict `{processed, valid, invalid, errors}` | Distributes log batches across CPU worker processes in bounded 500-event chunks. |
| **`NDJSONFileSink`** (`ulpf/sinks/ndjson_file.py`) | File handle (`write`, `flush`) | `Pipeline.process_event()` | `ues_event: dict[str, Any]` | Appended line to `events.ndjson` | Buffered line-delimited JSON sink. |
| **`ParquetSink`** (`ulpf/sinks/parquet_sink.py`) | `pyarrow.Table`, `pyarrow.parquet.write_table` | `Pipeline.process_event()` | `ues_event: dict[str, Any]` | Date/tenant partitioned Parquet files (`events.parquet`) | Columnar data lake sink with automated batching and partitioning. |
| **`KafkaProducerSink`** (`ulpf/sinks/kafka_producer.py`) | `kafka.KafkaProducer` | `Pipeline.process_event()` | `ues_event: dict[str, Any]` | Kafka message on `ulpf.events` topic | Production Kafka producer with idempotence and local fallback. |
| **`CEFEgressSink`** (`ulpf/sinks/cef_egress.py`) | File handle | `Pipeline.process_event()` | `ues_event: dict[str, Any]` | Appended ArcSight CEF:0 string | Egress sink serializing UES events to standard ArcSight syslog format. |
| **`LEEFEgressSink`** (`ulpf/sinks/leef_egress.py`) | File handle | `Pipeline.process_event()` | `ues_event: dict[str, Any]` | Appended IBM QRadar LEEF:2.0 string | Egress sink serializing UES events to standard QRadar syslog format. |
| **`EventIndexer`** (`ulpf/dashboard/indexer.py`) | `sqlite3` (`dashboard_index.db`) | FastAPI endpoints (`/api/events`, `/api/stats`, `/api/export`, `/api/reindex`) | `events.ndjson` stream or search query parameters | Relational database rows, JSON statistics, CSV/NDJSON streams | Incremental SQLite indexing engine with B-Tree indexes for sub-millisecond querying and KPI calculation. |
| **`FastAPI Application`** (`ulpf/dashboard/app.py`) | `EventIndexer`, `FileRawStore`, `Pipeline` | Web Browser, REST clients | HTTP Requests, JSON payloads | JSON HTTP Responses, SSE Streams, Static Assets | Operational dashboard server and REST API gateway. |
| **`AnomalyDetector`** (`ulpf/analytics/anomaly.py`) | `BaselineProfiler` (`ulpf/analytics/baseline.py`) | `ulpf.cli:analyze()`, FastAPI `/api/analytics/anomalies` | `ues_event: dict[str, Any]` | Annotated `ues_event` with `analytics` block | Multi-method statistical anomaly scoring across 6 weighted dimensions. |
| **`FeatureVectorExtractor`** (`ulpf/analytics/features.py`) | `math` | `ulpf.cli:analyze(--emit-features)` | `ues_event: dict[str, Any]` | `list[float]` (24 normalized floats) | Transforms UES event dicts into dense numeric feature vectors for ML models. |

---

## 2. Core Interface Signatures & Contracts

### 2.1 Ingestion Interface
```python
class ReaderBase(ABC):
    @abstractmethod
    def read(self) -> Iterator[RawEvent]: ...

@dataclass
class RawEvent:
    line: str
    source_tag: str
    raw_bytes: bytes = b''
    ingest_timestamp: datetime = field(default_factory=...)
```

### 2.2 Parser Interface
```python
class BaseParser(ABC):
    name: str = "base"
    version: str = "1.0.0"
    log_format: str = "unknown"

    @abstractmethod
    def match(self, raw_line: str) -> bool: ...

    @abstractmethod
    def extract(self, raw_line: str) -> dict[str, Any]: ...
```

### 2.3 Normalization Engine Interface
```python
class NormalizationEngine:
    def __init__(self, mappings_dir: str | Path): ...
    def normalize(self, extracted: dict[str, Any], parser_name: str) -> dict[str, Any]: ...
```

### 2.4 Raw Store Interface
```python
class RawStoreBase(ABC):
    @abstractmethod
    def put(self, event_id: str, raw_payload: str | bytes) -> str: ...
    @abstractmethod
    def get(self, event_id: str) -> str | None: ...
    @abstractmethod
    def get_bytes(self, event_id: str) -> bytes | None: ...
```

### 2.5 Validation Interface
```python
class Validator:
    def __init__(self, schema_path: str | Path, dead_letter_path: str | Path): ...
    def validate(self, event: dict[str, Any]) -> tuple[bool, list[str]]: ...
    def validate_and_route(self, event: dict[str, Any]) -> bool: ...
```

### 2.6 Sink Interface
```python
class SinkBase(ABC):
    @abstractmethod
    def write(self, event: dict[str, Any]) -> None: ...
    @abstractmethod
    def flush(self) -> None: ...
    def close(self) -> None: ...
```

---

## 3. Coupling & Cohesion Analysis

1. **Low Coupling via Registries & Abstractions**:
   - Parsers do not import or depend on the `Pipeline`, `Validator`, or `Sinks`. They only inherit from `BaseParser` and self-register with `@register_parser`.
   - Sinks inherit from `SinkBase` and only consume standard Python dictionaries conformant to UES 1.2.0.
   - Sinks are swappable and composable via list configuration in `Pipeline.__init__(sinks=[...])`.
2. **High Cohesion**:
   - `FileRawStore` handles binary filesystem persistence and path traversal protection; it does not perform parsing or schema validation.
   - `NormalizationEngine` handles schema key mapping and type resolution based on YAML configurations; it does not perform raw string parsing.
   - `EventIndexer` provides relational indexing and query acceleration; the authoritative source of truth remains the `events.ndjson` flat file.
