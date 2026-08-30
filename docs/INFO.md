# ULPF Documentation Index & Navigation Guide (`INFO.md`)

Welcome to the **Universal Log Pre-processing Framework (ULPF)** technical documentation and repository index.

This document provides a categorized, cross-referenced directory of all architectural specifications, data analyses, engineering investigation reports, and visual diagrams in `/docs`, mapped directly to their corresponding source code modules and configuration files.

---

## 🗺️ Quick Navigation Matrix

| Topic / Area | Documentation File | Primary Source Code Reference | Description |
|---|---|---|---|
| **System Overview & Pipeline** | [`docs/ARCHITECTURE.md`](file:///c:/ULPF/docs/ARCHITECTURE.md) | [`ulpf/core/pipeline.py`](file:///c:/ULPF/ulpf/core/pipeline.py) | High-level pipeline flow, core guarantees, and architecture overview. |
| **Complete System Architecture** | [`docs/02-architecture/current-system-architecture.md`](file:///c:/ULPF/docs/02-architecture/current-system-architecture.md) | [`ulpf/`](file:///c:/ULPF/ulpf) | Full deep dive into all 9 subsystems, invariants, and component structure. |
| **Raw Ingestion & Byte Preservation** | [`docs/03-data-analysis/raw-preservation.md`](file:///c:/ULPF/docs/03-data-analysis/raw-preservation.md) | [`ulpf/core/raw_store.py`](file:///c:/ULPF/ulpf/core/raw_store.py), [`ulpf/core/ingestion.py`](file:///c:/ULPF/ulpf/core/ingestion.py) | Authentic byte storage, surrogate decoding, SHA-256 validation, and raw sharding. |
| **Format Detection & Parser Registry** | [`docs/03-data-analysis/parser-analysis.md`](file:///c:/ULPF/docs/03-data-analysis/parser-analysis.md) | [`ulpf/core/detector.py`](file:///c:/ULPF/ulpf/core/detector.py), [`ulpf/core/registry.py`](file:///c:/ULPF/ulpf/core/registry.py) | Heuristic cascade, dynamic registration, and parsing rules across 11 formats. |
| **Declarative Normalization & UES** | [`docs/03-data-analysis/normalization-analysis.md`](file:///c:/ULPF/docs/03-data-analysis/normalization-analysis.md) | [`ulpf/core/normalization.py`](file:///c:/ULPF/ulpf/core/normalization.py), [`ulpf/schemas/`](file:///c:/ULPF/ulpf/schemas) | YAML mapping transformations, OCSF alignment, vendor attribute retention. |
| **UES JSON Schema Specification** | [`docs/03-data-analysis/schema-analysis.md`](file:///c:/ULPF/docs/03-data-analysis/schema-analysis.md) | [`ulpf/schemas/ues_schema.json`](file:///c:/ULPF/ulpf/schemas/ues_schema.json), [`ulpf/core/validation.py`](file:///c:/ULPF/ulpf/core/validation.py) | Draft-7 JSON schema fields, types, constraints, and validation logic. |
| **Losslessness & Forensic Traceability** | [`docs/03-data-analysis/losslessness-analysis.md`](file:///c:/ULPF/docs/03-data-analysis/losslessness-analysis.md) | [`ulpf/core/pipeline.py`](file:///c:/ULPF/ulpf/core/pipeline.py) | Deterministic UUIDv5 ID derivation, raw hash verification, and lineage tracking. |
| **Error Handling & Dead-Letter Queue** | [`docs/03-data-analysis/malformed-data-analysis.md`](file:///c:/ULPF/docs/03-data-analysis/malformed-data-analysis.md) | [`ulpf/core/validation.py`](file:///c:/ULPF/ulpf/core/validation.py) | Quarantine routing, error isolation, zero-silent-drop policy. |
| **Multi-Process Streaming & Scaling** | [`docs/02-architecture/diagrams/10-concurrency-architecture.md`](file:///c:/ULPF/docs/02-architecture/diagrams/10-concurrency-architecture.md) | [`ulpf/core/worker_pool.py`](file:///c:/ULPF/ulpf/core/worker_pool.py) | Memory-bounded chunked worker pool with multiprocessing and picklable factory. |
| **Real-time Syslog & Host Telemetry** | [`docs/02-architecture/runtime-data-flow.md`](file:///c:/ULPF/docs/02-architecture/runtime-data-flow.md) | [`ulpf/collectors/`](file:///c:/ULPF/ulpf/collectors) | UDP/TCP syslog listener (1514) and Win32 C-API live system monitor. |
| **Offline Enrichment (IP/Threat/Cloud)** | [`docs/03-data-analysis/critical-data-findings.md`](file:///c:/ULPF/docs/03-data-analysis/critical-data-findings.md) | [`ulpf/enrichment/ip_enrichment.py`](file:///c:/ULPF/ulpf/enrichment/ip_enrichment.py) | Zero-network offline CIDR threat intelligence, RFC1918, and cloud ASN lookup. |
| **Analytics, Baselines & ML Features** | [`docs/02-architecture/diagrams/09-analytics-architecture.md`](file:///c:/ULPF/docs/02-architecture/diagrams/09-analytics-architecture.md) | [`ulpf/analytics/`](file:///c:/ULPF/ulpf/analytics) | 6-dimension anomaly scoring, Welford rolling statistics, 24-dim ML feature vectors. |
| **Storage & Egress Sinks** | [`docs/02-architecture/diagrams/07-storage-sink-architecture.md`](file:///c:/ULPF/docs/02-architecture/diagrams/07-storage-sink-architecture.md) | [`ulpf/sinks/`](file:///c:/ULPF/ulpf/sinks) | NDJSON, Parquet (partitioned columnar), Kafka (idempotent), CEF/LEEF egress. |
| **Web Dashboard & SQLite Indexer** | [`docs/dashboard_walkthrough.md`](file:///c:/ULPF/docs/dashboard_walkthrough.md) | [`ulpf/dashboard/`](file:///c:/ULPF/ulpf/dashboard) | FastAPI backend, SQLite 8-index search engine, SSE real-time streaming, and UI. |
| **Onboarding New Parsers** | [`docs/03-data-analysis/source-onboarding-analysis.md`](file:///c:/ULPF/docs/03-data-analysis/source-onboarding-analysis.md) | [`ulpf/parsers/base.py`](file:///c:/ULPF/ulpf/parsers/base.py), [`ulpf/schemas/mappings/`](file:///c:/ULPF/ulpf/schemas/mappings) | Step-by-step guide for adding a new parser plugin and YAML schema mapping. |
| **Deployment & Containers** | [`docs/02-architecture/deployment-architecture.md`](file:///c:/ULPF/docs/02-architecture/deployment-architecture.md) | [`docker/`](file:///c:/ULPF/docker), [`packaging/`](file:///c:/ULPF/packaging) | Air-gapped multi-stage Docker build, wheelhouse, Windows MSI/EXE, macOS/Linux. |
| **Doc-to-Code Fact Check Matrix** | [`docs/00-investigation/documentation-vs-code.md`](file:///c:/ULPF/docs/00-investigation/documentation-vs-code.md) | *Full Repository* | Verification matrix comparing repository claims to actual source code. |

---

## 📁 Detailed Directory Breakdown

```
docs/
├── INFO.md                            <- (THIS FILE) Master documentation map and index
├── ARCHITECTURE.md                    <- Primary system architecture specification
├── dashboard_walkthrough.md           <- User interface and dashboard operations guide
├── demo_script.md                     <- Quick presentation and walkthrough steps
├── presentation_outline.md            <- Slide-by-slide technical defense outline
├── architecture-diagram.svg           <- Visual vector diagram of system components
│
├── 00-investigation/                  <- Deep-dive repository audits & technical proofs
│   ├── documentation-vs-code.md       <- Stated claims vs. concrete implementation verification
│   ├── entry-points.md                <- Comprehensive catalog of all CLI commands & APIs
│   ├── evidence-index.md              <- File-and-line evidence index for key requirements
│   ├── important-components.md        <- Catalog of core classes, functions, and responsibilities
│   ├── repository-inventory.md        <- Inventory of metrics, directories, scripts, configs
│   ├── technology-inventory.md        <- Dependencies, standard libraries, and framework versions
│   └── INVESTIGATION_RULES.md         <- Standards for audit documentation
│
├── 02-architecture/                   <- Subsystem architecture specifications
│   ├── current-system-architecture.md <- Comprehensive 9-subsystem technical spec
│   ├── runtime-data-flow.md           <- End-to-end data lifecycle across 11 discrete stages
│   ├── event-processing-sequence.md   <- Sequence diagrams for sync, async, and syslog paths
│   ├── component-interactions.md      <- Cross-subsystem interface definitions and contracts
│   ├── deployment-architecture.md     <- Container isolation, air-gapping, OS packaging
│   ├── architecture-anomalies.md      <- Design choices, intentional patterns, and tradeoffs
│   └── diagrams/                      <- Subsystem Mermaid diagrams
│       ├── 01-master-architecture.md
│       ├── 02-module-map.md
│       ├── 03-event-processing-flow.md
│       ├── 04-ingestion-architecture.md
│       ├── 05-parser-architecture.md
│       ├── 06-normalization-architecture.md
│       ├── 07-storage-sink-architecture.md
│       ├── 08-dashboard-architecture.md
│       ├── 09-analytics-architecture.md
│       ├── 10-concurrency-architecture.md
│       ├── 11-failure-flow.md
│       ├── 12-deployment-architecture.md
│       └── 13-complete-system-map.md
│
└── 03-data-analysis/                  <- Data model, schema validation, and parser specs
    ├── critical-data-findings.md      <- Key insights across schema, parsers, and raw storage
    ├── detection-analysis.md          <- Heuristic format detection and classification rules
    ├── event-identity.md              <- Deterministic UUIDv5 event ID generation formula
    ├── losslessness-analysis.md       <- Byte-level fidelity, SHA-256 verification, and lineage
    ├── malformed-data-analysis.md     <- Dead-letter queue isolation and error recovery
    ├── network-field-analysis.md      <- 5-tuple extraction, direction inference, port taxonomy
    ├── normalization-analysis.md      <- YAML mapping rules, OCSF taxonomy, and vendor bags
    ├── parser-analysis.md             <- Deep audit of all 11 format parsers
    ├── raw-preservation.md            <- Raw storage hashing, sharding, and surrogate handling
    ├── schema-analysis.md             <- UES Draft-7 JSON schema structure and field dictionary
    ├── source-onboarding-analysis.md  <- Blueprint for onboarding new custom log formats
    ├── test-coverage-map.md           <- Test module map covering unit, e2e, and criteria tests
    ├── timestamp-analysis.md          <- Timestamp normalization across UTC, epochs, and timezones
    ├── vendor-coverage.md             <- Matrix of vendor formats, categories, and sample logs
    └── diagrams/                      <- Data flow Mermaid diagrams
        ├── 01-raw-event-lifecycle.md
        ├── 02-parser-detection-flow.md
        ├── 03-parser-normalization-flow.md
        ├── 04-ues-data-model.md
        ├── 05-losslessness-traceability.md
        ├── 06-new-source-onboarding.md
        └── 07-malformed-event-flow.md
```

---

## 🧩 Source Code Correspondence Reference

### 1. Ingestion & Raw Store (`ulpf/core/`)
* **[`ulpf/core/ingestion.py`](file:///c:/ULPF/ulpf/core/ingestion.py)**: `FileReader`, `StdinReader`, `RawEvent` (immutable binary ingestion).
* **[`ulpf/core/raw_store.py`](file:///c:/ULPF/ulpf/core/raw_store.py)**: `FileRawStore`, `RawStoreBase` (sharded disk storage, UUID validation, SHA-256 hashing).
* **[`ulpf/core/detector.py`](file:///c:/ULPF/ulpf/core/detector.py)**: `FormatDetector` (format classification cascade and `sources.yaml` overrides).
* **[`ulpf/core/registry.py`](file:///c:/ULPF/ulpf/core/registry.py)**: `@register_parser`, `get_all_parsers`, dynamic parser discovery via `pkgutil`.
* **[`ulpf/core/normalization.py`](file:///c:/ULPF/ulpf/core/normalization.py)**: `NormalizationEngine`, YAML mapping loader, OCSF crosswalk, `vendor_attributes` fallback bag.
* **[`ulpf/core/validation.py`](file:///c:/ULPF/ulpf/core/validation.py)**: `Validator` (Draft-7 JSON schema validator, dead-letter routing).
* **[`ulpf/core/pipeline.py`](file:///c:/ULPF/ulpf/core/pipeline.py)**: `Pipeline` (central orchestrator coordinating raw write, parse, normalize, enrich, validate, and multi-sink fanout).
* **[`ulpf/core/worker_pool.py`](file:///c:/ULPF/ulpf/core/worker_pool.py)**: `ParallelPipeline` (memory-bounded streaming `multiprocessing.Pool` workers).

### 2. Format Parsers (`ulpf/parsers/` & `ulpf/schemas/mappings/`)
* **[`ulpf/parsers/base.py`](file:///c:/ULPF/ulpf/parsers/base.py)**: `BaseParser` abstract base class with safe coercers and timestamp parsers.
* **[`ulpf/parsers/cef.py`](file:///c:/ULPF/ulpf/parsers/cef.py)** ↔ `schemas/mappings/cef.yaml`: ArcSight Common Event Format (pipe-delimited header + K=V).
* **[`ulpf/parsers/leef.py`](file:///c:/ULPF/ulpf/parsers/leef.py)** ↔ `schemas/mappings/leef.yaml`: IBM QRadar LEEF 1.0 & 2.0 (tab/custom delimiter).
* **[`ulpf/parsers/syslog_rfc3164.py`](file:///c:/ULPF/ulpf/parsers/syslog_rfc3164.py)** ↔ `schemas/mappings/syslog_rfc3164.yaml`: BSD syslog with PRI header and year inference.
* **[`ulpf/parsers/syslog_rfc5424.py`](file:///c:/ULPF/ulpf/parsers/syslog_rfc5424.py)** ↔ `schemas/mappings/syslog_rfc5424.yaml`: IETF structured syslog with SD-IDs.
* **[`ulpf/parsers/cisco_asa.py`](file:///c:/ULPF/ulpf/parsers/cisco_asa.py)** ↔ `schemas/mappings/cisco_asa.yaml`: Cisco ASA `%ASA-` syslog messages with 5-tuples.
* **[`ulpf/parsers/paloalto_csv.py`](file:///c:/ULPF/ulpf/parsers/paloalto_csv.py)** ↔ `schemas/mappings/paloalto_csv.yaml`: Palo Alto PAN-OS 35+ column traffic CSV.
* **[`ulpf/parsers/aws_cloudtrail.py`](file:///c:/ULPF/ulpf/parsers/aws_cloudtrail.py)** ↔ `schemas/mappings/aws_cloudtrail.yaml`: AWS CloudTrail audit JSON events.
* **[`ulpf/parsers/azure_monitor.py`](file:///c:/ULPF/ulpf/parsers/azure_monitor.py)** ↔ `schemas/mappings/azure_monitor.yaml`: Azure Activity & Diagnostic JSON logs.
* **[`ulpf/parsers/gcp_audit.py`](file:///c:/ULPF/ulpf/parsers/gcp_audit.py)** ↔ `schemas/mappings/gcp_audit.yaml`: Google Cloud Platform Audit logs (`protoPayload`).
* **[`ulpf/parsers/xml_generic.py`](file:///c:/ULPF/ulpf/parsers/xml_generic.py)** ↔ `schemas/mappings/xml_generic.yaml`: Windows EventLog XML (4624, 4625, 5156, etc.) and generic XML.
* **[`ulpf/parsers/json_passthrough.py`](file:///c:/ULPF/ulpf/parsers/json_passthrough.py)** ↔ `schemas/mappings/json_passthrough.yaml`: Generic key-value and semi-structured JSON.

### 3. Stream Collectors (`ulpf/collectors/`)
* **[`ulpf/collectors/syslog_listener.py`](file:///c:/ULPF/ulpf/collectors/syslog_listener.py)**: `SyslogNetworkListener` (concurrent dual UDP + TCP daemon receiver on port 1514).
* **[`ulpf/collectors/live_monitor.py`](file:///c:/ULPF/ulpf/collectors/live_monitor.py)**: `LiveSystemMonitor` (Win32 API process tracking, `iphlpapi` TCP table, event synthesis).

### 4. Enrichment & Crosswalk (`ulpf/enrichment/` & `ulpf/crosswalk/`)
* **[`ulpf/enrichment/ip_enrichment.py`](file:///c:/ULPF/ulpf/enrichment/ip_enrichment.py)**: `IPEnrichmentPlugin` (offline RFC 1918, cloud ASN, and static threat intelligence CIDRs).
* **[`ulpf/enrichment/composite.py`](file:///c:/ULPF/ulpf/enrichment/composite.py)**: `CompositeEnrichmentPlugin` (chainable enrichment engine).
* **[`ulpf/crosswalk/ocsf.py`](file:///c:/ULPF/ulpf/crosswalk/ocsf.py)**: Open Cybersecurity Schema Framework (OCSF) crosswalk matrix.
* **[`ulpf/crosswalk/ecs.py`](file:///c:/ULPF/ulpf/crosswalk/ecs.py)**: Elastic Common Schema (ECS) field crosswalk.

### 5. Analytics & Machine Learning (`ulpf/analytics/`)
* **[`ulpf/analytics/baseline.py`](file:///c:/ULPF/ulpf/analytics/baseline.py)**: `RollingStats` (Welford's algorithm, Z-score, IQR) and `BaselineProfiler`.
* **[`ulpf/analytics/anomaly.py`](file:///c:/ULPF/ulpf/analytics/anomaly.py)**: `AnomalyDetector` (multi-dimensional scoring across severity, volume, bursts, rare categories, auth failures).
* **[`ulpf/analytics/features.py`](file:///c:/ULPF/ulpf/analytics/features.py)**: `FeatureVectorExtractor` (24-dimensional normalized ML feature extraction).

### 6. Storage & Egress Sinks (`ulpf/sinks/`)
* **[`ulpf/sinks/base.py`](file:///c:/ULPF/ulpf/sinks/base.py)**: `SinkBase` abstract base interface.
* **[`ulpf/sinks/ndjson_file.py`](file:///c:/ULPF/ulpf/sinks/ndjson_file.py)**: `NDJSONFileSink` (line-delimited JSON storage).
* **[`ulpf/sinks/parquet_sink.py`](file:///c:/ULPF/ulpf/sinks/parquet_sink.py)**: `ParquetSink` (date/tenant partitioned columnar storage with fallback).
* **[`ulpf/sinks/kafka_producer.py`](file:///c:/ULPF/ulpf/sinks/kafka_producer.py)**: `KafkaProducerSink` (Kafka cluster integration with fallback).
* **[`ulpf/sinks/cef_egress.py`](file:///c:/ULPF/ulpf/sinks/cef_egress.py)**: `CEFEgressSink` (ArcSight CEF format egress).
* **[`ulpf/sinks/leef_egress.py`](file:///c:/ULPF/ulpf/sinks/leef_egress.py)**: `LEEFEgressSink` (IBM QRadar LEEF format egress).

### 7. Dashboard & Query Engine (`ulpf/dashboard/`)
* **[`ulpf/dashboard/app.py`](file:///c:/ULPF/ulpf/dashboard/app.py)**: FastAPI web service, REST endpoints, SSE stream, API key authentication, and CORS enforcement.
* **[`ulpf/dashboard/indexer.py`](file:///c:/ULPF/ulpf/dashboard/indexer.py)**: `EventIndexer` (SQLite search engine, 8 B-Tree indexes, offset tracking, full-text queries).
* **[`ulpf/dashboard/static/`](file:///c:/ULPF/ulpf/dashboard/static)**: Single-page application frontend (`index.html`, `app.js`, `style.css`).

### 8. CLI & Entry Points
* **[`ulpf/cli.py`](file:///c:/ULPF/ulpf/cli.py)**: Central Click CLI entry point (`ulpf process`, `ulpf listen`, `ulpf dashboard`, `ulpf benchmark`, `ulpf monitor`).
* **[`test_all.py`](file:///c:/ULPF/test_all.py)**: Master criteria conformance and end-to-end integration test runner.
