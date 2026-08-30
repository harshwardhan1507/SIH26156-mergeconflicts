# 01 — Master Repository Architecture

This diagram captures the highest-level architectural subsystems of the Universal Log Parsing Framework (ULPF) and the concrete relationships connecting ingestion, core processing, storage, analytics, querying, and egress.

---

## Architecture Diagram

```mermaid
flowchart TD
    subgraph SOURCES["1. External Input Sources"]
        SRC_FILES["Log Files & Directories\n(Local / Mounted Volumes)"]
        SRC_STDIN["Standard Input Stream\n(Pipes / Redirection)"]
        SRC_SYSLOG["Syslog UDP / TCP Packets\n(Network Port 1514)"]
        SRC_HOST["Local OS Telemetry\n(Process / Socket Activity)"]
        SRC_REST["REST Ingestion Payloads\n(HTTP POST /api/ingest/*)"]
    end

    subgraph INGESTION["2. Ingestion Subsystem"]
        RDR_FILE["FileReader\n(core/ingestion.py)"]
        RDR_STDIN["StdinReader\n(core/ingestion.py)"]
        RDR_SYSLOG["SyslogNetworkListener\n(collectors/syslog_listener.py)"]
        RDR_HOST["LiveSystemMonitor\n(collectors/live_monitor.py)"]
    end

    subgraph ORCHESTRATION["3. Pipeline Core & Forensic Storage"]
        PIPE["Pipeline / ParallelPipeline\n(core/pipeline.py / worker_pool.py)"]
        RAW_STORE[("FileRawStore\n(core/raw_store.py)\n<base>/<aa>/<bb>/<id>.raw")]
        UUID_GEN["UUIDv5 & SHA-256 Digest\n(ulpf:tenant:source:hash)"]
    end

    subgraph PARSING["4. Classification & Parsing Engine"]
        DETECTOR["FormatDetector\n(core/detector.py)"]
        REGISTRY["ParserRegistry\n(core/registry.py)"]
        PARSERS["11 Parser Plugins\n(parsers/*.py)"]
    end

    subgraph NORMALIZATION["5. Normalization & Enrichment"]
        NORM_ENG["NormalizationEngine\n(core/normalization.py)"]
        YAML_MAP["Declarative YAML Mappings\n(schemas/mappings/*.yaml)"]
        OPEN_BAG["Vendor Attributes Bag\n(Lossless Unmapped Keys)"]
        ENRICH["IPEnrichmentPlugin\n(enrichment/ip_enrichment.py)"]
    end

    subgraph VALIDATION["6. Validation & Quarantine"]
        VAL_GATE{"Validator\n(core/validation.py)\nDraft7Validator"}
        DL_STORE[("Dead-Letter Store\n(dead_letter.ndjson)")]
    end

    subgraph SINKS["7. Egress & Data Lake Sinks"]
        SINK_NDJSON[("NDJSON File Sink\n(events.ndjson)")]
        SINK_PARQUET[("Parquet Lake Sink\n(parquet_lake/dt=.../tenant_id=...)")]
        SINK_KAFKA["Kafka Producer Sink\n(Topic: ulpf.events)"]
        SINK_CEF[("ArcSight CEF Egress\n(egress_cef.log)")]
        SINK_LEEF[("QRadar LEEF Egress\n(egress_leef.log)")]
    end

    subgraph ANALYTICS_SEC["8. Analytics & ML Subsystem"]
        ANOMALY["AnomalyDetector\n(analytics/anomaly.py)"]
        BASELINE["BaselineProfiler\n(analytics/baseline.py)"]
        FEATURES["FeatureVectorExtractor\n(analytics/features.py)\n24-Dim Vector"]
        BASE_FILE[("analytics_baseline.json")]
    end

    subgraph QUERY_UI["9. Dashboard & Query Subsystem"]
        INDEXER["EventIndexer (SQLite)\n(dashboard/indexer.py)"]
        DB_INDEX[("dashboard_index.db\nevents_index table")]
        FASTAPI["FastAPI Web Server\n(dashboard/app.py :8000)"]
        STATIC_UI["Operations Dashboard UI\n(dashboard/static/)"]
    end

    %% Ingestion connections
    SRC_FILES --> RDR_FILE
    SRC_STDIN --> RDR_STDIN
    SRC_SYSLOG --> RDR_SYSLOG
    SRC_HOST --> RDR_HOST
    SRC_REST --> FASTAPI

    RDR_FILE --> PIPE
    RDR_STDIN --> PIPE
    RDR_SYSLOG --> PIPE
    RDR_HOST -.->|Optional Callback| PIPE
    FASTAPI -->|POST /api/ingest| PIPE

    %% Orchestration connections
    PIPE --> UUID_GEN
    UUID_GEN --> RAW_STORE
    PIPE --> DETECTOR
    DETECTOR --> REGISTRY
    REGISTRY --> PARSERS
    PARSERS --> NORM_ENG
    YAML_MAP --> NORM_ENG
    NORM_ENG --> OPEN_BAG
    OPEN_BAG --> ENRICH
    ENRICH --> VAL_GATE

    %% Validation routing
    VAL_GATE -->|Valid Event| SINKS
    VAL_GATE -->|Invalid Event| DL_STORE
    PARSERS -.->|Extraction Error| DL_STORE
    DETECTOR -.->|Unmatched Format| DL_STORE

    %% Sinks routing
    SINKS --> SINK_NDJSON
    SINKS --> SINK_PARQUET
    SINKS --> SINK_KAFKA
    SINKS --> SINK_CEF
    SINKS --> SINK_LEEF

    %% Analytics routing
    SINK_NDJSON --> ANOMALY
    ANOMALY <--> BASELINE
    BASELINE <--> BASE_FILE
    ANOMALY --> FEATURES

    %% Query and UI routing
    SINK_NDJSON --> INDEXER
    INDEXER <--> DB_INDEX
    FASTAPI <--> DB_INDEX
    FASTAPI <--> RAW_STORE
    FASTAPI <--> STATIC_UI
```

---

## Evidence

| Component / Relationship | Source File | Symbol / Method | Confidence |
|---|---|---|---|
| Ingestion Readers $\to$ Pipeline | `ulpf/cli.py:173-220` | `ingest()` invoking `FileReader` / `StdinReader` / `_build_pipeline()` | **CONFIRMED** |
| Syslog Listener $\to$ Pipeline | `ulpf/cli.py:283-349`, `ulpf/collectors/syslog_listener.py:46-109` | `SyslogNetworkListener.start()` dispatching to `on_event()` | **CONFIRMED** |
| Pipeline $\to$ RawStore (Pre-Parse) | `ulpf/core/pipeline.py:118-119` | `self.raw_store.put(event_id, raw_bytes)` | **CONFIRMED** |
| Pipeline $\to$ Detector $\to$ Registry $\to$ Parsers | `ulpf/core/pipeline.py:122-132` | `self.detector.detect()`, `get_parser_for_format()` | **CONFIRMED** |
| Parsers $\to$ NormalizationEngine | `ulpf/core/pipeline.py:186` | `self.norm_engine.normalize(extracted, parser.name)` | **CONFIRMED** |
| NormalizationEngine $\to$ Vendor Attributes Bag | `ulpf/core/normalization.py:323-327` | `vendor_attrs[k] = v` for unmapped fields | **CONFIRMED** |
| Pipeline $\to$ IPEnrichmentPlugin | `ulpf/core/pipeline.py:211`, `ulpf/enrichment/ip_enrichment.py:184-209` | `self.enrichment.enrich(ues_event)` | **CONFIRMED** |
| Pipeline $\to$ Validator $\to$ Sinks / DeadLetter | `ulpf/core/pipeline.py:216-240` | `self.validator.validate_and_route()`, `sink.write()` | **CONFIRMED** |
| Sinks Implementation Suite | `ulpf/sinks/` | `NDJSONFileSink`, `ParquetSink`, `KafkaProducerSink`, `CEFEgressSink`, `LEEFEgressSink` | **CONFIRMED** |
| Analytics Subsystem & Features | `ulpf/cli.py:225-281`, `ulpf/analytics/` | `AnomalyDetector.analyze()`, `FeatureVectorExtractor.extract_vector()` | **CONFIRMED** |
| SQLite Indexer $\to$ FastAPI $\to$ UI | `ulpf/dashboard/app.py:159-245`, `ulpf/dashboard/indexer.py:69-120` | `EventIndexer.sync_from_ndjson()`, `EventIndexer.query_events()` | **CONFIRMED** |
