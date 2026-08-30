# 13 — Complete System Architecture Map ("How Everything Connects")

This is the **master architectural synthesis** of the entire Universal Log Parsing Framework (ULPF) codebase, mapping all entry points, ingestion paths, parsing engines, normalization rules, forensic storage, validation, sinks, analytics, and operational dashboard subsystems into one comprehensive blueprint.

---

## Master Architecture Map

```mermaid
flowchart TD
    subgraph S_INPUT["1. Log Ingestion Sources"]
        IN_FILE["Log Files & Directories\n(FileReader)"]
        IN_STDIN["Standard Input Stream\n(StdinReader)"]
        IN_SYSLOG["Syslog UDP/TCP on Port 1514\n(SyslogNetworkListener)"]
        IN_HOST["Real-Time Host OS Monitor\n(LiveSystemMonitor)"]
        IN_API["REST Ingestion Endpoints\n(POST /api/ingest/*)"]
    end

    subgraph S_CORE["2. Pipeline Orchestrator (core/pipeline.py)"]
        DIGEST["1. SHA-256 Digest & UUIDv5 Derivation\n(ulpf:tenant:source:hash)"]
        RAW_PUT["2. Pre-Parse Forensic Persistence\nFileRawStore.put(event_id, raw_bytes)"]
        
        DET_EXEC["3. Heuristic Format Classification\nFormatDetector.detect(raw_line)"]
        REG_DISC["4. Parser Registry Resolution\nget_parser_for_format(format_id)"]
        
        PARSE_EXEC["5. Parser Field Extraction\nparser.extract(raw_line)"]
        NORM_EXEC["6. Declarative Schema Normalization\nNormalizationEngine.normalize(extracted)"]
        BAG_EXEC["7. Vendor Attributes Bag\n(Lossless unmapped key retention)"]
        UES_BUILD["8. Canonical UES 1.2.0 Envelope Assembly\nPipeline._build_ues_event()"]
        
        ENRICH_EXEC["9. Offline IP & Threat Enrichment\nIPEnrichmentPlugin.enrich(ues_event)"]
        VAL_EXEC{"10. Schema Validation Gate\nValidator.validate_and_route()"}
        SINK_DISPATCH["11. At-Least-Once Multi-Sink Fan-Out"]

        DIGEST --> RAW_PUT --> DET_EXEC --> REG_DISC --> PARSE_EXEC --> NORM_EXEC --> BAG_EXEC --> UES_BUILD --> ENRICH_EXEC --> VAL_EXEC
    end

    subgraph S_PARSERS["3. Parser Plugin Suite (parsers/*.py)"]
        PARSERS_ALL["11 Formats: CEF, LEEF, Cisco ASA, Palo Alto CSV,\nAWS CloudTrail, Azure Monitor, GCP Audit,\nSyslog RFC 3164, Syslog RFC 5424, XML Generic, JSON"]
    end

    subgraph S_STORAGE["4. Primary Storage & Sinks"]
        RAW_STORE[("Forensic Raw Store\n<base>/<aa>/<bb>/<id>.raw\n(Exact Untouched Bytes)")]
        NDJSON_FILE[("Canonical Event Log\noutput/events.ndjson")]
        PARQUET_LAKE[("Columnar Parquet Lake\nparquet_lake/dt=.../tenant_id=...")]
        KAFKA_TOPIC["Apache Kafka Topic\n(ulpf.events)"]
        CEF_LOG[("ArcSight CEF Egress\noutput/egress_cef.log")]
        LEEF_LOG[("QRadar LEEF Egress\noutput/egress_leef.log")]
        DEAD_LETTER[("Unified Quarantine Queue\noutput/dead_letter.ndjson")]
    end

    subgraph S_ANALYTICS["5. Analytics & ML Subsystem (analytics/)"]
        ANOM_DET["AnomalyDetector\n(6-Method Weighted Scoring)"]
        BASE_PROF["BaselineProfiler & RollingStats\n(Welford Mean/Variance/IQR)"]
        FEAT_VEC["FeatureVectorExtractor\n(24-Dim Dense Vector)"]
        ANOM_OUT[("output/anomalies.ndjson")]
    end

    subgraph S_DASHBOARD["6. Query Acceleration & Web UI (dashboard/)"]
        INDEXER["EventIndexer (SQLite)\nIncremental offset-based sync"]
        SQLITE_DB[("dashboard_index.db\n(events_index table, 8 B-Trees)")]
        FASTAPI_APP["FastAPI Server\n(Uvicorn on Port 8000)"]
        STATIC_DASH["Operations Dashboard UI\n(HTML5 / CSS / Chart.js)"]
    end

    %% Ingestion to pipeline
    IN_FILE & IN_STDIN & IN_SYSLOG --> DIGEST
    IN_API --> DIGEST
    IN_HOST -.->|Optional Bridge| DIGEST

    %% Parser interaction
    REG_DISC <--> PARSERS_ALL
    PARSE_EXEC <--> PARSERS_ALL

    %% Forensic Raw Store
    RAW_PUT --> RAW_STORE

    %% Validation outcomes
    VAL_EXEC -->|Valid Event| SINK_DISPATCH
    VAL_EXEC -->|Invalid Schema| DEAD_LETTER
    PARSE_EXEC -.->|Extract Exception| DEAD_LETTER
    DET_EXEC -.->|Unmatched Format| DEAD_LETTER

    %% Sink writes
    SINK_DISPATCH --> NDJSON_FILE
    SINK_DISPATCH --> PARQUET_LAKE
    SINK_DISPATCH --> KAFKA_TOPIC
    SINK_DISPATCH --> CEF_LOG
    SINK_DISPATCH --> LEEF_LOG
    SINK_DISPATCH -.->|Sink Write Error| DEAD_LETTER

    %% Analytics flows
    NDJSON_FILE --> ANOM_DET
    ANOM_DET <--> BASE_PROF
    ANOM_DET --> FEAT_VEC
    ANOM_DET --> ANOM_OUT

    %% Dashboard and Indexing flows
    NDJSON_FILE --> INDEXER
    INDEXER <--> SQLITE_DB
    SQLITE_DB --> FASTAPI_APP
    RAW_STORE --> FASTAPI_APP
    DEAD_LETTER --> INDEXER
    FASTAPI_APP <--> STATIC_DASH
```

---

## Evidence

| Subsystem Linkage | Source File | Exact Method / Symbol | Confidence |
|---|---|---|---|
| Ingestion $\to$ Pipeline Orchestration | `ulpf/cli.py:159-349` | `_build_pipeline()`, `pipeline.process_event()`, `ParallelPipeline.run()` | **CONFIRMED** |
| Pre-Parse Forensic Raw Storage | `ulpf/core/pipeline.py:118-119` | `self.raw_store.put(event_id, raw_bytes)` | **CONFIRMED** |
| 11 Dynamic Parser Plugins | `ulpf/core/registry.py:19`, `ulpf/parsers/__init__.py:1-15` | `@register_parser`, `pkgutil.iter_modules()` | **CONFIRMED** |
| Lossless Attribute Preservation | `ulpf/core/normalization.py:323-327` | `vendor_attributes[k] = v` for unmapped extracted keys | **CONFIRMED** |
| Air-Gapped Static IP Enrichment | `ulpf/enrichment/ip_enrichment.py:106-209` | `_classify_ip()`, `IPEnrichmentPlugin.enrich()` | **CONFIRMED** |
| Schema Gate & Quarantine Routing | `ulpf/core/validation.py:59-79` | `Validator.validate_and_route()`, `dead_letter.ndjson` | **CONFIRMED** |
| Multi-Sink Egress Engine | `ulpf/core/pipeline.py:221-240`, `ulpf/sinks/` | `NDJSONFileSink`, `ParquetSink`, `KafkaProducerSink`, `CEFEgressSink`, `LEEFEgressSink` | **CONFIRMED** |
| Statistical Profiling & Anomaly Engine | `ulpf/analytics/baseline.py`, `ulpf/analytics/anomaly.py` | `BaselineProfiler`, `RollingStats`, `AnomalyDetector.analyze()` | **CONFIRMED** |
| 24-Dimensional ML Vectorizer | `ulpf/analytics/features.py:15-104` | `FeatureVectorExtractor.extract_vector()` | **CONFIRMED** |
| Incremental SQLite Indexer & Dashboard | `ulpf/dashboard/indexer.py:103-140`, `ulpf/dashboard/app.py:159-245` | `EventIndexer.sync_from_ndjson()`, `create_app()`, `/api/events` | **CONFIRMED** |
