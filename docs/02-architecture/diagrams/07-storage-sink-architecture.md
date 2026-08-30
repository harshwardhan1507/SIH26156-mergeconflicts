# 07 — Storage & Sink Architecture

This diagram maps all storage layers, forensic raw persistence, egress sinks, and secondary indexing engines in the ULPF repository.

---

## Storage & Sink Architecture Diagram

```mermaid
flowchart TD
    subgraph INTAKE["1. Incoming Event"]
        RAW_BYTES["Raw Bytes Payload (b'...')"]
        UES_EVENT["Normalized UES Event (dict)"]
    end

    subgraph FORENSIC_RAW["2. Forensic Raw Storage (core/raw_store.py)"]
        STORE_ENGINE["FileRawStore"]
        DIR_SHARD["2-Tier Hex Sharding\nshard = safe_id.replace('-', '')[:4]\n<base_dir>/<shard[:2]>/<shard[2:4]>/<safe_id>.raw"]
        RAW_FILES[("Exact Binary Files (*.raw)\n100% Byte-Exact Storage")]
        STORE_ENGINE --> DIR_SHARD --> RAW_FILES
    end

    subgraph SINKS_LAYER["3. Multi-Sink Egress Engine (sinks/*.py)"]
        SINK_BASE["SinkBase (Abstract Interface)\n+ write(event: dict) -> None\n+ flush() -> None\n+ close() -> None"]

        subgraph SINK_NDJSON["NDJSON Sink (ndjson_file.py)"]
            NDJSON_WRITER["NDJSONFileSink\nBuffered File Appends"]
            FILE_NDJSON[("output/events.ndjson\n(Single Source of Truth)")]
            NDJSON_WRITER --> FILE_NDJSON
        end

        subgraph SINK_PARQUET["Parquet Lake Sink (parquet_sink.py)"]
            PARQUET_WRITER["ParquetSink\nBatches 1000 events\nFlattens nested dicts\nGroups by (date, tenant)"]
            PYARROW_CHECK{"pyarrow\nInstalled?"}
            FILE_PARQUET[("parquet_lake/dt=YYYY-MM-DD/tenant_id=.../events.parquet\n(Snappy Compression)")]
            FILE_JSONL[("parquet_lake/dt=YYYY-MM-DD/tenant_id=.../events_columnar.jsonl\n(Air-Gap Fallback)")]
            PARQUET_WRITER --> PYARROW_CHECK
            PYARROW_CHECK -->|Yes| FILE_PARQUET
            PYARROW_CHECK -->|No| FILE_JSONL
        end

        subgraph SINK_KAFKA["Kafka Producer Sink (kafka_producer.py)"]
            KAFKA_WRITER["KafkaProducerSink\nKey: event_id\nAcks: all\nIdempotence: True"]
            KAFKA_CHECK{"Kafka Broker\nAvailable?"}
            TOPIC_KAFKA["Kafka Cluster\nTopic: ulpf.events"]
            FILE_KAFKA_FB[("output/kafka_events.ndjson\n(Air-Gap Fallback)")]
            KAFKA_WRITER --> KAFKA_CHECK
            KAFKA_CHECK -->|Yes| TOPIC_KAFKA
            KAFKA_CHECK -->|No| FILE_KAFKA_FB
        end

        subgraph SINK_CEF_LEEF["SIEM Egress Sinks (cef_egress.py / leef_egress.py)"]
            CEF_WRITER["CEFEgressSink\nFormat: CEF:0|vendor|product|..."]
            LEEF_WRITER["LEEFEgressSink\nFormat: LEEF:2.0|vendor|product|..."]
            FILE_CEF[("output/egress_cef.log")]
            FILE_LEEF[("output/egress_leef.log")]
            CEF_WRITER --> FILE_CEF
            LEEF_WRITER --> FILE_LEEF
        end
    end

    subgraph INDEX_LAYER["4. Accelerated Query Index (dashboard/indexer.py)"]
        SYNC_ENGINE["EventIndexer.sync_from_ndjson()\nByte-offset tracking in index_meta table"]
        SQLITE_DB[("dashboard_index.db\nSQLite Table: events_index\n8 B-Tree Indexes (ts, vendor, cat, sev, outcome...)")]
        FILE_NDJSON --> SYNC_ENGINE
        SYNC_ENGINE --> SQLITE_DB
    end

    subgraph QUARANTINE_LAYER["5. Unified Quarantine Queue (core/validation.py)"]
        DL_SINK["_DeadLetterSink"]
        FILE_DL[("output/dead_letter.ndjson\n(Unparsed, Invalid & Failed Events)")]
        DL_SINK --> FILE_DL
    end

    RAW_BYTES --> STORE_ENGINE
    UES_EVENT --> SINK_BASE
    SINK_BASE --> NDJSON_WRITER & PARQUET_WRITER & KAFKA_WRITER & CEF_WRITER & LEEF_WRITER
```

---

## Evidence

| Storage / Sink Component | Source File | Class / Method | Confidence |
|---|---|---|---|
| Sharded File Raw Store | `ulpf/core/raw_store.py:34-92` | `FileRawStore`, `_path()`, `put()`, `get()` | **CONFIRMED** |
| NDJSON Flat File Sink | `ulpf/sinks/ndjson_file.py:13-39` | `NDJSONFileSink.write()`, `events.ndjson` | **CONFIRMED** |
| Partitioned Parquet Lake & Fallback | `ulpf/sinks/parquet_sink.py:28-134` | `ParquetSink`, `dt=.../tenant_id=...`, `events.parquet` / `events_columnar.jsonl` | **CONFIRMED** |
| Kafka Producer & Fallback | `ulpf/sinks/kafka_producer.py:42-155` | `KafkaProducerSink`, `topic="ulpf.events"`, `kafka_events.ndjson` | **CONFIRMED** |
| ArcSight CEF Egress Formatter | `ulpf/sinks/cef_egress.py:15-64` | `CEFEgressSink.format_event()`, `egress_cef.log` | **CONFIRMED** |
| IBM QRadar LEEF Egress Formatter | `ulpf/sinks/leef_egress.py:14-60` | `LEEFEgressSink.format_event()`, `egress_leef.log` | **CONFIRMED** |
| Incremental SQLite Indexer | `ulpf/dashboard/indexer.py:69-140` | `EventIndexer`, `sync_from_ndjson()`, `last_byte_offset` | **CONFIRMED** |
| Unified Dead-Letter File | `ulpf/core/validation.py:21-50` | `_DeadLetterSink`, `Validator`, `dead_letter.ndjson` | **CONFIRMED** |
