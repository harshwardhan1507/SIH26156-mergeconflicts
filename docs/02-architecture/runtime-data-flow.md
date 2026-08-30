# Runtime Data Flow

This document details the exact **runtime data flow** across all execution paths within the Universal Log Parsing Framework (ULPF), tracing data structures, transformations, and function-to-function transitions from source ingestion to output sinks and user interfaces.

---

## 1. Primary Execution Paths Overview

The framework supports five distinct data intake and processing pipelines:

```text
[A. File/Batch Ingestion]  ──► FileReader  ─────────┐
[B. Stdin Stream Ingest]   ──► StdinReader ─────────┤
[C. Syslog Network Ingest] ──► SyslogListener ──────┼──► Pipeline.process_event() ──► Sinks ──► SQLite Indexer ──► Dashboard UI
[D. REST API Ingestion]    ──► FastAPI /api/ingest ─┤
[E. Live OS Monitoring]    ──► LiveSystemMonitor ───┘ (Internal Buffer + Optional Callback)
```

---

## 2. Deep-Dive Data Flow Traces

### 2.1 File / Batch Ingestion Data Flow

```mermaid
sequenceDiagram
    autonumber
    participant CLI as CLI (ulpf/cli.py:ingest)
    participant Reader as FileReader (core/ingestion.py)
    participant Pipe as Pipeline (core/pipeline.py)
    participant Store as FileRawStore (core/raw_store.py)
    participant Det as FormatDetector (core/detector.py)
    participant Reg as ParserRegistry (core/registry.py)
    participant Parser as BaseParser (parsers/*.py)
    participant Norm as NormalizationEngine (core/normalization.py)
    participant Enrich as IPEnrichmentPlugin (enrichment/*.py)
    participant Val as Validator (core/validation.py)
    participant Sink as SinkBase (sinks/*.py)

    CLI->>Reader: read()
    activate Reader
    Reader->>Reader: open(fpath, 'rb') -> raw bytes
    Reader-->>CLI: yield RawEvent(line, raw_bytes, source_tag, ingest_ts)
    deactivate Reader

    CLI->>Pipe: process_event(raw_line, source_tag, ingest_ts, raw_bytes)
    activate Pipe

    Note over Pipe: Step 1: Compute SHA-256 over raw_bytes
    Pipe->>Pipe: raw_hash = sha256(raw_bytes).hexdigest()
    
    Note over Pipe: Step 2: Generate UUIDv5
    Pipe->>Pipe: event_id = uuid5(NAMESPACE, "ulpf:tenant:source:hash")

    Note over Pipe: Step 3: Persist Raw Payload (Before Parsing)
    Pipe->>Store: put(event_id, raw_bytes)
    Store-->>Pipe: returns digest

    Note over Pipe: Step 4: Detect Log Format
    Pipe->>Det: detect(raw_line, source_tag)
    Det-->>Pipe: format_id (e.g. "cisco_asa")

    Note over Pipe: Step 5: Resolve Parser Instance
    Pipe->>Reg: get_parser_for_format(format_id)
    Reg-->>Pipe: CiscoASAParser instance

    Note over Pipe: Step 6: Extract Structured Fields
    Pipe->>Parser: extract(raw_line)
    Parser-->>Pipe: extracted dict[str, Any]

    Note over Pipe: Step 7: Declarative Normalization
    Pipe->>Norm: normalize(extracted, "cisco_asa")
    Norm-->>Pipe: normalized dict[str, Any] (with vendor_attributes)

    Note over Pipe: Step 8: Assemble Canonical UES Dict
    Pipe->>Pipe: _build_ues_event(...) -> ues_event dict

    Note over Pipe: Step 9: IP / Threat Enrichment
    Pipe->>Enrich: enrich(ues_event)
    Enrich-->>Pipe: ues_event (with enrichment block)

    Note over Pipe: Step 10: JSON Schema Validation Gate
    Pipe->>Val: validate_and_route(ues_event)
    alt Valid Event
        Val-->>Pipe: True
        Note over Pipe: Step 11: Fan-Out to Configured Sinks
        loop For each sink in sinks
            Pipe->>Sink: write(ues_event)
        end
        Pipe-->>CLI: True (processed counter incremented)
    else Invalid Event
        Val->>Val: write to dead_letter.ndjson
        Val-->>Pipe: False
        Pipe-->>CLI: False (error counter incremented)
    end
    deactivate Pipe

    CLI->>Sink: flush()
```

---

### 2.2 Syslog Network Ingestion Data Flow (UDP & TCP)

```mermaid
flowchart TD
    subgraph Sockets["Network Sockets"]
        UDP_SOCK["UDP Socket :1514\n(SOCK_DGRAM)"]
        TCP_SOCK["TCP Socket :1514\n(SOCK_STREAM)"]
    end

    subgraph Threads["Listener Daemon Threads"]
        UDP_TH["_udp_worker\n(Thread: ULPF-Syslog-UDP)"]
        TCP_TH["_tcp_worker\n(Thread: ULPF-Syslog-TCP)"]
        TCP_CLIENT_TH["_handle_tcp_client\n(1 thread per TCP connection)"]
    end

    subgraph Dispatch["Event Dispatch Callback"]
        ON_EVENT["on_event(line, source_tag)\n(Closure in ulpf/cli.py)"]
        FLUSH_CHECK{"packet_count % 50 == 0?"}
    end

    subgraph CorePipe["Pipeline Engine"]
        PROC["Pipeline.process_event()"]
        FLUSH["sink.flush()"]
    end

    UDP_SOCK -->|recvfrom 65535| UDP_TH
    UDP_TH -->|decode surrogateescape| ON_EVENT

    TCP_SOCK -->|accept| TCP_TH
    TCP_TH -->|spawn| TCP_CLIENT_TH
    TCP_CLIENT_TH -->|recv 4096 / split newline| ON_EVENT

    ON_EVENT --> PROC
    ON_EVENT --> FLUSH_CHECK
    FLUSH_CHECK -->|Yes| FLUSH
```

---

### 2.3 Dashboard Query & REST API Data Flow

```mermaid
flowchart LR
    subgraph Client["Web Browser / HTTP Client"]
        HTTP_REQ["HTTP GET /api/events?category=threat&sort_by=severity"]
        LOOKUP_REQ["HTTP GET /api/events/{event_id}"]
        STREAM_REQ["HTTP GET /api/stream (SSE)"]
    end

    subgraph FastAPI["FastAPI Backend (ulpf/dashboard/app.py)"]
        ROUTER["FastAPI Router & Lifespan"]
        API_KEY{"X-API-Key\nValidation"}
    end

    subgraph Storage["Storage & Indexing Engines"]
        SQLITE[("SQLite Index\ndashboard_index.db\n(events_index table)")]
        NDJSON[("NDJSON File\nevents.ndjson")]
        RAW_STORE[("FileRawStore\n<base>/<aa>/<bb>/<id>.raw")]
    end

    HTTP_REQ --> ROUTER
    ROUTER --> API_KEY
    API_KEY -->|Authorized| SQLITE
    SQLITE -->|Parameterized SQL Result| ROUTER
    ROUTER -->|JSON Response| HTTP_REQ

    LOOKUP_REQ --> ROUTER
    ROUTER --> SQLITE
    ROUTER --> RAW_STORE
    SQLITE -->|Normalized UES Record| ROUTER
    RAW_STORE -->|Exact Raw Bytes| ROUTER
    ROUTER -->|Joined JSON + Raw Payload| LOOKUP_REQ

    STREAM_REQ --> ROUTER
    ROUTER --> NDJSON
    NDJSON -->|Stream Yield| STREAM_REQ
```

---

### 2.4 Analytics & Anomaly Detection Data Flow

```mermaid
flowchart TD
    INPUT_FILE[("output/events.ndjson")] --> CLI_ANALYZE["ulpf analyze (ulpf/cli.py)"]
    
    subgraph DETECTOR["AnomalyDetector (ulpf/analytics/anomaly.py)"]
        LOAD_BASE["Load baseline\n(analytics_baseline.json)"]
        ANALYZE_EV["detector.analyze(event)"]
        
        subgraph SCORING["Weighted Multi-Dimensional Scoring"]
            Z_SCORE["1. Severity Z-Score (>3σ = +0.35, 2-3σ = +0.20)"]
            IQR["2. Bytes IQR Outlier (Out of Q1-Q3 = +0.25)"]
            BURST["3. Event Burst Detection (>3x baseline rate = +0.30)"]
            RARE_CAT["4. Rare Category (<1% historical = +0.15)"]
            THREAT_IP["5. Threat Intel Match (CIDR match = +0.40)"]
            AUTH_CHAIN["6. Auth Failure Chain (>=5 failures = +0.30)"]
        end
        
        UPDATE_BASE["detector.update_baseline(event)\n(Welford Rolling Mean/Variance)"]
        SAVE_BASE["detector.save_baseline()\n(Persist to JSON)"]
    end

    subgraph VECTORIZER["FeatureVectorExtractor (ulpf/analytics/features.py)"]
        EXTRACT_VEC["extract_vector(event)"]
        DENSE_24["24-Dimensional Dense Vector\n[-1.0 to 1.0 float values]"]
    end

    CLI_ANALYZE --> LOAD_BASE
    LOAD_BASE --> ANALYZE_EV
    ANALYZE_EV --> Z_SCORE & IQR & BURST & RARE_CAT & THREAT_IP & AUTH_CHAIN
    SCORING --> UPDATE_BASE
    UPDATE_BASE --> SAVE_BASE
    ANALYZE_EV -->|Annotated Event| EXTRACT_VEC
    EXTRACT_VEC --> DENSE_24
    ANALYZE_EV --> OUTPUT_FILE[("output/anomalies.ndjson")]
```

---

## 3. Data Transformation & Schema Evolution Matrix

At every point in the pipeline, data transitions through strictly typed objects:

```text
[1. Wire/Disk Bytes]
     │ (b'<134>1 2026-08-30T12:00:00Z firewall %ASA-4-106023: Deny tcp src outside:198.51.100.1...')
     ▼
[2. RawEvent Dataclass]
     │ (line: str, raw_bytes: bytes, source_tag: str, ingest_timestamp: datetime)
     ▼
[3. Extracted Dictionary]
     │ (asa_code: '106023', action: 'deny', protocol: 'tcp', src_ip: '198.51.100.1', ...)
     ▼
[4. Normalized Dictionary]
     │ (source: {...}, event: {...}, network: {...}, identity: null, vendor_attributes: {...})
     ▼
[5. Canonical UES 1.2.0 Dictionary]
     │ (schema_version, tenant_id, event_id, ingest_timestamp, raw, source, event, network, identity, rule, vendor_attributes, lineage, enrichment)
     ▼
[6. Egress Serialization / Database Rows]
     ├── Parquet: Tabular flattened record dictionary
     ├── Kafka / NDJSON: UTF-8 JSON string + newline
     ├── ArcSight CEF: "CEF:0|Cisco|ASA|1.2.0|106023|Deny|5|src=198.51.100.1 ..."
     ├── QRadar LEEF: "LEEF:2.0|Cisco|ASA|1.2.0|106023|\t|src=198.51.100.1 ..."
     └── SQLite: 24-column relational row in events_index table
```

---

## 4. Lossless Data Preservation Verification

The ULPF architecture guarantees complete, non-lossy log preservation across five distinct technical mechanisms:

1. **Pre-Processing Byte Storage**: `FileRawStore.put()` writes the original binary bytes to disk at Step 3, *before* parsing or normalization can throw an error or discard bytes.
2. **Surrogate-Escape String Conversion**: `decode('utf-8', errors='surrogateescape')` preserves unmappable binary bytes in log lines without character replacement corruption (`�`).
3. **Embedded Raw Envelope**: Every UES record includes `raw.raw_payload` (exact log string) and `raw.raw_hash` (SHA-256 hex digest) directly inside the JSON envelope.
4. **Vendor Attributes Open Bag**: In `NormalizationEngine.normalize()`, all key-value pairs extracted by the parser that do not map to canonical UES fields are placed into `vendor_attributes` (lines 323-327).
5. **Exact Retrieval via API & CLI**: Both `ulpf lookup --event-id <uuid>` and `GET /api/events/{event_id}` query `FileRawStore.get()` to return the exact original payload.
