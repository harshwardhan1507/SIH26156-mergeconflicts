# Event Processing Sequence Diagrams

This document illustrates the exact step-by-step execution sequences for log events traversing the Universal Log Parsing Framework (ULPF), covering happy paths, failure branches, and multi-process concurrency.

---

## 1. Happy-Path Single-Event Sequence

The diagram below details the exact execution path of a valid event through `Pipeline.process_event()`.

```mermaid
sequenceDiagram
    autonumber
    actor Source as Log Source (File/Syslog/API)
    participant Pipe as Pipeline (core/pipeline.py)
    participant Store as FileRawStore (core/raw_store.py)
    participant Det as FormatDetector (core/detector.py)
    participant Reg as ParserRegistry (core/registry.py)
    participant Parser as BaseParser (parsers/*.py)
    participant Norm as NormalizationEngine (core/normalization.py)
    participant Enrich as IPEnrichmentPlugin (enrichment/*.py)
    participant Val as Validator (core/validation.py)
    participant Sink as SinkBase (sinks/*.py)

    Source->>Pipe: process_event(raw_line, source_tag, ingest_ts, raw_bytes, tenant_id)
    activate Pipe

    Note over Pipe: Step 1: Capture authentic bytes & SHA-256
    Pipe->>Pipe: raw_hash = sha256(raw_bytes).hexdigest()

    Note over Pipe: Step 2: Deterministic UUIDv5 Event ID
    Pipe->>Pipe: event_id = uuid5(NAMESPACE, f"ulpf:{tenant}:{source}:{raw_hash}")

    Note over Pipe: Step 3: Zero-Loss Raw Persistence
    Pipe->>Store: put(event_id, raw_bytes)
    Store->>Store: write to <base>/<shard[:2]>/<shard[2:4]>/<event_id>.raw
    Store-->>Pipe: sha256 digest

    Note over Pipe: Step 4: Detect Log Format
    Pipe->>Det: detect(raw_line, source_tag)
    Det-->>Pipe: format_id (e.g. "cef")

    Note over Pipe: Step 5: Resolve Parser Instance
    Pipe->>Reg: get_parser_for_format("cef")
    Reg-->>Pipe: CEFParser instance

    Note over Pipe: Step 6: Extract Structured Dict
    Pipe->>Parser: extract(raw_line)
    Parser-->>Pipe: extracted dict

    Note over Pipe: Step 7: Declarative Normalization
    Pipe->>Norm: normalize(extracted, "cef")
    Norm-->>Pipe: normalized dict (with vendor_attributes)

    Note over Pipe: Step 8: Build Canonical UES Envelope
    Pipe->>Pipe: _build_ues_event(...) -> ues_event dict

    Note over Pipe: Step 9: IP / Threat Enrichment
    Pipe->>Enrich: enrich(ues_event)
    Enrich-->>Pipe: ues_event (enriched)

    Note over Pipe: Step 10: JSON Schema Validation
    Pipe->>Val: validate_and_route(ues_event)
    Val->>Val: Draft7Validator.validate(ues_event)
    Val-->>Pipe: True (valid)

    Note over Pipe: Step 11: Fan-out to Sinks
    loop For each sink in self.sinks
        Pipe->>Sink: write(ues_event)
    end

    Pipe->>Pipe: self._processed += 1
    Pipe-->>Source: True
    deactivate Pipe
```

---

## 2. Failure Handling & Dead-Letter Sequences

### 2.1 Parser Extraction Failure Sequence

```mermaid
sequenceDiagram
    autonumber
    actor Source as Ingestion Reader
    participant Pipe as Pipeline
    participant Store as FileRawStore
    participant Det as FormatDetector
    participant Parser as BaseParser
    participant DL as _DeadLetterSink (dead_letter.ndjson)

    Source->>Pipe: process_event(raw_line, ...)
    activate Pipe
    Pipe->>Store: put(event_id, raw_bytes)
    Store-->>Pipe: stored

    Pipe->>Det: detect(raw_line)
    Det-->>Pipe: "cisco_asa"

    Pipe->>Parser: extract(raw_line)
    Parser-->>Pipe: raises Exception("Corrupted header tokens")

    Note over Pipe: Exception caught; route to dead-letter
    Pipe->>Pipe: self._errors += 1
    Pipe->>DL: write({schema_version, tenant_id, event_id, ingest_timestamp, raw, error: "Extraction failed: ...", parser: "cisco_asa"})
    DL->>DL: append JSON line to dead_letter.ndjson
    Pipe-->>Source: False
    deactivate Pipe
```

---

### 2.2 Schema Validation Failure Sequence

```mermaid
sequenceDiagram
    autonumber
    actor Source as Ingestion Reader
    participant Pipe as Pipeline
    participant Norm as NormalizationEngine
    participant Val as Validator (core/validation.py)
    participant DL as dead_letter.ndjson

    Source->>Pipe: process_event(...)
    activate Pipe
    Pipe->>Norm: normalize(...)
    Norm-->>Pipe: normalized dict
    Pipe->>Pipe: _build_ues_event(...) -> ues_event

    Pipe->>Val: validate_and_route(ues_event)
    activate Val
    Val->>Val: Draft7Validator.iter_errors(ues_event)
    Note over Val: Errors found: [$.event.severity_numeric: 'high' is not of type 'number']
    Val->>Val: self._invalid_count += 1
    Val->>DL: write({event_id, raw_payload, errors, timestamp})
    Val-->>Pipe: False
    deactivate Val

    Pipe->>Pipe: self._errors += 1
    Pipe-->>Source: False
    deactivate Pipe
```

---

### 2.3 Sink Write Failure & At-Least-Once Delivery Sequence

```mermaid
sequenceDiagram
    autonumber
    participant Pipe as Pipeline
    participant Sink1 as NDJSONFileSink
    participant Sink2 as KafkaProducerSink
    participant DL as _DeadLetterSink (dead_letter.ndjson)

    Pipe->>Sink1: write(ues_event)
    Sink1-->>Pipe: success

    Pipe->>Sink2: write(ues_event)
    Sink2-->>Pipe: raises KafkaTimeoutError("Broker unreachable")

    Note over Pipe: Sink write error caught
    Pipe->>Pipe: self._errors += 1
    Pipe->>DL: write({ ...ues_event, _sink_error: "Broker unreachable", _failed_sink: "KafkaProducerSink" })
    DL->>DL: append to dead_letter.ndjson
    Pipe-->>Pipe: returns False
```

---

## 3. Multi-Worker Parallel Pipeline Sequence

```mermaid
sequenceDiagram
    autonumber
    actor User as User CLI (ulpf ingest -w 4)
    participant Main as ParallelPipeline (core/worker_pool.py)
    participant Pool as multiprocessing.Pool
    participant Worker1 as Worker Process 0 (_worker_process)
    participant Worker2 as Worker Process 1 (_worker_process)
    participant Pipe1 as Pipeline (Worker 0 instance)
    participant Pipe2 as Pipeline (Worker 1 instance)

    User->>Main: run(reader)
    activate Main
    Main->>Main: chunk_iter = _chunks(reader, chunk_size=500)
    
    Main->>Pool: imap_unordered(bound_worker, chunks)
    activate Pool

    Pool->>Worker1: _worker_process((chunk_0, 0, tenant_id), factory)
    activate Worker1
    Worker1->>Pipe1: instantiate Pipeline via factory()
    loop For each event in chunk_0
        Worker1->>Pipe1: process_event(...)
    end
    Worker1->>Pipe1: validator.close(), sinks.close()
    Worker1-->>Pool: returns stats_0 {processed: 500, valid: 500, invalid: 0, errors: 0}
    deactivate Worker1

    Pool->>Worker2: _worker_process((chunk_1, 1, tenant_id), factory)
    activate Worker2
    Worker2->>Pipe2: instantiate Pipeline via factory()
    loop For each event in chunk_1
        Worker2->>Pipe2: process_event(...)
    end
    Worker2->>Pipe2: validator.close(), sinks.close()
    Worker2-->>Pool: returns stats_1 {processed: 500, valid: 498, invalid: 2, errors: 2}
    deactivate Worker2

    Pool-->>Main: yields stats_0, stats_1...
    deactivate Pool

    Main->>Main: merge stats dictionaries
    Main-->>User: returns {processed: 1000, valid: 998, invalid: 2, errors: 2}
    deactivate Main
```

---

## 4. Canonical Event Lifecycle Table

| Stage | Component | Input | Output | Transformation | Raw Data Preserved? |
|---|---|---|---|---|---|
| **0. Raw Ingest** | `FileReader` / `StdinReader` | OS Stream Bytes | `RawEvent` dataclass | Binary decode with `surrogateescape` | **YES (100%)** |
| **1. Digest & ID** | `Pipeline.process_event` | `RawEvent` | `raw_hash`, `event_id` | SHA-256 calculation & UUIDv5 derivation | **YES** |
| **2. Raw Storage** | `FileRawStore.put` | `(event_id, raw_bytes)` | Disk file path | Sharded binary file write | **YES (100% exact replica)** |
| **3. Format Detection** | `FormatDetector.detect` | `(raw_line, source_tag)` | `format_id: str` | Regex / structure classification | **YES** |
| **4. Parser Extraction** | `BaseParser.extract` | `raw_line: str` | `extracted: dict[str, Any]` | Regex / token splitting / timestamp parsing | **YES** |
| **5. Normalization** | `NormalizationEngine.normalize` | `extracted: dict` | `normalized: dict` | Declarative YAML mapping, category/outcome inference, unmapped keys to `vendor_attributes` | **YES** |
| **6. UES Assembly** | `Pipeline._build_ues_event` | Components dicts | `ues_event: dict` | Standard UES 1.2.0 JSON dictionary assembly | **YES (`raw.raw_payload`)** |
| **7. IP Enrichment** | `IPEnrichmentPlugin.enrich` | `ues_event: dict` | `ues_event: dict` | In-place annotation of `enrichment` block | **YES** |
| **8. Validation Gate** | `Validator.validate_and_route` | `ues_event: dict` | `bool` | JSON Schema Draft 7 validation against `ues_schema.json` | **YES** |
| **9. Sink Fan-out** | `<Sink>.write` | `ues_event: dict` | Destination payload | Format serialization (NDJSON, Parquet, Kafka, CEF, LEEF) | **YES** |
| **10. Indexing** | `EventIndexer.sync_from_ndjson` | `events.ndjson` records | SQLite table row | Relational extraction into `events_index` | **YES (`full_event_json`)** |
