# 11 — Failure Boundaries & Error Flow

This diagram maps every failure boundary, exception catch site, fallback mechanism, and quarantine routing path in the ULPF framework.

---

## Failure Flow Diagram

```mermaid
flowchart TD
    INPUT_SRC(["Incoming Log Event / File"]) --> INGEST_STAGE

    subgraph STAGE_INGEST["1. Ingestion Failure Boundary"]
        INGEST_STAGE["FileReader.read() / StdinReader.read()"]
        INGEST_ERR{"File Unreadable\nor Missing?"}
        INGEST_LOG["Log Warning & Skip File\n(Pipeline Continues with Next File)"]
        INGEST_OK["Yield RawEvent\n(surrogateescape bytes)"]
        
        INGEST_STAGE --> INGEST_ERR
        INGEST_ERR -->|Yes| INGEST_LOG
        INGEST_ERR -->|No| INGEST_OK
    end

    subgraph STAGE_RAW_STORE["2. Raw Storage Boundary"]
        RAW_STORE_STAGE["FileRawStore.put(event_id, raw_bytes)"]
        UUID_VALID{"event_id Valid UUID?"}
        TRAVERSAL_ERR["Raise InvalidEventIdError\n(Blocks Path Traversal)"]
        RAW_WRITE_OK["Write exact bytes to disk\n<base>/<aa>/<bb>/<id>.raw"]
        
        INGEST_OK --> RAW_STORE_STAGE --> UUID_VALID
        UUID_VALID -->|No| TRAVERSAL_ERR
        UUID_VALID -->|Yes| RAW_WRITE_OK
    end

    subgraph STAGE_DETECTION["3. Detection & Parser Selection Boundary"]
        DET_STAGE["FormatDetector.detect(raw_line)"]
        PARSER_LOOKUP{"Parser Found\nin Registry?"}
        FALLBACK_LOOP{"Match Found in\nget_all_parsers()?"}
        PARSER_RESOLVED["Parser Instantiated\n(e.g. CiscoASAParser)"]
        
        RAW_WRITE_OK --> DET_STAGE --> PARSER_LOOKUP
        PARSER_LOOKUP -->|Yes| PARSER_RESOLVED
        PARSER_LOOKUP -->|No / 'unknown'| FALLBACK_LOOP
        FALLBACK_LOOP -->|Yes| PARSER_RESOLVED
    end

    subgraph STAGE_EXTRACTION["4. Extraction Failure Boundary"]
        EXTRACT_STAGE["parser.extract(raw_line)"]
        EXTRACT_TRY{"try ... except Exception"}
        EXTRACT_OK["extracted dict[str, Any]"]
        
        PARSER_RESOLVED --> EXTRACT_STAGE --> EXTRACT_TRY
        EXTRACT_TRY -->|Success| EXTRACT_OK
    end

    subgraph STAGE_NORMALIZATION["5. Normalization Failure Boundary"]
        NORM_STAGE["NormalizationEngine.normalize(extracted, parser.name)"]
        NORM_TRY{"try ... except Exception"}
        NORM_OK["normalized dict (UES)"]
        
        EXTRACT_OK --> NORM_STAGE --> NORM_TRY
        NORM_TRY -->|Success| NORM_OK
    end

    subgraph STAGE_VALIDATION["6. Schema Validation Failure Boundary"]
        VAL_STAGE["Validator.validate_and_route(ues_event)"]
        VAL_CHECK{"Draft7Validator\nConforms to ues_schema.json?"}
        VAL_OK["Valid Event (True)"]
        
        NORM_OK --> VAL_STAGE --> VAL_CHECK
        VAL_CHECK -->|Yes| VAL_OK
    end

    subgraph STAGE_SINK["7. Sink Write Failure Boundary"]
        SINK_STAGE["sink.write(ues_event)\n(For each configured sink)"]
        SINK_TRY{"try ... except Exception"}
        SINK_OK["Delivered to Sink\n(events.ndjson / Parquet / Kafka / CEF)"]
        
        VAL_OK --> SINK_STAGE --> SINK_TRY
        SINK_TRY -->|Success| SINK_OK
    end

    subgraph QUARANTINE_SINK["8. Unified Dead-Letter Quarantine (dead_letter.ndjson)"]
        DL_UNMATCHED["Record: {error: 'No parser matched format', raw, event_id}"]
        DL_EXTRACT["Record: {error: 'Extraction failed: <exc>', parser, raw, event_id}"]
        DL_SCHEMA["Record: {event_id, raw_payload, errors: [JSONPath errors]}"]
        DL_SINK["Record: {...ues_event, _sink_error: str(exc), _failed_sink}"]
        
        FALLBACK_LOOP -->|No: Unmatched| DL_UNMATCHED
        EXTRACT_TRY -->|Exception| DL_EXTRACT
        VAL_CHECK -->|No: Invalid Schema| DL_SCHEMA
        SINK_TRY -->|Exception| DL_SINK

        DL_FILE[("output/dead_letter.ndjson\n(Preserved for Investigation & Replay)")]
        DL_UNMATCHED --> DL_FILE
        DL_EXTRACT --> DL_FILE
        DL_SCHEMA --> DL_FILE
        DL_SINK --> DL_FILE
    end

    NORM_TRY -->|Exception| NORM_ERR_LOG["Log Warning & Increment _errors\n(Return False)"]
```

---

## Evidence

| Failure Boundary | Source File | Exception Handling / Catch Block | Confidence |
|---|---|---|---|
| Invalid UUID Traversal Guard | `ulpf/core/raw_store.py:46-55` | `_validate_event_id()`, raises `InvalidEventIdError` | **CONFIRMED** |
| Unmatched Parser Dead-Letter | `ulpf/core/pipeline.py:134-155` | `if parser is None:` routes to `dead_letter_sink` | **CONFIRMED** |
| Parser Extraction Exception | `ulpf/core/pipeline.py:160-183` | `except Exception as exc:` routes to `dead_letter_sink` | **CONFIRMED** |
| Normalization Exception | `ulpf/core/pipeline.py:187-190` | `except Exception as exc:` logs warning, `_errors += 1` | **CONFIRMED** |
| Schema Validation Quarantine | `ulpf/core/validation.py:59-79` | `validate_and_route()`, writes JSONPath errors to `dead_letter.ndjson` | **CONFIRMED** |
| Sink Write Exception | `ulpf/core/pipeline.py:226-239` | `except Exception as exc:` catches per sink, routes with `_sink_error` | **CONFIRMED** |
| Kafka Broker Degradation | `ulpf/sinks/kafka_producer.py:86-104` | Catches broker exception, falls back to `output/kafka_events.ndjson` | **CONFIRMED** |
| Parquet PyArrow Absence | `ulpf/sinks/parquet_sink.py:123-129` | `if not HAS_PYARROW:` falls back to `events_columnar.jsonl` | **CONFIRMED** |
