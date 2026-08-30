# 07 — Malformed Event & Quarantine Routing Diagram

This diagram visualizes how malformed bytes, extraction exceptions, schema validation violations, and sink errors are contained and routed to the unified dead-letter quarantine queue.

---

## Malformed Event Routing Diagram

```mermaid
flowchart TD
    RAW_INPUT(["Incoming Raw Log Event"]) --> STEP_INGEST

    subgraph PIPELINE_STAGES["Pipeline Execution Stages"]
        STEP_INGEST["1. Ingestion & Pre-Parse Storage\n(raw_bytes written to FileRawStore)"]
        STEP_DETECT["2. Format Detection\nFormatDetector.detect(raw_line)"]
        STEP_PARSE["3. Parser Extraction\nparser.extract(raw_line)"]
        STEP_NORM["4. Normalization Engine\nNormalizationEngine.normalize()"]
        STEP_VAL["5. JSON Schema Gate\nValidator.validate_and_route()"]
        STEP_SINK["6. Sink Delivery\nsink.write(ues_event)"]
        
        STEP_INGEST --> STEP_DETECT --> STEP_PARSE --> STEP_NORM --> STEP_VAL --> STEP_SINK
    end

    subgraph EXCEPTION_HANDLERS["Exception Catch Sites in Pipeline"]
        CATCH_UNMATCHED{"Parser Found in\nRegistry or Fallback?"}
        CATCH_EXTRACT{"try ... except Exception\n(Parser Extraction Failure)"}
        CATCH_NORM{"try ... except Exception\n(Normalization Failure)"}
        CATCH_VAL{"validate(ues_event)\n(Schema Draft 7 Violation)"}
        CATCH_SINK{"try ... except Exception\n(Sink Write Exception)"}
    end

    STEP_DETECT --> CATCH_UNMATCHED
    STEP_PARSE --> CATCH_EXTRACT
    STEP_NORM --> CATCH_NORM
    STEP_VAL --> CATCH_VAL
    STEP_SINK --> CATCH_SINK

    subgraph QUARANTINE_QUEUE["Unified Dead-Letter Queue (output/dead_letter.ndjson)"]
        REC_UNMATCHED["Record Type A: Unmatched Format\n{\n  'event_id': uuid,\n  'raw': {'raw_payload', 'raw_hash'},\n  'error': 'No parser matched format',\n  'source_tag': str\n}"]
        
        REC_EXTRACT["Record Type B: Extraction Failure\n{\n  'event_id': uuid,\n  'raw': {'raw_payload', 'raw_hash'},\n  'error': 'Extraction failed: <exc>',\n  'parser': str,\n  'source_tag': str\n}"]
        
        REC_SCHEMA["Record Type C: Schema Validation Error\n{\n  'event_id': uuid,\n  'raw_payload': str,\n  'errors': ['$.event.category: ...'],\n  'timestamp': ISO8601\n}"]
        
        REC_SINK["Record Type D: Sink Delivery Error\n{\n  ...full_ues_event,\n  '_sink_error': str(exc),\n  '_failed_sink': 'KafkaProducerSink'\n}"]

        DL_FILE[("output/dead_letter.ndjson\n(Single Quarantine Queue)")]
        
        REC_UNMATCHED --> DL_FILE
        REC_EXTRACT --> DL_FILE
        REC_SCHEMA --> DL_FILE
        REC_SINK --> DL_FILE
    end

    CATCH_UNMATCHED -->|No / 'unknown'| REC_UNMATCHED
    CATCH_EXTRACT -->|Parse Exception| REC_EXTRACT
    CATCH_NORM -->|Norm Exception| LOG_WARN["Log Warning & Increment _errors\n(Return False)"]
    CATCH_VAL -->|Invalid Schema| REC_SCHEMA
    CATCH_SINK -->|Sink Exception| REC_SINK
```

---

## Evidence

| Failure Catch Site | Source File | Line / Handler | Confidence |
|---|---|---|---|
| Unmatched Parser Dead-Letter | `ulpf/core/pipeline.py:134-155` | `dead_letter_sink.write(dead_letter_record)` | **CONFIRMED** |
| Parser Extraction Exception | `ulpf/core/pipeline.py:160-183` | `except Exception as exc:` routes to `dead_letter_sink` | **CONFIRMED** |
| Schema Validation Error Record | `ulpf/core/validation.py:68-78` | `Validator.validate_and_route()`, writes `dl_record` | **CONFIRMED** |
| Sink Write Failure Catch | `ulpf/core/pipeline.py:226-239` | `except Exception as exc:` appends `_sink_error` | **CONFIRMED** |
| Unified Dead-Letter File Handle | `ulpf/core/validation.py:44-47` | `_dl_fh = open(self.dead_letter_path, 'a', ...)` | **CONFIRMED** |
