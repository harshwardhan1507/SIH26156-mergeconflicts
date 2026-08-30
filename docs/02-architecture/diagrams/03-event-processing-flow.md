# 03 — Complete Event Processing Flow

This diagram details the full single-event lifecycle through `Pipeline.process_event()`, explicitly illustrating every data transformation step and all decision/error branches.

---

## Detailed Event Flow Diagram

```mermaid
flowchart TD
    START(["Raw Event Ingestion\n(raw_line: str, raw_bytes: bytes, source_tag: str)"]) --> STEP1

    subgraph STEP1_DIGEST["Step 1: Cryptographic Digest & Event ID"]
        STEP1["Synchronize raw bytes (surrogateescape)\nCompute SHA-256 Digest (raw_hash)"]
        STEP2["Generate Deterministic UUIDv5\nevent_id = uuid5(NAMESPACE, 'ulpf:tenant:source:hash')"]
        STEP1 --> STEP2
    end

    subgraph STEP2_RAW_STORE["Step 2: Pre-Parse Forensic Persistence"]
        STEP3["FileRawStore.put(event_id, raw_bytes)\nWrite to <base>/<aa>/<bb>/<event_id>.raw"]
        STEP2 --> STEP3
    end

    subgraph STEP3_DETECTION["Step 3: Format Classification"]
        STEP4["FormatDetector.detect(raw_line, source_tag)\n(Overrides -> Regex -> JSON/CSV -> Parser Registry)"]
        STEP3 --> STEP4
        MATCH_CHECK{"Parser Matched\nor Found in Registry?"}
        STEP4 --> MATCH_CHECK
    end

    subgraph STEP4_EXTRACTION["Step 4: Parser Extraction"]
        PARSE_EXEC["parser.extract(raw_line)\nParse Header, Timestamps, Attributes"]
        MATCH_CHECK -->|Yes (e.g. 'cisco_asa')| PARSE_EXEC
        EXTRACT_CHECK{"Extraction\nSucceeded?"}
        PARSE_EXEC --> EXTRACT_CHECK
    end

    subgraph STEP5_NORM["Step 5: Normalization & Vendor Bag"]
        NORM_EXEC["NormalizationEngine.normalize(extracted, parser.name)\nApply YAML rules, Taxonomy, OCSF UID"]
        EXTRACT_CHECK -->|Yes: extracted dict| NORM_EXEC
        VENDOR_BAG["Preserve unmapped keys in vendor_attributes\nAssemble Canonical UES 1.2.0 Event Dict"]
        NORM_EXEC --> VENDOR_BAG
    end

    subgraph STEP6_ENRICH["Step 6: Context Enrichment"]
        ENRICH_EXEC["IPEnrichmentPlugin.enrich(ues_event)\nMatch RFC1918, Cloud Provider, Threat CIDRs"]
        VENDOR_BAG --> ENRICH_EXEC
    end

    subgraph STEP7_VALIDATION["Step 7: Schema Validation Gate"]
        VAL_EXEC{"Validator.validate_and_route(ues_event)\nDraft7Validator against ues_schema.json"}
        ENRICH_EXEC --> VAL_EXEC
    end

    subgraph STEP8_SINKS["Step 8: Multi-Sink Egress Delivery"]
        SINK_LOOP["Fan-out to configured sinks\nsink.write(ues_event)"]
        VAL_EXEC -->|Valid Event| SINK_LOOP
        SINK_CHECK{"Sink Write\nSucceeded?"}
        SINK_LOOP --> SINK_CHECK
        SINK_SUCCESS(["Success: Processed Counter Incremented\nReturn True"])
        SINK_CHECK -->|All Sinks OK| SINK_SUCCESS
    end

    subgraph FAILURES["Quarantine & Dead-Letter Paths"]
        DL_UNMATCHED["Route to Dead-Letter Sink:\n{error: 'No parser matched format'}"]
        DL_EXTRACT["Route to Dead-Letter Sink:\n{error: 'Extraction failed: ...', parser}"]
        DL_SCHEMA["Route to Dead-Letter Sink:\n{event_id, errors: [JSONPath errors]}"]
        DL_SINK["Route to Dead-Letter Sink:\n{...ues_event, _sink_error, _failed_sink}"]
        
        MATCH_CHECK -->|No ('unknown')| DL_UNMATCHED
        EXTRACT_CHECK -->|Exception| DL_EXTRACT
        VAL_EXEC -->|Invalid Schema| DL_SCHEMA
        SINK_CHECK -->|Sink Error| DL_SINK

        DL_FILE[("dead_letter.ndjson")]
        DL_UNMATCHED --> DL_FILE
        DL_EXTRACT --> DL_FILE
        DL_SCHEMA --> DL_FILE
        DL_SINK --> DL_FILE

        FAIL_EXIT(["Failure: Error Counter Incremented\nReturn False"])
        DL_FILE --> FAIL_EXIT
    end
```

---

## Evidence

| Processing Stage | Source File | Method / Line Reference | Confidence |
|---|---|---|---|
| SHA-256 & UUIDv5 Generation | `ulpf/core/pipeline.py:111-116` | `hashlib.sha256()`, `uuid.uuid5()` | **CONFIRMED** |
| Pre-Parse Raw Persistence | `ulpf/core/pipeline.py:118-119` | `self.raw_store.put(event_id, raw_bytes)` | **CONFIRMED** |
| Format Detection & Fallback Loop | `ulpf/core/pipeline.py:122-133` | `self.detector.detect()`, loop over `get_all_parsers()` | **CONFIRMED** |
| Unmatched Parser Dead-Letter | `ulpf/core/pipeline.py:134-155` | `self.validator.dead_letter_sink.write(dead_letter_record)` | **CONFIRMED** |
| Parser Extraction & Error Catch | `ulpf/core/pipeline.py:158-183` | `parser.extract(raw_line)`, exception handler | **CONFIRMED** |
| Normalization & UES Assembly | `ulpf/core/pipeline.py:185-206` | `self.norm_engine.normalize()`, `_build_ues_event()` | **CONFIRMED** |
| IP & Threat Context Enrichment | `ulpf/core/pipeline.py:209-214` | `self.enrichment.enrich(ues_event)` | **CONFIRMED** |
| Schema Validation Gate | `ulpf/core/pipeline.py:216-220` | `self.validator.validate_and_route(ues_event)` | **CONFIRMED** |
| Sink Fan-Out & Write Error Quarantine | `ulpf/core/pipeline.py:222-240` | `sink.write(ues_event)`, `dead_letter_sink.write()` | **CONFIRMED** |
