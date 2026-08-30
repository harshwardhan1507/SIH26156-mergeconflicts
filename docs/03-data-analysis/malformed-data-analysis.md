# Malformed & Adversarial Data Flow Analysis

This document provides a stage-by-stage analysis of how corrupted, truncated, non-standard, or adversarial log payloads are handled across every phase of the ULPF pipeline.

---

## 1. Stage-by-Stage Malformed Data Behavior Matrix

| Pipeline Stage | Malformed Input Scenario | Exception Class Raised | Handled / Uncaught? | Pipeline Continuation | Raw Byte Stored? | Dead-Letter Record Structure & Routing |
|---|---|---|---|---|---|---|
| **0. Ingestion Stream** | Unreadable file / permission error on disk | `OSError` / `PermissionError` | Handled (`FileReader.read()`) | **Continues** (skips unreadable file) | No (File cannot be opened) | Logged to stderr; not sent to dead-letter. |
| **0. Binary Decoding** | Invalid UTF-8 / corrupted bytes (e.g. `\x80\xff\xfe`) | None (`surrogateescape` codec) | Handled (`surrogateescape`) | **Continues** | **YES (100%)** | Decoded to surrogate codepoints; proceeds normally to pipeline. |
| **1. Identity Derivation** | Non-string / corrupted payload | None (`hashlib.sha256`, `uuid5`) | Handled | **Continues** | **YES** | Deterministic SHA-256 and UUIDv5 calculated normally. |
| **2. Raw Store** | Path traversal attempt in event ID (`../../etc/passwd`) | `InvalidEventIdError` | Handled (`FileRawStore._path()`) | **Halts event** | No | Throws `InvalidEventIdError`, blocking filesystem access. |
| **3. Format Detection** | Random binary garbage / unsupported syntax | None (returns `'unknown'`) | Handled (`FormatDetector.detect()`) | **Continues** | **YES** | Routed to dead-letter: `{event_id, raw_payload, error: 'No parser matched format', source_tag}`. |
| **4. Parser Extraction** | Truncated header / missing delimiters / regex mismatch | `ParseError` (or arbitrary `Exception`) | Handled (`Pipeline.process_event()`) | **Continues** | **YES** | Routed to dead-letter: `{event_id, raw_payload, error: 'Extraction failed: ...', parser, source_tag}`. |
| **5. Normalization** | Corrupted extracted dict / invalid type | `Exception` | Handled (`Pipeline.process_event()`) | **Continues** | **YES** | Warning logged, `self._errors += 1`, returns `False`. |
| **6. Validation Gate** | Missing required property / invalid enum / type mismatch | `ValidationError` (`jsonschema`) | Handled (`Validator.validate_and_route()`) | **Continues** | **YES** | Routed to dead-letter: `{event_id, raw_payload, errors: [JSONPath errors], timestamp}`. |
| **7. Sink Delivery** | Network drop / disk full / broker timeout | `KafkaError` / `OSError` | Handled (`Pipeline.process_event()`) | **Continues** | **YES** | Routed to dead-letter: `{...ues_event, _sink_error: str(exc), _failed_sink: ...}`. |

---

## 2. Granular Quarantine & Containment Analysis

### 2.1 The Single Quarantine Queue Design (`_DeadLetterSink`)
* In `ulpf/core/validation.py:21-48`, the `Validator` exposes `self.dead_letter_sink` wrapping the append-only `dead_letter.ndjson` file handle with line buffering (`buffering=1`).
* **Unified Containment Contract**:
  - Detection failures (no parser matched)
  - Parser extraction exceptions (corrupted syntax)
  - Schema validation violations (Draft 7 schema errors)
  - Sink delivery exceptions (remote connection drops)
* **All failure records write to the same `output/dead_letter.ndjson` file**, allowing incident response and data engineering teams to inspect and replay all failed events from a single location.

### 2.2 ReDoS & Fuzzing Resistance
* Parsers avoiding regular expressions (e.g. `PaloAltoCSVParser` using Python's standard `csv` module and `JSONPassthroughParser` using C-accelerated `json.loads()`) are immune to regex Denial of Service.
* Parsers with compiled regular expressions (`CEFParser`, `LEEFParser`, `CiscoASAParser`, `SyslogRFC3164Parser`, `SyslogRFC5424Parser`) use strictly anchored, non-recursive patterns.
* Malformed input strings terminate matching immediately upon finding an unexpected delimiter without unbounded backtracking.
