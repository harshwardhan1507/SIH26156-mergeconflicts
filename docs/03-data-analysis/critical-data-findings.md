# Critical Data Findings & Architectural Risk Register

This document catalogs all verified technical limitations, edge-case vulnerabilities, semantic discrepancies, and data model findings discovered during the Phase 2 deep dive.

---

## 1. Categorized Findings Summary

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        PHASE 2 FINDINGS SUMMARY                        │
├─────────────────┬──────────────────┬─────────────────┬─────────────────┤
│ CRITICAL (0)    │ HIGH (4)         │ MEDIUM (5)      │ LOW (3)         │
│ Core SIH Blockers│ Major Limitations│ Interop / Edge  │ Minor Debt      │
└─────────────────┴──────────────────┴─────────────────┴─────────────────┘
```

---

## 2. Granular Risk & Finding Inventory

### Finding F-01: Key-Value Fallback Routes to Dead-Letter Without Extraction
* **Severity**: **HIGH**
* **Requirement Affected**: Plug-and-Play Onboarding / Generic Device Support
* **Source Location**: `ulpf/core/detector.py:133-134`, `ulpf/core/pipeline.py:125-136`
* **Evidence**: `FormatDetector.detect()` matches `\b\w+=\S+` and returns `'kv'`. However, `_REGISTRY` contains no parser named `'kv'`. In `Pipeline.process_event()`, `get_parser_for_format('kv')` returns `None`, routing all Fortinet, Check Point, and key-value logs directly to `dead_letter.ndjson`.
* **Observed Impact**: Key-value log formats from firewalls are categorized as detected format `'kv'` but cannot be parsed or normalized.
* **Confidence**: **CONFIRMED**

---

### Finding F-02: Cisco ASA IPv6 Connection Extraction Limitation
* **Severity**: **HIGH**
* **Requirement Affected**: Network Telemetry / IPv6 Dual-Stack Compliance
* **Source Location**: `ulpf/parsers/cisco_asa.py:40-44`
* **Evidence**: Regex `_ASA_CONN_RE` hardcodes `\d{1,3}(?:\.\d{1,3}){3}` for source and destination IP matching.
* **Observed Impact**: When Cisco ASA firewalls emit connection teardown or ACL logs containing IPv6 addresses (e.g. `2001:db8::1`), `conn_m` fails to match. `src_ip` and `dst_ip` resolve to `None` in the extracted dictionary.
* **Confidence**: **CONFIRMED**

---

### Finding F-03: BSD Syslog Year-Inference Rollover Anomaly
* **Severity**: **HIGH**
* **Requirement Affected**: Timestamp Integrity & Historical Forensics
* **Source Location**: `ulpf/parsers/syslog_rfc3164.py:68-70`, `ulpf/parsers/cisco_asa.py:84-86`
* **Evidence**: When timestamps omit the year (RFC 3164 standard `Aug 15 14:22:10`), the parser prepends `datetime.now(tz=timezone.utc).year`.
* **Observed Impact**: Ingesting historical log archives from 2024 or 2025 assigns the current year (`2026`). Ingesting logs during New Year's Eve across midnight will assign the wrong year to late-arriving packets.
* **Confidence**: **CONFIRMED**

---

### Finding F-04: Pytest Starlette Lifespan Fixture Incompatibility
* **Severity**: **HIGH**
* **Requirement Affected**: Automated Verification & CI/CD
* **Source Location**: `ulpf/tests/test_dashboard.py`, `ulpf/tests/test_live_monitor.py`
* **Evidence**: Instantiating Starlette's `TestClient` against FastAPI's async `lifespan` handler without an active event loop causes test collection to fail when running raw `pytest ulpf/tests/`.
* **Observed Impact**: Master test runner `test_all.py` succeeds via HTTP requests against the live server, but unit testing via `pytest` aborts during test fixture setup.
* **Confidence**: **CONFIRMED**

---

### Finding F-05: Naive Timestamp UTC Assumption
* **Severity**: **MEDIUM**
* **Requirement Affected**: Timezone Normalization
* **Source Location**: `ulpf/parsers/base.py:91-94`
* **Evidence**: `if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)`.
* **Observed Impact**: Log sources emitting local naive timestamps (e.g. `2026-08-30 14:00:00` in IST or PST) are treated as UTC without offset adjustment, shifting event chronology by up to $\pm 12$ hours.
* **Confidence**: **CONFIRMED**

---

### Finding F-06: PAN-OS Threat and System Logs Unhandled by CSV Parser
* **Severity**: **MEDIUM**
* **Requirement Affected**: Vendor Coverage (Palo Alto Networks)
* **Source Location**: `ulpf/parsers/paloalto_csv.py:76, 94-96`
* **Evidence**: `PaloAltoCSVParser` explicitly asserts `cols[2].strip().upper() == 'TRAFFIC'`.
* **Observed Impact**: Palo Alto Networks `THREAT`, `SYSTEM`, `CONFIG`, and `URL` CSV log streams raise `ParseError: Not a TRAFFIC log` and route to `dead_letter.ndjson`.
* **Confidence**: **CONFIRMED**

---

### Finding F-07: IP Threat Flag Decoupled from Event Severity
* **Severity**: **MEDIUM**
* **Requirement Affected**: Threat Intelligence & Risk Scoring
* **Source Location**: `ulpf/enrichment/ip_enrichment.py:199-204`
* **Evidence**: `IPEnrichmentPlugin` annotates `threat_ip_detected = True` but leaves `event.severity_numeric` unmodified.
* **Observed Impact**: Events matching known malicious Tor exit nodes or scanners retain their default source severity (e.g. `5.0`) until downstream `AnomalyDetector` processes them.
* **Confidence**: **CONFIRMED**

---

### Finding F-08: Live Host Monitor Circular Buffer Isolation
* **Severity**: **MEDIUM**
* **Requirement Affected**: Unified Telemetry & Central Search
* **Source Location**: `ulpf/collectors/live_monitor.py:88-89`
* **Evidence**: `write_to_main_pipeline = False` by default.
* **Observed Impact**: Live host process and network telemetry are kept in an in-memory ring buffer (`deque(maxlen=250)`) and do not appear in `events.ndjson` or SQLite historical searches.
* **Confidence**: **CONFIRMED**

---

### Finding F-09: Direction Resolution Zone Keyword Dependency
* **Severity**: **MEDIUM**
* **Requirement Affected**: Network Flow Orientation
* **Source Location**: `ulpf/core/normalization.py:71-80`
* **Evidence**: `_resolve_direction()` only checks for substrings `outside`, `untrust`, and `external`.
* **Observed Impact**: Enterprises using zone names like `WAN`, `Internet`, `DMZ_Out`, or `Public_VLAN` receive `direction = 'unknown'`.
* **Confidence**: **CONFIRMED**

---

### Finding F-10: In-Memory Parquet Buffer Flush on Sudden Process Termination
* **Severity**: **LOW**
* **Requirement Affected**: Durability on Unclean Shutdown
* **Source Location**: `ulpf/sinks/parquet_sink.py:37, 89-93`
* **Evidence**: `ParquetSink` buffers up to 1000 records in memory (`self._buffer`).
* **Observed Impact**: An unhandled `SIGKILL` or power failure before `flush()` drops up to 999 buffered events from the Parquet lake (though they remain preserved in `events.ndjson` and `raw_store`).
* **Confidence**: **CONFIRMED**

---

### Finding F-11: Trailing CRLF Line Delimiter Removal
* **Severity**: **LOW**
* **Requirement Affected**: Strict Bit-Level Raw Identity
* **Source Location**: `ulpf/core/ingestion.py:74`
* **Evidence**: `FileReader` executes `raw_line_bytes.rstrip(b'\r\n')`.
* **Observed Impact**: Line delimiters (`\r\n` or `\n`) are stripped prior to storage and hashing. Internal payload bytes are 100% preserved.
* **Confidence**: **CONFIRMED**

---

### Finding F-12: Single-Level JSON Flattening
* **Severity**: **LOW**
* **Requirement Affected**: Deep Structured JSON Extraction
* **Source Location**: `ulpf/parsers/json_passthrough.py:53-54`
* **Evidence**: Copies top-level keys only; nested objects are preserved as raw dictionaries in `fields`.
* **Observed Impact**: Nested JSON fields (e.g. `user.details.roles[0]`) are not flattened into dotted keys; they are preserved intact in `vendor_attributes`.
* **Confidence**: **CONFIRMED**
