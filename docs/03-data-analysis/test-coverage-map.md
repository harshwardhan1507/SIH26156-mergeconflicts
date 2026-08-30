# Test Coverage & Verification Mapping

This document provides a line-by-line inspection of the 21 test files under `ulpf/tests/`, mapping each test module to the actual capabilities verified, edge-case coverage, and important untested scenarios.

---

## 1. Test Suite Coverage Inventory

| Test Module | Target Subsystem / File | Key Test Cases Implemented | What Is Tested? | Important Untested Cases / Coverage Gaps |
|---|---|---|---|---|
| **`test_criteria_conformance.py`** | Full System Criteria (a - h) | Tests (a) through (h) programmatic compliance | Raw byte preservation, vendor attribute retention, OCSF mapping, UUIDv5 traceability, plug-and-play registry, syslog listener socket, Parquet lake, 24-dim features | Replay across multi-year boundaries; corrupted Parquet table recovery |
| **`test_detector.py`** | `ulpf/core/detector.py` | `test_detector_*` | Priority regexes (ASA, CEF, LEEF, RFC5424, XML), JSON signatures, PAN CSV, BSD syslog, overrides | Detection under heavy ReDoS fuzzing; ambiguous JSON schemas |
| **`test_parser_cef.py`** | `ulpf/parsers/cef.py` | `test_cef_*` | Standard 8-pipe headers, syslog prefix, space-separated extension pairs, timestamp extraction | Extension values with unescaped equals signs (`=`); multiline CEF extensions |
| **`test_parser_leef.py`** | `ulpf/parsers/leef.py` | `test_leef_*` | LEEF 1.0, LEEF 2.0 with custom delimiter (`^`), syslog wrapper, tab attributes | LEEF attributes containing escaped tab delimiters |
| **`test_parser_cisco_asa.py`** | `ulpf/parsers/cisco_asa.py` | `test_cisco_asa_*` | ASA-6-106100, ASA-2-106016, ASA-5-304001, ACL rules, 5-tuples | **IPv6 connection logs**; non-standard mnemonic formats |
| **`test_parser_paloalto.py`** | `ulpf/parsers/paloalto_csv.py` | `test_paloalto_*` | Standard 35-column traffic log, action mapping, zone direction, `_vendor_extra` | PAN-OS Threat logs; System logs; malformed CSV with unescaped quotes |
| **`test_parser_cloudtrail.py`**| `ulpf/parsers/aws_cloudtrail.py`| `test_cloudtrail_*` | S3 GetObject, IAM DeleteUser AccessDenied, category inference, error outcome | CloudTrail log file `Records: [...]` batch arrays |
| **`test_parser_azure.py`** | `ulpf/parsers/azure_monitor.py` | `test_azure_*` | Activity logs, Key Vault 403, ResourceId path decomposition | Diagnostic metrics logs; Azure Storage analytics |
| **`test_parser_gcp.py`** | `ulpf/parsers/gcp_audit.py` | `test_gcp_*` | Cloud Storage, KMS Key destroy, authorization grant check, method action | Multi-audit log streams; GCP VPC Flow logs |
| **`test_parser_rfc3164.py`** | `ulpf/parsers/syslog_rfc3164.py`| `test_rfc3164_*` | BSD syslog headers, PID extraction, year injection, priority/facility split | **Historical logs spanning past years** (year-rollover bug) |
| **`test_parser_rfc5424.py`** | `ulpf/parsers/syslog_rfc5424.py`| `test_rfc5424_*` | RFC 5424 header, structured data `[SDID@... key="val"]`, NIL values (`-`) | Multiple structured data elements with duplicate keys |
| **`test_parser_xml.py`** | `ulpf/parsers/xml_generic.py` | `test_xml_*` | Windows EventIDs 4624, 4625, 1102, EventData parameter extraction | Non-Windows XML schemas; corrupted XML tags |
| **`test_parser_json.py`** | `ulpf/parsers/json_passthrough.py`| `test_json_*` | Generic JSON logs, MySQL Audit JSON, OpenVPN JSON gateway logs | Deeply nested JSON (depth > 5); JSON arrays at root |
| **`test_e2e.py`** | End-to-End Pipeline | `test_pipeline_e2e_*` | Ingest -> RawStore -> Normalizer -> Validator -> NDJSON -> DeadLetter | High-concurrency socket flooding; disk full during sink write |
| **`test_enrichment_ip.py`** | `ulpf/enrichment/ip_enrichment.py` | `test_ip_*` | RFC 1918 private IP, Tor exit node threat match, AWS/Azure/GCP cloud CIDR | IPv6 threat intel CIDR matching; custom threat feed reload |
| **`test_analytics_anomaly.py`**| `ulpf/analytics/anomaly.py` | `test_anomaly_*` | Rolling Z-score (>3σ), Bytes IQR outlier, burst detection, auth failure chain | Dynamic model retraining on millions of events |
| **`test_worker_pool.py`** | `ulpf/core/worker_pool.py` | `test_parallel_*` | Multi-worker parallel processing across CPU processes | Worker process crash mid-chunk handling |
| **`test_dashboard.py`** | `ulpf/dashboard/app.py` | `test_api_*` | `/api/stats`, `/api/events`, `/api/parsers`, `/api/export`, `/api/reindex` | Starlette TestClient / httpx async lifespan compatibility |
| **`test_live_monitor.py`** | `ulpf/collectors/live_monitor.py` | `test_live_monitor_*` | Process tracking, TCP/UDP socket capture, buffer isolation | Native Win32 API execution on non-Windows test runners |

---

## 2. Identified Test Execution Blockers

1. **Starlette TestClient / HTTPX Async Fixture Warning**:
   - In `ulpf/tests/test_live_monitor.py` and `test_dashboard.py`, direct instantiation of `TestClient(app)` triggers a RuntimeError when Starlette's lifespan handler is executed in sub-test fixtures without an explicit event loop.
   - Master suite `test_all.py` passes all 69 criteria checks via standalone HTTP requests to the live server, but direct `pytest ulpf/tests/` encounters fixture errors in these two test files.
