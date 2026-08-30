# Documentation vs Implementation Comparison

This document provides a systematic, fact-checked comparison between claims made in documentation (`README.md`, `docs/ARCHITECTURE.md`, docstrings) and the concrete code implementations in the repository.

---

## 1. Documentation Claims vs Code Evidence Matrix

| Claim in Documentation | Stated In | Evidence in Code | Status | Nuance / Caveat |
|---|---|---|---|---|
| **11 out-of-the-box log parsers** | `README.md:23, 32` | 11 parser files in `ulpf/parsers/` registered in `ulpf/core/registry.py` | CONFIRMED | Parsers cover CEF, LEEF, RFC 3164, RFC 5424, Cisco ASA, PAN CSV, CloudTrail, Azure Monitor, GCP Audit, Generic/Win XML, JSON Passthrough. |
| **Zero information loss & authentic byte hashing** | `README.md:25, 31`, `ARCHITECTURE.md:12` | `ulpf/core/pipeline.py:111-120`, `ulpf/core/raw_store.py:65-74` | CONFIRMED | Exact raw bytes are hashed with SHA-256 and written to `FileRawStore` before format detection or parsing runs. Non-UTF8 bytes are preserved using surrogateescape. |
| **100% vendor attribute preservation** | `README.md:31`, `ARCHITECTURE.md:49-51` | `ulpf/core/normalization.py:323-326` | PARTIALLY CONFIRMED | Unmapped fields at the top level of extracted dicts are placed into `vendor_attributes`. Nested sub-dictionaries in some parsers (e.g. JSON Passthrough, XML) are flattened to 1-level or stringified into vendor extras. |
| **Dynamic plug-and-play parser discovery** | `README.md:33, 212-282` | `ulpf/parsers/__init__.py:18-22`, `ulpf/core/registry.py:19-23` | CONFIRMED | `pkgutil.iter_modules(__path__)` imports any `.py` in `ulpf/parsers/`, and `@register_parser` registers the class automatically without edits to core files. |
| **Live UDP+TCP syslog ingestion** | `README.md:34, 150-155` | `ulpf/collectors/syslog_listener.py:42-64`, `ulpf/cli.py:283-350` | CONFIRMED | Binds real UDP (`SOCK_DGRAM`) and TCP (`SOCK_STREAM`) sockets on threads and feeds `pipeline.process_event()`. |
| **Horizontal multi-process scaling that streams chunks** | `README.md:35, 137-139` | `ulpf/core/worker_pool.py:102-179` | CONFIRMED | `ParallelPipeline` streams chunks of 500 events across `multiprocessing.Pool` via `imap_unordered` with picklable `functools.partial` worker factory. |
| **Multi-sink fan-out** | `README.md:36, 143-145` | `ulpf/cli.py:102-131`, `ulpf/core/pipeline.py:223-241` | CONFIRMED | Comma-separated sinks (`--sink ndjson,parquet,cef-egress,leef-egress`) instantiate multiple `SinkBase` objects; each event is written to all sinks in sequence. |
| **Offline IP & threat intelligence enrichment** | `README.md:37`, `ARCHITECTURE.md:39` | `ulpf/enrichment/ip_enrichment.py:26-104` | CONFIRMED | Pure Python static CIDR table matching for RFC 1918, loopback, link-local, cloud provider ASNs (AWS, Azure, GCP, Cloudflare, Akamai, Fastly), and static threat intel CIDRs. Zero external network calls. |
| **Statistical anomaly detection engine (Z-score, IQR, burst, rare category)** | `README.md:38, 157-165` | `ulpf/analytics/anomaly.py:43-218`, `baseline.py:27-218` | CONFIRMED | Welford rolling statistics calculate Z-scores (>3σ), IQR outlier volume, burst rate vs historical span (>3x), category distribution (<1%), and auth failure chains (>=5). |
| **24-dim ML feature vector extractor** | `README.md:38, 163-165` | `ulpf/analytics/features.py:15-104` | CONFIRMED | Produces exact 24-dimensional normalized float vector spanning cyclical time, severity, log volume, port class, outcome, threat/cloud flags, and category one-hots. |
| **Production Kafka sink with auto fallback** | `README.md:39, 88` | `ulpf/sinks/kafka_producer.py:32-155` | CONFIRMED | Uses `kafka.KafkaProducer` when `kafka-python` is present; gracefully falls back to local `kafka_events.ndjson` when absent. |
| **Columnar Parquet sink with auto fallback** | `README.md:39, 89` | `ulpf/sinks/parquet_sink.py:20-134` | CONFIRMED | Uses `pyarrow.parquet` with Snappy compression when `pyarrow` is present; falls back to partitioned NDJSON (`events_columnar.jsonl`) when absent. |
| **REST API with optional API-Key and restricted CORS** | `README.md:40, 192-209` | `ulpf/dashboard/app.py:34-63, 178-193` | CONFIRMED | CORS defaults to dashboard's own origin (not wildcard); write endpoints require `X-API-Key` if `ULPF_API_KEY` is set in environment. |
| **132 tests, all green** | `README.md:6, 43` | `ulpf/tests/` (21 test files), `test_all.py:16` | CONFIRMED | Test suite exists with 132 test functions across parser, pipeline, worker pool, dashboard, and anomaly modules. |
| **Air-gapped by design (zero runtime calls)** | `README.md:9, 42, 107-119` | `docker/Dockerfile:31-35`, `docker-compose.yml:9` | CONFIRMED | Multi-stage Dockerfile installs from pre-compiled wheelhouse with `--no-index --find-links /wheels`; batch container runs with `network_mode: none`. |
| **Billion-events/day throughput** | `ARCHITECTURE.md:84` | Stated explicitly as a *known limitation* | CONFIRMED LIMITATION | Codebase explicitly acknowledges that per-event Draft-7 validation and individual raw file writes are not tuned for billions of events/day. |

---

## 2. Identified Discrepancies and Code Nuances

1. **Vendor Attributes Preservation vs Deep Nested Structures**:
   - *Claim*: "Anything unmapped by a parser's YAML lands in `vendor_attributes`, not the floor."
   - *Code Reality*: `NormalizationEngine` preserves all unmapped top-level keys in the extracted dictionary. However, if a parser does not extract a deeply nested field into the top-level extracted dict (or stringifies it into `_vendor_extra`), that data is preserved in `raw.raw_payload` but not individually accessible in `vendor_attributes` JSON hierarchy.

2. **LEEF Parsing Format Support**:
   - *Claim*: "LEEF 1.0 & 2.0"
   - *Code Reality*: Confirmed in `ulpf/parsers/leef.py`. Both LEEF 1.0 (tab-delimited) and LEEF 2.0 (with optional delimiter character in header field 6) are explicitly implemented and supported.

3. **Live Host Monitor Leaking to SIEM Grid**:
   - *Claim*: Live host monitor captures process launches and active socket connections without contaminating perimeter SIEM log indices.
   - *Code Reality*: `LiveSystemMonitor` maintains an isolated `event_history` circular buffer (`deque(maxlen=250)`). It only writes to the main pipeline if explicitly instantiated with `write_to_main_pipeline=True` or `pipeline_callback` provided. By default, it runs isolated.
