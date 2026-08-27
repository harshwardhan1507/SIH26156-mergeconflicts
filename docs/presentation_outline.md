# Presentation outline (5 slides, ~10 min)

---

## Slide 1 — The problem

**Title:** Why log normalization is harder than it looks

- Firewalls, IDS, VPN, proxies all emit different formats: syslog RFC 3164, RFC 5424, CEF, Palo Alto CSV, JSON
  - They're not just different formats — field names and severity scales are different too
- Every new vendor means a new ETL pipeline. A 10-vendor SOC is maintaining 10 separate pipelines
  - One vendor firmware update can silently break a parser with no alert
- You can't join `src_ip` from one source with `srcaddr` from another
  - Cross-source correlation, compliance queries, and analytics features all require a common schema first
- Goal: one pipeline, one schema, keep the original data, easy to add vendors

---

## Slide 2 — Architecture

**Title:** How ULPF works

*(show the Mermaid diagram from `docs/ARCHITECTURE.md`)*

- Each stage has an abstract base class — swap any component without touching the others
  - FileReader, Kafka reader, syslog UDP listener: same interface, different implementation
- Format detection is heuristic + per-source override in `sources.yaml`. No parsing at detect time
  - Priority chain: Cisco ASA > CEF > RFC 5424 > RFC 3164 > PAN CSV > JSON > LEEF > KV
- Field mapping lives in YAML files, not Python. You can update a mapping without redeploying
  - A YAML change is a one-line diff; no Python review needed for field renames
- The UUID is assigned before anything else. Raw bytes are on disk before normalization starts
  - If normalization crashes, the raw data is already safe

---

## Slide 3 — The schema

**Title:** Universal Event Schema

- 11 top-level groups. 6 required, 5 nullable. Validated by JSON Schema Draft 7 on every event
  - Required: event_id, ingest_timestamp, raw, source, event, lineage
- `raw`: `raw_payload` (original string), `raw_format` (enum), `raw_hash` (sha256)
  - You can always reconstruct what the device sent, and verify it hasn't changed
- `event`: category (6-value enum), action, outcome (success/failure/unknown), severity_numeric (0-10 float)
  - `severity_numeric` is the normalized scale; `severity_original` keeps whatever the vendor sent
- Nullable groups are `null`, not empty dicts
  - Analytics pipelines and SQL engines handle null cleanly; empty dicts need special-casing
- `lineage`: parser_name, parser_version, normalization_ruleset_version
  - You can tell exactly how any event was produced and reprocess with a fixed parser if needed
- Failed validation goes to `dead_letter.ndjson` with the original raw line and error list
  - Nothing is silently dropped

*(show the real normalized JSON for the Cisco ASA event)*

---

## Slide 4 — Adding parsers / running offline

**Title:** Extending the pipeline and running without a network

**Adding a parser:**
- One Python file (`parsers/my_vendor.py`) implementing `match()` and `extract()`
- One YAML file (`schemas/mappings/my_vendor.yaml`) mapping extracted fields to UES
- One import line in `parsers/__init__.py`
- `BaseParser` handles timestamp parsing, IP validation, int coercion — the new file is mostly field extraction
  - Shown in the demo: Fortinet parser in about 30 lines, picked up automatically

**Scaling later (not built yet, but the hooks are there):**
- `ReaderBase` is abstract — swap `FileReader` for a Kafka consumer, `Pipeline` doesn't change
- `SinkBase` is abstract — swap `NDJSONFileSink` for Elasticsearch, `Pipeline` doesn't change
- `RawStoreBase` is abstract — swap `FileRawStore` for S3, upstream code doesn't change

**Offline:**
- No runtime network calls anywhere. Verified with `--log-level debug`
- All 7 dependencies are pure-Python wheels, installable from a local mirror with `--no-index`
- Docker stage 2 installs with `--no-index`. `docker-compose.yml` sets `network_mode: none`
  - The container physically cannot make outbound connections

---

## Slide 5 — Results and what's next

**Title:** Where things stand

**Results:**
- 51/51 tests passing: 7 unit modules + 8 E2E assertions
  - E2E checks schema validity, raw-store lookup, hash integrity, and that all 6 parsers fired
- 28 events processed from 6 formats in one run. 0 dead-letter, 0 errors
  - 5 events each from syslog/CEF/ASA/JSON, 3 from PAN CSV
- 82% line coverage across core, parsers, sinks
  - Uncovered: error-path branches and the Kafka stub (not exercised by E2E)

**What's not built yet:**
- Real Kafka sink — `KafkaStubSink` already implements `SinkBase`, just needs the producer call
- LEEF parser — format detector already recognizes `LEEF:`, the schema has the enum value
- Geo-IP / TI enrichment — `EnrichmentPlugin` ABC is there, needs an offline data file (GeoLite2 etc.)
- Streaming reader — `pipeline.process_event()` is single-event already, just need a new `ReaderBase`
- Parquet output sink — UES flat schema maps directly to a Parquet schema, just needs `pyarrow`
