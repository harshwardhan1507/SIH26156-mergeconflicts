# ULPF Quick Reference & Team Cheat Sheet

> The 2-minute reference guide for developers, security analysts, and teammates working on ULPF.

---

## 1. ULPF in One Sentence

> **ULPF (Universal Log Pre-processing Framework) takes raw, mismatched security logs from any vendor, preserves the original evidence on disk, translates the data into a single Unified Event Schema (UES), verifies its quality, and streams clean events to storage, Kafka, and live web dashboards.**

---

## 2. ULPF in 30 Seconds

```text
Raw Vendor Logs ──► Preserve ──► Detect ──► Parse ──► Normalize ──► Enrich ──► Validate ──► Output Sinks
(Cisco, Syslog,     (SHA-256     (Find      (Extract  (Map to       (Offline   (Schema     (NDJSON, Kafka,
 Palo Alto, etc.)    Disk Save)   Format)    Fields)   UES)          Context)   Gate)       Parquet, UI)
```

Different security tools (firewalls, routers, cloud services) speak completely different log languages. ULPF sits in the middle as a high-speed pre-processor. It locks the raw evidence to disk with cryptographic SHA-256 hashes, auto-detects the log format, extracts structured fields, normalizes vendor terms into standard UES names, adds offline IP threat context, validates the event against strict JSON schema rules, and delivers clean data to analytics and dashboards. If anything goes wrong, the event is safely routed to a dead-letter quarantine queue so zero data is ever lost.

---

## 3. The Log Journey Summary

| Step | Stage | What Happens | Why We Do It |
| :--- | :--- | :--- | :--- |
| **1** | **Ingest** | Accept log via file, stdin, network syslog, or API | Supports diverse enterprise environments without network redesign |
| **2** | **Preserve** | Write raw bytes to disk & compute SHA-256 hash | Guarantees tamper-proof forensic evidence and legal compliance |
| **3** | **Detect** | Identify log format (Cisco, CEF, Syslog, etc.) | Determines which specialized parser should read the log |
| **4** | **Parse** | Break raw text into vendor key-value pairs | Turns unstructured text strings into queryable data fields |
| **5** | **Normalize** | Map vendor field names into standard UES fields | Eliminates vendor silos so one query works across all firewalls |
| **6** | **Enrich** | Attach IP scope, cloud provider, and threat flags | Adds valuable analyst context 100% offline (air-gap safe) |
| **7** | **Validate** | Test event against Draft-7 JSON Schema gate | Prevents corrupt or improperly typed data from polluting storage |
| **8** | **Output** | Deliver validated event to configured sinks | Routes clean data to files, streaming queues, and dashboards |

---

## 4. Key Terms Glossary

| Term | Simple Meaning |
| :--- | :--- |
| **ULPF** | Universal Log Pre-processing Framework — the core software engine. |
| **UES** | Unified Event Schema — our standard JSON event structure (v1.2.0). |
| **Raw Event** | The untouched, original binary log string as sent by the physical device. |
| **Parser** | A Python class that knows how to read and extract fields from one specific log format. |
| **Detection** | Pattern-matching logic that automatically figures out which format a log uses. |
| **Normalization** | Declarative YAML rules that translate vendor-specific names into standard UES fields. |
| **Enrichment** | In-memory metadata additions (private RFC 1918 check, cloud ASN, offline threat list). |
| **Validator** | The quality control gate that checks events against `ues_schema.json`. |
| **Sink** | An output destination driver (e.g. NDJSON file, Parquet columnar, Kafka, SQLite UI). |
| **Dead-Letter** | A quarantine file (`output/dead_letter.ndjson`) for failed events and diagnostic logs. |

---

## 5. Parsing vs. Normalization

```text
PARSING ("Syntax")          NORMALIZATION ("Semantics")
Reads vendor-specific text  ──►  Translates vendor fields into standard UES
Implemented in Python       ──►  Configured in declarative YAML files
```

* **Example:**
  * **Parser extracts:** `{"action": "permit", "src_ip": "10.0.0.1"}` *(Cisco syntax)*
  * **Normalizer produces:** `{"event": {"action": "allowed"}, "network": {"src_endpoint": {"ip": "10.0.0.1"}}}` *(UES standard)*

---

## 6. Major Repository Areas

```text
ulpf/
├── cli.py                  ──► Main CLI entry point (ingest, listen, serve)
├── core/
│   ├── ingestion.py        ──► File, stdin, and stream readers
│   ├── raw_store.py        ──► Binary disk evidence storage (<event_id>.raw)
│   ├── detector.py         ──► Format classification and signature matching
│   ├── registry.py         ──► Parser registration and lookup
│   ├── pipeline.py         ──► Central end-to-end processing orchestrator
│   ├── normalization.py    ──► YAML-driven schema translation engine
│   ├── validation.py       ──► JSON Schema gate & dead-letter writer
│   └── worker_pool.py      ──► Multiprocessing concurrency manager
├── parsers/                ──► 11 vendor parsers (Cisco, Palo Alto, CEF, Syslog, Cloud, etc.)
├── schemas/
│   ├── ues_schema.json     ──► Official UES v1.2.0 JSON Schema definition
│   └── mappings/*.yaml     ──► 11 vendor field-to-UES mapping rules
├── enrichment/             ──► Offline IP, cloud provider, and threat enrichment
├── sinks/                  ──► Output writers (NDJSON, Parquet, Kafka, CEF/LEEF egress)
├── analytics/              ──► Baseline profiling and statistical anomaly detection
├── dashboard/              ──► Web UI, search indexer, and real-time inspector
└── tests/                  ──► Pytest automated test suite
```

---

## 7. Where Do I Go If...?

| I want to... | Look at these files in the repository: |
| :--- | :--- |
| **Add a new log format** | 1. `ulpf/parsers/<name>.py`<br>2. `ulpf/schemas/mappings/<name>.yaml`<br>3. `ulpf/core/registry.py`<br>4. `ulpf/core/detector.py` |
| **Fix a field name translation** | `ulpf/schemas/mappings/<vendor>.yaml` |
| **Modify the standard UES schema** | `ulpf/schemas/ues_schema.json` |
| **Update threat IP lists or cloud CIDRs**| `ulpf/enrichment/ip_enrichment.py` |
| **Add a new output storage sink** | `ulpf/sinks/` (create class inheriting from `SinkBase`) |
| **Change how logs are ingested** | `ulpf/core/ingestion.py` or `ulpf/collectors/syslog_listener.py` |
| **Change the pipeline flow or hashing** | `ulpf/core/pipeline.py` and `ulpf/core/raw_store.py` |
| **Debug a failed log** | Check `output/dead_letter.ndjson` |
| **Update the Web Dashboard UI** | `ulpf/dashboard/app.py` and `ulpf/dashboard/static/` |
| **Run the automated test suite** | Run `pytest` or `Run_Tests.bat` |

---

## 8. Key Technical Decisions Cheat Sheet

1. **Canonical UES Schema (v1.2.0)**: Unifies vendor variances into one predictable JSON contract so detection rules are written once.
2. **Pre-Parse Raw Evidence Preservation**: Saves exact bytes to disk before parsing so forensic integrity and zero data loss are guaranteed.
3. **Declarative YAML Normalization**: Separates Python parsing from field renaming so non-developers can adjust mappings in YAML.
4. **100% Offline In-Memory Enrichment**: Uses embedded CIDR lookup tables for air-gap safety and microsecond speeds without external API calls.
5. **Strict JSON Schema Gate**: Intercepts and rejects malformed events before they can pollute analytical storage or dashboards.
6. **Centralized Dead-Letter Quarantine**: Routes format, parse, schema, and sink failures into `dead_letter.ndjson` with full diagnostic error traces.
7. **Multi-Sink Egress Architecture**: Sinks are fully decoupled, allowing simultaneous delivery to files, Kafka, and the live dashboard database.

---

## 9. Failure & Debugging Cheat Sheet

```text
WHERE DID IT FAIL?               WHAT CAUSED IT?                 HOW TO FIX IT:
┌───────────────────────────────┬───────────────────────────────┬────────────────────────────────┐
│ Format Unknown                │ No matching pattern or tag    │ Add pattern in detector.py     │
│ Extraction Failed             │ Regex error or truncated log  │ Fix parser in parsers/<file>.py│
│ Validation Failed             │ Missing required field / type │ Check schemas/mappings/*.yaml  │
│ Sink Delivery Failed          │ Broker offline / disk error   │ Check network & destination    │
└───────────────────────────────┴───────────────────────────────┴────────────────────────────────┘
```

### Quick Debugging Checklist:
1. Open `output/dead_letter.ndjson`.
2. Find the failed event by `event_id` or timestamp.
3. Read the `"error"` field to see the exact root cause.
4. Cross-reference the original raw bytes using `output/raw_store/`.

---

## 10. The Team Mental Model

Keep these seven questions in mind whenever you work on ULPF:

```text
1. INGESTION:    "How did the raw bytes enter the system?"
2. PRESERVATION: "Did we securely hash and store the raw evidence?"
3. DETECTION:    "What format signature does this log match?"
4. PARSING:      "Did the parser extract the raw key-value pairs?"
5. NORMALIZING:  "Are fields mapped into standard UES names?"
6. ENRICHING:    "Did we attach offline network and cloud context?"
7. VALIDATING:   "Does the final event pass our JSON Schema gate?"
```

---

## 11. If I Have 30 Seconds to Explain ULPF

> *"Security operations are overwhelmed by mismatched log formats across Cisco firewalls, Palo Alto gateways, Linux servers, and cloud providers. ULPF is a universal pre-processing framework that solves this. It ingests logs from any source, permanently locks the raw evidence to disk with SHA-256 hashes, standardizes proprietary vendor fields into a single Unified Event Schema (UES), enriches events with offline threat context, and guarantees schema quality before streaming data to analytical databases, Kafka, and live web dashboards. With ULPF, teams write detection rules once and guarantee zero data loss."*

---

## 12. Important Things to Remember

* **Zero data loss is rule #1**: Raw bytes are preserved on disk *before* parsing starts.
* **Never drop a log silently**: Unparseable or invalid events are quarantined into `dead_letter.ndjson`.
* **Events are processed in isolation**: A broken line on record 5 never stops the rest of the stream.
* **Parsers extract, YAML normalizes**: Never hardcode field renaming in Python parsers.
* **Enrichment is strictly offline**: No internet calls are made during pipeline execution.
* **UES preserves vendor extras**: Proprietary fields that don't map to UES standard paths live safely in `vendor_attributes`.
* **Validation is mandatory**: Only valid UES events reach output sinks.

---

## 13. Where to Go Deeper

| If You Need... | Consult This Document: |
| :--- | :--- |
| **Comprehensive Human Guide** | `docs/04-understanding/HOW_ULPF_WORKS.md` |
| **High-Level System Diagram** | `docs/04-understanding/diagrams/01-big-picture.md` |
| **Step-by-Step Log Lifecycle** | `docs/04-understanding/diagrams/02-log-journey.md` |
| **Codebase & Folder Map** | `docs/04-understanding/diagrams/03-repository-map.md` |
| **Error Handling & Quarantine** | `docs/04-understanding/diagrams/04-failure-path.md` |
| **Technical Architecture Report**| `docs/02-architecture/current-system-architecture.md` |
| **Data Schema & Parsers Audit** | `docs/03-data-analysis/schema-analysis.md` |
| **Code & Repository Truth Audit**| `docs/00-investigation/repository-inventory.md` |
