# How ULPF Works: The Human Guide

> A friendly, plain-English explanation of the Universal Log Pre-processing Framework — what it is, why we built it, how it works under the hood, and how to work with it as a developer or security teammate.

---

## Table of Contents
1. [What Is ULPF?](#1-what-is-ulpf)
2. [What Problem Are We Solving?](#2-what-problem-are-we-solving)
3. [The Basic Idea: The Universal Translator](#3-the-basic-idea-the-universal-translator)
4. [The Complete Log Journey](#4-the-complete-log-journey)
5. [Parsing vs. Normalization](#5-parsing-vs-normalization)
6. [What Is UES (Unified Event Schema)?](#6-what-is-ues-unified-event-schema)
7. [Where Does Everything Live?](#7-where-does-everything-live)
8. [How the Important Pieces Work Together](#8-how-the-important-pieces-work-together)
9. [What Happens When Something Goes Wrong?](#9-what-happens-when-something-goes-wrong)
10. [Why Do We Preserve the Original?](#10-why-do-we-preserve-the-original)
11. [The Key Technical Decisions We Made](#11-the-key-technical-decisions-we-made)
12. [Why These Decisions Matter Together](#12-why-these-decisions-matter-together)
13. [What a New Teammate Actually Needs to Know](#13-what-a-new-teammate-actually-needs-to-know)
14. [How to Think About ULPF While Working on It](#14-how-to-think-about-ulpf-while-working-on-it)
15. [ULPF in One Minute (The Pitch)](#15-ulpf-in-one-minute-the-pitch)

---

## 1. What Is ULPF?

**ULPF** stands for **Universal Log Pre-processing Framework**.

At its core, ULPF is a high-performance software engine that sits between messy, vendor-specific security devices and the downstream databases, analysts, and dashboards that need clean, reliable security data.

```text
Messy Vendor Logs  ──►  [ ULPF Pre-processing Engine ]  ──►  Clean, Standardized UES Events
(Cisco, Palo Alto,       - Preserves raw evidence            (Delivered to files, Kafka,
 Linux Syslog, Cloud)    - Translates vendor terms            and live web dashboards)
                         - Enriches with context
                         - Validates quality
```

Whenever security devices (such as firewalls, cloud platforms, intrusion detection sensors, or servers) generate activity logs, they write those logs in completely different formats. Some output comma-separated text, some output proprietary codes, and others output JSON or XML.

ULPF takes all of those mismatched logs, preserves the original unaltered evidence on disk, automatically identifies what kind of log it received, translates the information into a single shared language called the **Unified Event Schema (UES)**, enriches the data with offline threat and cloud context, verifies that the event matches strict quality rules, and delivers clean events to storage and real-time dashboards.

*(For a visual 30-second summary, see [Diagram 01: The Big Picture](diagrams/01-big-picture.md).)*

---

## 2. What Problem Are We Solving?

Every security team faces the **vendor silo problem**. 

In any realistic enterprise network, you don't have just one brand of security tool. You have:
* **Cisco ASA** firewalls protecting the data center.
* **Palo Alto Networks** firewalls handling perimeter traffic.
* **Linux servers** generating Syslog messages.
* **Snort / Suricata** sensors monitoring network packets.
* **AWS CloudTrail, Azure Monitor, and GCP Audit** logging cloud operations.

Here is the headache: **every single one of these vendors describes the exact same security events using different words.**

| Security Concept | Cisco ASA Log | Palo Alto CSV Log | Linux iptables | CloudTrail |
| :--- | :--- | :--- | :--- | :--- |
| **Source IP** | `src outside:192.168.1.5` | Column index 7 (`192.168.1.5`) | `SRC=192.168.1.5` | `sourceIPAddress: 192.168.1.5` |
| **Allowed Traffic** | `"access-list permit"` | `"allow"` | `"ACCEPT"` | `"ReadOnly: true"` |
| **Blocked Traffic** | `"Deny tcp"` | `"deny"` or `"drop"` | `"DROP"` or `"REJECT"` | `"AccessDenied"` |
| **Timestamp** | `Feb 28 2026 14:02:00` | `2026/02/28 14:02:00` | `1709128920` (epoch) | `2026-02-28T14:02:00Z` |

### Why This Breaks Security Operations
Without a framework like ULPF, security analysts and detection engineers must write custom code and complex queries for every single vendor format. 

If you want to write an alert for *"Show me any connection blocked from an external IP,"* you would have to write five different search queries for five different firewalls. When a vendor updates their firmware or you buy a new firewall brand, all of your security rules break.

Furthermore, traditional log forwarders often discard the original raw bytes or drop malformed logs silently, leaving digital forensics teams without tamper-proof legal evidence.

### The ULPF Solution
We built ULPF to solve this once and for all:
1. **Handle the translation before storage**: All vendor parsing, normalization, and quality validation happen before data is indexed.
2. **Guarantee zero data loss**: Save every raw byte to disk with a cryptographic SHA-256 fingerprint before touching it.
3. **Provide one universal schema (UES)**: Downstream analysts and automated alert rules only ever have to write one query against one clean schema.

---

## 3. The Basic Idea: The Universal Translator

> **Think of ULPF as a universal translator at an international conference.**

If you have delegates speaking English, Spanish, Mandarin, Japanese, and German, you have two choices:
* **The Messy Way**: Force every delegate to learn four other languages so they can speak directly to one another. (This is what happens when databases try to ingest raw vendor logs).
* **The ULPF Way**: Place a professional translator in the middle. Every delegate speaks their native language to the translator, and the translator instantly converts every message into a single shared working language.

In ULPF, the native languages are vendor formats (Cisco, Palo Alto, Syslog, CEF, LEEF, JSON, CloudTrail), and the shared working language is **UES (Unified Event Schema)**.

---

## 4. The Complete Log Journey

Let's follow the journey of **one single log line** as it travels through ULPF from start to finish.

*(For the visual workflow, see [Diagram 02: The Journey of a Log](diagrams/02-log-journey.md).)*

```text
[1. Ingest] ──► [2. Preserve] ──► [3. Detect] ──► [4. Select] ──► [5. Parse]
                                                                        │
[9. Sinks]  ◄── [8. Validate] ◄── [7. Enrich] ◄── [6. Normalize] ◄──────┘
```

---

### Step 1: The Log Arrives (Ingestion)
* **What happens:** A raw log string arrives at ULPF via a disk file, standard terminal input (`stdin`), a live network Syslog listener (UDP/TCP), or a web REST API.
* **Why do we do it:** Different networks ship logs differently; ULPF supports multiple intake methods so no customer network changes are needed.
* **What we get:** A `RawEvent` containing the raw binary bytes, decoded text, source label (`source_tag`), and UTC arrival timestamp (`ingest_timestamp`).
* **Where it lives:** `ulpf/core/ingestion.py`, `ulpf/collectors/syslog_listener.py`, and `ulpf/api/app.py`.
* **What if it fails:** Unreadable files log errors. For text decoding, ULPF uses Python's `surrogateescape` codec so non-UTF-8 characters never crash the intake.

---

### Step 2: The Original Is Preserved (Raw Storage & Evidence Lock)
* **What happens:** Before parsing or modifying anything, ULPF writes the exact raw bytes to a permanent disk folder (`output/raw_store/`), calculates its **SHA-256 cryptographic checksum**, and derives a deterministic **UUIDv5 event ID**.
* **Why do we do it:** Forensics and legal compliance. In a security breach investigation, we must be able to prove exactly what the physical device sent without a single bit of tampering.
* **What we get:** A permanent `.raw` file on disk, a `raw_hash` fingerprint, and a reproducible `event_id`.
* **Where it lives:** `ulpf/core/raw_store.py` (`FileRawStore`) and `ulpf/core/pipeline.py`.
* **What if it fails:** If disk write fails (e.g. disk full), an exception is raised because raw preservation is a mandatory security guarantee.

---

### Step 3: The Format Is Identified (Format Detection)
* **What happens:** ULPF inspects the raw text to classify which format it matches (e.g. Cisco `%ASA`, CEF header, RFC 5424 Syslog, Palo Alto CSV, JSON, etc.).
* **Why do we do it:** We must know what format a log is in before we can choose the right parser to read it.
* **What we get:** A format identifier string (such as `"cisco_asa"` or `"pan_csv"`).
* **Where it lives:** `ulpf/core/detector.py` (`FormatDetector`) and `ulpf/config/sources.yaml`.
* **What if it fails:** If the format cannot be identified, the detector returns `"unknown"`. The pipeline catches this and routes the raw log to the Dead-Letter quarantine (`output/dead_letter.ndjson`) with the reason `"No parser matched format"`.

---

### Step 4: The Correct Parser Is Selected (Parser Registry)
* **What happens:** The pipeline asks the `ParserRegistry` for the parser class registered for that format ID.
* **Why do we do it:** Modular design. Each log format has its own isolated parser class, keeping the codebase easy to maintain and test.
* **What we get:** An initialized parser instance ready to extract data.
* **Where it lives:** `ulpf/core/registry.py` and `ulpf/parsers/`.
* **What if it fails:** If the registry lookup fails, ULPF tests all registered parsers dynamically using `.match()`. If still unclaimed, the event is routed to dead-letter quarantine.

---

### Step 5: The Parser Extracts Fields (Parsing)
* **What happens:** The parser breaks the vendor text into a dictionary of key-value pairs (e.g. source IP, destination port, username, action).
* **Why do we do it:** Computers cannot query unstructured text strings; we need structured data fields.
* **What we get:** A dictionary containing the raw extracted vendor attributes.
* **Where it lives:** `ulpf/parsers/<vendor>.py` (e.g. `cisco_asa.py`, `paloalto_csv.py`, `cef.py`).
* **What if it fails:** If the log is malformed or truncated mid-line, the parser's extraction exception is caught safely. The raw log and error trace are saved to dead-letter quarantine while the pipeline continues to the next log.

---

### Step 6: The Event Is Normalized into UES (Standardization)
* **What happens:** The `NormalizationEngine` uses declarative YAML mapping rules to translate vendor field names into standard UES fields. For example, Cisco's `"permit"` and Palo Alto's `"allow"` both become `event.action: "allowed"`.
* **Why do we do it:** To give downstream systems one single, universal structure.
* **What we get:** A canonical UES dictionary where timestamps are ISO-8601 UTC, network fields are standard, and unmapped vendor attributes are preserved safely inside `vendor_attributes`.
* **Where it lives:** `ulpf/core/normalization.py` and `ulpf/schemas/mappings/*.yaml`.
* **What if it fails:** Schema mapping exceptions log a warning and route the event to quarantine.

---

### Step 7: The Event Is Enriched (Adding Offline Context)
* **What happens:** The `IPEnrichmentPlugin` inspects IP addresses in the event and attaches helpful context (RFC 1918 private vs public classification, cloud provider identification like AWS/Azure/GCP, and static threat flags).
* **Why do we do it:** To save analysts time by automatically tagging whether an IP is an internal workstation, a Google Cloud server, or a known malicious Tor exit node.
* **What we get:** An added `enrichment` block attached to the event. *(Runs 100% offline and in-memory—completely air-gap safe!)*
* **Where it lives:** `ulpf/enrichment/ip_enrichment.py`.
* **What if it fails:** Enrichment errors are non-fatal; ULPF logs a warning and allows the event to proceed without dropping it.

---

### Step 8: The Event Is Validated (Schema Gate)
* **What happens:** The `Validator` checks the finished event against the official JSON Schema (`ues_schema.json`).
* **Why do we do it:** Strict quality control. We guarantee that no corrupt or non-compliant event ever reaches downstream storage.
* **What we get:** A pass/fail decision. Valid events proceed to sinks; invalid events are rejected.
* **Where it lives:** `ulpf/core/validation.py`.
* **What if it fails:** The validator records the exact JSON schema violations (e.g. `'network.src_endpoint.port: must be integer'`), bundles the raw log, and writes it to `output/dead_letter.ndjson`.

---

### Step 9: The Event Reaches the Sinks (Delivery)
* **What happens:** The validated UES event is delivered to all configured output destinations (**Sinks**).
* **Why do we do it:** Different teams need data in different storage backends.
* **What we get:** The event is written to line-delimited JSON (`ndjson_file.py`), high-speed columnar files (`parquet_sink.py`), streaming queues (`kafka_producer.py`), the live web UI SQLite indexer (`indexer.py`), or re-encoded for legacy SIEMs (`cef_egress.py`, `leef_egress.py`).
* **Where it lives:** `ulpf/sinks/` and `ulpf/dashboard/indexer.py`.
* **What if it fails:** Sink exceptions are caught, error counters are incremented, and an error record is saved to dead-letter quarantine.

---

## 5. Parsing vs. Normalization

A common point of confusion for new developers is the difference between **parsing** and **normalization**. In ULPF, these are two strictly separate steps:

```text
           ┌───────────────────────────────────────────────┐
           │                  PARSING                      │
           │        "Understand the Source Format"         │
           │  Breaks vendor text into raw key-value pairs  │
           └───────────────────────┬───────────────────────┘
                                   │
                                   ▼
           ┌───────────────────────────────────────────────┐
           │               NORMALIZATION                   │
           │       "Convert into Common Language"          │
           │   Maps raw vendor pairs into standard UES     │
           └───────────────────────────────────────────────┘
```

### Why Keep Them Separate?
1. **Parsers only care about grammar**: The Cisco parser only needs to know how Cisco writes text. It doesn't need to know anything about our internal JSON schema.
2. **Normalizers only care about meaning**: The normalization engine uses simple YAML files (like `cisco_asa.yaml`) to map field names. If you want to rename a field, **you edit a simple YAML file without touching any Python code**.

---

## 6. What Is UES (Unified Event Schema)?

**UES (Unified Event Schema)** is our canonical, shared data structure (version 1.2.0).

Whenever any log passes through ULPF, the output is guaranteed to follow this clean, predictable JSON envelope:

```json
{
  "schema_version": "1.2.0",
  "event_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "tenant_id": "default",
  "ingest_timestamp": "2026-08-30T10:15:30.123456Z",
  "source_event_timestamp": "2026-08-30T10:15:28.000000Z",
  "raw": {
    "raw_payload": "%ASA-4-106023: Deny tcp src outside:198.51.100.20/443 dst inside:10.0.0.5/80",
    "raw_format": "cisco_asa",
    "raw_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "source": {
    "vendor": "cisco",
    "product": "asa",
    "category": "firewall"
  },
  "event": {
    "action": "blocked",
    "outcome": "failure",
    "category": "network",
    "severity": "medium"
  },
  "network": {
    "transport_protocol": "tcp",
    "direction": "inbound",
    "src_endpoint": { "ip": "198.51.100.20", "port": 443 },
    "dst_endpoint": { "ip": "10.0.0.5", "port": 80 }
  },
  "enrichment": {
    "src_ip_scope": "public",
    "dst_ip_scope": "private",
    "threat_intel_match": null
  },
  "vendor_attributes": {
    "asa_mnemonic": "106023",
    "src_interface": "outside",
    "dst_interface": "inside"
  },
  "lineage": {
    "parser_name": "cisco_asa",
    "parser_version": "1.0.0",
    "normalization_ruleset_version": "1.2.0"
  }
}
```

### Key Guarantees of UES:
* **Predictable Structure**: Always has `raw`, `source`, `event`, `network`, `enrichment`, and `lineage`.
* **Universal Enums**: Actions are strictly standardized (`allowed`, `blocked`, `alert`, `unknown`).
* **Lossless Storage**: Any proprietary vendor field that does not fit standard UES fields is safely stored in `vendor_attributes`. **Nothing is ever discarded.**

---

## 7. Where Does Everything Live?

*(For a visual map, see [Diagram 03: The Repository Map](diagrams/03-repository-map.md).)*

Here is the quick guide to the `ulpf/` package directories:

```text
ulpf/
├── cli.py                  # CLI commands (ulpf ingest, ulpf listen, ulpf serve)
├── collectors/             # Live network listeners (UDP/TCP Syslog server)
├── core/                   # The engine: Pipeline, Ingestion, RawStore, Detector, Registry, Normalization, Validation
├── parsers/                # 11 format parsers (Cisco, Palo Alto, CEF, Syslog, CloudTrail, etc.)
├── schemas/                # Official UES JSON Schema and 11 vendor YAML mapping files
├── enrichment/             # Offline IP, cloud ASN, and threat intelligence enrichment
├── sinks/                  # Output writers (NDJSON, Parquet, Kafka, CEF/LEEF egress)
├── analytics/              # Baseline profiling and statistical anomaly detection
├── dashboard/              # Web dashboard app, search indexer, and UI assets
└── tests/                  # Automated pytest suite verifying losslessness, performance, and parsing
```

---

## 8. How the Important Pieces Work Together

The entire framework is tied together by the **`Pipeline`** class in `ulpf/core/pipeline.py`.

```text
             ┌────────────────────────────────────────────────────────┐
             │                     FileReader / CLI                   │
             └───────────────────────────┬────────────────────────────┘
                                         │
                                         ▼
             ┌────────────────────────────────────────────────────────┐
             │                       Pipeline                         │
             │   1. FileRawStore.put(event_id, raw_bytes)             │
             │   2. FormatDetector.detect(raw_line)                   │
             │   3. ParserRegistry.get_parser_for_format(format_id)   │
             │   4. BaseParser.extract(raw_line)                      │
             │   5. NormalizationEngine.normalize(extracted)          │
             │   6. IPEnrichmentPlugin.enrich(ues_event)              │
             │   7. Validator.validate_and_route(ues_event)           │
             └───────────────┬────────────────────────┬───────────────┘
                             │                        │
                    (If Valid)                        (If Invalid / Error)
                             ▼                        ▼
             ┌────────────────────────┐      ┌────────────────────────┐
             │      Output Sinks      │      │  Dead-Letter File      │
             │ (NDJSON, Parquet, UI)  │      │  (dead_letter.ndjson)  │
             └────────────────────────┘      └────────────────────────┘
```

The pipeline acts like an assembly line supervisor: it hands the raw log to each station in order, collects the results, verifies the quality, and routes the finished product to storage or quarantine.

---

## 9. What Happens When Something Goes Wrong?

*(For the complete visual error flow, see [Diagram 04: The Failure Path](diagrams/04-failure-path.md).)*

In security telemetry, corrupted and malformed logs are inevitable. ULPF handles errors using two non-negotiable rules:
1. **Per-event isolation**: An error on log line 5 must never crash the pipeline or stop lines 6 through 1,000,000 from processing.
2. **Dead-letter quarantine**: Failed events are never silently discarded. They are packaged with full error diagnostics and written to `output/dead_letter.ndjson`.

### The Three Dead-Letter Scenarios:
* **Detection Failure**: Format not recognized → quarantined as `"No parser matched format"`.
* **Parser Failure**: Syntax broken or truncated → quarantined as `"Extraction failed: <reason>"`.
* **Validation Failure**: JSON schema violated → quarantined as `"Validation failed: <schema violations>"`.

In every single scenario, the **original raw bytes are already safely stored on disk in `output/raw_store/`**, so developers can easily inspect, fix, and replay failed events.

---

## 10. Why Do We Preserve the Original?

Many traditional log parsers discard raw log strings once they extract JSON fields. **ULPF strictly forbids this.**

```text
The Problem:
If a parser misinterprets a timestamp or a regex drops a custom firewall field, 
the original data is lost forever. In a legal audit or forensic investigation, 
modified data cannot be proven authentic.

Our Decision:
Save the raw binary payload to disk and compute a SHA-256 hash BEFORE parsing.

The Benefit:
100% forensic losslessness. Every UES event links directly back to its authentic 
raw file on disk via its deterministic UUIDv5 event ID.
```

---

## 11. The Key Technical Decisions We Made

Here is a summary of the core architectural decisions built into ULPF:

### Decision 1: Canonical Unified Event Schema (UES)
* **Problem:** Security tools can't support 50 different vendor schemas.
* **Decision:** Build one standardized, typed schema (UES v1.2.0).
* **Result:** Downstream rules and analytics are written once and work across all firewalls.

### Decision 2: Pre-Parsing Raw Evidence Preservation
* **Problem:** Normalization can accidentally alter or drop vendor fields.
* **Decision:** Write exact binary bytes to `FileRawStore` before invoking detectors or parsers.
* **Result:** Bit-exact forensic integrity and zero data loss.

### Decision 3: Declarative YAML Field Mapping
* **Problem:** Hardcoding field translations in Python code makes adding new formats slow and error-prone.
* **Decision:** Decouple parsing (Python) from field normalization (YAML mapping files).
* **Result:** Non-developers can adjust field mappings in YAML without changing code.

### Decision 4: 100% Offline, In-Memory Enrichment
* **Problem:** Querying external threat feeds or WHOIS servers over the internet causes network latency and fails in air-gapped networks.
* **Decision:** Embed static CIDR tables for private scopes, cloud providers, and known threat lists in-memory.
* **Result:** Microsecond enrichment speeds and total security in air-gapped environments.

### Decision 5: Strict JSON Schema Validation Gate
* **Problem:** Downstream databases crash when parsers output unexpected data types.
* **Decision:** Run every normalized event through a Draft-7 JSON Schema validator.
* **Result:** Zero dirty data enters production storage or dashboards.

### Decision 6: Centralized Dead-Letter Quarantine
* **Problem:** Silent data loss prevents developers from discovering broken parsers.
* **Decision:** Route all parse, format, and schema errors into `dead_letter.ndjson` with error traces.
* **Result:** Total visibility into parser failures with full debugging context.

---

## 12. Why These Decisions Matter Together

When combined, these decisions create a system that is:
* **Fast**: In-memory parsing and offline enrichment process tens of thousands of logs per second.
* **Forensically Sound**: Cryptographic SHA-256 hashing and raw storage guarantee tamper-proof evidence.
* **Resilient**: Isolated per-event processing and dead-letter queues prevent system crashes.
* **Easy to Extend**: Adding a new firewall format takes just one new parser file and one YAML mapping file.

---

## 13. What a New Teammate Actually Needs to Know

If you need to make changes to ULPF, here is your quick-start guide:

| If your task is... | Follow these steps in the repository: |
| :--- | :--- |
| **Add support for a new log format** | 1. Create parser in `ulpf/parsers/<name>.py` inheriting from `BaseParser`<br>2. Create YAML mapping in `ulpf/schemas/mappings/<name>.yaml`<br>3. Register the parser in `ulpf/core/registry.py`<br>4. Add detection signature in `ulpf/core/detector.py` |
| **Fix a field name mapping** | Edit the relevant YAML file in `ulpf/schemas/mappings/<vendor>.yaml` |
| **Update IP threat lists or cloud CIDRs** | Edit the static IP tables in `ulpf/enrichment/ip_enrichment.py` |
| **Add a new output destination (Sink)** | Create a new class in `ulpf/sinks/` inheriting from `SinkBase` |
| **Debug a failed log** | Check `output/dead_letter.ndjson` to see the exact error and raw log |
| **Run the automated test suite** | Run `pytest` or execute `Run_Tests.bat` |

---

## 14. How to Think About ULPF While Working on It

Whenever you are building or reviewing code in ULPF, keep this simple 7-question mental model in mind:

```text
1. INGESTION:    "How did we receive the log bytes?"
2. PRESERVATION: "Did we safely hash and store the raw evidence?"
3. DETECTION:    "Do we know what language this log speaks?"
4. PARSING:      "Did the parser extract the raw key-value pairs accurately?"
5. NORMALIZING:  "Are the fields translated into standard UES names?"
6. ENRICHING:    "Did we attach offline network and threat context?"
7. VALIDATING:   "Does the final event strictly pass our JSON Schema gate?"
```

If you can answer those seven questions, you understand how any part of ULPF works.

---

## 15. ULPF in One Minute (The Pitch)

> *"Modern security operations are overwhelmed by mismatched log formats from dozens of different firewall, cloud, and server vendors. ULPF is a Universal Log Pre-processing Framework that solves this problem. It ingests logs from any source, permanently locks the raw evidence to disk with cryptographic SHA-256 fingerprints, translates proprietary vendor fields into a single Unified Event Schema (UES), enriches events with offline threat intelligence, and verifies schema quality before streaming clean data to analytical databases, Kafka, and live web dashboards. With ULPF, security teams write their detection rules once, eliminate vendor silos, and guarantee zero data loss."*
