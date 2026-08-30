# 05 — Losslessness & Traceability Map

This diagram maps the three technical pillars of losslessness and the end-to-end cryptographic traceability chain in ULPF.

---

## Losslessness & Traceability Map

```mermaid
flowchart TD
    RAW_WIRE["Incoming Raw Wire / Disk Bytes\n(e.g. b'<166>Aug 15 14:22:10 asa01 %ASA-6-106100: ...')"] --> SURROGATE

    subgraph PILLAR1["Pillar 1: Raw-Byte Losslessness (100% Guaranteed)"]
        SURROGATE["Surrogateescape Decoded Bytes:\nline.encode('utf-8', errors='surrogateescape') == raw_bytes"]
        HASH_256["Cryptographic SHA-256 Digest:\nraw_hash = sha256(raw_bytes).hexdigest()"]
        DISK_STORE[("FileRawStore 2-Tier Sharded Disk File:\noutput/raw_store/e4/a1/e4a1b2c3...raw\n(Exact Untouched Binary Bytes)")]
        SURROGATE --> HASH_256 --> DISK_STORE
    end

    subgraph PILLAR2["Pillar 2: Semantic Losslessness (Parser + Open Bag)"]
        PARSER_EXTRACT["Parser Plugin Extraction\n(Header + Token Parsing)"]
        EXTRACTED_MAP["extracted dict[str, Any]"]
        
        NORM_MAPPED["Mapped Canonical Fields\n(source, event, network, identity, rule)"]
        VENDOR_BAG["vendor_attributes Open Bag\n(All unmapped extracted fields captured)"]
        
        PARSER_EXTRACT --> EXTRACTED_MAP
        EXTRACTED_MAP --> NORM_MAPPED & VENDOR_BAG
    end

    subgraph PILLAR3["Pillar 3: End-to-End Cryptographic Traceability"]
        UUID_DERIVE["Deterministic UUIDv5:\nevent_id = uuid5(NAMESPACE, f'ulpf:{tenant}:{source}:{raw_hash}')"]
        LINEAGE_BLOCK["lineage:\n• parser_name: 'cisco_asa'\n• parser_version: '1.0.0'\n• normalization_ruleset_version: '1.0.0'"]
        RAW_METADATA["raw container in UES:\n• raw_payload: exact log line\n• raw_hash: SHA-256 digest\n• raw_format: 'syslog_rfc3164'"]
        
        UUID_DERIVE --> UES_RECORD["Unified Canonical UES Record"]
        LINEAGE_BLOCK --> UES_RECORD
        RAW_METADATA --> UES_RECORD
    end

    DISK_STORE -.->|Deterministic UUIDv5 Link| UES_RECORD
    NORM_MAPPED & VENDOR_BAG --> UES_RECORD

    subgraph AUDIT_RETRIEVAL["Forensic Audit Retrieval"]
        CLI_LOOKUP["CLI: ulpf lookup --event-id <uuid>\n-> Queries FileRawStore directly"]
        API_LOOKUP["REST: GET /api/events/{event_id}\n-> Returns UES record + exact raw_payload"]
    end

    UES_RECORD --> CLI_LOOKUP & API_LOOKUP
    DISK_STORE --> CLI_LOOKUP & API_LOOKUP
```

---

## Evidence

| Pillar / Mechanism | Source File | Method / Line | Confidence |
|---|---|---|---|
| Binary Raw Retention | `ulpf/core/raw_store.py:64-75` | `FileRawStore.put(event_id, raw_bytes)` | **CONFIRMED** |
| Lossless Attribute Open Bag | `ulpf/core/normalization.py:323-327` | `vendor_attributes[k] = v` for unmapped extracted keys | **CONFIRMED** |
| Deterministic UUIDv5 Traceability | `ulpf/core/pipeline.py:116` | `uuid.uuid5(uuid.NAMESPACE_URL, f"ulpf:{tenant}:{source}:{raw_hash}")` | **CONFIRMED** |
| Forensic CLI & API Lookup | `ulpf/cli.py:351-363`, `ulpf/dashboard/app.py:237-262` | `store.get(event_id)`, `get_event_detail()` | **CONFIRMED** |
