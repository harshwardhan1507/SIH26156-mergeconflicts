# 01 — Raw Event Lifecycle Diagram

This diagram traces the exact byte-level transformation, cryptographic hashing, sharded disk storage, and UES envelope packaging of raw log events.

---

## Raw Event Lifecycle Diagram

```mermaid
flowchart TD
    SOURCE_LOG["Log Source Input\n(File on Disk / Stdin Stream / UDP Socket)"] --> B_CAPTURE

    subgraph STAGE0["Stage 0: Binary Stream Ingestion (core/ingestion.py)"]
        B_CAPTURE["Binary Read: open(fpath, 'rb') / socket.recvfrom(65535)"]
        B_STRIP["Strip Trailing CRLF:\nraw_bytes = raw_line_bytes.rstrip(b'\\r\\n')"]
        B_DECODE["Decode with surrogateescape:\nline_str = raw_bytes.decode('utf-8', errors='surrogateescape')"]
        B_OBJECT["Instantiate RawEvent:\nRawEvent(line=line_str, raw_bytes=raw_bytes, source_tag=...)"]
        
        B_CAPTURE --> B_STRIP --> B_DECODE --> B_OBJECT
    end

    subgraph STAGE1["Stage 1: Cryptographic Digest & Identity (core/pipeline.py)"]
        HASH_SHA["Compute SHA-256 Digest:\nraw_hash = hashlib.sha256(raw_bytes).hexdigest()"]
        UUID_DERIVE["Derive Deterministic UUIDv5:\nevent_id = uuid.uuid5(NAMESPACE_URL, f'ulpf:{tenant}:{source}:{raw_hash}')"]
        
        B_OBJECT --> HASH_SHA --> UUID_DERIVE
    end

    subgraph STAGE2["Stage 2: Pre-Parse Forensic Persistence (core/raw_store.py)"]
        VAL_UUID["Validate event_id as UUID (Path Traversal Guard)"]
        CALC_SHARD["Extract First 4 Hex Nibbles:\nshard = event_id.replace('-', '')[:4]"]
        TARGET_PATH[("Target File Path:\n<base_dir>/<shard[:2]>/<shard[2:4]>/<event_id>.raw")]
        WRITE_EXACT["dest.write_bytes(raw_bytes)\n(Exact Untouched Binary Bytes)"]
        
        UUID_DERIVE --> VAL_UUID --> CALC_SHARD --> TARGET_PATH --> WRITE_EXACT
    end

    subgraph STAGE3["Stage 3: Normalization & UES Embedding (core/pipeline.py)"]
        UES_RAW_BLOCK["Embed in UES 1.2.0 Envelope:\n'raw': {\n  'raw_payload': raw_line,\n  'raw_format': format_id,\n  'raw_hash': raw_hash\n}"]
        WRITE_EXACT --> UES_RAW_BLOCK
    end

    subgraph STAGE4["Stage 4: Audit & Forensic Retrieval (core/raw_store.py)"]
        GET_API["FileRawStore.get(event_id) -> Decoded String"]
        GET_BYTES["FileRawStore.get_bytes(event_id) -> Exact Binary Bytes"]
        UES_RAW_BLOCK --> GET_API & GET_BYTES
    end
```

---

## Evidence

| Processing Step | Source File | Exact Symbol / Line | Confidence |
|---|---|---|---|
| Binary Capture & Surrogateescape | `ulpf/core/ingestion.py:72-82` | `FileReader.read()`, `errors='surrogateescape'` | **CONFIRMED** |
| Pre-Parse SHA-256 & UUIDv5 | `ulpf/core/pipeline.py:113-116` | `hashlib.sha256()`, `uuid.uuid5()` | **CONFIRMED** |
| 2-Tier Sharded Disk Storage | `ulpf/core/raw_store.py:61-75` | `FileRawStore._path()`, `dest.write_bytes()` | **CONFIRMED** |
| UES Raw Block Assembly | `ulpf/core/pipeline.py:72-76` | `_build_ues_event()`, `'raw'` container | **CONFIRMED** |
| Exact Byte Retrieval | `ulpf/core/raw_store.py:83-92` | `FileRawStore.get_bytes()` | **CONFIRMED** |
