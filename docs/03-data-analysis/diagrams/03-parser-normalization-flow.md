# 03 — Parser & Normalization Flow Diagram

This diagram visualizes the transition from parser token extraction through declarative YAML mapping transformation into canonical Universal Event Schema records.

---

## Parser to Normalization Data Flow

```mermaid
flowchart TD
    RAW_LINE(["Raw Log Line (str)"]) --> PARSE_OP["parser.extract(raw_line)"]

    subgraph EXTRACTION["1. Parser Extraction Stage (parsers/*.py)"]
        PARSE_OP --> EXTRACTED_DICT["extracted: dict[str, Any]\n(Header fields, parsed timestamps, normalized IPs)"]
    end

    subgraph NORMALIZATION_STAGE["2. Normalization Engine (core/normalization.py)"]
        LOAD_YAML["Load Declarative Mapping:\nschemas/mappings/<parser_name>.yaml"]
        EXTRACTED_DICT --> LOAD_YAML

        subgraph TRANSFORMERS["Built-in Transformers & Taxonomy Mappers"]
            T_CAT["_infer_category(extracted)\n(Keyword matching: network, auth, threat...)"]
            T_ACT["_resolve_outcome(extracted, action_spec)\n(allow/permit -> success; deny/drop -> failure)"]
            T_DIR["_resolve_direction(extracted)\n(outside/untrust zone inspection)"]
            T_SEV["Resolve Severity Numeric [0.0 - 10.0]\n(Explicit numeric or default 5.0 with severity_inferred=True)"]
            T_OCSF["OCSF Taxonomy Crosswalk\n(_OCSF_CLASS_MAP & _OCSF_ACTIVITY_MAP)"]
        end

        LOAD_YAML --> T_CAT & T_ACT & T_DIR & T_SEV & T_OCSF

        subgraph BLOCKS["Standardized Subsystem Blocks"]
            B_SRC["source: {vendor, product, device_hostname, source_ip, log_format}"]
            B_EV["event: {category, class_name, class_uid, activity_name, action, outcome, severity_numeric...}"]
            B_NET["network: {src_ip, src_port, dst_ip, dst_port, protocol, bytes_in, bytes_out, direction}"]
            B_ID["identity: {username, user_domain}"]
            B_RULE["rule: {rule_id, rule_name, policy_action}"]
            B_BAG["vendor_attributes: {unmapped_key_1: val_1, unmapped_key_2: val_2, ...}"]
        end

        T_CAT & T_ACT & T_DIR & T_SEV & T_OCSF --> B_SRC & B_EV & B_NET & B_ID & B_RULE & B_BAG
    end

    subgraph UES_ASSEMBLY["3. UES 1.2.0 Envelope Assembly (core/pipeline.py)"]
        UES_FINAL["Canonical UES Event Dict\n{\n  'schema_version': '1.2.0',\n  'tenant_id': str,\n  'event_id': UUIDv5,\n  'ingest_timestamp': ISO8601,\n  'source_event_timestamp': ISO8601,\n  'raw': {'raw_payload', 'raw_format', 'raw_hash'},\n  'source': {...},\n  'event': {...},\n  'network': {...},\n  'identity': {...},\n  'rule': {...},\n  'vendor_attributes': {...},\n  'lineage': {'parser_name', 'parser_version', 'ruleset_version'}\n}"]
        B_SRC & B_EV & B_NET & B_ID & B_RULE & B_BAG --> UES_FINAL
    end
```

---

## Evidence

| Processing Step                   | Source File                          | Method / Constant                                        | Confidence    |
| --------------------------------- | ------------------------------------ | -------------------------------------------------------- | ------------- |
| Parser Extraction Call            | `ulpf/core/pipeline.py:159`          | `extracted = parser.extract(raw_line)`                   | **CONFIRMED** |
| Declarative YAML Mapping          | `ulpf/core/normalization.py:153-156` | `mapping = self._get_mapping(parser_name)`               | **CONFIRMED** |
| Category Keyword Inference        | `ulpf/core/normalization.py:46-62`   | `_infer_category()`, `_CATEGORY_KEYWORDS`                | **CONFIRMED** |
| Action-to-Outcome Mapping         | `ulpf/core/normalization.py:64-69`   | `_resolve_outcome()`, `_ACTION_OUTCOME_MAP`              | **CONFIRMED** |
| OCSF Class & Activity Crosswalk   | `ulpf/core/normalization.py:102-129` | `_OCSF_CLASS_MAP`, `_OCSF_ACTIVITY_MAP`                  | **CONFIRMED** |
| Lossless Attribute Bag Collection | `ulpf/core/normalization.py:323-327` | `for k, v in extracted.items(): if k not in mapped_keys` | **CONFIRMED** |
| UES Dictionary Assembly           | `ulpf/core/pipeline.py:50-89`        | `_build_ues_event()`                                     | **CONFIRMED** |
