# 06 — Normalization / UES Architecture

This diagram details the declarative normalization pipeline, YAML mapping engine, semantic taxonomy resolution, OCSF crosswalking, and lossless attribute preservation.

---

## Normalization Architecture Diagram

```mermaid
flowchart TD
    INPUT_DICT(["extracted: dict[str, Any]\n(From Parser Plugin)"]) --> NORM_ENGINE

    subgraph ENGINE["NormalizationEngine (core/normalization.py)"]
        NORM_ENGINE["NormalizationEngine.normalize(extracted, parser_name)"]
        
        subgraph YAML_CONFIGS["Declarative Mapping Definitions (schemas/mappings/*.yaml)"]
            YAML_FILES["cisco_asa.yaml\ncef.yaml\nleef.yaml\naws_cloudtrail.yaml\nazure_monitor.yaml\n... (11 YAML Specs)"]
        end

        YAML_CONFIGS --> NORM_ENGINE

        subgraph FIELD_MAPPERS["Block Transformers & Value Resolvers"]
            MAP_SRC["1. Source Block Resolver\n• vendor, product, device_hostname, source_ip"]
            
            MAP_EV["2. Event Block Resolver\n• _infer_category() -> network, auth, threat, system, policy, api, db, unknown\n• _resolve_outcome() -> success, failure, unknown\n• Severity numeric [0.0 - 10.0] & severity_inferred flag\n• OCSF Class Mapping (_OCSF_CLASS_MAP) -> 4001, 3001, 2001...\n• OCSF Activity Mapping (_OCSF_ACTIVITY_MAP)"]
            
            MAP_NET["3. Network Block Resolver\n• src_ip, src_port, dst_ip, dst_port, protocol\n• bytes_in, bytes_out\n• _resolve_direction() -> inbound, outbound, internal, unknown"]
            
            MAP_ID["4. Identity Block Resolver\n• username, user_domain"]
            
            MAP_RULE["5. Rule Block Resolver\n• rule_id, rule_name, policy_action"]
            
            MAP_BAG["6. Vendor Attributes Open Bag\n• Iterates all extracted keys\n• Captures all unmapped keys not starting with '_'\n• Guarantees 100% attribute preservation"]
        end

        NORM_ENGINE --> MAP_SRC & MAP_EV & MAP_NET & MAP_ID & MAP_RULE & MAP_BAG
    end

    subgraph UES_ASSEMBLY["Pipeline Envelope Assembly (core/pipeline.py:_build_ues_event)"]
        UES_DICT["Canonical Universal Event Schema (UES 1.2.0)\n\n{\n  'schema_version': '1.2.0',\n  'tenant_id': str,\n  'event_id': UUIDv5,\n  'ingest_timestamp': ISO8601,\n  'source_event_timestamp': ISO8601,\n  'raw': {\n    'raw_payload': str,\n    'raw_format': str,\n    'raw_hash': SHA256\n  },\n  'source': {...},\n  'event': {...},\n  'network': {...},\n  'identity': {...},\n  'rule': {...},\n  'vendor_attributes': {...},\n  'enrichment': null,\n  'lineage': {\n    'parser_name': str,\n    'parser_version': str,\n    'normalization_ruleset_version': str\n  }\n}"]
    end

    MAP_SRC & MAP_EV & MAP_NET & MAP_ID & MAP_RULE & MAP_BAG --> UES_DICT
```

---

## Evidence

| Component / Mapping Rule | Source File | Method / Constant | Confidence |
|---|---|---|---|
| YAML Mapping File Loading | `ulpf/core/normalization.py:141-145` | `self._load_all()` globbing `*.yaml` | **CONFIRMED** |
| Category Inference & Keywords | `ulpf/core/normalization.py:37-62` | `_CATEGORY_KEYWORDS`, `_infer_category()` | **CONFIRMED** |
| Outcome Resolution Map | `ulpf/core/normalization.py:21-35, 64-69` | `_ACTION_OUTCOME_MAP`, `_resolve_outcome()` | **CONFIRMED** |
| Direction Resolution Map | `ulpf/core/normalization.py:71-80` | `_resolve_direction()` checking zone substrings | **CONFIRMED** |
| OCSF Class & Activity Crosswalk | `ulpf/core/normalization.py:102-129, 232-236` | `_OCSF_CLASS_MAP`, `_OCSF_ACTIVITY_MAP` | **CONFIRMED** |
| Vendor Attribute Bag (Lossless) | `ulpf/core/normalization.py:323-327` | `for k, v in extracted.items(): if k not in mapped_keys` | **CONFIRMED** |
| Canonical UES 1.2.0 Builder | `ulpf/core/pipeline.py:50-89` | `Pipeline._build_ues_event()` | **CONFIRMED** |
