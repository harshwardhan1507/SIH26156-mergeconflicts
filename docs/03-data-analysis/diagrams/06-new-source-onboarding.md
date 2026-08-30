# 06 — Plug-and-Play Log Source Onboarding Flow

This diagram illustrates the step-by-step developer and administrator workflow for onboarding a new log source into the ULPF framework.

---

## Source Onboarding Workflow Diagram

```mermaid
flowchart TD
    NEW_DEVICE["New Perimeter Security Device\n(e.g. Fortinet FortiGate Firewall)"] --> DEV_DECISION{"Is Log Format JSON/XML\nor Custom Unstructured Text?"}

    subgraph WORKFLOW_STRUCTURED["Path A: Structured JSON / XML Source"]
        MAP_ONLY["1. Create Declarative Mapping Spec\nulpf/schemas/mappings/fortios_json.yaml"]
        CONF_OVERRIDE["2. Add Source Tag Match (Optional)\nulpf/config/sources.yaml"]
        MAP_ONLY --> CONF_OVERRIDE
    end

    subgraph WORKFLOW_UNSTRUCTURED["Path B: Custom Text / Syslog Source"]
        P_CODE["1. Create Parser Plugin Class\nulpf/parsers/fortigate.py\n• Subclass BaseParser\n• Implement match() & extract()\n• Add @register_parser decorator"]
        P_MAP["2. Create Declarative Mapping Spec\nulpf/schemas/mappings/fortigate.yaml\n• Define source, event, network, identity, rule mappings"]
        P_DET["3. Add Signature to FormatDetector (Optional)\nulpf/core/detector.py (for high-priority regex)"]
        P_TEST["4. Create Parser Unit Tests\nulpf/tests/test_parser_fortigate.py"]
        
        P_CODE --> P_MAP --> P_DET --> P_TEST
    end

    DEV_DECISION -->|JSON / XML| WORKFLOW_STRUCTURED
    DEV_DECISION -->|Custom Text / Syslog| WORKFLOW_UNSTRUCTURED

    subgraph ZERO_TOUCH_CORE["Zero-Touch Automated Subsystems"]
        ZT_REG["Parser Registry\n(Auto-imports via pkgutil.iter_modules)"]
        ZT_NORM["Normalization Engine\n(Auto-globs *.yaml on startup)"]
        ZT_SCHEMA["Universal Event Schema\n(No modifications required)"]
        ZT_STORE["FileRawStore\n(Agnostic raw byte persistence)"]
        ZT_SINKS["Egress Sinks\n(Auto-forwards to NDJSON/Parquet/Kafka)"]
        ZT_DASH["Dashboard & SQLite Indexer\n(Auto-indexes new format events)"]
    end

    WORKFLOW_STRUCTURED --> ZERO_TOUCH_CORE
    WORKFLOW_UNSTRUCTURED --> ZERO_TOUCH_CORE
```

---

## Evidence

| Onboarding Stage | Source File | Mechanism / Architecture | Confidence |
|---|---|---|---|
| Dynamic Parser Auto-Import | `ulpf/parsers/__init__.py:1-15` | `pkgutil.iter_modules(__path__)` imports all `.py` modules | **CONFIRMED** |
| Registry Decorator | `ulpf/core/registry.py:19-23` | `@register_parser` registers parser class | **CONFIRMED** |
| Dynamic Mapping Globbing | `ulpf/core/normalization.py:141-145` | `self.mappings_dir.glob('*.yaml')` | **CONFIRMED** |
| Schema Extensibility | `ulpf/schemas/ues_schema.json:92-95` | `vendor_attributes` captures unmapped keys without schema edits | **CONFIRMED** |
