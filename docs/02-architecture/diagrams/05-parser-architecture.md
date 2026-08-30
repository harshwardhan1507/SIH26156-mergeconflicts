# 05 — Parser Architecture

This diagram details the parser plugin architecture, discovery mechanics, heuristic format classification hierarchy, and extraction interfaces.

---

## Parser Subsystem Diagram

```mermaid
flowchart TD
    RAW_LINE(["Raw Log Line (raw_line: str, source_tag: str)"]) --> DETECTOR

    subgraph DETECTION_HIERARCHY["FormatDetector Classification Hierarchy (core/detector.py)"]
        DETECTOR["FormatDetector.detect()"]
        STEP_OVERRIDE["1. Manual Override Check\n(sources.yaml by source_tag)"]
        STEP_PRIORITY["2. Priority Regex / Marker Search\n• Cisco ASA: %ASA-\\d-\\d+\n• CEF: (?:^|\\s)CEF:\\d\n• LEEF: (?:^|\\s)LEEF:[0-9.]+\\|\n• RFC 5424: ^<\\d+>1\\s\n• XML: ^<\\?xml or ^\\s*<[a-zA-Z_]"]
        STEP_JSON["3. JSON Signature Inspection\n• CloudTrail: eventSource ending in .amazonaws.com\n• GCP Audit: protoPayload.@type contains google.cloud.audit\n• Azure Monitor: operationName + resourceId\n• Generic JSON: json_passthrough"]
        STEP_CSV["4. CSV Positional Checks\n• Palo Alto: col[2] == 'TRAFFIC' & >=30 cols"]
        STEP_BSD["5. BSD Syslog Matchers\n• RFC 3164: ^<\\d+>(Jan|Feb...) or ^<\\d+>\\d{4}-"]
        STEP_DYNAMIC["6. Dynamic Parser Evaluation\nIterate get_all_parsers() -> parser.match(raw_line)"]
        STEP_KV["7. Key-Value Fallback\n\\b\\w+=\\S+ -> 'kv'"]
        STEP_UNKNOWN["8. Unknown Fallback\n'unknown'"]

        DETECTOR --> STEP_OVERRIDE
        STEP_OVERRIDE -->|Not Found| STEP_PRIORITY
        STEP_PRIORITY -->|Not Matched| STEP_JSON
        STEP_JSON -->|Not Matched| STEP_CSV
        STEP_CSV -->|Not Matched| STEP_BSD
        STEP_BSD -->|Not Matched| STEP_DYNAMIC
        STEP_DYNAMIC -->|Not Matched| STEP_KV
        STEP_KV -->|Not Matched| STEP_UNKNOWN
    end

    subgraph REGISTRY_ENGINE["Parser Registry & Discovery (core/registry.py)"]
        REG_DICT[("_REGISTRY: dict[str, type[BaseParser]]\nGlobal Class Registry")]
        REG_DEC["@register_parser Class Decorator"]
        REG_DISC["pkgutil.iter_modules(ulpf.parsers.__path__)\n(Auto-import in parsers/__init__.py)"]
        REG_GET["get_parser_for_format(format_id) -> BaseParser instance"]
        REG_DISC --> REG_DICT
        REG_DEC --> REG_DICT
        REG_DICT --> REG_GET
    end

    subgraph BASE_CLASS["Abstract Base Parser (parsers/base.py)"]
        BASE_PARSER["BaseParser (ABC)\n+ name: str\n+ version: str\n+ log_format: str\n+ match(raw_line: str) -> bool\n+ extract(raw_line: str) -> dict[str, Any]\n\nHelper Utilities:\n• parse_timestamp() (dateutil / epochs)\n• validate_ip() (ipaddress)\n• safe_int(), safe_float(), safe_port()\n• strip_quotes()"]
    end

    subgraph PLUGINS["11 Verified Parser Implementations (parsers/*.py)"]
        P_CEF["CEFParser (cef.py)\nArcSight 8-pipe headers + K=V extensions"]
        P_LEEF["LEEFParser (leef.py)\nQRadar 1.0 & 2.0 headers + custom delimiters"]
        P_3164["SyslogRFC3164Parser (syslog_rfc3164.py)\nBSD syslog + current year injection"]
        P_5424["SyslogRFC5424Parser (syslog_rfc5424.py)\nStructured Syslog + SDID blocks"]
        P_ASA["CiscoASAParser (cisco_asa.py)\n%ASA- codes, ACL rules, 5-tuples"]
        P_PAN["PaloAltoCSVParser (paloalto_csv.py)\nPAN-OS 35+ column CSV traffic logs"]
        P_AWS["AWSCloudTrailParser (aws_cloudtrail.py)\nCloudTrail JSON, IAM, S3, ARN extraction"]
        P_AZURE["AzureMonitorParser (azure_monitor.py)\nAzure Activity / ResourceId path decomposition"]
        P_GCP["GCPAuditParser (gcp_audit.py)\nGoogle Cloud protoPayload & ServiceAccount"]
        P_XML["XMLGenericParser (xml_generic.py)\nWindows EVTX EventIDs (4624, 4625, 1102) & XML"]
        P_JSON["JSONPassthroughParser (json_passthrough.py)\nGeneric structured JSON flattener"]
    end

    STEP_OVERRIDE & STEP_PRIORITY & STEP_JSON & STEP_CSV & STEP_BSD & STEP_DYNAMIC -->|format_id| REG_GET
    REG_GET --> PLUGINS
    PLUGINS --|> BASE_PARSER
    PLUGINS -->|@register_parser| REG_DEC
    PLUGINS -->|extract(raw_line)| EXTRACTED_DICT(["extracted: dict[str, Any]"])
```

---

## Evidence

| Component / Subsystem | Source File | Symbol / Method | Confidence |
|---|---|---|---|
| Format Detection Hierarchy | `ulpf/core/detector.py:67-137` | `FormatDetector.detect()`, lines 67-137 | **CONFIRMED** |
| Global Registry Decorator | `ulpf/core/registry.py:16-38` | `_REGISTRY`, `@register_parser`, `get_parser_for_format()` | **CONFIRMED** |
| Auto-Discovery via `pkgutil` | `ulpf/parsers/__init__.py:1-15` | `pkgutil.iter_modules(__path__)` | **CONFIRMED** |
| `BaseParser` Base Class | `ulpf/parsers/base.py:32-150` | `BaseParser`, `parse_timestamp()`, `validate_ip()` | **CONFIRMED** |
| 11 Parser Plugin Implementations | `ulpf/parsers/` | `cef.py`, `leef.py`, `syslog_rfc3164.py`, `syslog_rfc5424.py`, `cisco_asa.py`, `paloalto_csv.py`, `aws_cloudtrail.py`, `azure_monitor.py`, `gcp_audit.py`, `xml_generic.py`, `json_passthrough.py` | **CONFIRMED** |
