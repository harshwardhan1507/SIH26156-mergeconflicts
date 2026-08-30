# 02 — Parser Detection Flow Diagram

This diagram visualizes the heuristic format detection decision hierarchy implemented in `FormatDetector.detect()` (`ulpf/core/detector.py:67-137`).

---

## Format Detection Decision Tree

```mermaid
flowchart TD
    RAW_IN(["Raw Log Line (raw_line: str, source_tag: str)"]) --> STEP1

    subgraph DETECTOR_HIERARCHY["FormatDetector.detect() Execution Steps"]
        STEP1{"1. Check sources.yaml\nOverride by source_tag?"}
        STEP1 -->|Match| RET_OVERRIDE["Return Configured format_id"]

        STEP2{"2. Match Cisco ASA?\nre.search(r'%ASA-\\d-\\d+', line)"}
        STEP1 -->|No Match| STEP2
        STEP2 -->|Match| RET_ASA["Return 'cisco_asa'"]

        STEP3{"3. Match ArcSight CEF?\nre.search(r'(?:^|\\s)CEF:\\d', line)"}
        STEP2 -->|No Match| STEP3
        STEP3 -->|Match| RET_CEF["Return 'cef'"]

        STEP4{"4. Match QRadar LEEF?\nre.search(r'(?:^|\\s)LEEF:[0-9.]+\\|', line)"}
        STEP3 -->|No Match| STEP4
        STEP4 -->|Match| RET_LEEF["Return 'leef'"]

        STEP5{"5. Match RFC 5424 Syslog?\nre.match(r'^<\\d+>1\\s', line)"}
        STEP4 -->|No Match| STEP5
        STEP5 -->|Match| RET_5424["Return 'syslog_rfc5424'"]

        STEP6{"6. Match XML / Windows Event?\nline.startswith('<?xml') or match(r'^\\s*<[a-zA-Z_]')"}
        STEP5 -->|No Match| STEP6
        STEP6 -->|Match| RET_XML["Return 'xml_generic'"]

        STEP7{"7. Starts with '{'?\nTry json.loads(line)"}
        STEP6 -->|No Match| STEP7
        
        subgraph JSON_DISPATCH["JSON Format Inspection"]
            JSON_CHECK{"Check JSON Signatures"}
            JSON_CHECK -->|eventSource.endswith('.amazonaws.com')| RET_CT["Return 'aws_cloudtrail'"]
            JSON_CHECK -->|protoPayload contains google.cloud.audit| RET_GCP["Return 'gcp_audit'"]
            JSON_CHECK -->|operationName + resourceId| RET_AZ["Return 'azure_monitor'"]
            JSON_CHECK -->|Generic JSON Object| RET_JSON["Return 'json_passthrough'"]
        end

        STEP7 -->|Valid JSON| JSON_CHECK

        STEP8{"8. Match PAN-OS CSV?\n',' in line & 'TRAFFIC' in line &\nlen(cols) >= 30 & cols[2] == 'TRAFFIC'"}
        STEP7 -->|Not JSON / Error| STEP8
        STEP8 -->|Match| RET_PAN["Return 'paloalto_csv'"]

        STEP9{"9. Match RFC 3164 BSD Syslog?\nmatch(r'^<\\d+>(Jan|Feb...)') or match(r'^<\\d+>\\d{4}-')"}
        STEP8 -->|No Match| STEP9
        STEP9 -->|Match| RET_3164["Return 'syslog_rfc3164'"]

        STEP10{"10. Dynamic Parser Registry Loop\nIterate get_all_parsers() -> parser.match(line)"}
        STEP9 -->|No Match| STEP10
        STEP10 -->|Match Found| RET_DYN["Return parser.name"]

        STEP11{"11. Key-Value Fallback?\nre.search(r'\\b\\w+=\\S+', line)"}
        STEP10 -->|No Match| STEP11
        STEP11 -->|Match| RET_KV["Return 'kv' (Routes to Dead-Letter)"]

        STEP12["12. Fallback to Unknown\nReturn 'unknown' (Routes to Dead-Letter)"]
        STEP11 -->|No Match| STEP12
    end
```

---

## Evidence

| Step / Rule | Source Code Location | Pattern / Signature | Confidence |
|---|---|---|---|
| Step 1: Config Overrides | `ulpf/core/detector.py:69-73` | `self._overrides.items()` from `sources.yaml` | **CONFIRMED** |
| Step 2: Cisco ASA | `ulpf/core/detector.py:78-79` | `_ASA_RE = re.compile(r'%ASA-\d-\d+')` | **CONFIRMED** |
| Step 3: ArcSight CEF | `ulpf/core/detector.py:82-83` | `_CEF_RE = re.compile(r'(?:^\|\s)CEF:\d')` | **CONFIRMED** |
| Step 4: QRadar LEEF | `ulpf/core/detector.py:86-87` | `_LEEF_RE = re.compile(r'(?:^\|\s)LEEF:[0-9.]+\|')` | **CONFIRMED** |
| Step 5: RFC 5424 | `ulpf/core/detector.py:90-91` | `_RFC5424_RE = re.compile(r'^<\d+>1\s')` | **CONFIRMED** |
| Step 6: Generic/Windows XML | `ulpf/core/detector.py:94-95` | `stripped.startswith('<?xml') or re.match(r'^\s*<[a-zA-Z_]', ...)` | **CONFIRMED** |
| Step 7: Cloud & Generic JSON | `ulpf/core/detector.py:98-109` | JSON structure checks for CloudTrail, GCP, Azure, generic | **CONFIRMED** |
| Step 8: PAN-OS CSV | `ulpf/core/detector.py:112-118` | `csv.reader`, `len(rows[0]) >= 30`, `cols[2] == 'TRAFFIC'` | **CONFIRMED** |
| Step 9: RFC 3164 Syslog | `ulpf/core/detector.py:121-122` | `_RFC3164_RE`, `_RFC3164_ALT_RE` | **CONFIRMED** |
| Step 10: Dynamic Parser Loop | `ulpf/core/detector.py:125-130` | `get_all_parsers()`, `parser.match(raw_line)` | **CONFIRMED** |
| Step 11: Key-Value Fallback | `ulpf/core/detector.py:133-134` | `_KV_RE = re.compile(r'\b\w+=\S+')` | **CONFIRMED** |
| Step 12: Unknown Fallback | `ulpf/core/detector.py:136` | `return 'unknown'` | **CONFIRMED** |
