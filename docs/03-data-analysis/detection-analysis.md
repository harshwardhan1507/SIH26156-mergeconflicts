# Format Detection Deep Dive Analysis

This document analyzes the exact heuristic decision tree implemented in `ulpf/core/detector.py`, evaluating classification accuracy, regex ordering, false positives, false negatives, and adversarial input resilience.

---

## 1. Concrete Format Detection Decision Flow

```mermaid
flowchart TD
    RAW_IN(["Incoming Log Line & Source Tag\n(raw_line: str, source_tag: str)"]) --> STEP1

    subgraph D_TREE["FormatDetector Decision Hierarchy (core/detector.py:67-137)"]
        STEP1{"1. Manual Override?\n(source_tag in sources.yaml)"}
        RET_OVERRIDE["Return Configured format_id"]
        STEP1 -->|Match| RET_OVERRIDE

        STEP2{"2. Cisco ASA Syslog?\n(%ASA-\\d-\\d+ in stripped)"}
        RET_ASA["Return 'cisco_asa'"]
        STEP1 -->|No| STEP2
        STEP2 -->|Match| RET_ASA

        STEP3{"3. ArcSight CEF?\n((?:^|\\s)CEF:\\d in stripped)"}
        RET_CEF["Return 'cef'"]
        STEP2 -->|No| STEP3
        STEP3 -->|Match| RET_CEF

        STEP4{"4. IBM QRadar LEEF?\n((?:^|\\s)LEEF:[0-9.]+\\| in stripped)"}
        RET_LEEF["Return 'leef'"]
        STEP3 -->|No| STEP4
        STEP4 -->|Match| RET_LEEF

        STEP5{"5. RFC 5424 Structured Syslog?\n(^<\\d+>1\\s in stripped)"}
        RET_5424["Return 'syslog_rfc5424'"]
        STEP4 -->|No| STEP5
        STEP5 -->|Match| RET_5424

        STEP6{"6. Generic / Windows XML?\n(^<\\?xml or ^\\s*<[a-zA-Z_])"}
        RET_XML["Return 'xml_generic'"]
        STEP5 -->|No| STEP6
        STEP6 -->|Match| RET_XML

        STEP7{"7. JSON Object?\n(stripped.startswith('{'))"}
        JSON_CHECK{"Check JSON Signatures:\n• eventSource ends in .amazonaws.com -> 'aws_cloudtrail'\n• protoPayload contains google.cloud.audit -> 'gcp_audit'\n• operationName + resourceId -> 'azure_monitor'\n• Otherwise -> 'json_passthrough'"}
        STEP6 -->|No| STEP7
        STEP7 -->|Yes| JSON_CHECK
        JSON_CHECK -->|CloudTrail| RET_CT["Return 'aws_cloudtrail'"]
        JSON_CHECK -->|GCP| RET_GCP["Return 'gcp_audit'"]
        JSON_CHECK -->|Azure| RET_AZ["Return 'azure_monitor'"]
        JSON_CHECK -->|Generic| RET_JSON["Return 'json_passthrough'"]

        STEP8{"8. Palo Alto Networks CSV?\n(',' & 'TRAFFIC' in line &\nlen(row) >= 30 & row[2] == 'TRAFFIC')"}
        RET_PAN["Return 'paloalto_csv'"]
        STEP7 -->|No / JSONDecodeError| STEP8
        STEP8 -->|Match| RET_PAN

        STEP9{"9. RFC 3164 BSD Syslog?\n(^<\\d+>(Jan|Feb...) or ^<\\d+>\\d{4}-)"}
        RET_3164["Return 'syslog_rfc3164'"]
        STEP8 -->|No| STEP9
        STEP9 -->|Match| RET_3164

        STEP10{"10. Dynamic Parser Loop?\n(Iterate get_all_parsers() -> parser.match())"}
        RET_DYN["Return parser.name"]
        STEP9 -->|No| STEP10
        STEP10 -->|Match| RET_DYN

        STEP11{"11. Key-Value Fallback?\n(\\b\\w+=\\S+ matched)"}
        RET_KV["Return 'kv' (Routes to Dead-Letter)"]
        STEP10 -->|No| STEP11
        STEP11 -->|Match| RET_KV

        STEP12["12. Unknown Format Fallback\nReturn 'unknown'"]
        STEP11 -->|No| STEP12
    end
```

---

## 2. Technical Evaluation of Detection Strengths & Failure Modes

### 2.1 Precedence Integrity (Encapsulation Resolution)
* **Observed Strength**: Cisco ASA messages and CEF/LEEF payloads are frequently encapsulated inside standard syslog envelopes (e.g. `<134>1 2026-08-30... CEF:0|...` or `<166>Aug 15... %ASA-6-106100:...`).
* `FormatDetector` checks `%ASA-`, `CEF:`, and `LEEF:` **before** testing generic RFC 5424 or RFC 3164 regexes. This prevents generic syslog parsers from consuming lines that belong to dedicated perimeter firewall parsers.

### 2.2 Potential False Positives & Conflicts
1. **XML vs. Syslog False Positive Protection**:
   - Generic XML regex `^\s*<[a-zA-Z_]` excludes digits (`\d`), ensuring syslog priority headers like `<134>` or `<38>` are not misclassified as XML tags.
2. **JSON Format Ambiguity**:
   - `json.loads()` is executed inline during detection.
   - If a JSON log contains `eventSource: "s3.amazonaws.com"`, it is routed to `aws_cloudtrail`.
   - If a custom application log happens to include `eventSource: "foo.amazonaws.com"`, it will be misrouted to `aws_cloudtrail` rather than `json_passthrough`.
3. **Key-Value Fallback Dead-Letter Hole**:
   - Step 11 matches `\b\w+=\S+` and returns format ID `'kv'`.
   - However, the repository contains no registered parser named `'kv'`.
   - In `Pipeline.process_event()`, `get_parser_for_format('kv')` returns `None`, causing all KV fallback logs to land directly in `dead_letter.ndjson`.

### 2.3 Performance & ReDoS (Regular Expression Denial of Service)
* All detection regexes (`_ASA_RE`, `_CEF_RE`, `_LEEF_RE`, `_RFC5424_RE`, `_RFC3164_RE`, `_KV_RE`) are pre-compiled module-level single-pass patterns with bounded anchors (`^` or `(?:^|\s)`).
* None contain nested unbounded quantifiers (`(a+)+`), ensuring $O(N)$ linear matching speed and zero vulnerability to catastrophic backtracking.
