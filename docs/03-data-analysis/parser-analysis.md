# Parser Architecture Deep Dive

This document provides a granular inspection of all 11 parser plugins implemented in `ulpf/parsers/`, detailing input grammar, extraction methods, nested data handling, timestamp resolution, error behavior, and known edge-case limitations.

---

## 1. Comprehensive Parser Specification Matrix

| Parser Name | Source File | Input Grammar / Protocol | Header Format / Regex | Key Fields Extracted | Nested Structures | Timestamp Parsing | Error Handling |
|---|---|---|---|---|---|---|---|
| **`CEFParser`** | `ulpf/parsers/cef.py` | ArcSight Common Event Format | `^CEF:\d+\|vendor\|product\|version\|sig_id\|name\|sev\|ext` (optional syslog prefix) | `cef_version`, `DeviceVendor`, `DeviceProduct`, `SignatureID`, `Name`, `Severity`, `src`, `dst`, `spt`, `dpt`, `proto`, `in`, `out`, `suser`, `act` | Key-value pairs in extension string (`key=value`) | Parses `rt`, `start`, `end`, `deviceReceiptTime` via `parse_timestamp()` | Raises `ParseError` on header regex failure |
| **`LEEFParser`** | `ulpf/parsers/leef.py` | IBM QRadar LEEF 1.0 & 2.0 | `^LEEF:[12]\.0\|vendor\|product\|version\|event_id\|[delimiter]?\|attrs` (optional syslog prefix) | `leef_version`, `vendor`, `product`, `event_id`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `username`, `bytes_in`, `bytes_out`, `severity_raw`, `action` | Tab or custom delimiter separated `k=v` pairs | Parses `devTime` via `parse_timestamp()` | Raises `ParseError` on header regex failure |
| **`CiscoASAParser`** | `ulpf/parsers/cisco_asa.py` | Cisco ASA Firewall Syslog | Outer RFC 3164 prefix + `%ASA-\d-\d+:\s*message` | `vendor`, `product`, `hostname`, `priority`, `facility`, `asa_severity`, `asa_mnemonic`, `acl_name`, `acl_action`, `proto`, `src_ip`, `src_port`, `dst_ip`, `dst_port` | Regex extraction of connection 5-tuples from message | Injects current UTC year if BSD timestamp has no year | Raises `ParseError` on envelope or ASA pattern mismatch |
| **`PaloAltoCSVParser`** | `ulpf/parsers/paloalto_csv.py` | PAN-OS CSV Traffic Stream | Positional CSV row (>=30 columns), column[2] == `'TRAFFIC'` | `vendor`, `product`, `device_serial`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`, `bytes_sent`, `bytes_received`, `action_raw`, `action_ues`, `rule`, `src_user`, `app`, `src_zone`, `dst_zone` | Additional columns beyond index 35 captured in `_vendor_extra` | Parses `receive_time` ISO/dateutil string | Raises `ParseError` on empty row, <30 cols, or non-TRAFFIC type |
| **`AWSCloudTrailParser`** | `ulpf/parsers/aws_cloudtrail.py` | AWS CloudTrail JSON Event | JSON object with `eventVersion`, `eventSource` (`*.amazonaws.com`), `eventName` | `vendor`, `product`, `event_name`, `event_source`, `aws_region`, `src_ip`, `username`, `user_arn`, `account_id`, `error_code`, `error_message`, `category`, `outcome` | Serializes `requestParameters` and `responseElements` as JSON strings | Parses `eventTime` ISO 8601 string | Raises `ParseError` on invalid JSON or missing `eventVersion` |
| **`AzureMonitorParser`** | `ulpf/parsers/azure_monitor.py` | Azure Activity & Diagnostic JSON | JSON object with `operationName`, `resourceId`, `resultType` | `vendor`, `product`, `operation_name`, `action`, `resource_id`, `az_category`, `result_type`, `src_ip`, `username`, `category`, `outcome`, parsed resource parts | Decomposes `resourceId` path into subscription, RG, provider, type | Parses `time` or `timestamp` ISO 8601 string | Raises `ParseError` on JSON syntax error |
| **`GCPAuditParser`** | `ulpf/parsers/gcp_audit.py` | GCP Cloud Audit JSON Log | JSON with `protoPayload` (`type.googleapis.com/google.cloud.audit...`) | `vendor`, `product`, `method_name`, `action`, `resource_name`, `principal_email`, `src_ip`, `user_agent`, `status_code`, `gcp_severity`, `project_id`, `log_name` | Extracts authorization grant status and request metadata | Parses `timestamp` ISO 8601 string | Raises `ParseError` on JSON syntax error |
| **`SyslogRFC3164Parser`**| `ulpf/parsers/syslog_rfc3164.py` | BSD Syslog (RFC 3164) | `^<(\d+)>(Mon DD HH:MM:SS|ISO)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$` | `priority`, `facility`, `syslog_severity`, `syslog_severity_name`, `hostname`, `tag`, `pid`, `message`, `severity_ues` | None (flat syslog headers) | Injects current UTC year for BSD month-day timestamps | Raises `ParseError` if PRI or format fails regex |
| **`SyslogRFC5424Parser`**| `ulpf/parsers/syslog_rfc5424.py` | IETF Structured Syslog (RFC 5424) | `^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+((?:\[.*?\])+|-)\s*(.*)$` | `priority`, `facility`, `syslog_severity`, `version`, `hostname`, `appname`, `procid`, `msgid`, `message`, flattened structured data | Parses `[SDID@... key="val"]` blocks into `sd_<sdid>_<key>` | Parses RFC 5424 high-precision ISO timestamp | Raises `ParseError` on header regex failure |
| **`XMLGenericParser`** | `ulpf/parsers/xml_generic.py` | Windows EVTX XML / Generic XML | `^<\?xml` or `^<[a-zA-Z_]` (Excludes syslog `<PRI>`) | Windows: `windows_event_id`, `category`, `severity_numeric`, `action`, `src_ip`, `dst_ip`, `username`, `process_name`, `process_path`. Generic: flattened tags | Recursively flattens XML elements to dotted paths (`tag.child.attr`) | Parses `TimeCreated.SystemTime` via `parse_timestamp()` | Raises `ParseError` on XML syntax error |
| **`JSONPassthroughParser`** | `ulpf/parsers/json_passthrough.py` | Generic Structured JSON Log | `^{.*}$` | Copies all top-level keys into `fields`; resolves common timestamp/IP/severity keys | Preserves nested JSON sub-objects as dicts in `_raw` | Inspects `ts`, `timestamp`, `time`, `@timestamp`, `event_time` | Raises `ParseError` on JSON syntax error |

---

## 2. Granular Parser Extraction & Edge-Case Findings

### 2.1 IPv6 Handling Across Parsers
* In `BaseParser.validate_ip()` (`ulpf/parsers/base.py:98-113`), validation tests `IPv4Address` first, then `IPv6Address`.
* **Confirmed Limitation**: Parsers using regex-based IP capture (e.g. `CiscoASAParser._ASA_CONN_RE` line 40: `\d{1,3}(?:\.\d{1,3}){3}`) **only match IPv4 dotted-quad addresses**. If Cisco ASA emits an IPv6 connection log, `conn_m` fails to capture the IP, resulting in `src_ip = None` and `dst_ip = None`.

### 2.2 BSD Syslog Year-Rollover Risk
* `SyslogRFC3164Parser` (lines 68-70) and `CiscoASAParser` (lines 84-86) prepend `datetime.now(tz=timezone.utc).year` when parsing year-less timestamps (e.g. `Aug 15 14:22:10`).
* **Observed Limitation**: When replaying historical logs or during a December 31 -> January 1 rollover, events ingested across year boundaries may receive the incorrect year.

### 2.3 Delimiter Escaping in CEF and LEEF
* `CEFParser._parse_extension()` (`ulpf/parsers/cef.py:51`) uses `(?<=\s\w+=|$)` lookahead to support values containing spaces.
* `LEEFParser._parse_leef_attributes()` (`ulpf/parsers/leef.py:54-60`) uses `attr_str.split(delimiter)`. If delimiter is tab (`\t`), values containing tabs will be corrupted into misaligned key-value pairs.
