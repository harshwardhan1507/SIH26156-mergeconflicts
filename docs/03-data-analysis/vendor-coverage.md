# Vendor & Log Source Coverage Matrix

This document evaluates the concrete vendor and log format coverage of ULPF against real-world perimeter security devices, firewalls, cloud infrastructures, operating systems, and databases.

---

## 1. Concrete Vendor & Format Support Matrix

| Vendor / Platform | Log Format / Subsystem | Detection Method | Parser Plugin | Normalization Mapping | Raw Byte Retention | Support Classification | Verified Evidence & Limitations |
|---|---|---|---|---|---|---|---|
| **Cisco Systems** | Cisco ASA Firewall / VPN Syslog | `%ASA-\d-\d+` regex | `CiscoASAParser` | `cisco_asa.yaml` | **100%** | **SUPPORTED** | Tested with ASA-4-106023, ASA-2-106016, ASA-6-106100. IPv4 only in connection regex. |
| **Palo Alto Networks** | PAN-OS Traffic CSV | CSV col[2] == `'TRAFFIC'`, >=30 cols | `PaloAltoCSVParser` | `paloalto_csv.yaml` | **100%** | **SUPPORTED** | Tested with 35+ column traffic logs. Threat/System PAN logs not handled by CSV parser. |
| **ArcSight SIEM Ecosystem** | Common Event Format (CEF) | `(?:^\|\s)CEF:\d` regex | `CEFParser` | `cef.yaml` | **100%** | **SUPPORTED** | Tested with 8 pipe headers + key-value extension pairs. Supports syslog prefix. |
| **IBM QRadar Ecosystem** | Log Event Extended Format (LEEF) | `(?:^\|\s)LEEF:[12]\.0\|` regex | `LEEFParser` | `leef.yaml` | **100%** | **SUPPORTED** | Tested with LEEF 1.0 and 2.0 with tab or custom delimiters. Supports syslog prefix. |
| **Amazon Web Services (AWS)** | AWS CloudTrail JSON Events | `eventSource.endswith('.amazonaws.com')` | `AWSCloudTrailParser`| `aws_cloudtrail.yaml` | **100%** | **SUPPORTED** | Tested with S3, IAM, EC2 CloudTrail events. Nested parameters preserved as JSON strings. |
| **Microsoft Azure** | Azure Monitor / Activity Logs | `operationName` + `resourceId` | `AzureMonitorParser` | `azure_monitor.yaml` | **100%** | **SUPPORTED** | Tested with Azure Key Vault, Compute activity logs. Resource hierarchy parsed into attributes. |
| **Google Cloud Platform (GCP)**| GCP Cloud Audit JSON Logs | `protoPayload.@type` audit signature | `GCPAuditParser` | `gcp_audit.yaml` | **100%** | **SUPPORTED** | Tested with Cloud Storage, KMS audit logs. Project ID and method actions decomposed. |
| **Microsoft Windows** | Windows Event Log (EVTX / XML) | `<Event xmlns="...">` root tag | `XMLGenericParser` | `xml_generic.yaml` | **100%** | **SUPPORTED** | Tested with EventIDs 4624, 4625, 4688, 4689, 5156, 1102. Flattens EventData parameters. |
| **Linux / BSD Systems** | Standard Syslog (RFC 3164) | `<PRI>Mon DD HH:MM:SS` regex | `SyslogRFC3164Parser`| `syslog_rfc3164.yaml` | **100%** | **SUPPORTED** | Tested with Squid, SSH, Auth syslog messages. Injects current year if missing. |
| **IETF Standards** | Structured Syslog (RFC 5424) | `<PRI>1 ISO8601 HOST...` regex | `SyslogRFC5424Parser`| `syslog_rfc5424.yaml` | **100%** | **SUPPORTED** | Tested with structured data blocks `[SDID@... key="val"]`. |
| **Generic JSON Applications** | Structured JSON Streams | Top-level `{...}` JSON | `JSONPassthroughParser`| `json_passthrough.yaml`| **100%** | **SUPPORTED** | Tested with MySQL Audit JSON, OpenVPN JSON gateway logs. Top-level keys copied directly. |
| **Fortinet (FortiGate)** | FortiOS Key-Value Log Stream | `\b\w+=\S+` regex | None (`'kv'` fallback) | None | **100% (Raw store)** | **NOT SUPPORTED** | Detected as format `'kv'`, but lack of `KVParser` routes to `dead_letter.ndjson`. |
| **Check Point** | Check Point OPSEC / LEA / Log | None | None | None | **100% (Raw store)** | **NOT SUPPORTED** | Detected as `'unknown'`, routed to `dead_letter.ndjson`. |
| **Snort / Suricata** | EVE JSON / Fast Alert format | JSON format -> `json_passthrough` | `JSONPassthroughParser`| `json_passthrough.yaml`| **100%** | **PARTIALLY SUPPORTED** | EVE JSON handled generically; Fast Alert text (`[**] [1:100:1] ...`) routed to `'unknown'`. |

---

## 2. Support Level Definitions

1. **SUPPORTED (11 Formats)**: Dedicated `BaseParser` subclass, format detection heuristic rule, declarative YAML mapping spec, and active test coverage exist in the codebase.
2. **PARTIALLY SUPPORTED**: Handled via generic parsers (`JSONPassthroughParser` or `XMLGenericParser`) where core fields are extracted, but specialized vendor semantics (e.g. Suricata flow IDs) are placed in `vendor_attributes` rather than dedicated standard fields.
3. **NOT SUPPORTED**: No dedicated parser plugin or matching grammar exists; logs are safely captured in `FileRawStore` but quarantined in `dead_letter.ndjson`.
