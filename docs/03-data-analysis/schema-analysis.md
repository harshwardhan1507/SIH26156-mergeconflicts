# Universal Event Schema (UES) Deep Dive Analysis

This document provides a comprehensive structural and semantic analysis of the canonical data model defined in `ulpf/schemas/ues_schema.json` (UES version 1.2.0, compiled via JSON Schema Draft 7).

---

## 1. UES Schema Specification & Field Inventory

The Universal Event Schema defines 10 top-level blocks. Below is the complete field definition matrix verifying required status, types, nullability, constraints, and source origin.

| Field Path | JSON Schema Type | Required? | Nullable? | Purpose / Semantic Definition | Source Origin | Constraints / Enum Values |
|---|---|---|---|---|---|---|
| `schema_version` | `string` | Optional | No | Semantic schema specification version. | Pipeline constant | Default `'1.2.0'` |
| `tenant_id` | `string` | Optional | No | Multi-tenant logical isolation partition. | Ingestion argument | Default `'default'` |
| `event_id` | `string` | **YES** | No | Deterministic unique event identifier. | Pipeline (`uuid.uuid5`) | Formatted as RFC 4122 UUIDv5 |
| `ingest_timestamp` | `string` | **YES** | No | UTC timestamp when framework ingested event. | Pipeline (`datetime.now`) | ISO 8601 string |
| `source_event_timestamp` | `string` | Optional | **Yes** | Original event timestamp reported by device. | Parser extraction | ISO 8601 string or `null` |
| **`raw`** | `object` | **YES** | No | Forensic traceability container. | Pipeline wrapper | `additionalProperties: false` |
| `raw.raw_payload` | `string` | **YES** | No | Exact text representation of the log. | Ingestion Reader | String (surrogateescape decoded) |
| `raw.raw_format` | `string` | **YES** | No | Detected source format identifier. | FormatDetector / Parser | Format string (e.g. `'cisco_asa'`) |
| `raw.raw_hash` | `string` | **YES** | No | SHA-256 cryptographic digest of raw bytes. | Pipeline (`hashlib.sha256`) | Regex pattern: `^[a-f0-9]{64}$` |
| **`source`** | `object` | **YES** | No | Originating device and vendor metadata. | NormalizationEngine | `additionalProperties: false` |
| `source.vendor` | `string` | Optional | **Yes** | Manufacturer / Cloud provider name. | YAML mapping | String or `null` |
| `source.product` | `string` | Optional | **Yes** | Specific device model or service name. | YAML mapping | String or `null` |
| `source.device_hostname` | `string` | Optional | **Yes** | Hostname or reporting device tag. | Extracted field | String or `null` |
| `source.source_ip` | `string` | Optional | **Yes** | Reporting gateway / collector IP. | Extracted field | String or `null` |
| `source.log_format` | `string` | **YES** | No | Format identifier. | Parser / Extracted | Non-empty string |
| **`event`** | `object` | **YES** | No | Security taxonomy and action details. | NormalizationEngine | `additionalProperties: true` |
| `event.category` | `string` | **YES** | No | Standardized high-level event domain. | NormalizationEngine | `enum: [network, authentication, threat, system, policy, api, database, unknown]` |
| `event.class_name` | `string` | Optional | **Yes** | OCSF canonical class name. | OCSF Taxonomy Map | e.g. `'Network Activity'`, `'Authentication'` |
| `event.class_uid` | `integer` | Optional | **Yes** | OCSF numeric class UID. | `_OCSF_CLASS_MAP` | `4001, 3001, 2001, 1001, 5001, 6003, 6004, 1` |
| `event.activity_name` | `string` | Optional | **Yes** | OCSF activity action verb. | `_OCSF_ACTIVITY_MAP` | e.g. `'Logon'`, `'Permit'`, `'Deny'` |
| `event.activity_id` | `integer` | Optional | **Yes** | OCSF activity numeric ID. | `_OCSF_ACTIVITY_MAP` | e.g. `1, 2, 3, 4, 5` |
| `event.action` | `string` | Optional | **Yes** | Normalized action verb. | YAML mapping | String or `null` |
| `event.outcome` | `string` | Optional | **Yes** | Binary result of the event. | `_resolve_outcome()` | `enum: [success, failure, unknown, null]` |
| `event.severity_numeric` | `number` | Optional | **Yes** | Standardized 0.0-10.0 scale. | NormalizationEngine | `minimum: 0, maximum: 10` |
| `event.severity_original`| `string` | Optional | **Yes** | Unmodified source severity string. | Extracted field | String or `null` |
| `event.severity_inferred`| `boolean`| Optional | **Yes** | Flag indicating default assignment. | NormalizationEngine | `true` if defaulted to 5.0 |
| `event.event_type_vendor_specific`| `string` | Optional | **Yes** | Raw vendor event ID/mnemonic. | Extracted field | String or `null` |
| **`network`** | `object` | Optional | **Yes** | Network connection 5-tuple and volume. | NormalizationEngine | `additionalProperties: false` |
| `network.src_ip` | `string` | Optional | **Yes** | Source IP address (IPv4 / IPv6). | Parser / Normalizer | Validated IP string or `null` |
| `network.src_port` | `integer` | Optional | **Yes** | Source TCP/UDP port number. | Parser (`safe_port`) | `minimum: 0, maximum: 65535` |
| `network.dst_ip` | `string` | Optional | **Yes** | Destination IP address (IPv4 / IPv6). | Parser / Normalizer | Validated IP string or `null` |
| `network.dst_port` | `integer` | Optional | **Yes** | Destination TCP/UDP port number. | Parser (`safe_port`) | `minimum: 0, maximum: 65535` |
| `network.protocol` | `string` | Optional | **Yes** | Transport protocol. | Parser (`lower()`) | e.g. `'tcp'`, `'udp'`, `'icmp'` |
| `network.bytes_in` | `integer` | Optional | **Yes** | Bytes received by target. | Parser (`safe_int`) | `minimum: 0` |
| `network.bytes_out` | `integer` | Optional | **Yes** | Bytes transmitted by target. | Parser (`safe_int`) | `minimum: 0` |
| `network.direction` | `string` | Optional | **Yes** | Flow orientation relative to perimeter.| `_resolve_direction()`| `enum: [inbound, outbound, internal, unknown, null]` |
| `network.interface` | `string` | Optional | **Yes** | Network interface name. | Extracted field | String or `null` |
| **`identity`** | `object` | Optional | **Yes** | User authentication identity. | NormalizationEngine | `additionalProperties: false` |
| `identity.username` | `string` | Optional | **Yes** | Subject user account / principal. | Extracted field | String or `null` |
| `identity.user_domain` | `string` | Optional | **Yes** | Realm / Domain / AWS Account ID. | Extracted field | String or `null` |
| **`rule`** | `object` | Optional | **Yes** | Applied security rule or policy. | NormalizationEngine | `additionalProperties: false` |
| `rule.rule_id` | `string` | Optional | **Yes** | Unique rule or mnemonic identifier. | Extracted field | String or `null` |
| `rule.rule_name` | `string` | Optional | **Yes** | Human-readable rule or ACL name. | Extracted field | String or `null` |
| `rule.policy_action` | `string` | Optional | **Yes** | Configured rule policy action. | Extracted field | String or `null` |
| **`vendor_attributes`**| `object`| Optional | **Yes** | Open bag of unmapped extracted keys. | NormalizationEngine | `additionalProperties: true` |
| **`enrichment`** | `object` | Optional | **Yes** | Context decoration container. | `IPEnrichmentPlugin` | `additionalProperties: true` |
| `enrichment.threat_ip_detected` | `boolean` | Optional | **Yes** | Flag for threat intel IP matches. | `IPEnrichmentPlugin` | `boolean` or `null` |
| `enrichment.src_ip_context` | `object` | Optional | **Yes** | IP classification metadata. | `_classify_ip()` | Includes `ip_type`, `cloud_provider`, etc. |
| **`analytics`** | `object` | Optional | **Yes** | Statistical anomaly scoring output. | `AnomalyDetector` | `additionalProperties: true` |
| `analytics.anomaly_score` | `number` | Optional | No | Aggregated anomaly score [0.0 - 1.0]. | `AnomalyDetector` | `minimum: 0.0, maximum: 1.0` |
| `analytics.anomaly_reasons` | `array` | Optional | No | Human-readable explanation strings. | `AnomalyDetector` | Array of strings |
| `analytics.is_anomalous` | `boolean` | Optional | No | Boolean flag for score >= 0.7. | `AnomalyDetector` | `true` / `false` |
| `analytics.risk_score` | `number` | Optional | No | Normalized risk score [0.0 - 10.0]. | `AnomalyDetector` | `minimum: 0.0, maximum: 10.0` |
| **`lineage`** | `object` | **YES** | No | Provenance and parsing lineage. | Pipeline metadata | `additionalProperties: false` |
| `lineage.parser_name` | `string` | **YES** | No | Exact parser plugin that extracted log. | `BaseParser.name` | Non-empty string |
| `lineage.parser_version` | `string` | **YES** | No | Version of parser plugin. | `BaseParser.version` | Semantic version string |
| `lineage.normalization_ruleset_version` | `string` | **YES** | No | Ruleset version of YAML mapping. | YAML mapping | Semantic version string |

---

## 2. Structural & Schema Behavior Insights

1. **Strict Required Envelope**: An event fails schema validation and routes to `dead_letter.ndjson` if any of `event_id`, `ingest_timestamp`, `raw`, `source`, `event`, or `lineage` is missing.
2. **Nullable Child Blocks**: The blocks `network`, `identity`, `rule`, `vendor_attributes`, `enrichment`, and `analytics` are completely nullable. If an event contains no network information (e.g. AWS IAM policy update), `network` resolves to `null` without triggering schema errors.
3. **Closed Envelope vs. Open Extensibility**:
   - `raw`, `source`, `network`, `identity`, `rule`, and `lineage` enforce `additionalProperties: false`, preventing accidental schema drift.
   - `event`, `enrichment`, `analytics`, and `vendor_attributes` set `additionalProperties: true`, allowing open-bag field retention and enrichment expansion.
4. **OCSF & ECS Crosswalk**: UES 1.2.0 incorporates dual taxonomy alignment via `event.class_uid` / `event.class_name` (OCSF 1.1.0 standard) and standardized field naming (`src_ip`, `dst_ip`, `bytes_in`, `bytes_out`) matching Elastic Common Schema (ECS).
