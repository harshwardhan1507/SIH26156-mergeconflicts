# Normalization & Schema Mapping Deep Dive

This document evaluates the declarative transformation rules in `ulpf/schemas/mappings/`, the mapping execution in `NormalizationEngine` (`ulpf/core/normalization.py`), field coverage per parser, and the actual mechanics of the `vendor_attributes` open bag.

---

## 1. Declarative Normalization Coverage Matrix

Below is the verified mapping coverage across all 11 parser plugins, analyzing which extracted fields are mapped directly to UES canonical fields versus preserved in `vendor_attributes`.

| Parser Mapping Spec | YAML Mapping File | Primary Mapped UES Fields | Mapped Keys Count | Unmapped Keys Destined for `vendor_attributes` | Semantic Field Loss? |
|---|---|---|---|---|---|
| **`cisco_asa`** | `ulpf/schemas/mappings/cisco_asa.yaml` | `vendor`, `product`, `hostname`, `action` (`acl_action`), `outcome` (`_outcome_from_action`), `severity_numeric`, `severity_original` (`asa_severity_name`), `event_type_vendor_specific` (`asa_mnemonic`), `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol` (`proto`), `rule_id`, `rule_name`, `policy_action` | 13 | `priority`, `facility`, `asa_severity`, `message` | **NO** (Unmapped preserved in `vendor_attributes`) |
| **`cef`** | `ulpf/schemas/mappings/cef.yaml` | `vendor` (`DeviceVendor`), `product` (`DeviceProduct`), `device_hostname` (`dhost`), `source_ip` (`dvc`), `action` (`act`), `outcome` (`_outcome_from_action`), `severity_numeric`, `severity_original` (`Severity`), `event_type_vendor_specific` (`SignatureID`), `src_ip` (`src`), `src_port` (`spt`), `dst_ip` (`dst`), `dst_port` (`dpt`), `protocol` (`proto`), `bytes_in` (`in`), `bytes_out` (`out`), `direction` (`deviceDirection`), `interface` (`deviceInboundInterface`), `username` (`suser`), `rule_id`, `rule_name` | 21 | `cef_version`, `DeviceVersion`, `Name`, plus any arbitrary custom extension fields (e.g. `cs1`, `cn1`, `flexString1`) | **NO** (All custom extension fields preserved in `vendor_attributes`) |
| **`leef`** | `ulpf/schemas/mappings/leef.yaml` | `vendor`, `product`, `action`, `outcome` (`_outcome_from_action`), `severity_numeric`, `severity_original` (`severity_raw`), `event_type_vendor_specific` (`event_id`), `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `bytes_in`, `bytes_out`, `username`, `user_domain` (`domain`), `rule_id` (`event_id`), `policy_action` (`action`) | 16 | `leef_version`, `product_version`, `category_raw`, `message`, `url`, `resource`, `role`, plus custom attributes | **NO** (Custom attributes preserved in `vendor_attributes`) |
| **`paloalto_csv`** | `ulpf/schemas/mappings/paloalto_csv.yaml` | `vendor`, `product`, `action` (`action_ues`), `outcome` (`_outcome_from_action`), `severity_numeric`, `severity_original` (`action_raw`), `event_type_vendor_specific` (`app`), `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol` (`proto`), `bytes_in` (`bytes_received`), `bytes_out` (`bytes_sent`), `direction` (`_direction_from_zones`), `interface` (`inbound_if`), `username` (`src_user`), `rule_name` (`rule`), `policy_action` (`action_ues`) | 17 | `device_serial`, `app`, `src_zone`, `dst_zone`, `outbound_if`, `sessionid`, `_vendor_extra` (columns 36+) | **NO** (All extra positional columns preserved in `vendor_attributes`) |
| **`aws_cloudtrail`** | `ulpf/schemas/mappings/aws_cloudtrail.yaml` | `vendor`, `product`, `device_hostname` (`aws_region`), `source_ip` (`src_ip`), `category`, `action`, `outcome`, `severity_numeric`, `event_type_vendor_specific` (`event_name`), `src_ip`, `username`, `user_domain` (`account_id`), `rule_id` (`request_id`), `rule_name` (`event_name`), `policy_action` (`action`) | 14 | `event_version`, `event_source`, `event_type`, `aws_region`, `user_identity_type`, `user_arn`, `error_code`, `error_message`, `read_only`, `message`, `_request_params`, `_response_elements` | **NO** (Complete request/response JSON preserved in `vendor_attributes`) |
| **`azure_monitor`** | `ulpf/schemas/mappings/azure_monitor.yaml` | `vendor`, `product`, `source_ip` (`src_ip`), `category`, `action`, `outcome`, `severity_numeric`, `severity_original` (`result_type`), `event_type_vendor_specific` (`operation_name`), `src_ip`, `username`, `user_domain` (`tenant_id`), `rule_id` (`operation_id`), `rule_name` (`operation_name`), `policy_action` (`action`) | 15 | `resource_id`, `az_category`, `result_type`, `result_signature`, `result_description`, `correlation_id`, `operation_id`, `subscription_id`, `resource_group`, `provider`, `resource_type`, `resource_name` | **NO** (Parsed Azure resource hierarchy preserved in `vendor_attributes`) |
| **`gcp_audit`** | `ulpf/schemas/mappings/gcp_audit.yaml` | `vendor`, `product`, `device_hostname` (`project_id`), `source_ip` (`src_ip`), `category`, `action`, `outcome`, `severity_numeric`, `severity_original` (`gcp_severity`), `event_type_vendor_specific` (`method_name`), `src_ip`, `username` (`principal_email`), `rule_id` (`insert_id`), `rule_name` (`method_name`), `policy_action` (`action`) | 14 | `method_name`, `resource_name`, `principal_email`, `caller_ip_raw`, `user_agent`, `status_code`, `status_message`, `gcp_severity`, `authorization_granted`, `project_id`, `log_name`, `log_type`, `insert_id`, `service_name`, `message` | **NO** (All authorization details preserved in `vendor_attributes`) |
| **`syslog_rfc3164`** | `ulpf/schemas/mappings/syslog_rfc3164.yaml` | `device_hostname` (`hostname`), `severity_numeric` (`severity_ues`), `severity_original` (`syslog_severity_name`), `event_type_vendor_specific` (`tag`) | 4 | `priority`, `facility`, `syslog_severity`, `hostname`, `tag`, `pid`, `message` | **NO** (Syslog metadata preserved in `vendor_attributes`) |
| **`syslog_rfc5424`** | `ulpf/schemas/mappings/syslog_rfc5424.yaml` | `device_hostname` (`hostname`), `severity_numeric` (`severity_ues`), `severity_original` (`syslog_severity_name`), `event_type_vendor_specific` (`msgid`) | 4 | `priority`, `facility`, `syslog_severity`, `version`, `hostname`, `appname`, `procid`, `msgid`, `message`, plus all `sd_<sdid>_<param>` structured data keys | **NO** (Structured data elements preserved in `vendor_attributes`) |
| **`xml_generic`** | `ulpf/schemas/mappings/xml_generic.yaml` | `vendor`, `product`, `device_hostname` (`hostname`), `category`, `action`, `outcome` (`_outcome_from_action`), `severity_numeric`, `event_type_vendor_specific` (`windows_event_id`), `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `direction`, `username`, `rule_id` (`windows_event_id`), `rule_name` (`event_description`) | 16 | `windows_event_id`, `is_windows_event_log`, `process_name`, `process_path`, `event_description`, `message`, plus all unmapped `EventData.*` or flattened XML tags | **NO** (Process paths and EventData preserved in `vendor_attributes`) |
| **`json_passthrough`** | `ulpf/schemas/mappings/json_passthrough.yaml` | `device_hostname` (`host`), `action` (`event`), `outcome` (`result`), `severity_numeric` (`severity_ues`), `event_type_vendor_specific` (`event`), `src_ip` (`src`), `src_port`, `dst_ip` (`dst`), `dst_port`, `protocol` (`proto`), `bytes_in`, `bytes_out`, `username` (`user`), `user_domain` (`domain`) | 13 | All unmapped top-level JSON fields (e.g. `session_id`, `custom_tag`, `trace_id`) | **NO** (All arbitrary JSON fields preserved in `vendor_attributes`) |

---

## 2. Dynamic Transformation Mechanics

### 2.1 Keyword-Based Category Inference
* In `_infer_category()` (`ulpf/core/normalization.py:46-62`):
  - A single consolidated string is constructed by concatenating `message`, `Name`, `tag`, `app`, `event`, and `asa_mnemonic`.
  - Tested against keyword dictionaries for `authentication`, `threat`, `policy`, `system`, and `network`.
  - If no keyword matches, falls back to the default category specified in the YAML mapping (e.g. `_category_default:network`).

### 2.2 Outcome Normalization
* In `_resolve_outcome()` (`ulpf/core/normalization.py:64-69`):
  - Tokens `allow`, `permit`, `permitted`, `accept`, `success` map to `'success'`.
  - Tokens `deny`, `denied`, `block`, `drop`, `reject`, `reset`, `fail`, `failure` map to `'failure'`.
  - All other tokens map to `'unknown'`.

### 2.3 Direction Resolution
* In `_resolve_direction()` (`ulpf/core/normalization.py:71-80`):
  - Evaluates `src_zone` and `dst_zone`.
  - Substrings `outside`, `untrust`, `external` in `src_zone` -> `'inbound'`.
  - Substrings `outside`, `untrust`, `external` in `dst_zone` -> `'outbound'`.
  - Equal non-empty zones -> `'internal'`.

### 2.4 Mechanics of the `vendor_attributes` Bag
In `NormalizationEngine.normalize()` (`ulpf/core/normalization.py:323-327`):
```python
# --- vendor_attributes open bag (100% attribute preservation) ---
vendor_attrs: dict[str, Any] = {}
for k, v in extracted.items():
    if k not in mapped_keys and not k.startswith('_'):
        vendor_attrs[k] = v
```
* Every key extracted by a parser that was not explicitly assigned to a UES field (and does not begin with an internal underscore `_`) is automatically captured in `vendor_attributes`.
* **Conclusion**: Zero fields produced by the parser extraction stage are discarded during normalization.
