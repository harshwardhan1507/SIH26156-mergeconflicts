# Network Field & IP Address Analysis

This document provides a deep dive into how network connection fields (5-tuples, byte volumes, interfaces, zones, and protocols) and IP addresses (IPv4 vs. IPv6) are parsed, validated, and normalized across ULPF.

---

## 1. Network Block Specification & Normalization Mapping

The `network` block in UES 1.2.0 (`ulpf/schemas/ues_schema.json:57-74`) models network telemetry according to Elastic Common Schema (ECS) and OCSF conventions:

| Network Field | Schema Type | Constraints / Validation | Mapped Source Fields | Fallback Behavior if Missing |
|---|---|---|---|---|
| `network.src_ip` | `string` (or `null`) | Validated via `BaseParser.validate_ip()` (IPv4 / IPv6) | `src`, `src_ip`, `sourceIPAddress`, `callerIpAddress`, `callerIp`, `EventData.IpAddress` | `null` |
| `network.src_port` | `integer` (or `null`) | Validated via `BaseParser.safe_port()` (`0 <= port <= 65535`) | `spt`, `src_port`, `EventData.SourcePort` | `null` |
| `network.dst_ip` | `string` (or `null`) | Validated via `BaseParser.validate_ip()` (IPv4 / IPv6) | `dst`, `dst_ip`, `EventData.DestAddress`, `TargetAddress` | `null` |
| `network.dst_port` | `integer` (or `null`) | Validated via `BaseParser.safe_port()` (`0 <= port <= 65535`) | `dpt`, `dst_port`, `EventData.DestPort` | `null` |
| `network.protocol` | `string` (or `null`) | Normalized to lowercase (`lower()`) | `proto`, `protocol`, `EventData.ProtocolName` (`6` -> `'tcp'`, `17` -> `'udp'`) | `null` |
| `network.bytes_in` | `integer` (or `null`) | Validated via `BaseParser.safe_int()` (`minimum: 0`) | `in`, `bytes_in`, `bytes_received`, `srcBytes` | `null` |
| `network.bytes_out` | `integer` (or `null`) | Validated via `BaseParser.safe_int()` (`minimum: 0`) | `out`, `bytes_out`, `bytes_sent`, `dstBytes` | `null` |
| `network.direction`| `string` (or `null`) | Enum: `[inbound, outbound, internal, unknown, null]` | `_resolve_direction()` (zone substrings), `deviceDirection`, `EventData.Direction` | `'unknown'` or `null` |
| `network.interface`| `string` (or `null`) | Raw string identifier | `deviceInboundInterface`, `inbound_if` | `null` |

---

## 2. IP Address Validation & Dual-Stack (IPv4 / IPv6) Analysis

In `BaseParser.validate_ip()` (`ulpf/parsers/base.py:98-113`):

```python
def validate_ip(self, value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    try:
        IPv4Address(value)
        return value
    except AddressValueError:
        pass
    try:
        IPv6Address(value)
        return value
    except AddressValueError:
        return None
```

### Analysis of Dual-Stack Coverage:
1. **Helper Level Support (IPv4 & IPv6)**: `BaseParser.validate_ip()` accepts both standard IPv4 (e.g. `198.51.100.1`) and IPv6 strings (e.g. `2001:db8::1`, `fe80::1ff:fe23:4567:890a`).
2. **Parser Regex Bottlenecks**:
   - **`CiscoASAParser`**: Uses `_ASA_CONN_RE` with pattern `\d{1,3}(?:\.\d{1,3}){3}`. **Fails to extract IPv6 addresses** from Cisco ASA connection logs.
   - **`CEFParser` & `LEEFParser`**: Extract `src` and `dst` as arbitrary string tokens between delimiters, passing them to `validate_ip()`. **Fully supports IPv6**.
   - **`XMLGenericParser`**: Extracts `EventData.IpAddress` directly. **Fully supports IPv6**.
   - **`Cloud Parsers` (AWS, Azure, GCP)**: Extract source IP directly from JSON strings. **Fully supports IPv6**.

---

## 3. Direction & Zone Resolution Evaluation

In `_resolve_direction()` (`ulpf/core/normalization.py:71-80`):
* Inspects `src_zone` and `dst_zone` extracted from firewall logs (e.g. Palo Alto Networks CSV).
* Resolves:
  - `src_zone` contains `outside` / `untrust` / `external` -> `'inbound'`
  - `dst_zone` contains `outside` / `untrust` / `external` -> `'outbound'`
  - `src_zone == dst_zone` -> `'internal'`
  - Otherwise -> `'unknown'`
* **Limitation**: Custom zone naming conventions (e.g. `dmz`, `wan`, `internet_gw`, `corp_lan`) that do not contain the specific keywords default to `'unknown'` unless explicitly mapped in YAML.

---

## 4. NAT & Extended Network Fields Retention

* Fields like `natsrc`, `natdst`, `natsport`, `natdport`, `vsys`, `flags`, and `sessionid` in PAN-OS CSV logs are not part of the standard UES 1.2.0 `network` block.
* **Preservation Status**: They are automatically preserved in the `vendor_attributes` dictionary via the open-bag mechanism (`ulpf/core/normalization.py:324-327`), guaranteeing zero data loss for forensic auditing.
