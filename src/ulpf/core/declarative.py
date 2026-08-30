"""
Declarative Generic Parser & No-Code Source Onboarding Engine.

Allows onboarding new vendor log sources through YAML/JSON configuration files
without writing Python code or modifying core pipeline components.

Supports:
- Parsing types: Key-Value, CSV, JSON, Regex, Delimiter
- Framers: Line, Delimiter, Multiline Regex, JSON Stream, Syslog Octet
- Detection rules: Substrings (ALL/ANY), Regex, Prefix, JSON Keys
- Type conversions: string, int, float, ip, port, bool, timestamps
- Direct taxonomy mapping to UES v1.2.0 with vendor attributes retention
- Dynamic discovery, schema validation, enable/disable toggles, and starter mapping inference
"""
from __future__ import annotations

import csv
import io
import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from ulpf import resources
from ulpf.core.framing import (
    BaseFramer,
    DelimiterFramer,
    JSONStreamFramer,
    LineFramer,
    MultilineRegexFramer,
    SyslogOctetFramer,
)
from ulpf.core.normalization import UES_CATEGORIES
from ulpf.parsers.base import BaseParser, ParseError

logger = logging.getLogger("ulpf.core.declarative")

# Cache for declarative schema
_SCHEMA_CACHE: dict[str, Any] | None = None

#: Mirrors the ``name`` pattern in declarative_source_schema.json. Anything
#: that becomes a filename or a registry key is checked against it.
_SOURCE_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


def get_declarative_schema() -> dict[str, Any]:
    """Load and cache the declarative source JSON schema."""
    global _SCHEMA_CACHE
    if _SCHEMA_CACHE is None:
        schema_path = resources.declarative_schema_path()
        if schema_path.exists():
            with open(schema_path, encoding="utf-8") as f:
                _SCHEMA_CACHE = json.load(f)
        else:
            _SCHEMA_CACHE = {"type": "object"}
    return _SCHEMA_CACHE


def validate_declarative_config(config: dict[str, Any]) -> tuple[bool, list[str]]:
    """Validate a declarative source configuration dict against schema."""
    schema = get_declarative_schema()
    errors: list[str] = []
    try:
        jsonschema.validate(instance=config, schema=schema)
    except jsonschema.ValidationError as e:
        errors.append(f"Validation error at '{'.'.join(str(p) for p in e.path)}': {e.message}")
    except Exception as e:
        errors.append(f"Schema validation error: {e}")

    # Specific functional validation
    parser_cfg = config.get("parser", {})
    ptype = parser_cfg.get("type")
    if ptype == "regex":
        pattern = parser_cfg.get("pattern", "")
        if not pattern:
            errors.append("Regex parser requires non-empty 'pattern'")
        else:
            try:
                re.compile(pattern)
            except re.error as re_err:
                errors.append(f"Invalid regex pattern: {re_err}")
    elif ptype == "csv":
        if not parser_cfg.get("columns") and not parser_cfg.get("has_header"):
            errors.append("CSV parser requires 'columns' list or 'has_header: true'")

    return len(errors) == 0, errors


class DeclarativeSourceParser(BaseParser):
    """
    Generic, configuration-driven parser that executes extraction,
    typing, and normalization entirely from declarative YAML/JSON rules.
    """

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.name = config.get("name", "custom_declarative")
        self.vendor = config.get("vendor", "Custom")
        self.product = config.get("product", "CustomProduct")
        self.version = str(config.get("version", "1.0.0"))
        self.enabled = bool(config.get("enabled", True))
        self.log_format = config.get("log_format", self.name)
        self.description = config.get("description", "")

        self.framing_cfg = config.get("framing", {})
        self.framer: BaseFramer = self._build_framer()
        self.detection_cfg = config.get("detection", {})
        self.parser_cfg = config.get("parser", {})
        self.fields_cfg = config.get("fields", {})
        self.normalize_cfg = config.get("normalize", {})

        # Pre-compile regexes if present
        self._detection_regex = None
        if self.detection_cfg.get("regex"):
            try:
                self._detection_regex = re.compile(self.detection_cfg["regex"])
            except re.error:
                pass

        self._parser_regex = None
        if self.parser_cfg.get("type") == "regex" and self.parser_cfg.get("pattern"):
            flags = 0
            for f in self.parser_cfg.get("flags", []):
                if f.lower() in ("i", "ignorecase"):
                    flags |= re.IGNORECASE
                elif f.lower() in ("m", "multiline"):
                    flags |= re.MULTILINE
                elif f.lower() in ("s", "dotall"):
                    flags |= re.DOTALL
            try:
                self._parser_regex = re.compile(self.parser_cfg["pattern"], flags)
            except re.error:
                pass

    def _build_framer(self) -> BaseFramer:
        """Instantiate framing layer from framing configuration."""
        if not self.framing_cfg or not isinstance(self.framing_cfg, dict):
            return LineFramer()

        ftype = str(self.framing_cfg.get("type", "line")).lower()
        max_bytes = int(self.framing_cfg.get("max_bytes", 2 * 1024 * 1024))

        if ftype in ("multiline", "multiline_regex", "regex_multiline", "regex"):
            pattern = self.framing_cfg.get("pattern") or self.framing_cfg.get("start_pattern") or r"^\d{4}-\d{2}-\d{2}"
            flags = re.MULTILINE
            if self.framing_cfg.get("case_insensitive"):
                flags |= re.IGNORECASE
            return MultilineRegexFramer(
                start_pattern=pattern,
                flags=flags,
                max_bytes=max_bytes,
            )
        elif ftype == "delimiter":
            delim = self.framing_cfg.get("delimiter", "###EVENT_END###")
            return DelimiterFramer(delimiter=delim, max_bytes=max_bytes)
        elif ftype in ("json_stream", "json"):
            return JSONStreamFramer(max_bytes=max_bytes)
        elif ftype in ("syslog_octet", "octet_counting"):
            return SyslogOctetFramer(max_bytes=max_bytes)
        else:
            return LineFramer(max_bytes=max_bytes)

    def get_framer(self) -> BaseFramer:
        """Return the configured framer for this declarative source."""
        return self.framer

    def frame(self, stream: Any) -> Any:
        """Frame an incoming stream or iterable of chunks into discrete FrameResults."""
        return self.framer.frame(stream)

    def match(self, raw_line: str) -> bool:
        """Evaluate detection rules against raw log line."""
        if not self.enabled:
            return False

        stripped = raw_line.strip()
        if not stripped:
            return False

        # 1. Prefix check
        prefix = self.detection_cfg.get("prefix")
        if prefix and not stripped.startswith(prefix):
            return False

        # 2. Contains check (substrings)
        contains = self.detection_cfg.get("contains")
        if contains:
            if isinstance(contains, str):
                contains = [contains]
            mode = self.detection_cfg.get("contains_mode", "all")
            if mode == "all":
                if not all(term in stripped for term in contains):
                    return False
            else:
                if not any(term in stripped for term in contains):
                    return False

        # 3. Regex check
        if self._detection_regex and not self._detection_regex.search(stripped):
            return False

        # 4. JSON keys check
        json_keys = self.detection_cfg.get("json_keys")
        if json_keys:
            if not stripped.startswith("{"):
                return False
            try:
                data = json.loads(stripped)
                if not isinstance(data, dict):
                    return False
                if not all(k in data for k in json_keys):
                    return False
            except Exception:
                return False

        # 5. Parser-level self-match if no explicit detection rules
        if not prefix and not contains and not self._detection_regex and not json_keys:
            ptype = self.parser_cfg.get("type")
            if ptype == "regex" and self._parser_regex:
                return self._parser_regex.search(stripped) is not None
            elif ptype == "json":
                return stripped.startswith("{") and stripped.endswith("}")
            elif ptype == "key_value":
                kv_delim = self.parser_cfg.get("kv_delimiter", "=")
                return kv_delim in stripped

        return True

    def extract(self, raw_line: str) -> dict[str, Any]:
        """Extract structured fields according to parser configuration."""
        stripped = raw_line.strip()
        ptype = self.parser_cfg.get("type", "key_value")

        fields: dict[str, Any] = {
            "_raw": raw_line,
            "_log_format": self.log_format,
            "_vendor": self.vendor,
            "_product": self.product,
        }

        if ptype == "key_value":
            extracted = self._extract_key_value(stripped)
        elif ptype == "csv":
            extracted = self._extract_csv(stripped)
        elif ptype == "json":
            extracted = self._extract_json(stripped)
        elif ptype == "regex":
            extracted = self._extract_regex(stripped)
        elif ptype == "delimiter":
            extracted = self._extract_delimiter(stripped)
        else:
            raise ParseError(f"Unsupported parser type: {ptype}")

        fields.update(extracted)

        # Apply type conversions
        type_mappings = self.fields_cfg.get("types", {})
        for fld, ftype in type_mappings.items():
            if fld in fields and fields[fld] is not None:
                fields[fld] = self._convert_type(fields[fld], ftype)

        # Extract timestamp
        ts_field = self.fields_cfg.get("timestamp")
        if isinstance(ts_field, str) and ts_field in fields:
            ts_val = fields[ts_field]
            dt = self.parse_timestamp(str(ts_val)) if ts_val else None
            fields["timestamp_dt"] = dt.isoformat() if dt else None
        elif isinstance(ts_field, dict):
            field_name = ts_field.get("field")
            if field_name and field_name in fields:
                ts_val = fields[field_name]
                dt = self.parse_timestamp(str(ts_val)) if ts_val else None
                fields["timestamp_dt"] = dt.isoformat() if dt else None

        # If timestamp_dt is still None, scan common timestamp names
        if "timestamp_dt" not in fields or fields["timestamp_dt"] is None:
            for candidate in ("time", "timestamp", "event_time", "devtime", "datetime", "date", "@timestamp", "rt", "ts"):
                if fields.get(candidate):
                    dt = self.parse_timestamp(str(fields[candidate]))
                    if dt:
                        fields["timestamp_dt"] = dt.isoformat()
                        break

        # Validate IPs
        for ip_cand in ("src", "dst", "src_ip", "dst_ip", "source_ip", "dest_ip", "srcip", "dstip", "remip", "locip"):
            if ip_cand in fields and isinstance(fields[ip_cand], str):
                val_ip = self.validate_ip(fields[ip_cand])
                if val_ip:
                    fields[ip_cand] = val_ip

        return fields

    def _extract_key_value(self, text: str) -> dict[str, Any]:
        """Parse key=value pairs handling quotes and custom delimiters."""
        pair_delim = self.parser_cfg.get("pair_delimiter", " ")
        kv_delim = self.parser_cfg.get("kv_delimiter", "=")
        strip_quotes = self.parser_cfg.get("strip_quotes", True)

        result: dict[str, Any] = {}
        # Regex matching key=value where value may be quoted with double or single quotes
        # or unquoted up to whitespace / pair delimiter
        escaped_kv = re.escape(kv_delim)
        pattern = re.compile(
            rf'(?:^|[\s{re.escape(pair_delim)}])([a-zA-Z0-9_.-]+){escaped_kv}(?:"([^"]*)"|\'([^\']*)\'|(\S+))'
        )

        for match in pattern.finditer(text):
            k = match.group(1)
            v = match.group(2) if match.group(2) is not None else (
                match.group(3) if match.group(3) is not None else match.group(4)
            )
            if strip_quotes and v is not None:
                v = self.strip_quotes(v)
            result[k] = v

        if not result and kv_delim in text:
            # Fallback simple split
            tokens = text.split(pair_delim)
            for tok in tokens:
                if kv_delim in tok:
                    parts = tok.split(kv_delim, 1)
                    k = parts[0].strip()
                    v = parts[1].strip()
                    if strip_quotes:
                        v = self.strip_quotes(v) or v
                    result[k] = v

        return result

    def _extract_csv(self, text: str) -> dict[str, Any]:
        """Parse CSV record into named columns."""
        delim = self.parser_cfg.get("delimiter", ",")
        cols = self.parser_cfg.get("columns", [])
        try:
            reader = csv.reader(io.StringIO(text), delimiter=delim)
            row = next(reader)
        except Exception as e:
            raise ParseError(f"CSV parsing failed: {e}") from e

        result: dict[str, Any] = {}
        for i, val in enumerate(row):
            if i < len(cols):
                result[cols[i]] = val.strip()
            else:
                result[f"col_{i}"] = val.strip()
        return result

    def _extract_json(self, text: str) -> dict[str, Any]:
        """Parse JSON object and extract properties."""
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise ParseError(f"JSON decode failed: {e}") from e

        if not isinstance(data, dict):
            raise ParseError(f"Expected JSON dict, got {type(data).__name__}")

        result: dict[str, Any] = {}
        json_paths = self.parser_cfg.get("json_paths", {})
        if json_paths:
            for field_name, path in json_paths.items():
                result[field_name] = self._resolve_json_path(data, path)

        # Merge top-level keys
        for k, v in data.items():
            if k not in result:
                result[k] = v

        return result

    def _resolve_json_path(self, data: Any, path: str) -> Any:
        """Resolve dotted JSON path e.g. 'user.identity.name' or 'records[0].id'."""
        cur = data
        for part in path.split("."):
            if not isinstance(cur, dict):
                return None
            if "[" in part and part.endswith("]"):
                name, idx_str = part[:-1].split("[", 1)
                cur = cur.get(name)
                if isinstance(cur, list):
                    try:
                        cur = cur[int(idx_str)]
                    except (IndexError, ValueError):
                        return None
                else:
                    return None
            else:
                cur = cur.get(part)
        return cur

    def _extract_regex(self, text: str) -> dict[str, Any]:
        """Parse using compiled regular expression."""
        if not self._parser_regex:
            raise ParseError("Regex parser missing compiled pattern")

        m = self._parser_regex.search(text)
        if not m:
            raise ParseError(f"Regex pattern did not match raw log line: {text[:60]}...")

        return m.groupdict()

    def _extract_delimiter(self, text: str) -> dict[str, Any]:
        """Split text by custom delimiter."""
        delim = self.parser_cfg.get("delimiter", "|")
        cols = self.parser_cfg.get("columns", [])
        parts = text.split(delim)

        result: dict[str, Any] = {}
        for i, part in enumerate(parts):
            val = part.strip()
            if i < len(cols):
                result[cols[i]] = val
            else:
                result[f"col_{i}"] = val
        return result

    def _convert_type(self, val: Any, target_type: str) -> Any:
        """Convert extracted value to target type safely."""
        if val is None or val == "":
            return None
        s = str(val).strip()
        try:
            if target_type == "int":
                return int(s)
            elif target_type == "float":
                return float(s)
            elif target_type == "bool":
                return s.lower() in ("true", "1", "yes", "t", "y")
            elif target_type == "port":
                return self.safe_port(s)
            elif target_type == "ip":
                return self.validate_ip(s) or s
            elif target_type in ("epoch_timestamp_s", "epoch_timestamp_ms", "epoch_timestamp_us"):
                num = float(s)
                if target_type == "epoch_timestamp_ms":
                    num /= 1000.0
                elif target_type == "epoch_timestamp_us":
                    num /= 1000000.0
                return datetime.fromtimestamp(num, tz=UTC).isoformat()
            elif target_type == "iso_timestamp":
                dt = self.parse_timestamp(s)
                return dt.isoformat() if dt else s
        except Exception:
            return val
        return s

    def build_normalized_event(self, extracted: dict[str, Any]) -> dict[str, Any]:
        """
        Produce a normalized UES dictionary directly from declarative normalization rules.
        """
        norm_cfg = self.normalize_cfg
        vendor = norm_cfg.get("source.vendor") or self.vendor
        product = norm_cfg.get("source.product") or self.product

        # Resolve field references
        def _res(field_expr: Any, default: Any = None) -> Any:
            if field_expr is None:
                return default
            expr_str = str(field_expr).strip()
            if expr_str in extracted:
                return extracted[expr_str]
            return field_expr

        # Category mapping
        cat_raw = _res(norm_cfg.get("event.category"), "network")
        category = str(cat_raw).lower()
        if category not in UES_CATEGORIES:
            category = "unknown"

        # Action & Outcome mapping
        action = _res(norm_cfg.get("event.action"))
        outcome = _res(norm_cfg.get("event.outcome"))
        if action and not outcome:
            act_lower = str(action).lower()
            if act_lower in ("allow", "permit", "permitted", "accept", "success", "login_success", "ok", "pass"):
                outcome = "success"
            elif act_lower in ("deny", "denied", "block", "blocked", "drop", "dropped", "reject", "fail", "failure", "failed", "error"):
                outcome = "failure"
            else:
                outcome = "unknown"

        # Value mappings lookup table
        val_maps = norm_cfg.get("value_mappings", {})
        if outcome and "outcome" in val_maps:
            outcome = val_maps["outcome"].get(str(outcome).lower(), outcome)
        elif outcome:
            out_lower = str(outcome).lower()
            if out_lower in ("allow", "permit", "permitted", "accept", "success", "login_success", "ok", "pass"):
                outcome = "success"
            elif out_lower in ("deny", "denied", "block", "blocked", "drop", "dropped", "reject", "fail", "failure", "failed", "error"):
                outcome = "failure"
            elif out_lower not in ("success", "failure", "unknown"):
                outcome = "unknown"

        # Severity
        sev_raw = _res(norm_cfg.get("event.severity_numeric"))
        severity = self.safe_float(sev_raw)
        if severity is None:
            severity = 5.0

        # Unmapped attributes bag
        mapped_keys = {
            "_raw", "_log_format", "_vendor", "_product", "timestamp_dt",
        }
        for v in norm_cfg.values():
            if isinstance(v, str) and v in extracted:
                mapped_keys.add(v)
        for v in self.fields_cfg.values():
            if isinstance(v, str) and v in extracted:
                mapped_keys.add(v)

        vendor_attributes: dict[str, Any] = {}
        if norm_cfg.get("retain_unmapped", True):
            for k, v in extracted.items():
                if k not in mapped_keys and not k.startswith("_"):
                    vendor_attributes[k] = v

        normalized: dict[str, Any] = {
            "source": {
                "vendor": str(vendor) if vendor else None,
                "product": str(product) if product else None,
                "device_hostname": _res(norm_cfg.get("source.device_hostname")),
                "source_ip": _res(norm_cfg.get("source.source_ip")),
                "log_format": self.log_format,
            },
            "event": {
                "category": category,
                "action": str(action) if action else None,
                "outcome": str(outcome) if outcome else None,
                "severity_numeric": severity,
                "severity_original": str(_res(norm_cfg.get("event.severity_original"))) if norm_cfg.get("event.severity_original") else None,
                "event_type_vendor_specific": str(_res(norm_cfg.get("event.event_type_vendor_specific"))) if norm_cfg.get("event.event_type_vendor_specific") else None,
            },
            "network": {
                "src_ip": _res(norm_cfg.get("network.src_ip")),
                "src_port": self.safe_port(_res(norm_cfg.get("network.src_port"))),
                "dst_ip": _res(norm_cfg.get("network.dst_ip")),
                "dst_port": self.safe_port(_res(norm_cfg.get("network.dst_port"))),
                "protocol": str(_res(norm_cfg.get("network.protocol"))).lower() if _res(norm_cfg.get("network.protocol")) else None,
                "bytes_in": self.safe_int(_res(norm_cfg.get("network.bytes_in"))),
                "bytes_out": self.safe_int(_res(norm_cfg.get("network.bytes_out"))),
                "direction": _res(norm_cfg.get("network.direction")),
                "interface": _res(norm_cfg.get("network.interface")),
            },
            "identity": {
                "username": _res(norm_cfg.get("identity.username")),
                "user_domain": _res(norm_cfg.get("identity.user_domain")),
            },
            "rule": {
                "rule_id": _res(norm_cfg.get("rule.rule_id")),
                "rule_name": _res(norm_cfg.get("rule.rule_name")),
                "policy_action": _res(norm_cfg.get("rule.policy_action")),
            },
            "vendor_attributes": vendor_attributes,
            "_ruleset_version": self.version,
        }
        return normalized


class DeclarativeSourceRegistry:
    """
    Discovers, loads, validates, and manages dynamic declarative source definitions.
    """

    def __init__(self, sources_dir: Path | str | None = None):
        """
        Args:
            sources_dir: Writable directory for runtime-authored sources. Defaults
                to the per-user data directory. Definitions shipped inside the
                wheel are always loaded read-only in addition to this directory —
                the installed package is never written to, because site-packages
                is routinely root-owned or mounted read-only.
        """
        explicit = sources_dir is not None
        self.sources_dir = (
            Path(sources_dir)  # type: ignore[arg-type]  # guarded by `explicit`
            if explicit
            else resources.user_declarative_sources_dir()
        )
        # An explicit directory means "only this one" — callers that pass a path
        # (tests, single-tenant deployments) expect an isolated registry. The
        # default configuration additionally loads the definitions shipped in
        # the wheel.
        self.bundled_dir = None if explicit else resources.bundled_declarative_sources_dir()
        self._sources: dict[str, DeclarativeSourceParser] = {}

    def _ensure_writable_dir(self) -> Path:
        """Create the user sources directory on first write, not at import time."""
        self.sources_dir.mkdir(parents=True, exist_ok=True)
        return self.sources_dir

    def _load_dir(self, directory: Path | None) -> int:
        """Load and register every valid declarative source YAML in a directory."""
        count = 0
        if directory is None or not directory.exists():
            return 0
        for path in sorted(directory.glob("*.yaml")):
            try:
                with open(path, encoding="utf-8") as f:
                    cfg = yaml.safe_load(f)
                if not (isinstance(cfg, dict) and "name" in cfg):
                    continue
                valid, errors = validate_declarative_config(cfg)
                if not valid:
                    logger.warning(
                        "Invalid declarative source '%s': %s", path.name, ", ".join(errors)
                    )
                    continue
                parser = DeclarativeSourceParser(cfg)
                self._sources[parser.name] = parser
                self._register_with_global(parser)
                count += 1
            except Exception as e:
                logger.error("Error loading declarative source '%s': %s", path, e)
        return count

    def scan_and_register(self) -> int:
        """
        Discover declarative sources and register them with the parser registry.

        Bundled definitions load first so that a user-authored source of the
        same name deliberately overrides the shipped one.
        """
        loaded = self._load_dir(self.bundled_dir) if self.bundled_dir else 0
        return loaded + self._load_dir(self.sources_dir)

    def add_source(self, config: dict[str, Any]) -> tuple[bool, list[str], DeclarativeSourceParser | None]:
        """Validate, save, and dynamically register a new declarative source configuration."""
        valid, errors = validate_declarative_config(config)
        if not valid:
            return False, errors, None

        parser = DeclarativeSourceParser(config)
        self._sources[parser.name] = parser

        # Persist to the writable user directory (never into the wheel).
        # parser.name is schema-constrained to ^[a-zA-Z0-9_-]+$, so it cannot
        # escape this directory.
        file_path = self._ensure_writable_dir() / f"{parser.name}.yaml"
        with open(file_path, "w", encoding="utf-8") as f:
            yaml.dump(config, f, sort_keys=False, default_flow_style=False)

        self._register_with_global(parser)
        return True, [], parser

    def get_source(self, name: str) -> DeclarativeSourceParser | None:
        """Retrieve a registered declarative source by name."""
        return self._sources.get(name)

    def list_sources(self) -> list[DeclarativeSourceParser]:
        """List all loaded declarative sources."""
        return list(self._sources.values())

    def remove_source(self, name: str) -> bool:
        """
        Remove a runtime-authored declarative source.

        Only the writable user directory is touched: bundled definitions are
        part of the installed artifact and are unregistered in memory but left
        on disk. The name is re-validated here because this is reachable from
        the dashboard's DELETE endpoint, where it arrives as a URL segment.
        """
        if name not in self._sources:
            return False
        if not _SOURCE_NAME_RE.fullmatch(name):
            logger.warning("Refusing to remove source with unsafe name %r", name)
            return False
        del self._sources[name]
        from ulpf.core import registry as _registry

        _registry.unregister_parser(name)
        file_path = self.sources_dir / f"{name}.yaml"
        if file_path.exists():
            file_path.unlink()
        return True

    def _register_with_global(self, parser: DeclarativeSourceParser) -> None:
        """Inject the declarative parser instance into the global registry."""
        from ulpf.core import registry
        # Wrap as a dynamically registered class
        class _DynamicParser(BaseParser):
            name = parser.name
            version = parser.version
            log_format = parser.log_format

            def match(self, raw_line: str) -> bool:
                return parser.match(raw_line)

            def extract(self, raw_line: str) -> dict[str, Any]:
                return parser.extract(raw_line)

        registry._REGISTRY[parser.name] = _DynamicParser


# Process-wide registry, created on first use rather than at import time so
# that importing ulpf never touches the filesystem.
_GLOBAL_DECLARATIVE_REGISTRY: DeclarativeSourceRegistry | None = None


def get_declarative_registry() -> DeclarativeSourceRegistry:
    """Return the process-wide declarative source registry."""
    global _GLOBAL_DECLARATIVE_REGISTRY
    if _GLOBAL_DECLARATIVE_REGISTRY is None:
        _GLOBAL_DECLARATIVE_REGISTRY = DeclarativeSourceRegistry()
    return _GLOBAL_DECLARATIVE_REGISTRY


def reset_declarative_registry(sources_dir: Path | str | None = None) -> DeclarativeSourceRegistry:
    """Replace the process-wide registry. Intended for tests and embedders."""
    global _GLOBAL_DECLARATIVE_REGISTRY
    _GLOBAL_DECLARATIVE_REGISTRY = DeclarativeSourceRegistry(sources_dir)
    return _GLOBAL_DECLARATIVE_REGISTRY


def infer_declarative_mapping(
    sample_event: str,
    name_hint: str = "custom_source",
    vendor: str = "CustomVendor",
    product: str = "CustomLog",
    name: str | None = None,
) -> dict[str, Any]:
    """
    Intelligently inspects a sample log string to infer log format,
    delimiters, key-value pairs, timestamps, IP addresses, and draft normalization mappings.
    """
    src_name = (name or name_hint).lower().replace(" ", "_")
    stripped = sample_event.strip()
    config: dict[str, Any] = {
        "name": src_name,
        "vendor": vendor,
        "product": product,
        "version": "1.0.0",
        "enabled": True,
        "description": f"Auto-inferred declarative log source definition for {product}",
        "detection": {},
        "parser": {},
        "fields": {
            "types": {}
        },
        "normalize": {
            "retain_unmapped": True
        }
    }

    # 1. JSON inference
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                config["parser"] = {
                    "type": "json"
                }
                config["detection"] = {
                    "json_keys": list(data.keys())[:3]
                }
                # Inspect fields
                for k, _v in data.items():
                    k_lower = k.lower()
                    if any(t in k_lower for t in ("time", "date", "ts", "timestamp")):
                        config["fields"]["timestamp"] = k
                    if any(t in k_lower for t in ("src", "source_ip", "client_ip", "srcip")):
                        config["normalize"]["network.src_ip"] = k
                    if any(t in k_lower for t in ("dst", "dest_ip", "server_ip", "dstip")):
                        config["normalize"]["network.dst_ip"] = k
                    if "user" in k_lower or "username" in k_lower:
                        config["normalize"]["identity.username"] = k
                    if "action" in k_lower or "act" in k_lower:
                        config["normalize"]["event.action"] = k
                return config
        except Exception:
            pass

    # 2. Key-Value inference (e.g. key=value or key:value)
    kv_matches = re.findall(r'([a-zA-Z0-9_.-]+)=("[^"]*"|\'[^\']*\'|\S+)', stripped)
    if len(kv_matches) >= 3:
        sample_keys = [m[0] for m in kv_matches]
        config["parser"] = {
            "type": "key_value",
            "pair_delimiter": " ",
            "kv_delimiter": "=",
            "strip_quotes": True
        }
        config["detection"] = {
            "contains": [f"{sample_keys[0]}=", f"{sample_keys[1]}="],
            "contains_mode": "all"
        }
        for k, _v in kv_matches:
            k_lower = k.lower()
            if any(t in k_lower for t in ("time", "date", "ts", "devtime")):
                config["fields"]["timestamp"] = k
            if any(t in k_lower for t in ("srcport", "spt", "src_port", "sport")):
                config["normalize"]["network.src_port"] = k
                config["fields"]["types"][k] = "port"
            elif any(t in k_lower for t in ("srcip", "src_ip", "src", "source", "client_ip", "clientip")):
                config["normalize"]["network.src_ip"] = k

            if any(t in k_lower for t in ("dstport", "dpt", "dst_port", "dport")):
                config["normalize"]["network.dst_port"] = k
                config["fields"]["types"][k] = "port"
            elif any(t in k_lower for t in ("dstip", "dst_ip", "dst", "dest", "server_ip", "serverip")):
                config["normalize"]["network.dst_ip"] = k
            if any(t in k_lower for t in ("user", "username", "usr")):
                config["normalize"]["identity.username"] = k
            if any(t in k_lower for t in ("action", "act", "status")):
                config["normalize"]["event.action"] = k
            if any(t in k_lower for t in ("proto", "protocol")):
                config["normalize"]["network.protocol"] = k
        return config

    # 3. CSV inference
    if "," in stripped and len(stripped.split(",")) >= 4:
        cols = [f"field_{i+1}" for i in range(len(stripped.split(",")))]
        config["parser"] = {
            "type": "csv",
            "delimiter": ",",
            "columns": cols
        }
        config["detection"] = {
            "contains": [stripped.split(",")[0]]
        }
        return config

    # 4. Delimiter inference (e.g. pipe or tab)
    for delim in ("|", "\t"):
        if delim in stripped and len(stripped.split(delim)) >= 3:
            cols = [f"col_{i+1}" for i in range(len(stripped.split(delim)))]
            config["parser"] = {
                "type": "delimiter",
                "delimiter": delim,
                "columns": cols
            }
            config["detection"] = {
                "contains": [stripped.split(delim)[0]]
            }
            return config

    # 5. Regex default
    config["parser"] = {
        "type": "regex",
        "pattern": r'^(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+(?P<message>.*)$'
    }
    config["fields"]["timestamp"] = "timestamp"
    config["normalize"]["source.device_hostname"] = "hostname"
    return config
