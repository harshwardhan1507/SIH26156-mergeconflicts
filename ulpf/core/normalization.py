"""
Normalization Engine.

Loads per-parser YAML mapping files and maps extracted fields into UES.
Mapping values starting with '_' are built-in transform hints:
  _category_default:<value>  — use <value> as default category
  _outcome_from_action       — derive outcome from action field
  _direction_from_zones      — derive direction from src_zone/dst_zone
  null                       — field gets None
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_ACTION_OUTCOME_MAP = {
    'allow':    'success',
    'permit':   'success',
    'permitted':'success',
    'accept':   'success',
    'success':  'success',
    'deny':     'failure',
    'denied':   'failure',
    'block':    'failure',
    'drop':     'failure',
    'reject':   'failure',
    'reset':    'failure',
    'fail':     'failure',
    'failure':  'failure',
}

_CATEGORY_KEYWORDS = {
    'authentication': ['login', 'logon', 'auth', 'vpn', 'ssh', 'rdp', 'kerberos', 'ldap', 'password'],
    'threat': ['malware', 'virus', 'exploit', 'attack', 'intrusion', 'alert', 'ids', 'ips', 'threat', 'scan', 'flood', 'dos', 'ddos'],
    'policy': ['acl', 'policy', 'rule', 'compliance', 'violation'],
    'system': ['system', 'config', 'startup', 'shutdown', 'cpu', 'memory', 'interface up', 'interface down'],
    'network': ['tcp', 'udp', 'icmp', 'traffic', 'connection', 'session', 'nat', 'routing'],
}


def _infer_category(extracted: dict[str, Any], default: str = 'network') -> str:
    """Infer event category from extracted fields using keyword matching."""
    searchable = ' '.join([
        str(extracted.get('message', '')),
        str(extracted.get('Name', '')),
        str(extracted.get('tag', '')),
        str(extracted.get('app', '')),
        str(extracted.get('event', '')),
        str(extracted.get('asa_mnemonic', '')),
    ]).lower()

    for category, keywords in _CATEGORY_KEYWORDS.items():
        if any(kw in searchable for kw in keywords):
            return category

    return default


def _resolve_outcome(extracted: dict[str, Any], action_field: str | None) -> str | None:
    if not action_field:
        return 'unknown'
    action_val = str(extracted.get(action_field, '')).lower().strip()
    return _ACTION_OUTCOME_MAP.get(action_val, 'unknown')


def _resolve_direction(extracted: dict[str, Any]) -> str | None:
    src_zone = str(extracted.get('src_zone', '')).lower()
    dst_zone = str(extracted.get('dst_zone', '')).lower()
    if 'outside' in src_zone or 'untrust' in src_zone or 'external' in src_zone:
        return 'inbound'
    if 'outside' in dst_zone or 'untrust' in dst_zone or 'external' in dst_zone:
        return 'outbound'
    if src_zone and dst_zone and src_zone == dst_zone:
        return 'internal'
    return 'unknown'


def _get_field(extracted: dict[str, Any], field_spec: Any) -> Any:
    """Resolve a field_spec (a key name, literal, transform, or None) from the extracted dict."""
    if field_spec is None:
        return None
    spec = str(field_spec).strip()
    if spec in ('null', 'none', '~', ''):
        return None
    if spec.startswith('_literal:'):
        return spec.split(':', 1)[1]
    if spec.startswith('_upper:'):
        target = spec.split(':', 1)[1].strip()
        val = extracted.get(target)
        return str(val).upper() if val is not None else None
    if spec.startswith('_lower:'):
        target = spec.split(':', 1)[1].strip()
        val = extracted.get(target)
        return str(val).lower() if val is not None else None
    if spec.startswith('_strip:'):
        target = spec.split(':', 1)[1].strip()
        val = extracted.get(target)
        return str(val).strip() if val is not None else None
    if spec.startswith('_first:'):
        candidates = [c.strip() for c in spec.split(':', 1)[1].split(',') if c.strip()]
        for c in candidates:
            if extracted.get(c) is not None and str(extracted.get(c)).strip() != '':
                return extracted.get(c)
        return None
    if spec.startswith('_split:'):
        body = spec.split(':', 1)[1]
        if ',' in body:
            rem, idx_s = body.rsplit(',', 1)
            idx_s = idx_s.strip()
            if ',' in rem and idx_s.isdigit():
                fld, delim = rem.split(',', 1)
                raw_v = extracted.get(fld.strip())
                if raw_v is not None:
                    tokens = str(raw_v).split(delim)
                    idx = int(idx_s)
                    if 0 <= idx < len(tokens):
                        return tokens[idx].strip()
        return None
    if spec.startswith('_default:'):
        parts = spec.split(':', 1)[1].split(',', 1)
        fld = parts[0].strip()
        dflt = parts[1].strip() if len(parts) > 1 else ''
        val = extracted.get(fld)
        return val if (val is not None and str(val).strip() != '') else dflt
    if spec.startswith('_category_default:'):
        return None  # handled separately
    if spec == '_outcome_from_action':
        return None  # handled separately
    if spec == '_direction_from_zones':
        return None  # handled separately
    # Direct field name lookup
    return extracted.get(spec)


_OCSF_CLASS_MAP = {
    'network': ('Network Activity', 4001),
    'authentication': ('Authentication', 3001),
    'threat': ('Security Finding', 2001),
    'system': ('System Activity', 1001),
    'policy': ('Policy Activity', 5001),
    'api': ('API Activity', 6003),
    'database': ('Database Activity', 6004),
    'unknown': ('Base Event', 1),
}

_OCSF_ACTIVITY_MAP = {
    'logon': ('Logon', 1),
    'login': ('Logon', 1),
    'logoff': ('Logoff', 2),
    'logout': ('Logoff', 2),
    'connect': ('Connect', 1),
    'permit': ('Permit', 2),
    'permitted': ('Permit', 2),
    'allow': ('Allow', 2),
    'deny': ('Deny', 3),
    'denied': ('Deny', 3),
    'block': ('Block', 3),
    'drop': ('Drop', 4),
    'query': ('Query', 5),
    'create': ('Create', 1),
    'delete': ('Delete', 3),
}


class NormalizationEngine:
    """Loads YAML mappings and normalizes extracted dicts into UES dicts."""

    def __init__(self, mappings_dir: str | Path):
        self.mappings_dir = Path(mappings_dir)
        self._mappings: dict[str, dict] = {}
        self._load_all()

    def _load_all(self) -> None:
        for yaml_file in self.mappings_dir.glob('*.yaml'):
            parser_name = yaml_file.stem
            with open(yaml_file, 'r', encoding='utf-8') as fh:
                self._mappings[parser_name] = yaml.safe_load(fh) or {}
            logger.debug('Loaded mapping: %s', parser_name)

    def _get_mapping(self, parser_name: str) -> dict:
        if parser_name not in self._mappings:
            logger.warning('No mapping found for parser %r, using empty mapping', parser_name)
            return {}
        return self._mappings[parser_name]

    def normalize(self, extracted: dict[str, Any], parser_name: str) -> dict[str, Any]:
        """Map extracted fields → UES dict (without envelope fields like event_id)."""
        # Check declarative source registry first for dynamic no-code source definitions
        try:
            from ulpf.core.declarative import get_declarative_registry
            decl_source = get_declarative_registry().get_source(parser_name)
            if decl_source is not None:
                return decl_source.build_normalized_event(extracted)
        except Exception:
            pass

        mapping = self._get_mapping(parser_name)

        ruleset_version = mapping.get('ruleset_version', '1.2.0')
        mapped_keys: set[str] = {'_raw', '_log_format', 'timestamp_dt', 'timestamp_raw'}

        def track_key(spec: Any) -> None:
            if spec and isinstance(spec, str) and not spec.startswith('_') and spec != 'null':
                mapped_keys.add(spec)

        # --- source block ---
        src_map = mapping.get('source', {})
        for v in src_map.values():
            track_key(v)

        source: dict[str, Any] = {
            'vendor': _get_field(extracted, src_map.get('vendor')),
            'product': _get_field(extracted, src_map.get('product')),
            'device_hostname': _get_field(extracted, src_map.get('device_hostname')),
            'source_ip': _get_field(extracted, src_map.get('source_ip')),
            'log_format': extracted.get('_log_format', 'unknown'),
        }

        # --- event block ---
        ev_map = mapping.get('event', {})
        for v in ev_map.values():
            track_key(v)

        # Category
        cat_spec = str(ev_map.get('category', '')).strip()
        if cat_spec.startswith('_category_default:'):
            default_cat = cat_spec.split(':', 1)[1]
            category = _infer_category(extracted, default=default_cat)
        else:
            category = _get_field(extracted, cat_spec) or 'unknown'

        valid_categories = {'network', 'authentication', 'threat', 'system', 'policy', 'api', 'database', 'unknown'}
        if category not in valid_categories:
            category = 'unknown'

        # Action
        action_spec = ev_map.get('action')
        action_val = _get_field(extracted, action_spec)
        action_str = str(action_val).lower() if action_val else None

        # Outcome
        outcome_spec = str(ev_map.get('outcome', '')).strip()
        if outcome_spec == '_outcome_from_action':
            outcome = _ACTION_OUTCOME_MAP.get(str(action_val).lower().strip(), 'unknown') if action_val else 'unknown'
        else:
            outcome = _get_field(extracted, outcome_spec)

        # Map result/outcome strings
        if outcome:
            outcome_str = str(outcome).lower()
            outcome = _ACTION_OUTCOME_MAP.get(outcome_str, 'unknown')
        
        valid_outcomes = {'success', 'failure', 'unknown', None}
        if outcome not in valid_outcomes:
            outcome = 'unknown'

        # Severity resolution (explicit vs inferred)
        sev_raw = _get_field(extracted, ev_map.get('severity_numeric'))
        if sev_raw is None:
            sev_raw = extracted.get('severity_ues')
        
        if sev_raw is not None:
            try:
                sev_numeric = float(sev_raw)
                sev_numeric = max(0.0, min(10.0, sev_numeric))
                severity_inferred = False
            except (ValueError, TypeError):
                sev_numeric = 5.0
                severity_inferred = True
        else:
            sev_numeric = 5.0
            severity_inferred = True

        # OCSF Taxonomy mapping
        ocsf_class_name, ocsf_class_uid = _OCSF_CLASS_MAP.get(category, ('Base Event', 1))
        act_key = action_str or (str(extracted.get('event_type_vendor_specific', '')).lower() if extracted.get('event_type_vendor_specific') else '')
        ocsf_act_name, ocsf_act_id = _OCSF_ACTIVITY_MAP.get(act_key, (action_str.capitalize() if action_str else None, None))

        event_block: dict[str, Any] = {
            'category': category,
            'class_name': ocsf_class_name,
            'class_uid': ocsf_class_uid,
            'activity_name': ocsf_act_name,
            'activity_id': ocsf_act_id,
            'action': action_str,
            'outcome': outcome,
            'severity_numeric': sev_numeric,
            'severity_original': _get_field(extracted, ev_map.get('severity_original')),
            'severity_inferred': severity_inferred,
            'event_type_vendor_specific': str(_get_field(extracted, ev_map.get('event_type_vendor_specific')) or ''),
        }

        if not event_block['event_type_vendor_specific']:
            event_block['event_type_vendor_specific'] = None

        # --- network block ---
        net_map = mapping.get('network', {})
        for v in net_map.values():
            track_key(v)

        dir_spec = str(net_map.get('direction', '')).strip()
        if dir_spec == '_direction_from_zones':
            direction = _resolve_direction(extracted)
        else:
            direction = _get_field(extracted, dir_spec)

        valid_directions = {'inbound', 'outbound', 'internal', 'unknown', None}
        if direction not in valid_directions:
            direction = 'unknown'

        def safe_int_field(key: str) -> int | None:
            v = _get_field(extracted, net_map.get(key))
            if v is None:
                return None
            try:
                return int(v)
            except (ValueError, TypeError):
                return None

        network_block: dict[str, Any] = {
            'src_ip': _get_field(extracted, net_map.get('src_ip')),
            'src_port': safe_int_field('src_port'),
            'dst_ip': _get_field(extracted, net_map.get('dst_ip')),
            'dst_port': safe_int_field('dst_port'),
            'protocol': _get_field(extracted, net_map.get('protocol')),
            'bytes_in': safe_int_field('bytes_in'),
            'bytes_out': safe_int_field('bytes_out'),
            'direction': direction,
            'interface': _get_field(extracted, net_map.get('interface')),
        }
        # Normalize protocol to lowercase
        if network_block['protocol']:
            network_block['protocol'] = str(network_block['protocol']).lower()

        # Only include network block if any field is non-null
        has_network = any(v is not None for v in network_block.values())
        final_network = network_block if has_network else None

        # --- identity block ---
        id_map = mapping.get('identity', {})
        for v in id_map.values():
            track_key(v)

        identity_block: dict[str, Any] = {
            'username': _get_field(extracted, id_map.get('username')),
            'user_domain': _get_field(extracted, id_map.get('user_domain')),
        }
        has_identity = any(v is not None for v in identity_block.values())
        final_identity = identity_block if has_identity else None

        # --- rule block ---
        rl_map = mapping.get('rule', {})
        for v in rl_map.values():
            track_key(v)

        rule_block: dict[str, Any] = {
            'rule_id': str(_get_field(extracted, rl_map.get('rule_id')) or '') or None,
            'rule_name': _get_field(extracted, rl_map.get('rule_name')),
            'policy_action': _get_field(extracted, rl_map.get('policy_action')),
        }
        has_rule = any(v is not None for v in rule_block.values())
        final_rule = rule_block if has_rule else None

        # --- vendor_attributes open bag (100% attribute preservation) ---
        vendor_attrs: dict[str, Any] = {}
        for k, v in extracted.items():
            if k not in mapped_keys and not k.startswith('_'):
                vendor_attrs[k] = v

        return {
            'source': source,
            'event': event_block,
            'network': final_network,
            'identity': final_identity,
            'rule': final_rule,
            'vendor_attributes': vendor_attrs if vendor_attrs else None,
            'enrichment': None,
            '_ruleset_version': ruleset_version,
        }
