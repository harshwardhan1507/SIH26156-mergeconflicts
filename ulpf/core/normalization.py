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
    """Resolve a field_spec (a key name or None) from the extracted dict."""
    if field_spec is None:
        return None
    spec = str(field_spec).strip()
    if spec == 'null':
        return None
    if spec.startswith('_category_default:'):
        return None  # handled separately
    if spec == '_outcome_from_action':
        return None  # handled separately
    if spec == '_direction_from_zones':
        return None  # handled separately
    # Direct field name lookup
    return extracted.get(spec)


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
        mapping = self._get_mapping(parser_name)

        ruleset_version = mapping.get('ruleset_version', '0.0.0')

        # --- source block ---
        src_map = mapping.get('source', {})
        source: dict[str, Any] = {
            'vendor': _get_field(extracted, src_map.get('vendor')),
            'product': _get_field(extracted, src_map.get('product')),
            'device_hostname': _get_field(extracted, src_map.get('device_hostname')),
            'source_ip': _get_field(extracted, src_map.get('source_ip')),
            'log_format': extracted.get('_log_format', 'unknown'),
        }

        # --- event block ---
        ev_map = mapping.get('event', {})

        # Category
        cat_spec = str(ev_map.get('category', '')).strip()
        if cat_spec.startswith('_category_default:'):
            default_cat = cat_spec.split(':', 1)[1]
            category = _infer_category(extracted, default=default_cat)
        else:
            category = _get_field(extracted, cat_spec) or 'unknown'

        valid_categories = {'network', 'authentication', 'threat', 'system', 'policy', 'unknown'}
        if category not in valid_categories:
            category = 'unknown'

        # Action
        action_spec = ev_map.get('action')
        action_val = _get_field(extracted, action_spec)
        action_str = str(action_val).lower() if action_val else None

        # Outcome
        outcome_spec = str(ev_map.get('outcome', '')).strip()
        if outcome_spec == '_outcome_from_action':
            outcome = _resolve_outcome(extracted, action_spec)
        else:
            outcome = _get_field(extracted, outcome_spec)

        # Map result/outcome strings
        if outcome:
            outcome_str = str(outcome).lower()
            outcome = _ACTION_OUTCOME_MAP.get(outcome_str, 'unknown')
        
        valid_outcomes = {'success', 'failure', 'unknown', None}
        if outcome not in valid_outcomes:
            outcome = 'unknown'

        sev_raw = _get_field(extracted, ev_map.get('severity_numeric'))
        sev_numeric = float(sev_raw) if sev_raw is not None else 5.0
        sev_numeric = max(0.0, min(10.0, sev_numeric))

        event_block: dict[str, Any] = {
            'category': category,
            'action': action_str,
            'outcome': outcome,
            'severity_numeric': sev_numeric,
            'severity_original': _get_field(extracted, ev_map.get('severity_original')),
            'event_type_vendor_specific': str(_get_field(extracted, ev_map.get('event_type_vendor_specific')) or ''),
        }

        if not event_block['event_type_vendor_specific']:
            event_block['event_type_vendor_specific'] = None

        # --- network block ---
        net_map = mapping.get('network', {})

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
        identity_block: dict[str, Any] = {
            'username': _get_field(extracted, id_map.get('username')),
            'user_domain': _get_field(extracted, id_map.get('user_domain')),
        }
        has_identity = any(v is not None for v in identity_block.values())
        final_identity = identity_block if has_identity else None

        # --- rule block ---
        rl_map = mapping.get('rule', {})
        rule_block: dict[str, Any] = {
            'rule_id': str(_get_field(extracted, rl_map.get('rule_id')) or '') or None,
            'rule_name': _get_field(extracted, rl_map.get('rule_name')),
            'policy_action': _get_field(extracted, rl_map.get('policy_action')),
        }
        has_rule = any(v is not None for v in rule_block.values())
        final_rule = rule_block if has_rule else None

        return {
            'source': source,
            'event': event_block,
            'network': final_network,
            'identity': final_identity,
            'rule': final_rule,
            'enrichment': None,
            '_ruleset_version': ruleset_version,
        }
