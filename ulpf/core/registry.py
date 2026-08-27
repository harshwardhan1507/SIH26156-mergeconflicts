"""
Parser Plugin Registry.

Plugins self-register via the @register_parser decorator.
The registry is an ordered dict keyed by parser name.
Priority order: entries registered first have highest priority
(can be overridden via sources.yaml config).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ulpf.parsers.base import BaseParser

_REGISTRY: dict[str, type["BaseParser"]] = {}


def register_parser(cls: type["BaseParser"]) -> type["BaseParser"]:
    """Class decorator — adds the parser to the global registry."""
    _REGISTRY[cls.name] = cls
    return cls


def get_parser_for_format(format_id: str) -> "BaseParser | None":
    """Return an instantiated parser whose name matches format_id, or None."""
    cls = _REGISTRY.get(format_id)
    return cls() if cls else None


def get_all_parsers() -> list["BaseParser"]:
    """Return all registered parsers as instances, in registration order."""
    return [cls() for cls in _REGISTRY.values()]


def list_parser_names() -> list[str]:
    return list(_REGISTRY.keys())
