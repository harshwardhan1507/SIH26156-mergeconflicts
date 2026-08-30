"""
Parser Plugin Registry.

Python plugins self-register via the :func:`register_parser` class decorator at
import time; declarative (no-code) sources register through
:func:`ulpf.core.declarative.DeclarativeSourceRegistry`.

The registry is an ordered mapping keyed by parser name. Registration order is
the tie-break priority when several parsers claim the same line, and can be
overridden per source via ``sources.yaml``.

Importing this module has no side effects. Declarative sources are discovered
explicitly through :func:`load_declarative_sources`, which the CLI and the
dashboard both call during start-up — discovery that runs at import time is
impossible to control from tests or from an embedding application.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ulpf.parsers.base import BaseParser

logger = logging.getLogger(__name__)

_REGISTRY: dict[str, type[BaseParser]] = {}

__all__ = [
    "get_all_parsers",
    "get_parser_for_format",
    "list_parser_names",
    "load_declarative_sources",
    "parser_count",
    "register_parser",
    "unregister_parser",
]


def register_parser(cls: type[BaseParser]) -> type[BaseParser]:
    """Class decorator — adds the parser to the global registry."""
    if not getattr(cls, "name", ""):
        raise ValueError(f"{cls.__name__} must define a non-empty class-level 'name'")
    _REGISTRY[cls.name] = cls
    return cls


def unregister_parser(name: str) -> bool:
    """Remove a parser by name. Returns True if it was registered."""
    return _REGISTRY.pop(name, None) is not None


def get_parser_for_format(format_id: str) -> BaseParser | None:
    """Return an instantiated parser whose name matches format_id, or None."""
    cls = _REGISTRY.get(format_id)
    return cls() if cls else None


def get_all_parsers() -> list[BaseParser]:
    """Return all registered parsers as instances, in registration order."""
    return [cls() for cls in _REGISTRY.values()]


def list_parser_names() -> list[str]:
    """Names of every registered parser, in registration order."""
    return list(_REGISTRY.keys())


def parser_count() -> int:
    """Number of registered parsers (built-in plugins plus declarative sources)."""
    return len(_REGISTRY)


def load_declarative_sources(sources_dir: str | None = None) -> int:
    """
    Discover and register declarative YAML sources.

    Returns the number registered. Import failures are logged rather than
    raised: a malformed user-authored source must not prevent the framework
    from starting with its built-in parsers.
    """
    try:
        from ulpf.core.declarative import DeclarativeSourceRegistry

        registry = DeclarativeSourceRegistry(sources_dir)
        return registry.scan_and_register()
    except Exception as exc:
        logger.warning("Declarative source discovery failed: %s", exc)
        return 0
