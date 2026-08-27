"""
Auto-import all parser modules so they self-register.

Uses dynamic discovery (pkgutil) rather than a hardcoded import list:
any .py file dropped into this package that defines a class decorated
with @register_parser is picked up automatically at import time.
Adding a new source parser requires creating exactly one file here
(plus its YAML mapping in schemas/mappings/) — nothing else in this
package or in ulpf/core/ needs to change.
"""
from __future__ import annotations

import importlib
import pkgutil

_EXCLUDED = {"base"}  # abstract base class module — not a parser itself

for _finder, _module_name, _is_pkg in pkgutil.iter_modules(__path__):
    if _module_name.startswith("_") or _module_name in _EXCLUDED:
        continue
    importlib.import_module(f"{__name__}.{_module_name}")

