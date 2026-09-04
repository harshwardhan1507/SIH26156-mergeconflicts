"""
Architectural boundary tests.

The framework must remain independent of the dashboard: ``ulpf`` may be
installed and run with no web stack present, and the dependency between the two
distributions must point one way only. These are cheap to check and easy to
regress, so they are asserted rather than documented.
"""
from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
FRAMEWORK = SRC / "ulpf"
DASHBOARD = SRC / "ulpf_dashboard"

#: Third-party modules the framework must never import at any level.
FORBIDDEN_IN_FRAMEWORK = {"fastapi", "uvicorn", "starlette", "ulpf_dashboard"}


def _imported_modules(path: Path) -> set[str]:
    """Top-level module names imported by a Python file, including inside functions."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module.split(".")[0])
    return modules


@pytest.mark.parametrize(
    "source_file",
    sorted(FRAMEWORK.rglob("*.py")),
    ids=lambda p: str(p.relative_to(SRC)),
)
def test_framework_never_imports_the_web_stack(source_file: Path) -> None:
    """No module under ``ulpf`` may import FastAPI, uvicorn, or the dashboard."""
    # The CLI's `dashboard` shim is the one sanctioned reference, and it defers
    # the import to call time so a missing dashboard degrades to a clear error.
    if source_file.name == "cli.py":
        pytest.skip("cli.py delegates to the dashboard through a deferred import")

    forbidden = _imported_modules(source_file) & FORBIDDEN_IN_FRAMEWORK
    assert not forbidden, (
        f"{source_file.relative_to(SRC)} imports {sorted(forbidden)}; "
        "the framework must not depend on the dashboard or a web server"
    )


def test_cli_dashboard_import_is_deferred() -> None:
    """``ulpf.cli`` must not import the dashboard at module scope."""
    tree = ast.parse((FRAMEWORK / "cli.py").read_text(encoding="utf-8"))
    top_level = {
        alias.name.split(".")[0]
        for node in tree.body
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".")[0]
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert not (top_level & FORBIDDEN_IN_FRAMEWORK)


def test_framework_imports_without_the_web_stack_installed() -> None:
    """
    Importing ``ulpf`` and running a pipeline must work when FastAPI and uvicorn
    are unavailable — the condition of a framework-only install.
    """
    script = """
import sys

class _Blocked:
    def find_module(self, name, path=None):
        if name.split(".")[0] in {"fastapi", "uvicorn", "starlette"}:
            raise ImportError(f"{name} is blocked for this check")
        return None

sys.meta_path.insert(0, _Blocked())

import ulpf
assert ulpf.bootstrap() > 0, "no parsers registered"
from ulpf.runtime import build_session
print("OK", ulpf.__version__)
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=120,
        stdin=subprocess.DEVNULL,
    )
    assert result.returncode == 0, result.stderr
    assert "OK" in result.stdout


def test_dashboard_depends_on_the_framework() -> None:
    """The dashboard is expected to import the framework — the arrow points this way."""
    imports: set[str] = set()
    for source_file in DASHBOARD.rglob("*.py"):
        imports |= _imported_modules(source_file)
    assert "ulpf" in imports
