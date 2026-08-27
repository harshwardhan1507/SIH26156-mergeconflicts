"""Shared pytest fixtures."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import ulpf.parsers  # noqa — triggers self-registration
from ulpf.core.detector import FormatDetector
from ulpf.core.normalization import NormalizationEngine
from ulpf.core.validation import Validator

_SCHEMA_DIR = Path(__file__).parent.parent / 'schemas'
_MAPPINGS_DIR = _SCHEMA_DIR / 'mappings'
_SCHEMA_FILE = _SCHEMA_DIR / 'ues_schema.json'


@pytest.fixture(scope='session')
def schema_dir() -> Path:
    return _SCHEMA_DIR


@pytest.fixture(scope='session')
def norm_engine() -> NormalizationEngine:
    return NormalizationEngine(_MAPPINGS_DIR)


@pytest.fixture(scope='session')
def detector() -> FormatDetector:
    return FormatDetector()


@pytest.fixture(scope='session')
def ues_schema() -> dict:
    with open(_SCHEMA_FILE) as f:
        return json.load(f)
