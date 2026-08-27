"""
Ingestion Layer.

Provides abstract ReaderBase and concrete implementations:
  - FileReader: reads a single file or all files in a directory
  - StdinReader: reads line-by-line from stdin

Each reader yields RawEvent dataclass instances.
"""
from __future__ import annotations

import sys
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator


@dataclass
class RawEvent:
    """A single raw log line/record as received by the pipeline."""
    line: str                     # Original raw text
    source_tag: str               # File path, 'stdin', or a logical source label
    ingest_timestamp: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )


class ReaderBase(ABC):
    """Abstract base class for all ingestion readers."""

    @abstractmethod
    def read(self) -> Iterator[RawEvent]:
        """Yield RawEvent objects one at a time."""


class FileReader(ReaderBase):
    """
    Reads from a single file or from all files in a directory.
    Skips empty lines and lines containing only whitespace.
    """

    def __init__(self, path: str | Path, recursive: bool = False,
                 extensions: tuple[str, ...] | None = None):
        self.path = Path(path)
        self.recursive = recursive
        self.extensions = extensions  # e.g. ('.log', '.csv')

    def _files(self) -> list[Path]:
        if self.path.is_file():
            return [self.path]
        pattern = '**/*' if self.recursive else '*'
        candidates = list(self.path.glob(pattern))
        files = [f for f in candidates if f.is_file()]
        if self.extensions:
            files = [f for f in files if f.suffix.lower() in self.extensions]
        return sorted(files)

    def read(self) -> Iterator[RawEvent]:
        for fpath in self._files():
            source_tag = str(fpath)
            with open(fpath, 'r', encoding='utf-8', errors='replace') as fh:
                for raw_line in fh:
                    line = raw_line.rstrip('\n').rstrip('\r')
                    if line.strip():
                        yield RawEvent(
                            line=line,
                            source_tag=source_tag,
                            ingest_timestamp=datetime.now(tz=timezone.utc),
                        )


class StdinReader(ReaderBase):
    """Reads newline-delimited events from stdin."""

    def read(self) -> Iterator[RawEvent]:
        for raw_line in sys.stdin:
            line = raw_line.rstrip('\n').rstrip('\r')
            if line.strip():
                yield RawEvent(
                    line=line,
                    source_tag='stdin',
                    ingest_timestamp=datetime.now(tz=timezone.utc),
                )
