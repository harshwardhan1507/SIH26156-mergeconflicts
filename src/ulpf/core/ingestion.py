"""
Ingestion Layer.

Provides abstract ReaderBase and concrete implementations:
  - FileReader: reads a single file or all files in a directory
  - StdinReader: reads line-by-line from stdin

Each reader yields RawEvent dataclass instances.
"""
from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path


@dataclass
class RawEvent:
    """A single raw log line/record as received by the pipeline."""
    line: str                     # Text representation
    source_tag: str               # File path, 'stdin', or a logical source label
    raw_bytes: bytes = field(default=b'')  # Exact untouched raw bytes
    ingest_timestamp: datetime = field(
        default_factory=lambda: datetime.now(tz=UTC)
    )

    def __post_init__(self) -> None:
        if not self.raw_bytes and self.line:
            self.raw_bytes = self.line.encode('utf-8', errors='surrogateescape')
        elif self.raw_bytes and not self.line:
            self.line = self.raw_bytes.decode('utf-8', errors='surrogateescape')


class ReaderBase(ABC):
    """Abstract base class for all ingestion readers."""

    @abstractmethod
    def read(self) -> Iterator[RawEvent]:
        """Yield RawEvent objects one at a time."""


class FileReader(ReaderBase):
    """
    Reads from a single file or from all files in a directory.
    Preserves exact binary bytes without lossy encoding corruption.
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
            with open(fpath, 'rb') as fh:
                for raw_line_bytes in fh:
                    # Strip trailing CR/LF
                    b = raw_line_bytes.rstrip(b'\r\n')
                    if b.strip():
                        line_str = b.decode('utf-8', errors='surrogateescape')
                        yield RawEvent(
                            line=line_str,
                            raw_bytes=b,
                            source_tag=source_tag,
                            ingest_timestamp=datetime.now(tz=UTC),
                        )


class StdinReader(ReaderBase):
    """Reads newline-delimited events from stdin preserving raw bytes."""

    def read(self) -> Iterator[RawEvent]:
        stream = getattr(sys.stdin, 'buffer', sys.stdin)
        for raw_line in stream:
            if isinstance(raw_line, bytes):
                b = raw_line.rstrip(b'\r\n')
                if b.strip():
                    line_str = b.decode('utf-8', errors='surrogateescape')
                    yield RawEvent(
                        line=line_str,
                        raw_bytes=b,
                        source_tag='stdin',
                        ingest_timestamp=datetime.now(tz=UTC),
                    )
            else:
                line = raw_line.rstrip('\r\n')
                if line.strip():
                    yield RawEvent(
                        line=line,
                        raw_bytes=line.encode('utf-8', errors='surrogateescape'),
                        source_tag='stdin',
                        ingest_timestamp=datetime.now(tz=UTC),
                    )
