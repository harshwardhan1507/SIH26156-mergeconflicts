"""
Event Framing Layer.

Transforms raw byte streams, files, network chunks, or text into discrete,
well-bounded log records before format detection and parsing.

Supports:
- LineFramer (standard \\n / \\r\\n line boundaries)
- DelimiterFramer (custom record separator tokens)
- MultilineRegexFramer (start/end pattern-based multiline aggregation)
- JSONStreamFramer (balanced bracket multiline JSON records)
- SyslogOctetFramer (RFC 5425 octet-counting framing: '<LEN> <MSG>')
- CSVRecordFramer (RFC 4180 multiline quoted CSV records)
- Max event size enforcement & quarantine of oversized frames
"""
from __future__ import annotations

import io
import json
import re
from abc import ABC, abstractmethod
from typing import Iterator, Iterable, Any


class FramingError(Exception):
    """Raised when an incoming stream cannot be framed safely."""


class FrameResult:
    """Represents a framed log record with metadata."""

    def __init__(
        self,
        raw_text: str,
        raw_bytes: bytes | None = None,
        is_oversized: bool = False,
        error: str | None = None,
    ):
        self.raw_text = raw_text
        self.raw_bytes = raw_bytes if raw_bytes is not None else raw_text.encode("utf-8", errors="surrogateescape")
        self.is_oversized = is_oversized
        self.error = error

    @property
    def size_bytes(self) -> int:
        return len(self.raw_bytes)


class BaseFramer(ABC):
    """Abstract base class for event framers."""

    def __init__(self, max_bytes: int = 2 * 1024 * 1024):
        self.max_bytes = max_bytes  # Default 2MB limit per event

    @abstractmethod
    def frame(self, stream: Iterable[str | bytes]) -> Iterator[FrameResult]:
        """Yield discrete FrameResult objects from the input stream."""


class LineFramer(BaseFramer):
    """Standard single-line event framer (splits on \\n and \\r\\n)."""

    def frame(self, stream: Iterable[str | bytes]) -> Iterator[FrameResult]:
        for item in stream:
            if isinstance(item, bytes):
                text = item.decode("utf-8", errors="surrogateescape")
                b = item
            else:
                text = str(item)
                b = text.encode("utf-8", errors="surrogateescape")

            # Split lines
            lines = text.splitlines()
            for line in lines:
                stripped = line.rstrip("\r\n")
                if stripped.strip():
                    line_bytes = stripped.encode("utf-8", errors="surrogateescape")
                    if len(line_bytes) > self.max_bytes:
                        yield FrameResult(
                            raw_text=stripped[:1024] + "...[TRUNCATED]",
                            raw_bytes=line_bytes,
                            is_oversized=True,
                            error=f"Event exceeds max_bytes limit ({len(line_bytes)} > {self.max_bytes})",
                        )
                    else:
                        yield FrameResult(raw_text=stripped, raw_bytes=line_bytes)


class DelimiterFramer(BaseFramer):
    """Frames records separated by a custom delimiter string (e.g. '###END###' or '\x00')."""

    def __init__(self, delimiter: str = "###EVENT_END###", max_bytes: int = 2 * 1024 * 1024):
        super().__init__(max_bytes)
        self.delimiter = delimiter

    def frame(self, stream: Iterable[str | bytes]) -> Iterator[FrameResult]:
        buffer = ""
        for chunk in stream:
            if isinstance(chunk, bytes):
                chunk_str = chunk.decode("utf-8", errors="surrogateescape")
            else:
                chunk_str = str(chunk)
            buffer += chunk_str

            while self.delimiter in buffer:
                part, buffer = buffer.split(self.delimiter, 1)
                stripped = part.strip()
                if stripped:
                    b = stripped.encode("utf-8", errors="surrogateescape")
                    if len(b) > self.max_bytes:
                        yield FrameResult(stripped[:1024], b, is_oversized=True, error="Oversized delimited frame")
                    else:
                        yield FrameResult(stripped, b)

        remainder = buffer.strip()
        if remainder:
            b = remainder.encode("utf-8", errors="surrogateescape")
            if len(b) > self.max_bytes:
                yield FrameResult(remainder[:1024], b, is_oversized=True, error="Oversized delimited frame")
            else:
                yield FrameResult(remainder, b)


class MultilineRegexFramer(BaseFramer):
    """
    Aggregates multiline logs (e.g. Java stack traces, EVTX multiline XML)
    using a regular expression that matches the start of each new record.
    """

    def __init__(
        self,
        start_pattern: str = r"^(?:\d{4}-\d{2}-\d{2}|<\d+>|\[\d{4})",
        flags: int = re.MULTILINE,
        max_bytes: int = 2 * 1024 * 1024,
    ):
        super().__init__(max_bytes)
        self.pattern = re.compile(start_pattern, flags)

    def frame(self, stream: Iterable[str | bytes]) -> Iterator[FrameResult]:
        current_lines: list[str] = []

        def _flush() -> FrameResult | None:
            if not current_lines:
                return None
            full_text = "\n".join(current_lines).strip()
            if not full_text:
                return None
            b = full_text.encode("utf-8", errors="surrogateescape")
            if len(b) > self.max_bytes:
                return FrameResult(
                    raw_text=full_text[:1024] + "...[TRUNCATED]",
                    raw_bytes=b,
                    is_oversized=True,
                    error=f"Multiline event exceeds max_bytes limit ({len(b)} > {self.max_bytes})",
                )
            return FrameResult(raw_text=full_text, raw_bytes=b)

        for chunk in stream:
            if isinstance(chunk, bytes):
                text = chunk.decode("utf-8", errors="surrogateescape")
            else:
                text = str(chunk)

            for line in text.splitlines():
                line_str = line.rstrip("\r\n")
                if not line_str.strip():
                    continue

                if self.pattern.search(line_str):
                    res = _flush()
                    if res:
                        yield res
                    current_lines = [line_str]
                else:
                    if current_lines:
                        current_lines.append(line_str)
                    else:
                        current_lines = [line_str]

        res = _flush()
        if res:
            yield res


class JSONStreamFramer(BaseFramer):
    """
    Extracts individual JSON objects from a stream with support for
    multiline formatted JSON, NDJSON, and JSON arrays.
    """

    def frame(self, stream: Iterable[str | bytes]) -> Iterator[FrameResult]:
        buffer = ""
        bracket_count = 0
        in_string = False
        escape = False

        for chunk in stream:
            if isinstance(chunk, bytes):
                text = chunk.decode("utf-8", errors="surrogateescape")
            else:
                text = str(chunk)

            for char in text:
                buffer += char

                if char == '"' and not escape:
                    in_string = not in_string
                elif char == '\\' and in_string:
                    escape = not escape
                    continue
                else:
                    escape = False

                if not in_string:
                    if char == '{':
                        bracket_count += 1
                    elif char == '}':
                        bracket_count -= 1
                        if bracket_count == 0:
                            candidate = buffer.strip()
                            if candidate.startswith('{') and candidate.endswith('}'):
                                b = candidate.encode("utf-8", errors="surrogateescape")
                                if len(b) > self.max_bytes:
                                    yield FrameResult(candidate[:1024], b, is_oversized=True, error="Oversized JSON frame")
                                else:
                                    yield FrameResult(candidate, b)
                            buffer = ""
                            bracket_count = 0


class SyslogOctetFramer(BaseFramer):
    """
    RFC 5425 / RFC 6587 Octet Counting Syslog Framer.
    Format: '<MSG-LEN> <SYSLOG-MSG>'
    """

    _OCTET_PREFIX = re.compile(r"^(\d+)\s+")

    def frame(self, stream: Iterable[str | bytes]) -> Iterator[FrameResult]:
        buffer = ""
        for chunk in stream:
            if isinstance(chunk, bytes):
                text = chunk.decode("utf-8", errors="surrogateescape")
            else:
                text = str(chunk)
            buffer += text

            while buffer:
                m = self._OCTET_PREFIX.match(buffer)
                if not m:
                    # Not octet counting, fall back to line
                    if "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        s = line.strip()
                        if s:
                            yield FrameResult(s)
                    else:
                        break
                else:
                    msg_len = int(m.group(1))
                    start_idx = m.end()
                    if len(buffer) - start_idx >= msg_len:
                        msg = buffer[start_idx : start_idx + msg_len].strip()
                        buffer = buffer[start_idx + msg_len :].lstrip()
                        if msg:
                            yield FrameResult(msg)
                    else:
                        break
