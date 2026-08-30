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

import re
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator


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
            else:
                text = str(item)

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

            # A stream that never produces the delimiter would otherwise grow
            # this buffer without limit. Cut it loose as one oversized frame so
            # a malformed or hostile source degrades instead of exhausting RAM.
            if len(buffer) > self.max_bytes:
                over = buffer
                buffer = ""
                yield FrameResult(
                    over[:1024] + "...[TRUNCATED]",
                    over.encode("utf-8", errors="surrogateescape"),
                    is_oversized=True,
                    error=f"No delimiter within max_bytes ({len(over)} > {self.max_bytes})",
                )
                continue

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
                    current_lines.append(line_str)
                    # Guard against a start pattern that never matches again:
                    # without this the record grows for the life of the stream.
                    if sum(len(x) for x in current_lines) > self.max_bytes:
                        res = _flush()
                        current_lines = []
                        if res:
                            yield res

        res = _flush()
        if res:
            yield res


class JSONStreamFramer(BaseFramer):
    """
    Extracts individual JSON objects from a stream, supporting multiline
    pretty-printed JSON, NDJSON, and concatenated objects.

    Brace depth is tracked outside of string literals so that braces inside
    values do not split a record.
    """

    def frame(self, stream: Iterable[str | bytes]) -> Iterator[FrameResult]:
        parts: list[str] = []
        size = 0
        depth = 0
        in_string = False
        escape = False

        for chunk in stream:
            if isinstance(chunk, bytes):
                text = chunk.decode("utf-8", errors="surrogateescape")
            else:
                text = str(chunk)

            for char in text:
                if depth > 0 or char == "{":
                    # Accumulate into a list and join once per record; appending
                    # to a str per character is quadratic on large payloads.
                    parts.append(char)
                    size += 1

                if escape:
                    escape = False
                elif in_string and char == "\\":
                    escape = True
                elif char == '"':
                    in_string = not in_string
                elif not in_string:
                    if char == "{":
                        depth += 1
                    elif char == "}":
                        depth -= 1
                        if depth <= 0:
                            candidate = "".join(parts).strip()
                            parts, size, depth = [], 0, 0
                            if candidate.startswith("{") and candidate.endswith("}"):
                                b = candidate.encode("utf-8", errors="surrogateescape")
                                if len(b) > self.max_bytes:
                                    yield FrameResult(
                                        candidate[:1024] + "...[TRUNCATED]",
                                        b,
                                        is_oversized=True,
                                        error="Oversized JSON frame",
                                    )
                                else:
                                    yield FrameResult(candidate, b)

                # An object that never closes must not consume unbounded memory.
                if size > self.max_bytes:
                    candidate = "".join(parts)
                    parts, size, depth, in_string, escape = [], 0, 0, False, False
                    yield FrameResult(
                        candidate[:1024] + "...[TRUNCATED]",
                        candidate.encode("utf-8", errors="surrogateescape"),
                        is_oversized=True,
                        error=f"Unterminated JSON object exceeded max_bytes ({self.max_bytes})",
                    )


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

            if len(buffer) > self.max_bytes:
                over = buffer
                buffer = ""
                yield FrameResult(
                    over[:1024] + "...[TRUNCATED]",
                    over.encode("utf-8", errors="surrogateescape"),
                    is_oversized=True,
                    error=f"Unframed syslog data exceeded max_bytes ({self.max_bytes})",
                )
                continue

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
