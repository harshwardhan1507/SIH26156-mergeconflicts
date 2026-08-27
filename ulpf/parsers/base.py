"""
BaseParser — abstract base class for all ULPF parser plugins.

New parsers must:
  1. Subclass BaseParser.
  2. Set class-level: name, version, log_format.
  3. Implement match(raw_line) -> bool.
  4. Implement extract(raw_line) -> dict.
  5. Decorate with @register_parser.

BaseParser provides shared helpers that handle:
  - Timestamp parsing (ISO8601 and common syslog variants)
  - IP address validation
  - Port and integer coercion
  - Float coercion
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address, AddressValueError
from typing import Any

from dateutil import parser as dateutil_parser


class ParseError(Exception):
    """Raised when a parser cannot parse a raw line."""


class BaseParser(ABC):
    # Subclasses MUST set these as class attributes
    name: str = ""
    version: str = "1.0.0"
    log_format: str = "unknown"

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    def match(self, raw_line: str) -> bool:
        """Return True if this parser should handle raw_line."""

    @abstractmethod
    def extract(self, raw_line: str) -> dict[str, Any]:
        """
        Parse raw_line into a flat dict of vendor-specific field names.
        Raise ParseError on unrecoverable parse failure.
        Returns at minimum: {'_raw': raw_line, '_log_format': self.log_format}
        """

    # ------------------------------------------------------------------
    # Shared helper methods (available to all subclasses)
    # ------------------------------------------------------------------

    def parse_timestamp(self, value: str | None) -> datetime | None:
        """Parse a timestamp string into a UTC-aware datetime. Returns None if unparseable."""
        if not value:
            return None
        value = value.strip()
        if not value:
            return None

        # Bare epoch timestamps (CEF `rt`, many JSON APIs) — dateutil cannot
        # parse these as calendar dates, so detect and convert explicitly.
        # Magnitude distinguishes seconds vs milliseconds vs microseconds:
        # ~1.7e9 = seconds, ~1.7e12 = milliseconds, ~1.7e15 = microseconds (as of 2026).
        if re.fullmatch(r'-?\d+', value):
            try:
                num = int(value)
                abs_num = abs(num)
                if abs_num >= 1e17:
                    return None  # implausible, don't guess
                elif abs_num >= 1e14:
                    dt = datetime.fromtimestamp(num / 1_000_000, tz=timezone.utc)
                elif abs_num >= 1e11:
                    dt = datetime.fromtimestamp(num / 1_000, tz=timezone.utc)
                elif abs_num >= 1e8:
                    dt = datetime.fromtimestamp(num, tz=timezone.utc)
                else:
                    dt = None
                if dt is not None:
                    return dt
            except (ValueError, OverflowError, OSError):
                pass  # fall through to dateutil for anything unexpected

        try:
            dt = dateutil_parser.parse(value)
            if dt.tzinfo is None:
                # Treat naive timestamps as UTC
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except (ValueError, OverflowError):
            return None

    def validate_ip(self, value: str | None) -> str | None:
        """Validate and return an IP address string, or None if invalid."""
        if not value:
            return None
        value = value.strip()
        try:
            IPv4Address(value)
            return value
        except AddressValueError:
            pass
        try:
            IPv6Address(value)
            return value
        except AddressValueError:
            return None

    def safe_int(self, value: Any) -> int | None:
        """Safely coerce value to int, returning None on failure."""
        if value is None:
            return None
        try:
            return int(str(value).strip())
        except (ValueError, TypeError):
            return None

    def safe_float(self, value: Any) -> float | None:
        """Safely coerce value to float, returning None on failure."""
        if value is None:
            return None
        try:
            return float(str(value).strip())
        except (ValueError, TypeError):
            return None

    def safe_port(self, value: Any) -> int | None:
        """Coerce to int and validate as a valid port (0-65535)."""
        port = self.safe_int(value)
        if port is None:
            return None
        return port if 0 <= port <= 65535 else None

    def strip_quotes(self, value: str | None) -> str | None:
        """Strip leading/trailing double or single quotes."""
        if value is None:
            return None
        value = value.strip()
        if len(value) >= 2 and value[0] in ('"', "'") and value[0] == value[-1]:
            return value[1:-1]
        return value

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r} version={self.version!r}>"
