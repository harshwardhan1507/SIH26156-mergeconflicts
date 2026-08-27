"""
Raw Event Store.

Persists the untouched raw payload keyed by event_id (UUID).
The FileRawStore writes one file per event under a configurable base directory.
The abstract RawStoreBase allows future plug-in of S3/object-store backends.
"""
from __future__ import annotations

import hashlib
import uuid
from abc import ABC, abstractmethod
from pathlib import Path


class InvalidEventIdError(ValueError):
    """Raised when an event_id is not a valid UUID (blocks path traversal)."""


class RawStoreBase(ABC):
    @abstractmethod
    def put(self, event_id: str, raw_payload: str | bytes) -> str:
        """Persist raw_payload keyed by event_id. Returns sha256 hex of authentic payload bytes."""

    @abstractmethod
    def get(self, event_id: str) -> str | None:
        """Retrieve the raw payload text for event_id. Returns None if not found."""

    @abstractmethod
    def get_bytes(self, event_id: str) -> bytes | None:
        """Retrieve the exact raw bytes for event_id. Returns None if not found."""


class FileRawStore(RawStoreBase):
    """
    Stores each raw event as an exact binary file:
      <base_dir>/<aa>/<bb>/<event_id>.raw
    The first two hex-nibble directories shard the namespace to avoid
    huge flat directories.
    """

    def __init__(self, base_dir: str | Path):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _validate_event_id(self, event_id: str) -> str:
        """
        Normalize and validate event_id as a UUID.
        Rejects anything else — including path-traversal payloads like
        '../../../etc/passwd' — before it ever reaches the filesystem.
        """
        try:
            return str(uuid.UUID(str(event_id)))
        except (ValueError, AttributeError, TypeError) as exc:
            raise InvalidEventIdError(f'event_id is not a valid UUID: {event_id!r}') from exc

    def _path(self, event_id: str) -> Path:
        # event_id is validated as a UUID first, so it is safe to interpolate.
        safe_id = self._validate_event_id(event_id)
        # Shard by first 4 hex chars of the UUID
        shard = safe_id.replace('-', '')[:4]
        return self.base_dir / shard[:2] / shard[2:4] / f'{safe_id}.raw'

    def put(self, event_id: str, raw_payload: str | bytes) -> str:
        """Write raw_payload to disk and return its sha256 hex digest over authentic bytes."""
        if isinstance(raw_payload, bytes):
            raw_bytes = raw_payload
        else:
            raw_bytes = str(raw_payload).encode('utf-8', errors='surrogateescape')
        digest = hashlib.sha256(raw_bytes).hexdigest()
        dest = self._path(event_id)  # raises InvalidEventIdError on bad input
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw_bytes)
        return digest

    def get(self, event_id: str) -> str | None:
        """Return the raw payload string, or None if not found or event_id is invalid."""
        raw_b = self.get_bytes(event_id)
        if raw_b is None:
            return None
        return raw_b.decode('utf-8', errors='surrogateescape')

    def get_bytes(self, event_id: str) -> bytes | None:
        """Return the exact raw payload bytes, or None if not found or event_id is invalid."""
        try:
            path = self._path(event_id)
        except InvalidEventIdError:
            return None
        if not path.exists():
            return None
        return path.read_bytes()
