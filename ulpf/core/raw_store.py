"""
Raw Event Store.

Persists the untouched raw payload keyed by event_id (UUID).
The FileRawStore writes one file per event under a configurable base directory.
The abstract RawStoreBase allows future plug-in of S3/object-store backends.
"""
from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from pathlib import Path


class RawStoreBase(ABC):
    @abstractmethod
    def put(self, event_id: str, raw_payload: str) -> str:
        """Persist raw_payload keyed by event_id. Returns sha256 hex of payload."""

    @abstractmethod
    def get(self, event_id: str) -> str | None:
        """Retrieve the raw payload for event_id. Returns None if not found."""


class FileRawStore(RawStoreBase):
    """
    Stores each raw event as a UTF-8 text file:
      <base_dir>/<aa>/<bb>/<event_id>.raw
    The first two hex-nibble directories shard the namespace to avoid
    huge flat directories.
    """

    def __init__(self, base_dir: str | Path):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, event_id: str) -> Path:
        # Shard by first 4 chars of the UUID
        shard = event_id.replace('-', '')[:4]
        return self.base_dir / shard[:2] / shard[2:4] / f'{event_id}.raw'

    def put(self, event_id: str, raw_payload: str) -> str:
        """Write raw_payload to disk and return its sha256 hex digest."""
        raw_bytes = raw_payload.encode('utf-8', errors='surrogateescape')
        digest = hashlib.sha256(raw_bytes).hexdigest()
        dest = self._path(event_id)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw_bytes)
        return digest

    def get(self, event_id: str) -> str | None:
        """Return the raw payload string, or None if not found."""
        path = self._path(event_id)
        if not path.exists():
            return None
        return path.read_bytes().decode('utf-8', errors='surrogateescape')
