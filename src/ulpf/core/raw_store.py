"""
Raw Event Store.

Persists the untouched raw payload keyed by event_id (UUID) so that every
normalized event can be traced back to the exact bytes that produced it.

``FileRawStore`` writes one file per event, which keeps forensic retrieval
trivial and is the right default for moderate volumes. For high-throughput
sites see :mod:`ulpf.core.segmented_raw_store`, which packs payloads into
rotating segments behind a SQLite offset index.
"""
from __future__ import annotations

import hashlib
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path


class InvalidEventIdError(ValueError):
    """Raised when an event_id is not a valid UUID (blocks path traversal)."""


class RawStoreBase(ABC):
    """
    Backend-agnostic raw payload store.

    Every backend accepts the same call signature — including ``tenant_id`` and
    ``ingest_ts``, which partitioned backends use and flat ones ignore — so the
    pipeline can treat all stores uniformly instead of probing for support.
    """

    @abstractmethod
    def put(
        self,
        event_id: str,
        raw_payload: str | bytes,
        tenant_id: str = "default",
        ingest_ts: datetime | None = None,
    ) -> str:
        """Persist raw_payload keyed by event_id. Returns sha256 hex of the authentic bytes."""

    @abstractmethod
    def get(self, event_id: str) -> str | None:
        """Retrieve the raw payload text for event_id. Returns None if not found."""

    @abstractmethod
    def get_bytes(self, event_id: str) -> bytes | None:
        """Retrieve the exact raw bytes for event_id. Returns None if not found."""

    def close(self) -> None:
        """Release any held resources. Backends that hold none may ignore this."""


class FileRawStore(RawStoreBase):
    """
    Stores each raw event as an exact binary file::

        <base_dir>/<aa>/<bb>/<event_id>.raw

    The two hex-nibble directories shard the namespace so no single directory
    accumulates millions of entries.
    """

    def __init__(self, base_dir: str | Path):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _validate_event_id(self, event_id: str) -> str:
        """
        Normalize and validate event_id as a UUID.

        Rejects anything else — including path-traversal payloads such as
        ``../../../etc/passwd`` — before it can reach the filesystem.
        """
        try:
            return str(uuid.UUID(str(event_id)))
        except (ValueError, AttributeError, TypeError) as exc:
            raise InvalidEventIdError(f"event_id is not a valid UUID: {event_id!r}") from exc

    def _path(self, event_id: str) -> Path:
        # event_id is validated as a UUID first, so it is safe to interpolate.
        safe_id = self._validate_event_id(event_id)
        shard = safe_id.replace("-", "")[:4]
        return self.base_dir / shard[:2] / shard[2:4] / f"{safe_id}.raw"

    def put(
        self,
        event_id: str,
        raw_payload: str | bytes,
        tenant_id: str = "default",
        ingest_ts: datetime | None = None,
    ) -> str:
        """
        Write raw_payload to disk and return its sha256 hex digest.

        ``tenant_id`` and ``ingest_ts`` are accepted for interface parity with
        partitioned backends; this store keys purely on the event UUID.
        """
        if isinstance(raw_payload, bytes):
            raw_bytes = raw_payload
        else:
            raw_bytes = str(raw_payload).encode("utf-8", errors="surrogateescape")
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
        return raw_b.decode("utf-8", errors="surrogateescape")

    def get_bytes(self, event_id: str) -> bytes | None:
        """Return the exact raw payload bytes, or None if not found or event_id is invalid."""
        try:
            path = self._path(event_id)
        except InvalidEventIdError:
            return None
        if not path.exists():
            return None
        return path.read_bytes()


class NullRawStore(RawStoreBase):
    """
    Discards payloads, returning only their hash.

    Used by the benchmark harness to measure pipeline throughput without
    storage I/O in the way. It implements the full :class:`RawStoreBase`
    signature so that a change to that interface fails loudly here rather than
    silently quarantining every event.
    """

    def put(
        self,
        event_id: str,
        raw_payload: str | bytes,
        tenant_id: str = "default",
        ingest_ts: datetime | None = None,
    ) -> str:
        if isinstance(raw_payload, bytes):
            raw_bytes = raw_payload
        else:
            raw_bytes = str(raw_payload).encode("utf-8", errors="surrogateescape")
        return hashlib.sha256(raw_bytes).hexdigest()

    def get(self, event_id: str) -> str | None:
        return None

    def get_bytes(self, event_id: str) -> bytes | None:
        return None
