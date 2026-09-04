"""
Scalable Segmented Raw Event Store.

High-throughput, append-oriented raw storage for multi-gigabyte ingestion.

Directory structure::

    <base_dir>/YYYY/MM/DD/<tenant_id>/segment-<seq:06d>.bin

An embedded SQLite index maps ``event_id -> (segment, offset, length, sha256)``,
giving O(1) retrieval: seek to the offset and read exactly ``length`` bytes.

Concurrency contract
--------------------
The write offset is taken from the file handle itself under an exclusive OS
file lock, never from a cached size. That is what makes the recorded offset
correct when several processes (``ulpf ingest --workers N``) append to the same
partition — a cached size is stale the moment another writer appends, and an
``O_APPEND`` write then lands somewhere other than where the index says it did.
"""
from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

from ulpf.core.raw_store import RawStoreBase

logger = logging.getLogger(__name__)

try:  # POSIX
    import fcntl

    _HAVE_FCNTL = True
except ImportError:  # Windows
    fcntl = None  # type: ignore[assignment]
    _HAVE_FCNTL = False

try:  # Windows
    import msvcrt

    _HAVE_MSVCRT = True
except ImportError:
    msvcrt = None  # type: ignore[assignment]
    _HAVE_MSVCRT = False


@dataclass(slots=True)
class RawRecord:
    """Index metadata locating one payload inside a segment."""

    event_id: str
    tenant_id: str
    segment_path: str
    offset: int
    length: int
    sha256: str
    ingest_ts: str


def _lock_exclusive(fh: BinaryIO) -> None:
    """Take an exclusive advisory lock on an open file, blocking until granted."""
    if _HAVE_FCNTL:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
    elif _HAVE_MSVCRT:
        cur = fh.tell()
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)  # type: ignore[attr-defined]
        fh.seek(cur)


def _unlock(fh: BinaryIO) -> None:
    """Release the advisory lock taken by :func:`_lock_exclusive`."""
    if _HAVE_FCNTL:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    elif _HAVE_MSVCRT:
        try:
            cur = fh.tell()
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]
            fh.seek(cur)
        except OSError:
            pass


class SegmentedRawStore(RawStoreBase):
    """Append-only segmented raw payload store with an embedded SQLite index."""

    def __init__(
        self,
        base_dir: str | Path = "output/raw_segments",
        segment_max_bytes: int = 32 * 1024 * 1024,  # 32MB default
        max_segment_size: int | None = None,
    ):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.segment_max_bytes = (
            max_segment_size if max_segment_size is not None else segment_max_bytes
        )

        self.db_path = self.base_dir / "index.sqlite3"
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    # -- index -----------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        """
        Return this instance's long-lived SQLite connection.

        Reconnecting per event dominated the write path; WAL mode lets readers
        proceed while the append transaction commits.
        """
        if self._conn is None:
            conn = sqlite3.connect(str(self.db_path), check_same_thread=False, timeout=30.0)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._conn = conn
        return self._conn

    def _init_db(self) -> None:
        """Create the index table and its lookup indexes if absent."""
        conn = self._connect()
        with self._lock, conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS raw_index (
                    event_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    segment_path TEXT NOT NULL,
                    offset INTEGER NOT NULL,
                    length INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    ingest_ts TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_raw_tenant ON raw_index (tenant_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_raw_hash ON raw_index (sha256)")

    # -- segment selection -----------------------------------------------

    @staticmethod
    def _safe_tenant(tenant_id: str) -> str:
        """Reduce a tenant id to a filesystem-safe directory component."""
        return "".join(c for c in tenant_id if c.isalnum() or c in "_-") or "default"

    def _partition_dir(self, dt: datetime, tenant_id: str) -> Path:
        """Resolve (and create) the ``YYYY/MM/DD/<tenant>`` partition directory."""
        part_dir = self.base_dir / dt.strftime("%Y/%m/%d") / self._safe_tenant(tenant_id)
        part_dir.mkdir(parents=True, exist_ok=True)
        return part_dir

    def _segment_for_append(self, part_dir: Path) -> Path:
        """
        Pick the segment to append to: the highest-numbered one still under the
        rotation threshold, otherwise the next sequence number.
        """
        existing = sorted(part_dir.glob("segment-*.bin"))
        if existing:
            latest = existing[-1]
            if latest.stat().st_size < self.segment_max_bytes:
                return latest
            try:
                seq = int(latest.stem.split("-")[1]) + 1
            except (IndexError, ValueError):
                seq = len(existing) + 1
        else:
            seq = 1
        return part_dir / f"segment-{seq:06d}.bin"

    # -- write path ------------------------------------------------------

    def put(
        self,
        event_id: str,
        raw_payload: str | bytes,
        tenant_id: str = "default",
        ingest_ts: datetime | None = None,
    ) -> str:
        """Append the payload to the active segment, index it, and return its SHA-256."""
        if isinstance(raw_payload, str):
            raw_bytes = raw_payload.encode("utf-8", errors="surrogateescape")
        else:
            raw_bytes = bytes(raw_payload)

        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        if ingest_ts is None:
            ingest_ts = datetime.now(UTC)
        length = len(raw_bytes)

        part_dir = self._partition_dir(ingest_ts, tenant_id)

        with self._lock:
            seg_path = self._segment_for_append(part_dir)
            # Open r+b (creating if needed) rather than 'ab': O_APPEND ignores
            # the seek position, so the only way to know where the bytes landed
            # is to seek to the end ourselves while holding the lock.
            with open(seg_path, "a+b") as fh:
                _lock_exclusive(fh)
                try:
                    fh.seek(0, os.SEEK_END)
                    offset = fh.tell()
                    fh.write(raw_bytes)
                    fh.flush()
                    os.fsync(fh.fileno())
                finally:
                    _unlock(fh)

            rel_path = str(seg_path.relative_to(self.base_dir)).replace("\\", "/")
            conn = self._connect()
            with conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO raw_index
                    (event_id, tenant_id, segment_path, offset, length, sha256, ingest_ts)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        tenant_id,
                        rel_path,
                        offset,
                        length,
                        sha256_hash,
                        ingest_ts.isoformat(),
                    ),
                )

        return sha256_hash

    # -- read path -------------------------------------------------------

    def _lookup(self, sql: str, params: list[Any]) -> tuple | None:
        """Run a single-row index query."""
        conn = self._connect()
        with self._lock:
            return conn.execute(sql, params).fetchone()

    def get_bytes(self, event_id: str, tenant_id: str | None = None) -> bytes | None:
        """Retrieve the exact byte sequence for event_id via direct random seek."""
        query = "SELECT segment_path, offset, length FROM raw_index WHERE event_id = ?"
        params: list[Any] = [event_id]
        if tenant_id:
            query += " AND tenant_id = ?"
            params.append(tenant_id)

        row = self._lookup(query, params)
        if not row:
            return None

        rel_path, offset, length = row
        seg_file = self.base_dir / rel_path
        if not seg_file.exists():
            logger.warning("Segment %s referenced by index is missing", rel_path)
            return None

        with open(seg_file, "rb") as fh:
            fh.seek(offset)
            return fh.read(length)

    def get(self, event_id: str, tenant_id: str | None = None) -> str | None:
        """Retrieve the decoded raw payload, or None if not found."""
        raw_b = self.get_bytes(event_id, tenant_id=tenant_id)
        if raw_b is None:
            return None
        return raw_b.decode("utf-8", errors="surrogateescape")

    def get_record(self, event_id: str, tenant_id: str | None = None) -> RawRecord | None:
        """Fetch the full index metadata record for event_id."""
        query = (
            "SELECT event_id, tenant_id, segment_path, offset, length, sha256, ingest_ts "
            "FROM raw_index WHERE event_id = ?"
        )
        params: list[Any] = [event_id]
        if tenant_id:
            query += " AND tenant_id = ?"
            params.append(tenant_id)

        row = self._lookup(query, params)
        return RawRecord(*row) if row else None

    def get_metadata(self, event_id: str) -> dict[str, Any] | None:
        """Storage coordinates and hash for event_id, as a plain dict."""
        record = self.get_record(event_id)
        if record is None:
            return None
        return {
            "event_id": record.event_id,
            "tenant_id": record.tenant_id,
            "segment_path": record.segment_path,
            "offset": record.offset,
            "length": record.length,
            "sha256": record.sha256,
            "ingest_timestamp": record.ingest_ts,
        }

    def close(self) -> None:
        """Close the SQLite index connection."""
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None
