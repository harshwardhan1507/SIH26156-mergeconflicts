"""
Scalable Segmented Raw Event Store.

High-throughput, append-oriented raw storage backend designed for multi-gigabyte
and high-volume enterprise ingestion.

Directory structure:
  <base_dir>/YYYY/MM/DD/<tenant_id>/segment-<seq:06d>.bin

Maintains an atomic SQLite index:
  event_id -> (segment_rel_path, offset, length, sha256, ingest_timestamp)

Features:
- Byte-exact original payload retention (non-UTF8 safe)
- SHA-256 computation over authentic bytes
- O(1) random retrieval by event_id (seeks directly to offset and reads exact length)
- Automatic segment rotation when file size reaches segment_max_bytes
- Thread-safe append locks & crash recovery across restarts
- Time and tenant partitioned
"""
from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ulpf.core.raw_store import RawStoreBase

logger = logging.getLogger("ulpf.core.segmented_raw_store")


@dataclass
class RawRecord:
    event_id: str
    tenant_id: str
    segment_path: str
    offset: int
    length: int
    sha256: str
    ingest_ts: str


class SegmentedRawStore(RawStoreBase):
    """
    Append-only segmented raw payload store with an embedded SQLite index.
    """

    def __init__(
        self,
        base_dir: str | Path = "output/raw_segments",
        segment_max_bytes: int = 32 * 1024 * 1024,  # 32MB default
        max_segment_size: int | None = None,
    ):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.segment_max_bytes = max_segment_size if max_segment_size is not None else segment_max_bytes

        self.db_path = self.base_dir / "index.sqlite3"
        self._lock = threading.Lock()
        self._active_segments: dict[str, tuple[Path, int]] = {}  # partition_key -> (path, current_size)

        self._init_db()

    def _init_db(self) -> None:
        """Initialize SQLite index table for fast O(1) segment lookups."""
        conn = sqlite3.connect(self.db_path)
        try:
            with conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS raw_index (
                        event_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        segment_path TEXT NOT NULL,
                        offset INTEGER NOT NULL,
                        length INTEGER NOT NULL,
                        sha256 TEXT NOT NULL,
                        ingest_ts TEXT NOT NULL
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_raw_tenant ON raw_index (tenant_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_raw_hash ON raw_index (sha256)")
        finally:
            conn.close()

    def _get_partition_dir(self, dt: datetime, tenant_id: str) -> Path:
        """Partition path: YYYY/MM/DD/tenant_id."""
        date_str = dt.strftime("%Y/%m/%d")
        safe_tenant = "".join(c for c in tenant_id if c.isalnum() or c in "_-") or "default"
        part_dir = self.base_dir / date_str / safe_tenant
        part_dir.mkdir(parents=True, exist_ok=True)
        return part_dir

    def _get_active_segment_file(self, dt: datetime, tenant_id: str) -> tuple[Path, int]:
        """Return the current appendable segment file and its existing size."""
        part_dir = self._get_partition_dir(dt, tenant_id)
        part_key = f"{dt.strftime('%Y%m%d')}:{tenant_id}"

        if part_key in self._active_segments:
            seg_path, cur_size = self._active_segments[part_key]
            if cur_size < self.segment_max_bytes:
                return seg_path, cur_size

        # Find highest numbered segment
        existing = sorted(part_dir.glob("segment-*.bin"))
        if existing:
            latest = existing[-1]
            size = latest.stat().st_size
            if size < self.segment_max_bytes:
                self._active_segments[part_key] = (latest, size)
                return latest, size
            seq = int(latest.stem.split("-")[1]) + 1
        else:
            seq = 1

        new_segment = part_dir / f"segment-{seq:06d}.bin"
        self._active_segments[part_key] = (new_segment, 0)
        return new_segment, 0

    def put(
        self,
        event_id: str,
        raw_payload: str | bytes,
        tenant_id: str = "default",
        ingest_ts: datetime | None = None,
    ) -> str:
        """
        Append raw_payload bytes to active segment, record index, and return SHA-256.
        """
        if isinstance(raw_payload, str):
            raw_bytes = raw_payload.encode("utf-8", errors="surrogateescape")
        else:
            raw_bytes = bytes(raw_payload)

        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        if ingest_ts is None:
            ingest_ts = datetime.now(timezone.utc)

        length = len(raw_bytes)

        with self._lock:
            seg_path, offset = self._get_active_segment_file(ingest_ts, tenant_id)

            # Append bytes
            with open(seg_path, "ab") as f:
                f.write(raw_bytes)

            new_size = offset + length
            part_key = f"{ingest_ts.strftime('%Y%m%d')}:{tenant_id}"
            self._active_segments[part_key] = (seg_path, new_size)

            # Relative path from base_dir
            rel_path = str(seg_path.relative_to(self.base_dir)).replace("\\", "/")

            # Record in SQLite index
            conn = sqlite3.connect(self.db_path)
            try:
                with conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO raw_index 
                        (event_id, tenant_id, segment_path, offset, length, sha256, ingest_ts)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (event_id, tenant_id, rel_path, offset, length, sha256_hash, ingest_ts.isoformat()))
            finally:
                conn.close()

        return sha256_hash

    def get_bytes(self, event_id: str, tenant_id: str | None = None) -> bytes | None:
        """Retrieve exact byte-sequence for event_id by direct random seek."""
        query = "SELECT segment_path, offset, length FROM raw_index WHERE event_id = ?"
        params: list[Any] = [event_id]
        if tenant_id:
            query += " AND tenant_id = ?"
            params.append(tenant_id)

        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(query, params)
            row = cursor.fetchone()
        finally:
            conn.close()

        if not row:
            return None

        rel_path, offset, length = row
        seg_file = self.base_dir / rel_path
        if not seg_file.exists():
            return None

        with open(seg_file, "rb") as f:
            f.seek(offset)
            return f.read(length)

    def get(self, event_id: str, tenant_id: str | None = None) -> str | None:
        """Retrieve decoded raw payload string, or None if not found."""
        raw_b = self.get_bytes(event_id, tenant_id=tenant_id)
        if raw_b is None:
            return None
        return raw_b.decode("utf-8", errors="surrogateescape")

    def get_record(self, event_id: str, tenant_id: str | None = None) -> RawRecord | None:
        """Fetch index metadata record for event_id."""
        query = "SELECT event_id, tenant_id, segment_path, offset, length, sha256, ingest_ts FROM raw_index WHERE event_id = ?"
        params: list[Any] = [event_id]
        if tenant_id:
            query += " AND tenant_id = ?"
            params.append(tenant_id)

        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(query, params)
            row = cursor.fetchone()
        finally:
            conn.close()

        if not row:
            return None
        return RawRecord(*row)

    def close(self) -> None:
        """Flush and release any active file handles."""
        pass

    def get_metadata(self, event_id: str) -> dict[str, Any] | None:
        """Get storage coordinates and hash for event_id."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT tenant_id, segment_path, offset, length, sha256, ingest_ts FROM raw_index WHERE event_id = ?", (event_id,))
            row = cursor.fetchone()
        finally:
            conn.close()

        if not row:
            return None

        return {
            "event_id": event_id,
            "tenant_id": row[0],
            "segment_path": row[1],
            "offset": row[2],
            "length": row[3],
            "sha256": row[4],
            "ingest_timestamp": row[5],
        }
