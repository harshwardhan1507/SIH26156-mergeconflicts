"""
SQLite Indexing Engine for the ULPF Dashboard.

Provides fast filtering, pagination, and aggregation over normalized UES events
without linearly scanning the NDJSON file on every request.

The NDJSON file remains the single source of truth. This index is disposable
and is rebuilt from it, so losing the database costs nothing but a resync.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import sqlite3
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ulpf.core.registry import get_all_parsers

logger = logging.getLogger(__name__)

#: Hard ceiling on rows returned by one query page.
MAX_PAGE_SIZE = 1000

#: Ceiling on rows streamed by a single export, so an export cannot pin an
#: unbounded amount of memory or run indefinitely.
MAX_EXPORT_ROWS = 100_000

#: Batch size used when streaming an export out of SQLite.
_EXPORT_BATCH = 1000

CREATE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS events_index (
    event_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    ingest_timestamp TEXT NOT NULL,
    source_event_timestamp TEXT,
    vendor TEXT,
    product TEXT,
    device_hostname TEXT,
    category TEXT NOT NULL,
    action TEXT,
    outcome TEXT,
    severity_numeric REAL NOT NULL,
    severity_original TEXT,
    src_ip TEXT,
    src_port INTEGER,
    dst_ip TEXT,
    dst_port INTEGER,
    protocol TEXT,
    bytes_in INTEGER,
    bytes_out INTEGER,
    username TEXT,
    rule_name TEXT,
    parser_name TEXT NOT NULL,
    raw_format TEXT NOT NULL,
    raw_hash TEXT NOT NULL,
    full_event_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events_index(ingest_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_tenant ON events_index(tenant_id);
CREATE INDEX IF NOT EXISTS idx_events_vendor ON events_index(vendor);
CREATE INDEX IF NOT EXISTS idx_events_category ON events_index(category);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events_index(severity_numeric);
CREATE INDEX IF NOT EXISTS idx_events_outcome ON events_index(outcome);
CREATE INDEX IF NOT EXISTS idx_events_parser ON events_index(parser_name);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events_index(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON events_index(dst_ip);

CREATE TABLE IF NOT EXISTS index_meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""

#: Sort keys the API accepts, mapped to the SQL they expand to. Sorting is the
#: one place a column name reaches SQL as text rather than a bound parameter,
#: so it is resolved strictly through this allowlist.
_SORT_COLUMNS: dict[str, str] = {
    "ingest_timestamp": "COALESCE(source_event_timestamp, ingest_timestamp)",
    "source_event_timestamp": "COALESCE(source_event_timestamp, ingest_timestamp)",
    "severity": "severity_numeric",
    "severity_numeric": "severity_numeric",
    "vendor": "vendor",
    "category": "category",
    "action": "action",
    "outcome": "outcome",
    "src_ip": "src_ip",
    "parser_name": "parser_name",
}

_SEARCH_COLUMNS = (
    "event_id", "vendor", "product", "device_hostname", "src_ip", "dst_ip",
    "CAST(src_port AS TEXT)", "CAST(dst_port AS TEXT)", "username",
    "rule_name", "action", "category", "parser_name",
)


def _escape_like(term: str) -> str:
    """
    Escape LIKE wildcards in a user search term.

    Values are already bound as parameters, so this is not about injection: an
    unescaped ``%`` simply makes the search match everything, which reads as a
    broken filter.
    """
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class EventIndexer:
    """Manages the SQLite index database backing the dashboard's queries."""

    def __init__(self, output_dir: str | Path, db_path: str | Path | None = None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.ndjson_path = self.output_dir / "events.ndjson"
        self.dead_letter_path = self.output_dir / "dead_letter.ndjson"

        if db_path is None:
            self.db_path: str | Path = self.output_dir / "dashboard_index.db"
        else:
            self.db_path = ":memory:" if str(db_path) == ":memory:" else Path(db_path)

        self._conn: sqlite3.Connection | None = None
        self._lock = threading.RLock()
        self._init_db()

    # -- connection ------------------------------------------------------

    def _connection(self) -> sqlite3.Connection:
        """
        Return this indexer's connection, opening it on first use.

        One connection is held for the indexer's lifetime rather than one per
        query: SSE clients poll stats on a timer, and a connect/close cycle per
        poll dominated the cost. WAL keeps those readers from blocking on the
        incremental sync's commit.

        ``row_factory`` is set on every path. It was previously applied only to
        the file-backed connection, so the ``:memory:`` backend returned bare
        tuples and every ``row["column"]`` access raised TypeError.
        """
        if self._conn is None:
            target = ":memory:" if self.db_path == ":memory:" else str(self.db_path)
            conn = sqlite3.connect(target, check_same_thread=False, timeout=30.0)
            conn.row_factory = sqlite3.Row
            if target != ":memory:":
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
            self._conn = conn
        return self._conn

    def close(self) -> None:
        """Close the SQLite connection. Idempotent."""
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def _init_db(self) -> None:
        """Create the schema, migrating older databases that predate tenant_id."""
        conn = self._connection()
        with self._lock, conn:
            cur = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='events_index'"
            )
            if cur.fetchone() is not None:
                cols = {r["name"] for r in conn.execute("PRAGMA table_info(events_index)")}
                if "tenant_id" not in cols:
                    conn.execute(
                        "ALTER TABLE events_index "
                        "ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'"
                    )
            conn.executescript(CREATE_TABLES_SQL)

    # -- ingest ----------------------------------------------------------

    def sync_from_ndjson(self) -> int:
        """
        Incrementally index records appended to events.ndjson since the last sync.

        Returns the number of newly indexed records.
        """
        if not self.ndjson_path.exists():
            return 0

        with self._lock:
            conn = self._connection()
            row = conn.execute(
                "SELECT value FROM index_meta WHERE key = 'last_byte_offset'"
            ).fetchone()
            last_offset = int(row["value"]) if row and row["value"] else 0

            file_size = self.ndjson_path.stat().st_size
            if file_size == last_offset:
                return 0
            if file_size < last_offset:
                # The file was truncated or rotated; the offset no longer refers
                # to anything meaningful, so reindex from the start.
                logger.info("events.ndjson shrank — rebuilding index from offset 0")
                conn.execute("DELETE FROM events_index")
                last_offset = 0

            new_records: list[tuple] = []
            # Byte mode: seek offsets and file sizes are both byte counts. Text
            # mode returns an opaque cookie from tell(), which is only
            # coincidentally a byte offset and not safe to compare with st_size.
            with open(self.ndjson_path, "rb") as fh:
                fh.seek(last_offset)
                for raw in fh:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        logger.warning("Skipping malformed JSON line in %s", self.ndjson_path)
                        continue
                    record = self._extract_index_record(event, line)
                    if record:
                        new_records.append(record)
                current_offset = fh.tell()

            with conn:
                if new_records:
                    conn.executemany(
                        """
                        INSERT OR REPLACE INTO events_index (
                            event_id, tenant_id, ingest_timestamp, source_event_timestamp,
                            vendor, product, device_hostname, category, action,
                            outcome, severity_numeric, severity_original, src_ip,
                            src_port, dst_ip, dst_port, protocol, bytes_in,
                            bytes_out, username, rule_name, parser_name, raw_format,
                            raw_hash, full_event_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        new_records,
                    )
                # The offset advances even when a batch yielded no valid records,
                # so malformed lines are skipped once rather than re-read forever.
                conn.execute(
                    "INSERT OR REPLACE INTO index_meta (key, value) VALUES ('last_byte_offset', ?)",
                    (str(current_offset),),
                )
                conn.execute(
                    "INSERT OR REPLACE INTO index_meta (key, value) VALUES ('last_sync_timestamp', ?)",
                    (datetime.now(tz=UTC).isoformat(),),
                )

            return len(new_records)

    def rebuild_index(self) -> int:
        """Drop and rebuild the entire index from the NDJSON source of truth."""
        with self._lock:
            conn = self._connection()
            with conn:
                conn.execute("DELETE FROM events_index")
                conn.execute("DELETE FROM index_meta")
        return self.sync_from_ndjson()

    def _extract_index_record(self, event: dict[str, Any], full_json: str) -> tuple | None:
        """Project a UES event onto the indexed column tuple."""
        event_id = event.get("event_id")
        if not event_id:
            return None

        raw = event.get("raw") or {}
        source = event.get("source") or {}
        ev = event.get("event") or {}
        net = event.get("network") or {}
        ident = event.get("identity") or {}
        rule = event.get("rule") or {}
        lineage = event.get("lineage") or {}

        severity = ev.get("severity_numeric")
        try:
            severity = float(severity) if severity is not None else 5.0
        except (TypeError, ValueError):
            severity = 5.0

        return (
            event_id,
            event.get("tenant_id") or "default",
            event.get("ingest_timestamp") or datetime.now(tz=UTC).isoformat(),
            event.get("source_event_timestamp"),
            source.get("vendor"),
            source.get("product"),
            source.get("device_hostname"),
            ev.get("category") or "unknown",
            ev.get("action"),
            ev.get("outcome"),
            severity,
            # Preserved as NULL rather than "" so absent and empty stay distinct.
            ev.get("severity_original"),
            net.get("src_ip"),
            net.get("src_port"),
            net.get("dst_ip"),
            net.get("dst_port"),
            net.get("protocol"),
            net.get("bytes_in"),
            net.get("bytes_out"),
            ident.get("username"),
            rule.get("rule_name"),
            lineage.get("parser_name") or "unknown",
            raw.get("raw_format") or "unknown",
            raw.get("raw_hash") or "",
            full_json,
        )

    # -- filtering -------------------------------------------------------

    @staticmethod
    def _build_filters(
        search: str | None = None,
        vendor: str | None = None,
        category: str | None = None,
        severity_min: float | None = None,
        severity_max: float | None = None,
        outcome: str | None = None,
        action: str | None = None,
        parser_name: str | None = None,
        tenant_id: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> tuple[str, list[Any]]:
        """Compose a parameterized WHERE clause from the supported filters."""
        clauses: list[str] = []
        params: list[Any] = []

        if tenant_id:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)
        if search and search.strip():
            pattern = f"%{_escape_like(search.strip())}%"
            ors = " OR ".join(f"{col} LIKE ? ESCAPE '\\'" for col in _SEARCH_COLUMNS)
            clauses.append(f"({ors})")
            params.extend([pattern] * len(_SEARCH_COLUMNS))
        for column, value in (
            ("vendor", vendor), ("category", category),
            ("outcome", outcome), ("action", action), ("parser_name", parser_name),
        ):
            if value:
                clauses.append(f"{column} = ?")
                params.append(value)
        if severity_min is not None:
            clauses.append("severity_numeric >= ?")
            params.append(severity_min)
        if severity_max is not None:
            clauses.append("severity_numeric <= ?")
            params.append(severity_max)
        if start_time:
            clauses.append("ingest_timestamp >= ?")
            params.append(start_time)
        if end_time:
            clauses.append("ingest_timestamp <= ?")
            params.append(end_time)

        return ("WHERE " + " AND ".join(clauses)) if clauses else "", params

    def query_events(
        self,
        page: int = 1,
        page_size: int = 50,
        search: str | None = None,
        vendor: str | None = None,
        category: str | None = None,
        severity_min: float | None = None,
        severity_max: float | None = None,
        outcome: str | None = None,
        action: str | None = None,
        parser_name: str | None = None,
        tenant_id: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        sort_by: str = "ingest_timestamp",
        sort_order: str = "desc",
    ) -> dict[str, Any]:
        """Execute a filtered, sorted, paginated event query."""
        self.sync_from_ndjson()

        sort_column = _SORT_COLUMNS.get(sort_by, "ingest_timestamp")
        sort_direction = "DESC" if str(sort_order).lower() == "desc" else "ASC"
        where_sql, params = self._build_filters(
            search, vendor, category, severity_min, severity_max,
            outcome, action, parser_name, tenant_id, start_time, end_time,
        )

        page = max(1, page)
        page_size = max(1, min(MAX_PAGE_SIZE, page_size))
        offset = (page - 1) * page_size

        with self._lock:
            conn = self._connection()
            total_count = conn.execute(
                f"SELECT COUNT(*) FROM events_index {where_sql}", params
            ).fetchone()[0]
            rows = conn.execute(
                f"SELECT full_event_json FROM events_index {where_sql} "
                f"ORDER BY {sort_column} {sort_direction} LIMIT ? OFFSET ?",
                [*params, page_size, offset],
            ).fetchall()

        return {
            "total": total_count,
            "page": page,
            "page_size": page_size,
            "total_pages": (total_count + page_size - 1) // page_size if total_count else 1,
            "events": [json.loads(row["full_event_json"]) for row in rows],
        }

    def get_event_by_id(self, event_id: str) -> dict[str, Any] | None:
        """Fetch a single indexed event by id."""
        self.sync_from_ndjson()
        with self._lock:
            row = self._connection().execute(
                "SELECT full_event_json FROM events_index WHERE event_id = ?", (event_id,)
            ).fetchone()
        return json.loads(row["full_event_json"]) if row else None

    # -- aggregation -----------------------------------------------------

    def get_stats(self, tenant_id: str | None = None) -> dict[str, Any]:
        """
        Aggregate statistics for the dashboard's metric cards and charts.

        Every aggregate honours ``tenant_id``. Several previously ignored it,
        so a tenant-scoped view silently mixed in other tenants' outcome,
        action, and velocity counts.
        """
        self.sync_from_ndjson()
        where = " WHERE tenant_id = ?" if tenant_id else ""
        args: list[Any] = [tenant_id] if tenant_id else []

        def _and(extra: str) -> str:
            return f"{where} AND {extra}" if where else f" WHERE {extra}"

        with self._lock:
            conn = self._connection()
            total_events = conn.execute(
                f"SELECT COUNT(*) FROM events_index{where}", args
            ).fetchone()[0]

            by_category = {
                r["category"]: r["count"]
                for r in conn.execute(
                    f"SELECT category, COUNT(*) AS count FROM events_index{where} "
                    "GROUP BY category ORDER BY count DESC", args
                )
            }
            vendor_rows = conn.execute(
                f"SELECT COALESCE(vendor, 'Unknown') AS vendor, COUNT(*) AS count "
                f"FROM events_index{where} GROUP BY vendor ORDER BY count DESC", args
            ).fetchall()
            by_outcome = {
                r["outcome"]: r["count"]
                for r in conn.execute(
                    f"SELECT COALESCE(outcome, 'unknown') AS outcome, COUNT(*) AS count "
                    f"FROM events_index{where} GROUP BY outcome", args
                )
            }
            by_action = {
                r["action"]: r["count"]
                for r in conn.execute(
                    f"SELECT COALESCE(action, 'unknown') AS action, COUNT(*) AS count "
                    f"FROM events_index{where} GROUP BY action", args
                )
            }
            sev_row = conn.execute(
                f"""
                SELECT
                    SUM(CASE WHEN severity_numeric < 4.0 THEN 1 ELSE 0 END) AS low,
                    SUM(CASE WHEN severity_numeric >= 4.0 AND severity_numeric < 7.0 THEN 1 ELSE 0 END) AS medium,
                    SUM(CASE WHEN severity_numeric >= 7.0 THEN 1 ELSE 0 END) AS high
                FROM events_index{where}
                """, args
            ).fetchone()

            now = datetime.now(tz=UTC)
            events_last_1h = conn.execute(
                f"SELECT COUNT(*) FROM events_index{_and('ingest_timestamp >= ?')}",
                [*args, (now - timedelta(hours=1)).isoformat()],
            ).fetchone()[0]
            events_last_24h = conn.execute(
                f"SELECT COUNT(*) FROM events_index{_and('ingest_timestamp >= ?')}",
                [*args, (now - timedelta(hours=24)).isoformat()],
            ).fetchone()[0]

        dead_letter_count = self._count_dead_letter(tenant_id)
        denominator = total_events + dead_letter_count

        return {
            "total_events": total_events,
            "dead_letter_count": dead_letter_count,
            "valid_rate_percent": round(
                (total_events / denominator * 100) if denominator else 100.0, 1
            ),
            "top_vendors": [
                {"vendor": r["vendor"], "count": r["count"]} for r in vendor_rows[:3]
            ],
            "by_vendor": {r["vendor"]: r["count"] for r in vendor_rows},
            "by_category": by_category,
            "by_outcome": by_outcome,
            "by_action": by_action,
            "severity_distribution": {
                "low": sev_row["low"] or 0,
                "medium": sev_row["medium"] or 0,
                "high": sev_row["high"] or 0,
            },
            "events_last_1h": events_last_1h,
            "events_last_24h": events_last_24h,
            "last_indexed_at": datetime.now(tz=UTC).isoformat(),
        }

    def _count_dead_letter(self, tenant_id: str | None = None) -> int:
        """Count dead-letter records, streaming the file rather than loading it."""
        if not self.dead_letter_path.exists():
            return 0
        count = 0
        with open(self.dead_letter_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line.strip():
                    continue
                if tenant_id is None:
                    count += 1
                    continue
                try:
                    if json.loads(line).get("tenant_id") == tenant_id:
                        count += 1
                except json.JSONDecodeError:
                    pass
        return count

    def get_parsers_health(self) -> list[dict[str, Any]]:
        """Registered parsers joined with their indexed event counts."""
        self.sync_from_ndjson()
        with self._lock:
            counts = {
                r["parser_name"]: r["count"]
                for r in self._connection().execute(
                    "SELECT parser_name, COUNT(*) AS count FROM events_index GROUP BY parser_name"
                )
            }
        result = [
            {
                "name": p.name,
                "version": p.version,
                "log_format": p.log_format,
                "event_count": counts.get(p.name, 0),
                "status": "active" if counts.get(p.name, 0) > 0 else "idle",
            }
            for p in get_all_parsers()
        ]
        return sorted(result, key=lambda x: x["event_count"], reverse=True)

    def get_dead_letter_records(self, page: int = 1, page_size: int = 50) -> dict[str, Any]:
        """
        Paginated dead-letter records, newest first.

        Offsets are collected in a single streaming pass so that a large DLQ
        does not have to be fully deserialized into memory to serve one page.
        """
        page = max(1, page)
        page_size = max(1, min(MAX_PAGE_SIZE, page_size))
        empty = {"total": 0, "page": page, "page_size": page_size, "total_pages": 1, "records": []}
        if not self.dead_letter_path.exists():
            return empty

        offsets: list[int] = []
        with open(self.dead_letter_path, "rb") as fh:
            pos = fh.tell()
            for raw in fh:
                if raw.strip():
                    offsets.append(pos)
                pos = fh.tell()

        total = len(offsets)
        if total == 0:
            return empty

        offsets.reverse()  # newest first
        window = offsets[(page - 1) * page_size : (page - 1) * page_size + page_size]

        records: list[dict[str, Any]] = []
        with open(self.dead_letter_path, "rb") as fh:
            for off in window:
                fh.seek(off)
                try:
                    records.append(json.loads(fh.readline().decode("utf-8", errors="replace")))
                except json.JSONDecodeError:
                    pass

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size,
            "records": records,
        }

    # -- export ----------------------------------------------------------

    def export_events(
        self,
        export_format: str = "json",
        search: str | None = None,
        vendor: str | None = None,
        category: str | None = None,
        outcome: str | None = None,
        tenant_id: str | None = None,
        limit: int = MAX_EXPORT_ROWS,
    ) -> Iterator[str]:
        """
        Stream matching events as NDJSON or CSV.

        Rows are fetched from SQLite in batches rather than through
        ``query_events``, whose page size is capped at ``MAX_PAGE_SIZE``. Going
        through it silently truncated every export to that cap, so "export all"
        quietly returned the first page's worth of rows.
        """
        self.sync_from_ndjson()
        where_sql, params = self._build_filters(
            search=search, vendor=vendor, category=category,
            outcome=outcome, tenant_id=tenant_id,
        )
        limit = max(1, min(MAX_EXPORT_ROWS, limit))

        if export_format == "csv":
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow([
                "event_id", "ingest_timestamp", "vendor", "product", "category",
                "action", "outcome", "severity_numeric", "src_ip", "src_port",
                "dst_ip", "dst_port", "protocol", "parser_name",
            ])
            yield buffer.getvalue()
            buffer.seek(0)
            buffer.truncate(0)

            for event in self._iter_export_rows(where_sql, params, limit):
                net = event.get("network") or {}
                src = event.get("source") or {}
                ev = event.get("event") or {}
                lineage = event.get("lineage") or {}
                writer.writerow([
                    event.get("event_id"), event.get("ingest_timestamp"),
                    src.get("vendor"), src.get("product"), ev.get("category"),
                    ev.get("action"), ev.get("outcome"), ev.get("severity_numeric"),
                    net.get("src_ip"), net.get("src_port"),
                    net.get("dst_ip"), net.get("dst_port"), net.get("protocol"),
                    lineage.get("parser_name"),
                ])
                yield buffer.getvalue()
                buffer.seek(0)
                buffer.truncate(0)
        else:
            for event in self._iter_export_rows(where_sql, params, limit):
                yield json.dumps(event) + "\n"

    def _iter_export_rows(
        self, where_sql: str, params: list[Any], limit: int
    ) -> Iterator[dict[str, Any]]:
        """Yield events matching a filter, paging through SQLite in batches."""
        emitted = 0
        offset = 0
        while emitted < limit:
            batch = min(_EXPORT_BATCH, limit - emitted)
            with self._lock:
                rows = self._connection().execute(
                    f"SELECT full_event_json FROM events_index {where_sql} "
                    "ORDER BY ingest_timestamp DESC LIMIT ? OFFSET ?",
                    [*params, batch, offset],
                ).fetchall()
            if not rows:
                return
            for row in rows:
                try:
                    yield json.loads(row["full_event_json"])
                except json.JSONDecodeError:
                    continue
                emitted += 1
            offset += len(rows)
