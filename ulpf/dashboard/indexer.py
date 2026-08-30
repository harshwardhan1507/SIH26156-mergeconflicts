"""
SQLite Indexing Engine for ULPF Dashboard.

Provides sub-millisecond querying, multi-field filtering, and aggregation
over normalized UES events without linear scanning of the raw NDJSON file.
The raw NDJSON file remains the single source of truth; this SQLite index is
disposable and automatically synchronized/rebuilt.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Iterator

import ulpf.parsers  # noqa: F401 (triggers @register_parser)
from ulpf.core.registry import get_all_parsers

logger = logging.getLogger(__name__)

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


class EventIndexer:
    """Manages the SQLite index database for the ULPF dashboard."""

    def __init__(self, output_dir: str | Path, db_path: str | Path | None = None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.ndjson_path = self.output_dir / "events.ndjson"
        self.dead_letter_path = self.output_dir / "dead_letter.ndjson"

        if db_path is None:
            self.db_path = self.output_dir / "dashboard_index.db"
        else:
            self.db_path = Path(db_path) if str(db_path) != ":memory:" else ":memory:"

        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self.db_path == ":memory:":
            if not hasattr(self, "_mem_conn") or self._mem_conn is None:
                self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
            return self._mem_conn
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        conn = self._get_connection()
        try:
            with conn:
                # Check if table exists
                cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events_index'")
                table_exists = cur.fetchone() is not None
                if table_exists:
                    # Check if tenant_id column exists
                    info = conn.execute("PRAGMA table_info(events_index)").fetchall()
                    col_names = [r[1] if isinstance(r, (tuple, list)) else r["name"] for r in info]
                    if "tenant_id" not in col_names:
                        conn.execute("ALTER TABLE events_index ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'")
                conn.executescript(CREATE_TABLES_SQL)
        finally:
            if self.db_path != ":memory:":
                conn.close()

    def sync_from_ndjson(self) -> int:
        """
        Incrementally index new records from events.ndjson.
        Returns number of newly indexed records.
        """
        if not self.ndjson_path.exists():
            return 0

        conn = self._get_connection()
        try:
            # Check last processed byte offset
            cur = conn.cursor()
            cur.execute("SELECT value FROM index_meta WHERE key = 'last_byte_offset'")
            row = cur.fetchone()
            last_offset = int(row["value"]) if row and row["value"] else 0

            file_size = self.ndjson_path.stat().st_size
            if file_size <= last_offset and last_offset > 0:
                # No new data
                return 0

            # If file shrank, full resync needed
            if file_size < last_offset:
                last_offset = 0

            new_records = []
            current_offset = last_offset

            with open(self.ndjson_path, "r", encoding="utf-8", errors="replace") as fh:
                if last_offset > 0:
                    fh.seek(last_offset)

                for line in fh:
                    line_str = line.strip()
                    if not line_str:
                        continue
                    try:
                        event = json.loads(line_str)
                        record = self._extract_index_record(event, line_str)
                        if record:
                            new_records.append(record)
                    except json.JSONDecodeError:
                        logger.warning("Skipping invalid JSON line in %s", self.ndjson_path)

                current_offset = fh.tell()

            if new_records:
                insert_sql = """
                INSERT OR REPLACE INTO events_index (
                    event_id, tenant_id, ingest_timestamp, source_event_timestamp,
                    vendor, product, device_hostname, category, action,
                    outcome, severity_numeric, severity_original, src_ip,
                    src_port, dst_ip, dst_port, protocol, bytes_in,
                    bytes_out, username, rule_name, parser_name, raw_format,
                    raw_hash, full_event_json
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """
                with conn:
                    conn.executemany(insert_sql, new_records)
                    conn.execute(
                        "INSERT OR REPLACE INTO index_meta (key, value) VALUES ('last_byte_offset', ?)",
                        (str(current_offset),),
                    )
                    conn.execute(
                        "INSERT OR REPLACE INTO index_meta (key, value) VALUES ('last_sync_timestamp', ?)",
                        (datetime.now(tz=timezone.utc).isoformat(),),
                    )

            return len(new_records)
        finally:
            if self.db_path != ":memory:":
                conn.close()

    def rebuild_index(self) -> int:
        """Clear and rebuild the entire SQLite index from scratch."""
        conn = self._get_connection()
        try:
            with conn:
                conn.execute("DELETE FROM events_index")
                conn.execute("DELETE FROM index_meta")
        finally:
            if self.db_path != ":memory:":
                conn.close()
        return self.sync_from_ndjson()

    def _extract_index_record(self, event: dict[str, Any], full_json: str) -> tuple | None:
        event_id = event.get("event_id")
        if not event_id:
            return None

        tenant_id = event.get("tenant_id") or "default"
        raw = event.get("raw") or {}
        source = event.get("source") or {}
        ev = event.get("event") or {}
        net = event.get("network") or {}
        ident = event.get("identity") or {}
        rule = event.get("rule") or {}
        lineage = event.get("lineage") or {}

        return (
            event_id,
            tenant_id,
            event.get("ingest_timestamp") or datetime.now(tz=timezone.utc).isoformat(),
            event.get("source_event_timestamp"),
            source.get("vendor"),
            source.get("product"),
            source.get("device_hostname"),
            ev.get("category") or "unknown",
            ev.get("action"),
            ev.get("outcome"),
            float(ev.get("severity_numeric") if ev.get("severity_numeric") is not None else 5.0),
            str(ev.get("severity_original") or ""),
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
        """
        Execute filtered and paginated event queries.
        """
        self.sync_from_ndjson()

        allowed_sort_fields = {
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
        sort_column = allowed_sort_fields.get(sort_by, "ingest_timestamp")
        sort_direction = "DESC" if sort_order.lower() == "desc" else "ASC"

        where_clauses: list[str] = []
        params: list[Any] = []

        if tenant_id:
            where_clauses.append("tenant_id = ?")
            params.append(tenant_id)

        if search:
            search_pattern = f"%{search.strip()}%"
            where_clauses.append(
                """(
                    event_id LIKE ? OR
                    vendor LIKE ? OR
                    product LIKE ? OR
                    device_hostname LIKE ? OR
                    src_ip LIKE ? OR
                    dst_ip LIKE ? OR
                    CAST(src_port AS TEXT) LIKE ? OR
                    CAST(dst_port AS TEXT) LIKE ? OR
                    username LIKE ? OR
                    rule_name LIKE ? OR
                    action LIKE ? OR
                    category LIKE ? OR
                    parser_name LIKE ?
                )"""
            )
            params.extend([search_pattern] * 13)

        if vendor:
            where_clauses.append("vendor = ?")
            params.append(vendor)

        if category:
            where_clauses.append("category = ?")
            params.append(category)

        if severity_min is not None:
            where_clauses.append("severity_numeric >= ?")
            params.append(severity_min)

        if severity_max is not None:
            where_clauses.append("severity_numeric <= ?")
            params.append(severity_max)

        if outcome:
            where_clauses.append("outcome = ?")
            params.append(outcome)

        if action:
            where_clauses.append("action = ?")
            params.append(action)

        if parser_name:
            where_clauses.append("parser_name = ?")
            params.append(parser_name)

        if start_time:
            where_clauses.append("ingest_timestamp >= ?")
            params.append(start_time)

        if end_time:
            where_clauses.append("ingest_timestamp <= ?")
            params.append(end_time)

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        page = max(1, page)
        page_size = max(1, min(1000, page_size))
        offset = (page - 1) * page_size

        conn = self._get_connection()
        try:
            cur = conn.cursor()
            # Count total matching rows
            count_sql = f"SELECT COUNT(*) FROM events_index {where_sql}"
            cur.execute(count_sql, params)
            total_count = cur.fetchone()[0]

            # Select paginated results
            select_sql = f"""
            SELECT full_event_json
            FROM events_index
            {where_sql}
            ORDER BY {sort_column} {sort_direction}
            LIMIT ? OFFSET ?
            """
            cur.execute(select_sql, params + [page_size, offset])
            rows = cur.fetchall()

            events = [json.loads(row["full_event_json"]) for row in rows]

            total_pages = (total_count + page_size - 1) // page_size if total_count > 0 else 1

            return {
                "total": total_count,
                "page": page,
                "page_size": page_size,
                "total_pages": total_pages,
                "events": events,
            }
        finally:
            if self.db_path != ":memory:":
                conn.close()

    def get_event_by_id(self, event_id: str) -> dict[str, Any] | None:
        """Fetch single event JSON by event_id."""
        self.sync_from_ndjson()
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT full_event_json FROM events_index WHERE event_id = ?", (event_id,))
            row = cur.fetchone()
            if row:
                return json.loads(row["full_event_json"])
            return None
        finally:
            if self.db_path != ":memory:":
                conn.close()

    def get_stats(self, tenant_id: str | None = None) -> dict[str, Any]:
        """Compute aggregated statistics for summary metrics and visual charts."""
        self.sync_from_ndjson()
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            t_filter = " WHERE tenant_id = ?" if tenant_id else ""
            t_params = [tenant_id] if tenant_id else []

            # Total events
            cur.execute(f"SELECT COUNT(*) FROM events_index{t_filter}", t_params)
            total_events = cur.fetchone()[0]

            # Dead letter count
            dead_letter_count = 0
            if self.dead_letter_path.exists():
                with open(self.dead_letter_path, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        if line.strip():
                            if tenant_id:
                                try:
                                    rec = json.loads(line.strip())
                                    if rec.get("tenant_id") == tenant_id:
                                        dead_letter_count += 1
                                except Exception:
                                    pass
                            else:
                                dead_letter_count += 1

            # Category breakdown
            cur.execute(f"SELECT category, COUNT(*) as count FROM events_index{t_filter} GROUP BY category ORDER BY count DESC", t_params)
            by_category = {row["category"]: row["count"] for row in cur.fetchall()}

            # Vendor breakdown & Top 3 vendors
            cur.execute(
                f"SELECT COALESCE(vendor, 'Unknown') as vendor, COUNT(*) as count FROM events_index{t_filter} GROUP BY vendor ORDER BY count DESC",
                t_params
            )
            vendor_rows = cur.fetchall()
            by_vendor = {row["vendor"]: row["count"] for row in vendor_rows}
            top_vendors = [{"vendor": row["vendor"], "count": row["count"]} for row in vendor_rows[:3]]

            # Severity distribution
            cur.execute(f"""
                SELECT
                    SUM(CASE WHEN severity_numeric < 4.0 THEN 1 ELSE 0 END) as low,
                    SUM(CASE WHEN severity_numeric >= 4.0 AND severity_numeric < 7.0 THEN 1 ELSE 0 END) as medium,
                    SUM(CASE WHEN severity_numeric >= 7.0 THEN 1 ELSE 0 END) as high
                FROM events_index{t_filter}
            """, t_params)
            sev_row = cur.fetchone()
            severity_dist = {
                "low": sev_row["low"] or 0,
                "medium": sev_row["medium"] or 0,
                "high": sev_row["high"] or 0,
            }

            # Outcome breakdown
            cur.execute(
                "SELECT COALESCE(outcome, 'unknown') as outcome, COUNT(*) as count FROM events_index GROUP BY outcome"
            )
            by_outcome = {row["outcome"]: row["count"] for row in cur.fetchall()}

            # Action breakdown
            cur.execute(
                "SELECT COALESCE(action, 'unknown') as action, COUNT(*) as count FROM events_index GROUP BY action"
            )
            by_action = {row["action"]: row["count"] for row in cur.fetchall()}

            # Time velocities (events in last 1 hour and 24 hours based on ingest_timestamp)
            now = datetime.now(tz=timezone.utc)
            one_hour_ago = (now - timedelta(hours=1)).isoformat()
            twenty_four_hours_ago = (now - timedelta(hours=24)).isoformat()

            cur.execute("SELECT COUNT(*) FROM events_index WHERE ingest_timestamp >= ?", (one_hour_ago,))
            events_last_1h = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM events_index WHERE ingest_timestamp >= ?", (twenty_four_hours_ago,))
            events_last_24h = cur.fetchone()[0]

            return {
                "total_events": total_events,
                "dead_letter_count": dead_letter_count,
                "valid_rate_percent": round(
                    (total_events / (total_events + dead_letter_count) * 100)
                    if (total_events + dead_letter_count) > 0
                    else 100.0,
                    1,
                ),
                "top_vendors": top_vendors,
                "by_vendor": by_vendor,
                "by_category": by_category,
                "by_outcome": by_outcome,
                "by_action": by_action,
                "severity_distribution": severity_dist,
                "events_last_1h": events_last_1h,
                "events_last_24h": events_last_24h,
                "last_indexed_at": datetime.now(tz=timezone.utc).isoformat(),
            }
        finally:
            if self.db_path != ":memory:":
                conn.close()

    def get_parsers_health(self) -> list[dict[str, Any]]:
        """List registered parsers combined with live event counts from index."""
        self.sync_from_ndjson()
        registered = get_all_parsers()
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT parser_name, COUNT(*) as count FROM events_index GROUP BY parser_name")
            counts = {row["parser_name"]: row["count"] for row in cur.fetchall()}

            result = []
            for p in registered:
                cnt = counts.get(p.name, 0)
                result.append({
                    "name": p.name,
                    "version": p.version,
                    "log_format": p.log_format,
                    "event_count": cnt,
                    "status": "active" if cnt > 0 else "idle",
                })
            return sorted(result, key=lambda x: x["event_count"], reverse=True)
        finally:
            if self.db_path != ":memory:":
                conn.close()

    def get_dead_letter_records(self, page: int = 1, page_size: int = 50) -> dict[str, Any]:
        """Fetch paginated dead-letter records."""
        if not self.dead_letter_path.exists():
            return {"total": 0, "page": page, "page_size": page_size, "records": []}

        all_records = []
        with open(self.dead_letter_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line_str = line.strip()
                if line_str:
                    try:
                        all_records.append(json.loads(line_str))
                    except json.JSONDecodeError:
                        pass

        all_records.reverse()  # Newest first
        total = len(all_records)
        offset = (page - 1) * page_size
        sliced = all_records[offset : offset + page_size]

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size if total > 0 else 1,
            "records": sliced,
        }

    def _format_table_aligned_event(self, e: dict[str, Any]) -> dict[str, Any]:
        """Format an event into a clear, nested structure aligned with the table view."""
        net = e.get("network") or {}
        src = e.get("source") or {}
        ev = e.get("event") or {}
        lineage = e.get("lineage") or {}
        ident = e.get("identity") or {}
        rule = e.get("rule") or {}
        raw = e.get("raw") or {}
        enrich = e.get("enrichment") or {}
        vendor_attrs = e.get("vendor_attributes") or {}

        # Build formatted connection flow string e.g. "10.0.0.1:443 -> 1.1.1.1:80 [TCP]"
        src_str = f"{net.get('src_ip')}:{net.get('src_port')}" if net.get("src_port") else (net.get("src_ip") or "-")
        dst_str = f"{net.get('dst_ip')}:{net.get('dst_port')}" if net.get("dst_port") else (net.get("dst_ip") or "-")
        proto_str = f" [{str(net.get('protocol')).upper()}]" if net.get("protocol") else ""
        flow_path = f"{src_str} -> {dst_str}{proto_str}" if (net.get("src_ip") or net.get("dst_ip")) else "-"

        sev_num = ev.get("severity_numeric")
        if sev_num is not None:
            sev_level = "High" if float(sev_num) >= 7.0 else ("Medium" if float(sev_num) >= 4.0 else "Low")
        else:
            sev_level = "Unknown"

        return {
            "event_id": e.get("event_id"),
            "tenant_id": e.get("tenant_id", "default"),
            "timestamp": {
                "ingest_timestamp": e.get("ingest_timestamp"),
                "source_event_timestamp": e.get("source_event_timestamp"),
            },
            "source": {
                "vendor": src.get("vendor"),
                "product": src.get("product"),
                "device_hostname": src.get("device_hostname"),
                "source_ip": src.get("source_ip"),
                "log_format": src.get("log_format"),
            },
            "event": {
                "category": ev.get("category"),
                "action": ev.get("action"),
                "outcome": ev.get("outcome"),
                "severity": {
                    "numeric": sev_num,
                    "level": sev_level,
                    "original": ev.get("severity_original"),
                    "inferred": ev.get("severity_inferred"),
                },
                "event_type_vendor_specific": ev.get("event_type_vendor_specific"),
                "ocsf_class": ev.get("class_name"),
                "ocsf_class_uid": ev.get("class_uid"),
                "ocsf_activity": ev.get("activity_name"),
                "ocsf_activity_id": ev.get("activity_id"),
            },
            "connection": {
                "flow_path": flow_path,
                "src": {
                    "ip": net.get("src_ip"),
                    "port": net.get("src_port"),
                },
                "dst": {
                    "ip": net.get("dst_ip"),
                    "port": net.get("dst_port"),
                },
                "protocol": net.get("protocol"),
                "direction": net.get("direction"),
                "bytes_in": net.get("bytes_in"),
                "bytes_out": net.get("bytes_out"),
                "interface": net.get("interface"),
            },
            "identity": {
                "username": ident.get("username"),
                "user_domain": ident.get("user_domain"),
            } if any(ident.values()) else None,
            "rule": {
                "rule_id": rule.get("rule_id"),
                "rule_name": rule.get("rule_name"),
                "policy_action": rule.get("policy_action"),
            } if any(rule.values()) else None,
            "parser": {
                "name": lineage.get("parser_name"),
                "version": lineage.get("parser_version"),
                "ruleset_version": lineage.get("normalization_ruleset_version"),
            },
            "forensics": {
                "raw_format": raw.get("raw_format"),
                "raw_hash": raw.get("raw_hash"),
                "raw_payload": raw.get("raw_payload"),
            },
            "vendor_attributes": vendor_attrs if vendor_attrs else None,
            "enrichment": enrich if enrich else None,
        }

    def export_events(
        self,
        export_format: str = "json",
        search: str | None = None,
        vendor: str | None = None,
        category: str | None = None,
        outcome: str | None = None,
        action: str | None = None,
        parser_name: str | None = None,
        tenant_id: str | None = None,
    ) -> Iterator[str]:
        """Stream export records in nested formatted JSON or CSV."""
        res = self.query_events(
            page=1,
            page_size=10000,
            search=search,
            vendor=vendor,
            category=category,
            outcome=outcome,
            action=action,
            parser_name=parser_name,
            tenant_id=tenant_id,
        )
        events = res["events"]

        if export_format == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "event_id",
                "ingest_timestamp",
                "vendor",
                "product",
                "category",
                "action",
                "outcome",
                "severity_numeric",
                "src_ip",
                "src_port",
                "dst_ip",
                "dst_port",
                "protocol",
                "parser_name",
            ])
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)

            for e in events:
                net = e.get("network") or {}
                src = e.get("source") or {}
                ev = e.get("event") or {}
                lineage = e.get("lineage") or {}
                writer.writerow([
                    e.get("event_id"),
                    e.get("ingest_timestamp"),
                    src.get("vendor"),
                    src.get("product"),
                    ev.get("category"),
                    ev.get("action"),
                    ev.get("outcome"),
                    ev.get("severity_numeric"),
                    net.get("src_ip"),
                    net.get("src_port"),
                    net.get("dst_ip"),
                    net.get("dst_port"),
                    net.get("protocol"),
                    lineage.get("parser_name"),
                ])
                yield output.getvalue()
                output.seek(0)
                output.truncate(0)
        else:
            # Table-aligned nested JSON structure, formatted with indentation
            formatted_list = [self._format_table_aligned_event(e) for e in events]
            yield json.dumps(formatted_list, indent=2)

