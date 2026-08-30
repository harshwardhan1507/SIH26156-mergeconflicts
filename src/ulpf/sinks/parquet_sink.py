"""
Columnar Parquet Data Lake Sink.

Writes normalized UES events to high-performance columnar Apache Parquet files,
partitioned by date and tenant for direct querying via Snowflake, Databricks,
AWS Athena, DuckDB, or ClickHouse.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ulpf.sinks.base import SinkBase

logger = logging.getLogger(__name__)


def _as_int(value: Any) -> int | None:
    """Coerce to int, preserving NULL. A missing port is not port 0."""
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> float | None:
    """Coerce to float, preserving NULL."""
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_str(value: Any) -> str | None:
    """Coerce to str, preserving NULL so empty and absent stay distinguishable."""
    return None if value is None else str(value)

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
    HAS_PYARROW = True
except ImportError:
    HAS_PYARROW = False


class ParquetSink(SinkBase):
    """
    Columnar Parquet Sink with automated date & tenant partitioning:
      <base_dir>/dt=YYYY-MM-DD/tenant_id=<tenant>/events.parquet
    """

    def __init__(self, base_dir: str | Path, batch_size: int = 1000):
        self.base_dir = Path(base_dir)
        self.batch_size = batch_size
        self._buffer: list[dict[str, Any]] = []
        self._schema = None
        self._part_seq = 0
        # Distinguishes files written by concurrent writers into one partition.
        self._run_id = uuid.uuid4().hex[:8]

    #: Column name -> Arrow type. Kept in the same order as the flattened row.
    _COLUMNS: tuple[tuple[str, Any], ...] = (
        ("schema_version", "string"), ("tenant_id", "string"), ("event_id", "string"),
        ("ingest_timestamp", "string"), ("source_event_timestamp", "string"),
        ("raw_payload", "string"), ("raw_format", "string"), ("raw_hash", "string"),
        ("vendor", "string"), ("product", "string"), ("device_hostname", "string"),
        ("source_ip", "string"), ("category", "string"), ("class_name", "string"),
        ("class_uid", "int64"), ("activity_name", "string"), ("activity_id", "int64"),
        ("action", "string"), ("outcome", "string"), ("severity_numeric", "float64"),
        ("severity_inferred", "bool"), ("src_ip", "string"), ("src_port", "int64"),
        ("dst_ip", "string"), ("dst_port", "int64"), ("protocol", "string"),
        ("bytes_in", "int64"), ("bytes_out", "int64"), ("direction", "string"),
        ("username", "string"), ("user_domain", "string"), ("rule_name", "string"),
        ("anomaly_score", "float64"), ("is_anomalous", "bool"),
        ("parser_name", "string"), ("vendor_attributes", "string"),
    )

    def _flatten_event_for_columnar(self, event: dict[str, Any]) -> dict[str, Any]:
        """Flatten nested UES event into flat dictionary for columnar tabular layout."""
        src = event.get("source") or {}
        ev = event.get("event") or {}
        net = event.get("network") or {}
        ident = event.get("identity") or {}
        rule = event.get("rule") or {}
        raw = event.get("raw") or {}
        lineage = event.get("lineage") or {}
        analytics = event.get("analytics") or {}

        return {
            "schema_version": str(event.get("schema_version", "1.2.0")),
            "tenant_id": str(event.get("tenant_id", "default")),
            "event_id": str(event.get("event_id", "")),
            "ingest_timestamp": str(event.get("ingest_timestamp", "")),
            "source_event_timestamp": _as_str(event.get("source_event_timestamp")),
            "raw_payload": str(raw.get("raw_payload", "")),
            "raw_format": str(raw.get("raw_format", "")),
            "raw_hash": str(raw.get("raw_hash", "")),
            "vendor": _as_str(src.get("vendor")),
            "product": _as_str(src.get("product")),
            "device_hostname": _as_str(src.get("device_hostname")),
            "source_ip": _as_str(src.get("source_ip")),
            "category": str(ev.get("category") or "unknown"),
            "class_name": _as_str(ev.get("class_name")),
            "class_uid": _as_int(ev.get("class_uid")),
            "activity_name": _as_str(ev.get("activity_name")),
            "activity_id": _as_int(ev.get("activity_id")),
            "action": _as_str(ev.get("action")),
            "outcome": _as_str(ev.get("outcome")),
            "severity_numeric": _as_float(ev.get("severity_numeric")),
            "severity_inferred": bool(ev.get("severity_inferred", False)),
            "src_ip": _as_str(net.get("src_ip")),
            "src_port": _as_int(net.get("src_port")),
            "dst_ip": _as_str(net.get("dst_ip")),
            "dst_port": _as_int(net.get("dst_port")),
            "protocol": _as_str(net.get("protocol")),
            "bytes_in": _as_int(net.get("bytes_in")),
            "bytes_out": _as_int(net.get("bytes_out")),
            "direction": _as_str(net.get("direction")),
            "username": _as_str(ident.get("username")),
            "user_domain": _as_str(ident.get("user_domain")),
            "rule_name": _as_str(rule.get("rule_name")),
            "anomaly_score": _as_float(analytics.get("anomaly_score")),
            "is_anomalous": bool(analytics.get("is_anomalous", False)),
            "parser_name": str(lineage.get("parser_name", "")),
            "vendor_attributes": json.dumps(event.get("vendor_attributes") or {}),
        }

    def _arrow_schema(self):
        """
        Explicit Arrow schema.

        Without it, pyarrow infers types per batch, so an all-null column in one
        batch infers as null and fails to concatenate or query against a batch
        where the same column held strings.
        """
        if self._schema is None:
            self._schema = pa.schema(
                [(name, dtype) for name, dtype in self._COLUMNS]
            )
        return self._schema

    def _next_part_path(self, part_dir: Path) -> Path:
        """Allocate the next part filename within a partition directory."""
        self._part_seq += 1
        return part_dir / f"part-{self._run_id}-{self._part_seq:05d}.parquet"

    def write(self, event: dict[str, Any]) -> None:
        self._buffer.append(event)
        if len(self._buffer) >= self.batch_size:
            self.flush()

    def flush(self) -> None:
        if not self._buffer:
            return

        # Group events by partition key: (date_str, tenant_id)
        partitions: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for ev in self._buffer:
            ingest_ts = ev.get("ingest_timestamp", "")
            date_str = ingest_ts[:10] if len(ingest_ts) >= 10 else datetime.now(UTC).strftime("%Y-%m-%d")
            tenant = ev.get("tenant_id", "default")
            key = (date_str, tenant)
            if key not in partitions:
                partitions[key] = []
            partitions[key].append(self._flatten_event_for_columnar(ev))

        for (dt_val, tenant_val), rows in partitions.items():
            part_dir = self.base_dir / f"dt={dt_val}" / f"tenant_id={tenant_val}"
            part_dir.mkdir(parents=True, exist_ok=True)

            if HAS_PYARROW:
                # One file per flush rather than read-concat-rewrite. Rewriting
                # the whole partition on every batch is quadratic in the number
                # of events, and a failed read of the existing file previously
                # fell through to overwriting it — silently destroying data.
                # Query engines (Athena, DuckDB, Spark, ClickHouse) read a
                # directory of Parquet files as one table, so this is also the
                # conventional layout.
                table = pa.Table.from_pylist(rows, schema=self._arrow_schema())
                pq.write_table(table, self._next_part_path(part_dir), compression="snappy")
            else:
                # Portable NDJSON tabular fallback when pyarrow is not installed in air-gap env
                fallback_path = part_dir / "events_columnar.jsonl"
                with open(fallback_path, "a", encoding="utf-8") as f:
                    for row in rows:
                        f.write(json.dumps(row) + "\n")

        self._buffer.clear()

    def close(self) -> None:
        self.flush()
