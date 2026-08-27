"""
Columnar Parquet Data Lake Sink.

Writes normalized UES events to high-performance columnar Apache Parquet files,
partitioned by date and tenant for direct querying via Snowflake, Databricks,
AWS Athena, DuckDB, or ClickHouse.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ulpf.sinks.base import SinkBase

logger = logging.getLogger(__name__)

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
            "source_event_timestamp": str(event.get("source_event_timestamp") or ""),
            "raw_payload": str(raw.get("raw_payload", "")),
            "raw_format": str(raw.get("raw_format", "")),
            "raw_hash": str(raw.get("raw_hash", "")),
            "vendor": str(src.get("vendor") or ""),
            "product": str(src.get("product") or ""),
            "device_hostname": str(src.get("device_hostname") or ""),
            "source_ip": str(src.get("source_ip") or ""),
            "category": str(ev.get("category") or "unknown"),
            "class_name": str(ev.get("class_name") or ""),
            "class_uid": int(ev.get("class_uid") or 0),
            "activity_name": str(ev.get("activity_name") or ""),
            "activity_id": int(ev.get("activity_id") or 0),
            "action": str(ev.get("action") or ""),
            "outcome": str(ev.get("outcome") or ""),
            "severity_numeric": float(ev.get("severity_numeric") or 0.0),
            "severity_inferred": bool(ev.get("severity_inferred", False)),
            "src_ip": str(net.get("src_ip") or ""),
            "src_port": int(net.get("src_port") or 0),
            "dst_ip": str(net.get("dst_ip") or ""),
            "dst_port": int(net.get("dst_port") or 0),
            "protocol": str(net.get("protocol") or ""),
            "bytes_in": int(net.get("bytes_in") or 0),
            "bytes_out": int(net.get("bytes_out") or 0),
            "direction": str(net.get("direction") or ""),
            "username": str(ident.get("username") or ""),
            "user_domain": str(ident.get("user_domain") or ""),
            "rule_name": str(rule.get("rule_name") or ""),
            "anomaly_score": float(analytics.get("anomaly_score") or 0.0),
            "is_anomalous": bool(analytics.get("is_anomalous", False)),
            "parser_name": str(lineage.get("parser_name", "")),
            "vendor_attributes": json.dumps(event.get("vendor_attributes") or {}),
        }

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
            date_str = ingest_ts[:10] if len(ingest_ts) >= 10 else datetime.now(timezone.utc).strftime("%Y-%m-%d")
            tenant = ev.get("tenant_id", "default")
            key = (date_str, tenant)
            if key not in partitions:
                partitions[key] = []
            partitions[key].append(self._flatten_event_for_columnar(ev))

        for (dt_val, tenant_val), rows in partitions.items():
            part_dir = self.base_dir / f"dt={dt_val}" / f"tenant_id={tenant_val}"
            part_dir.mkdir(parents=True, exist_ok=True)
            file_path = part_dir / "events.parquet"

            if HAS_PYARROW:
                table = pa.Table.from_pylist(rows)
                if file_path.exists():
                    try:
                        existing = pq.read_table(file_path)
                        table = pa.concat_tables([existing, table])
                    except Exception:
                        pass
                pq.write_table(table, file_path, compression="snappy")
            else:
                # Portable NDJSON tabular fallback when pyarrow is not installed in air-gap env
                fallback_path = part_dir / "events_columnar.jsonl"
                with open(fallback_path, "a", encoding="utf-8") as f:
                    for row in rows:
                        f.write(json.dumps(row) + "\n")

        self._buffer.clear()

    def close(self) -> None:
        self.flush()
