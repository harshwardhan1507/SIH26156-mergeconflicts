"""
Persistent Source Registry & Observability Engine.

Maintains an atomic SQLite registry of log sources, their configurations,
and live real-time operational telemetry (events/sec, validity %, DLQ rates, health).
"""
from __future__ import annotations

import json
import logging
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from ulpf.core.declarative import (
    DeclarativeSourceParser,
    get_declarative_registry,
    validate_declarative_config,
)

logger = logging.getLogger("ulpf.core.source_manager")


class SourceManager:
    """
    Manages persistent log source records and real-time observability telemetry.
    """

    def __init__(self, output_dir: str | Path = "output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.output_dir / "sources_registry.sqlite3"
        self._init_db()
        self._sync_built_in_sources()

    def _init_db(self) -> None:
        """Create sources registry SQLite table if not exists."""
        conn = sqlite3.connect(self.db_path)
        try:
            with conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS sources (
                        source_id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        vendor TEXT,
                        product TEXT,
                        source_type TEXT NOT NULL, -- 'plugin' | 'declarative'
                        input_type TEXT,           -- 'syslog' | 'json' | 'csv' | 'kafka' | 'file'
                        address_port TEXT,
                        parser_version TEXT NOT NULL,
                        enabled INTEGER NOT NULL DEFAULT 1,
                        health_state TEXT NOT NULL DEFAULT 'healthy', -- 'healthy' | 'warning' | 'error'
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        last_event_at TEXT,
                        events_received INTEGER NOT NULL DEFAULT 0,
                        events_processed INTEGER NOT NULL DEFAULT 0,
                        valid_events INTEGER NOT NULL DEFAULT 0,
                        invalid_events INTEGER NOT NULL DEFAULT 0,
                        dead_letter_count INTEGER NOT NULL DEFAULT 0,
                        current_eps REAL NOT NULL DEFAULT 0.0,
                        last_error TEXT,
                        config_yaml TEXT
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_src_vendor ON sources (vendor)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_src_enabled ON sources (enabled)")
        finally:
            conn.close()

    def _sync_built_in_sources(self) -> None:
        """Seed registry with built-in standard parsers and declarative sources if empty."""
        now = datetime.now(timezone.utc).isoformat()
        built_ins = [
            ("cef_firewalls", "ArcSight / Fortinet / CheckPoint CEF", "Multi-Vendor", "Firewall & Security", "plugin", "syslog/file", "1.2.0"),
            ("cisco_asa", "Cisco ASA Firewall Syslog", "Cisco", "ASA 5500 / Firepower", "plugin", "syslog_rfc3164", "1.2.0"),
            ("paloalto_traffic", "Palo Alto Networks CSV Traffic", "Palo Alto Networks", "PAN-OS Firewall", "plugin", "csv", "1.2.0"),
            ("aws_cloudtrail", "AWS CloudTrail Audit Logs", "Amazon Web Services", "CloudTrail", "plugin", "json", "1.2.0"),
            ("azure_monitor", "Azure Monitor / Activity Logs", "Microsoft", "Azure Cloud", "plugin", "json", "1.2.0"),
            ("gcp_audit", "GCP Cloud Audit protoPayload", "Google Cloud", "Cloud Audit", "plugin", "json", "1.2.0"),
            ("windows_evtx", "Windows Event Log / EVTX XML", "Microsoft", "Windows Server", "plugin", "xml", "1.2.0"),
            ("qradar_leef", "IBM QRadar LEEF 1.0/2.0", "IBM / QRadar", "SIEM Event Forwarder", "plugin", "leef", "1.2.0"),
            ("syslog_rfc5424", "RFC 5424 Structured Syslog", "Standard", "Enterprise Network", "plugin", "syslog_rfc5424", "1.2.0"),
            ("syslog_rfc3164", "RFC 3164 BSD Syslog", "Standard", "Unix / Linux", "plugin", "syslog_rfc3164", "1.2.0"),
            ("json_passthrough", "Generic JSON / Database Logs", "Generic / MySQL", "App & Database", "plugin", "json", "1.2.0"),
        ]

        conn = sqlite3.connect(self.db_path)
        try:
            with conn:
                for s_id, name, vendor, prod, stype, itype, ver in built_ins:
                    conn.execute("""
                        INSERT OR IGNORE INTO sources 
                        (source_id, name, vendor, product, source_type, input_type, address_port, 
                         parser_version, enabled, health_state, created_at, updated_at, 
                         events_received, events_processed, valid_events, invalid_events, dead_letter_count, current_eps)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 'healthy', ?, ?, 0, 0, 0, 0, 0, 0.0)
                    """, (s_id, name, vendor, prod, stype, itype, "port 1514/files", ver, now, now))

                # Also sync declarative sources from disk
                decl_reg = get_declarative_registry()
                decl_reg.scan_and_register()
                for src in decl_reg.list_sources():
                    cfg_yaml = yaml.dump(src.config, sort_keys=False)
                    conn.execute("""
                        INSERT OR REPLACE INTO sources 
                        (source_id, name, vendor, product, source_type, input_type, address_port,
                         parser_version, enabled, health_state, created_at, updated_at, config_yaml)
                        VALUES (?, ?, ?, ?, 'declarative', ?, 'declarative_stream', ?, ?, 'healthy', ?, ?, ?)
                    """, (
                        src.name,
                        src.description or f"{src.vendor} {src.product} (Declarative)",
                        src.vendor,
                        src.product,
                        src.parser_cfg.get("type", "key_value"),
                        src.version,
                        1 if src.enabled else 0,
                        now,
                        now,
                        cfg_yaml,
                    ))
        finally:
            conn.close()

    def list_sources(self) -> list[dict[str, Any]]:
        """Return list of all registered sources with health and telemetry."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM sources ORDER BY updated_at DESC").fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_source(self, source_id: str) -> dict[str, Any] | None:
        """Get source definition and stats by source_id."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM sources WHERE source_id = ?", (source_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def register_declarative_source(self, config: dict[str, Any]) -> tuple[bool, list[str], dict[str, Any] | None]:
        """Validate, store, and activate a new declarative log source."""
        valid, errors = validate_declarative_config(config)
        if not valid:
            return False, errors, None

        decl_reg = get_declarative_registry()
        success, reg_errors, parser = decl_reg.add_source(config)
        if not success:
            return False, reg_errors, None

        now = datetime.now(timezone.utc).isoformat()
        cfg_yaml = yaml.dump(config, sort_keys=False)

        conn = sqlite3.connect(self.db_path)
        try:
            with conn:
                conn.execute("""
                    INSERT OR REPLACE INTO sources 
                    (source_id, name, vendor, product, source_type, input_type, address_port,
                     parser_version, enabled, health_state, created_at, updated_at, config_yaml)
                    VALUES (?, ?, ?, ?, 'declarative', ?, 'declarative_stream', ?, ?, 'healthy', ?, ?, ?)
                """, (
                    parser.name,
                    config.get("description") or f"{parser.vendor} {parser.product} (No-Code)",
                    parser.vendor,
                    parser.product,
                    config.get("parser", {}).get("type", "key_value"),
                    parser.version,
                    1 if parser.enabled else 0,
                    now,
                    now,
                    cfg_yaml,
                ))
        finally:
            conn.close()

        return True, [], self.get_source(parser.name)

    def set_source_enabled(self, source_id: str, enabled: bool) -> bool:
        """Enable or disable a log source."""
        conn = sqlite3.connect(self.db_path)
        try:
            with conn:
                conn.execute("""
                    UPDATE sources SET enabled = ?, updated_at = ? WHERE source_id = ?
                """, (1 if enabled else 0, datetime.now(timezone.utc).isoformat(), source_id))
        finally:
            conn.close()

        decl_src = get_declarative_registry().get_source(source_id)
        if decl_src:
            decl_src.enabled = enabled
        return True

    def delete_source(self, source_id: str) -> bool:
        """Delete a declarative source definition."""
        conn = sqlite3.connect(self.db_path)
        try:
            with conn:
                conn.execute("DELETE FROM sources WHERE source_id = ?", (source_id,))
        finally:
            conn.close()

        return get_declarative_registry().remove_source(source_id)

    def record_event_telemetry(
        self,
        source_id: str,
        is_valid: bool = True,
        is_dead_letter: bool = False,
        error_msg: str | None = None,
    ) -> None:
        """Record live event ingestion telemetry for a source."""
        now = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect(self.db_path)
        try:
            with conn:
                conn.execute("""
                    UPDATE sources SET 
                        events_received = events_received + 1,
                        events_processed = events_processed + 1,
                        valid_events = valid_events + (CASE WHEN ? = 1 THEN 1 ELSE 0 END),
                        invalid_events = invalid_events + (CASE WHEN ? = 0 THEN 1 ELSE 0 END),
                        dead_letter_count = dead_letter_count + (CASE WHEN ? = 1 THEN 1 ELSE 0 END),
                        last_event_at = ?,
                        updated_at = ?,
                        last_error = COALESCE(?, last_error),
                        health_state = CASE 
                            WHEN ? = 1 THEN 'warning'
                            WHEN ? IS NOT NULL THEN 'error'
                            ELSE 'healthy'
                        END
                    WHERE source_id = ?
                """, (
                    1 if is_valid else 0,
                    1 if is_valid else 0,
                    1 if is_dead_letter else 0,
                    now,
                    now,
                    error_msg,
                    1 if is_dead_letter else 0,
                    error_msg,
                    source_id,
                ))
        finally:
            conn.close()

    def get_pipeline_metrics(self) -> dict[str, Any]:
        """Aggregate total pipeline health metrics across all sources."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM sources").fetchall()
        finally:
            conn.close()

        total_received = sum(r["events_received"] for r in rows)
        total_valid = sum(r["valid_events"] for r in rows)
        total_invalid = sum(r["invalid_events"] for r in rows)
        total_dlq = sum(r["dead_letter_count"] for r in rows)
        active_sources = sum(1 for r in rows if r["enabled"] == 1)

        valid_rate = (total_valid / max(1, total_received)) * 100.0
        dlq_rate = (total_dlq / max(1, total_received)) * 100.0

        return {
            "total_events": total_received,
            "total_valid": total_valid,
            "total_invalid": total_invalid,
            "total_dead_letter": total_dlq,
            "validity_rate_pct": round(valid_rate, 2),
            "dead_letter_rate_pct": round(dlq_rate, 2),
            "total_sources_registered": len(rows),
            "active_sources": active_sources,
            "active_parsers": len(get_declarative_registry().list_sources()) + 11,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def close(self) -> None:
        """Cleanly close any handles."""
        pass


_GLOBAL_SOURCE_MANAGER: SourceManager | None = None


def get_source_manager(output_dir: str | Path = "output") -> SourceManager:
    """Singleton getter for SourceManager."""
    global _GLOBAL_SOURCE_MANAGER
    if _GLOBAL_SOURCE_MANAGER is None or str(_GLOBAL_SOURCE_MANAGER.output_dir) != str(Path(output_dir)):
        _GLOBAL_SOURCE_MANAGER = SourceManager(output_dir)
    return _GLOBAL_SOURCE_MANAGER

