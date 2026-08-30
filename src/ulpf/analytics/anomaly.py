"""
Anomaly Detection Engine for ULPF.

Implements multiple complementary detection methods:
1. Z-Score: severity_numeric > 3 sigma from per-source-IP rolling mean
2. IQR Outlier: bytes_in/bytes_out falls outside Q1-1.5*IQR..Q3+1.5*IQR
3. Burst Detection: events/min from src_ip > 3x rolling baseline rate
4. Rare Category: event category appears in < 1% of historical events

Each detected anomaly:
- Gets an anomaly_score (0.0 to 1.0) — higher is more suspicious
- Gets an anomaly_reasons list (human-readable strings)
- Has severity bumped if score >= 0.7

Pure Python, air-gap safe, zero external dependencies required.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from ulpf.analytics.baseline import BaselineProfiler

logger = logging.getLogger(__name__)

# Score weights for each detection method
_SCORE_WEIGHTS = {
    "severity_zscore_high": 0.35,     # Z-score > 3 sigma
    "severity_zscore_medium": 0.20,   # Z-score 2-3 sigma
    "bytes_iqr_outlier": 0.25,        # Unusual byte volume
    "burst_detected": 0.30,           # IP sending too many events
    "rare_category": 0.15,            # Unusual category for this environment
    "threat_ip": 0.40,                # IP matches threat intel CIDR
    "auth_failure_chain": 0.30,       # Repeated auth failures from same IP
}

# Minimum anomaly score to annotate the event
_SCORE_THRESHOLD = 0.15


class AnomalyDetector:
    """
    Stateful anomaly detector — maintains rolling baselines and detects anomalies
    in a stream of normalized UES events.

    Usage:
        detector = AnomalyDetector(output_dir="output")
        for event in stream:
            annotated = detector.analyze(event)
            detector.update_baseline(event)
        detector.save_baseline()
    """

    def __init__(self, output_dir: Path | str = "output") -> None:
        self.output_dir = Path(output_dir)
        self.baseline = BaselineProfiler(output_dir=output_dir)
        # Track recent auth failures per IP
        self._auth_failures: dict[str, int] = {}

    def analyze(self, event: dict[str, Any]) -> dict[str, Any]:
        """
        Analyze a UES event for anomalies.
        Adds analytics block to event and returns annotated event.
        Does NOT modify baseline (call update_baseline separately).
        """
        score = 0.0
        reasons: list[str] = []

        network = event.get("network") or {}
        ev = event.get("event") or {}
        enrichment = event.get("enrichment") or {}

        src_ip = network.get("src_ip") or "unknown"
        severity = float(ev.get("severity_numeric", 5))
        category = ev.get("category", "unknown")
        outcome = ev.get("outcome", "unknown")
        bytes_in = float(network.get("bytes_in") or 0)

        # 1. Severity Z-Score
        z = self.baseline.severity_z_score(src_ip, severity)
        if z >= 3.0:
            score += _SCORE_WEIGHTS["severity_zscore_high"]
            reasons.append(f"Severity z-score={z:.1f}σ (>3σ from baseline for {src_ip})")
        elif z >= 2.0:
            score += _SCORE_WEIGHTS["severity_zscore_medium"]
            reasons.append(f"Elevated severity z-score={z:.1f}σ for {src_ip}")

        # 2. Bytes IQR Outlier
        if bytes_in > 0 and self.baseline.bytes_iqr_outlier(src_ip, bytes_in):
            score += _SCORE_WEIGHTS["bytes_iqr_outlier"]
            reasons.append(f"Unusual bytes_in={bytes_in:.0f} (IQR outlier for {src_ip})")

        # 3. Burst Detection
        if self.baseline.is_burst(src_ip):
            score += _SCORE_WEIGHTS["burst_detected"]
            reasons.append(f"Event burst detected from {src_ip} (>3x baseline rate)")

        # 4. Rare Category
        if self.baseline.is_rare_category(category):
            score += _SCORE_WEIGHTS["rare_category"]
            reasons.append(f"Rare event category: '{category}' (<1% of historical events)")

        # 5. Threat IP from enrichment
        if enrichment.get("threat_ip_detected"):
            score += _SCORE_WEIGHTS["threat_ip"]
            threat_intel = enrichment.get("src_ip_context", {}).get("threat_intel", [])
            reasons.append(f"Threat intelligence match for {src_ip}: {threat_intel}")

        # 6. Auth Failure Chain — only authentication-category events touch this
        # counter. Unrelated traffic from the same IP (the common case: a
        # brute-forcer also generating normal packets) must NOT reset it, or
        # the chain never accumulates. Only a *successful* auth from that IP
        # clears it.
        if category == "authentication":
            if outcome == "failure":
                fail_count = self._auth_failures.get(src_ip, 0) + 1
                self._auth_failures[src_ip] = fail_count
                if fail_count >= 5:
                    score += _SCORE_WEIGHTS["auth_failure_chain"]
                    reasons.append(
                        f"Authentication failure chain: {fail_count} failures from {src_ip}"
                    )
            elif outcome == "success" and src_ip in self._auth_failures:
                del self._auth_failures[src_ip]

        # Clamp score to [0.0, 1.0]
        score = min(1.0, round(score, 3))

        # Annotate event (pure annotation — never mutates original event block)
        if score >= _SCORE_THRESHOLD:
            orig_sev = float(ev.get("severity_numeric") or 5.0)
            calculated_risk = round(min(10.0, orig_sev * (1.0 + score)), 1)
            analytics_block = {
                "anomaly_score": score,
                "anomaly_reasons": reasons,
                "is_anomalous": score >= 0.5,
                "risk_score": calculated_risk,
            }
            event["analytics"] = analytics_block

            logger.debug(
                "Anomaly detected: event_id=%s score=%.3f reasons=%s",
                event.get("event_id", "?"), score, reasons,
            )

        return event

    def update_baseline(self, event: dict[str, Any]) -> None:
        """Update baseline with a processed event."""
        self.baseline.update(event)

    def save_baseline(self) -> None:
        """Persist baseline to disk."""
        self.baseline.save()

    def analyze_file(self, ndjson_path: Path, output_path: Path | None = None) -> dict[str, Any]:
        """
        Analyze all events in an NDJSON file.
        Returns summary stats. Optionally writes anomalous events to output_path.
        """
        ndjson_path = Path(ndjson_path)
        if not ndjson_path.exists():
            raise FileNotFoundError(f"Events file not found: {ndjson_path}")

        total = 0
        anomalous = 0
        out_file = None

        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            out_file = open(output_path, "w", encoding="utf-8")

        try:
            with open(ndjson_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    # First pass: update baseline
                    self.update_baseline(event)
                    total += 1

            # Second pass: analyze with populated baseline
            with open(ndjson_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    annotated = self.analyze(event)
                    if "analytics" in annotated:
                        anomalous += 1
                        if out_file:
                            out_file.write(json.dumps(annotated, default=str) + "\n")
        finally:
            if out_file:
                out_file.close()

        self.save_baseline()

        return {
            "total_events": total,
            "anomalous_events": anomalous,
            "anomaly_rate_pct": round(100 * anomalous / total, 2) if total > 0 else 0.0,
        }
