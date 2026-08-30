"""
ML-Ready Feature Vector Extractor for UES Events.

Converts structured Universal Event Schema (UES) records into dense, normalized
numerical feature vectors (numpy / list of floats) for machine learning anomaly
detection, classification, and clustering models (e.g. Isolation Forest, Autoencoders, PCA).
"""
from __future__ import annotations

import math
from datetime import datetime
from typing import Any


class FeatureVectorExtractor:
    """Transforms UES event dicts into standardized 24-dimensional numeric feature vectors."""

    CATEGORIES = [
        "network", "authentication", "threat", "system",
        "policy", "api", "database", "unknown"
    ]

    OUTCOMES = ["success", "failure", "unknown"]

    @classmethod
    def extract_vector(cls, event: dict[str, Any]) -> list[float]:
        """
        Extract normalized numerical features from a UES event dict.
        Returns a list of 24 floating-point features in range [-1.0, 1.0].
        """
        vector: list[float] = []

        # 1. Temporal cyclical features (Hour of day & Day of week)
        ts_str = event.get("source_event_timestamp") or event.get("ingest_timestamp")
        hour = 0
        dow = 0
        if ts_str:
            try:
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                hour = dt.hour
                dow = dt.weekday()
            except Exception:
                pass

        # Hour cyclic (2 features)
        vector.append(math.sin(2 * math.pi * hour / 24.0))
        vector.append(math.cos(2 * math.pi * hour / 24.0))

        # Day of week cyclic (2 features)
        vector.append(math.sin(2 * math.pi * dow / 7.0))
        vector.append(math.cos(2 * math.pi * dow / 7.0))

        # 2. Severity features
        ev = event.get("event") or {}
        sev = float(ev.get("severity_numeric") or 5.0)
        vector.append(sev / 10.0)  # Normalized severity in [0, 1]
        vector.append(1.0 if ev.get("severity_inferred") else 0.0)

        # 3. Network Volume features (Log-scaled)
        net = event.get("network") or {}
        bytes_in = float(net.get("bytes_in") or 0)
        bytes_out = float(net.get("bytes_out") or 0)
        # Log10(1 + bytes) normalized by max typical 1GB (log10(1e9) ~ 9)
        vector.append(min(1.0, math.log10(1 + bytes_in) / 9.0))
        vector.append(min(1.0, math.log10(1 + bytes_out) / 9.0))

        # 4. Port Categorization (Well-known < 1024, Registered 1024-49151, Dynamic > 49151)
        dst_port = int(net.get("dst_port") or 0)
        vector.append(1.0 if (0 < dst_port < 1024) else 0.0)
        vector.append(1.0 if (1024 <= dst_port <= 49151) else 0.0)
        vector.append(1.0 if (dst_port > 49151) else 0.0)

        # 5. Outcome One-Hot (3 features)
        outcome = (ev.get("outcome") or "unknown").lower()
        for out_opt in cls.OUTCOMES:
            vector.append(1.0 if outcome == out_opt else 0.0)

        # 6. Threat & Cloud Indicators (2 features)
        enrichment = event.get("enrichment") or {}
        vector.append(1.0 if enrichment.get("threat_ip_detected") else 0.0)
        src_ctx = enrichment.get("src_ip_context") or {}
        vector.append(1.0 if src_ctx.get("cloud_provider") else 0.0)

        # 7. Category One-Hot (8 features)
        cat = (ev.get("category") or "unknown").lower()
        for cat_opt in cls.CATEGORIES:
            vector.append(1.0 if cat == cat_opt else 0.0)

        return vector

    @classmethod
    def get_feature_names(cls) -> list[str]:
        names = [
            "hour_sin", "hour_cos", "dow_sin", "dow_cos",
            "severity_norm", "severity_inferred",
            "log_bytes_in", "log_bytes_out",
            "port_well_known", "port_registered", "port_dynamic",
            "outcome_success", "outcome_failure", "outcome_unknown",
            "threat_detected", "cloud_origin",
        ]
        for c in cls.CATEGORIES:
            names.append(f"category_{c}")
        return names
