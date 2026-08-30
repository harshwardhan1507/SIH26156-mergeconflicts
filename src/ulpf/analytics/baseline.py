"""
Baseline Profiler for ULPF Analytics Engine.

Builds and persists rolling statistical baselines from normalized UES events.
Baselines power the anomaly detector by providing per-dimension expected ranges.

Persists to output/analytics_baseline.json — reloaded on next run.
No external dependencies — pure Python math only.
"""
from __future__ import annotations

import json
import logging
import math
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_BASELINE_FILE = "analytics_baseline.json"
# Rolling window: keep last N observations per dimension
_WINDOW_SIZE = 1000


class RollingStats:
    """Welford online algorithm for rolling mean and variance."""

    def __init__(self, window: int = _WINDOW_SIZE) -> None:
        self._window = window
        self._values: deque[float] = deque(maxlen=window)
        self._count = 0
        self._mean = 0.0
        self._M2 = 0.0  # sum of squared deviations

    def update(self, value: float) -> None:
        # Remove oldest value from Welford if window full
        if len(self._values) == self._window:
            old = self._values[0]
            self._count -= 1
            old_mean = self._mean
            self._mean -= (old - self._mean) / max(self._count, 1)
            self._M2 -= (old - old_mean) * (old - self._mean)

        self._values.append(value)
        self._count += 1
        delta = value - self._mean
        self._mean += delta / self._count
        delta2 = value - self._mean
        self._M2 += delta * delta2

    @property
    def mean(self) -> float:
        return self._mean

    @property
    def variance(self) -> float:
        return self._M2 / self._count if self._count > 1 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)

    @property
    def count(self) -> int:
        return self._count

    def z_score(self, value: float) -> float:
        """Return standard deviations from mean. Handles zero-variance spike when value differs from constant baseline."""
        s = self.std
        if s > 0:
            return abs(value - self._mean) / s
        if self._count >= 5 and abs(value - self._mean) > 1e-4:
            return 10.0  # Deviation from constant baseline
        return 0.0

    def iqr_outlier(self, value: float) -> bool:
        """True if value is an IQR outlier (> Q3 + 1.5*IQR or < Q1 - 1.5*IQR)."""
        if len(self._values) < 10:
            return False
        sorted_vals = sorted(self._values)
        n = len(sorted_vals)
        q1 = sorted_vals[n // 4]
        q3 = sorted_vals[3 * n // 4]
        iqr = q3 - q1
        return value < (q1 - 1.5 * iqr) or value > (q3 + 1.5 * iqr)

    def to_dict(self) -> dict:
        return {
            "count": self._count,
            "mean": self._mean,
            "std": self.std,
            "values": list(self._values)[-100:],  # keep last 100 for persistence
        }

    @classmethod
    def from_dict(cls, d: dict, window: int = _WINDOW_SIZE) -> RollingStats:
        obj = cls(window)
        for v in d.get("values", []):
            obj.update(float(v))
        return obj


class BaselineProfiler:
    """
    Tracks rolling baselines for multiple dimensions:
    - severity_numeric per source IP
    - events per minute per source IP (burst detection)
    - category distribution (rare category detection)
    - bytes_in / bytes_out per source IP
    """

    def __init__(self, output_dir: Path | str = "output") -> None:
        self.output_dir = Path(output_dir)
        self.baseline_path = self.output_dir / _BASELINE_FILE

        # Per-IP severity baseline
        self._ip_severity: dict[str, RollingStats] = defaultdict(RollingStats)
        # Per-IP bytes baseline
        self._ip_bytes: dict[str, RollingStats] = defaultdict(RollingStats)
        # Category counts
        self._category_counts: dict[str, int] = defaultdict(int)
        self._total_events = 0
        # Per-IP event timestamps (for burst detection)
        self._ip_event_times: dict[str, deque] = defaultdict(lambda: deque(maxlen=500))

        self._load()

    def _load(self) -> None:
        if not self.baseline_path.exists():
            return
        try:
            with open(self.baseline_path, encoding="utf-8") as f:
                data = json.load(f)
            for ip, d in data.get("ip_severity", {}).items():
                self._ip_severity[ip] = RollingStats.from_dict(d)
            for ip, d in data.get("ip_bytes", {}).items():
                self._ip_bytes[ip] = RollingStats.from_dict(d)
            self._category_counts = defaultdict(int, data.get("category_counts", {}))
            self._total_events = data.get("total_events", 0)
            logger.info("Baseline loaded: %d events", self._total_events)
        except Exception as exc:
            logger.warning("Could not load baseline: %s", exc)

    def save(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        data = {
            "total_events": self._total_events,
            "category_counts": dict(self._category_counts),
            "ip_severity": {ip: s.to_dict() for ip, s in self._ip_severity.items()},
            "ip_bytes": {ip: s.to_dict() for ip, s in self._ip_bytes.items()},
        }
        try:
            with open(self.baseline_path, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception as exc:
            logger.warning("Could not save baseline: %s", exc)

    def update(self, event: dict[str, Any]) -> None:
        """Update baseline stats from a UES event."""
        self._total_events += 1

        network = event.get("network") or {}
        ev = event.get("event") or {}
        src_ip = network.get("src_ip") or "unknown"
        severity = float(ev.get("severity_numeric", 5))
        category = ev.get("category", "unknown")
        bytes_in = float(network.get("bytes_in") or 0)
        bytes_out = float(network.get("bytes_out") or 0)

        self._ip_severity[src_ip].update(severity)
        if bytes_in > 0:
            self._ip_bytes[src_ip].update(bytes_in)
        if bytes_out > 0:
            self._ip_bytes[src_ip].update(bytes_out)
        self._category_counts[category] += 1
        self._ip_event_times[src_ip].append(time.time())

    def is_burst(self, src_ip: str, window_seconds: int = 60, threshold_multiplier: float = 3.0) -> bool:
        """
        True if src_ip recent event rate (events/sec in recent window) exceeds
        threshold_multiplier x historical baseline rate (events/sec across observation span).
        Requires minimum 15 total events and minimum 10 recent events to prevent false positives.
        """
        times = self._ip_event_times.get(src_ip)
        if not times or len(times) < 15:
            return False
        now = time.time()
        span = times[-1] - times[0]
        if span < 10.0:
            return False
        baseline_rate = len(times) / span
        recent_count = sum(1 for t in times if now - t <= window_seconds)
        if recent_count < 10:
            return False
        recent_rate = recent_count / float(window_seconds)
        return recent_rate > (baseline_rate * threshold_multiplier)

    def is_rare_category(self, category: str, threshold_pct: float = 0.01) -> bool:
        """True if this category accounts for < threshold_pct of total events."""
        if self._total_events < 100:
            return False
        count = self._category_counts.get(category, 0)
        return (count / self._total_events) < threshold_pct

    def severity_z_score(self, src_ip: str, severity: float) -> float:
        stats = self._ip_severity.get(src_ip)
        if stats is None or stats.count < 5:
            return 0.0
        return stats.z_score(severity)

    def bytes_iqr_outlier(self, src_ip: str, bytes_val: float) -> bool:
        stats = self._ip_bytes.get(src_ip)
        if stats is None or stats.count < 10:
            return False
        return stats.iqr_outlier(bytes_val)
