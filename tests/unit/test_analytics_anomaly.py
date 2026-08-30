"""Tests for statistical anomaly detection engine."""
import json
import tempfile
from pathlib import Path

from ulpf.analytics.anomaly import AnomalyDetector
from ulpf.analytics.baseline import BaselineProfiler, RollingStats


def make_ues_event(src_ip="10.0.0.1", severity=5, category="network", outcome="success", bytes_in=1000):
    return {
        "event_id": "test-001",
        "ingest_timestamp": "2026-08-27T08:00:00Z",
        "event": {"category": category, "severity_numeric": severity, "outcome": outcome},
        "network": {"src_ip": src_ip, "dst_ip": "8.8.8.8", "bytes_in": bytes_in},
        "enrichment": None,
    }


# --- RollingStats tests ---

def test_rolling_stats_basic():
    rs = RollingStats(window=100)
    for i in range(10):
        rs.update(float(i))
    assert rs.count == 10
    assert rs.mean > 0


def test_rolling_stats_z_score():
    rs = RollingStats(window=100)
    for _ in range(50):
        rs.update(5.0)
    # std is 0 when all values equal -> z_score returns 0
    assert rs.z_score(5.0) == 0.0
    # Add some variance
    rs2 = RollingStats(window=100)
    for i in range(50):
        rs2.update(float(i))  # mean=24.5, std > 0
    # Value very close to mean -> low z-score
    assert rs2.z_score(24.5) < 1.0
    # Value very far from mean -> high z-score
    assert rs2.z_score(10000.0) > 3.0


def test_rolling_stats_iqr_outlier():
    rs = RollingStats(window=100)
    for _ in range(50):
        rs.update(100.0)
    rs.update(100.0)  # ensure enough data
    assert rs.iqr_outlier(100000.0) is True
    assert rs.iqr_outlier(100.0) is False


# --- BaselineProfiler tests ---

def test_baseline_update_and_category():
    with tempfile.TemporaryDirectory() as tmpdir:
        profiler = BaselineProfiler(output_dir=tmpdir)
        for _ in range(200):
            profiler.update(make_ues_event(category="network"))
        for _ in range(1):
            profiler.update(make_ues_event(category="threat"))
        # "threat" is rare
        assert profiler.is_rare_category("threat")
        # "network" is common
        assert not profiler.is_rare_category("network")


def test_baseline_save_and_reload():
    with tempfile.TemporaryDirectory() as tmpdir:
        profiler = BaselineProfiler(output_dir=tmpdir)
        for _ in range(10):
            profiler.update(make_ues_event())
        profiler.save()
        # Reload
        profiler2 = BaselineProfiler(output_dir=tmpdir)
        assert profiler2._total_events == 10


# --- AnomalyDetector tests ---

def test_anomaly_detector_no_baseline_no_anomaly():
    """With empty baseline, no anomalies should be raised."""
    with tempfile.TemporaryDirectory() as tmpdir:
        detector = AnomalyDetector(output_dir=tmpdir)
        event = make_ues_event()
        result = detector.analyze(event)
        # Without baseline, z-score is 0 -> no anomaly
        assert "analytics" not in result or result.get("analytics", {}).get("anomaly_score", 0) < 0.5


def test_anomaly_detector_severity_spike():
    """After stable baseline, a high-severity event should score high."""
    with tempfile.TemporaryDirectory() as tmpdir:
        detector = AnomalyDetector(output_dir=tmpdir)
        # Build baseline: all severity 3
        for _ in range(50):
            detector.update_baseline(make_ues_event(severity=3))
        # Now analyze severity 10 — should be anomalous
        event = make_ues_event(severity=10)
        result = detector.analyze(event)
        analytics = result.get("analytics", {})
        assert analytics.get("anomaly_score", 0) > 0


def test_anomaly_detector_auth_failure_chain():
    """Repeated auth failures from same IP should accumulate score."""
    with tempfile.TemporaryDirectory() as tmpdir:
        detector = AnomalyDetector(output_dir=tmpdir)
        src = "203.0.113.99"
        for _i in range(6):
            event = make_ues_event(src_ip=src, category="authentication", outcome="failure")
            result = detector.analyze(event)
        # After 6 failures, auth_failure_chain should trigger
        analytics = result.get("analytics", {})
        reasons = analytics.get("anomaly_reasons", [])
        assert any("failure chain" in r.lower() for r in reasons)


def test_anomaly_detector_file_analysis():
    """Test analyze_file method on a temp NDJSON file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        events_file = Path(tmpdir) / "events.ndjson"
        with open(events_file, "w") as f:
            for _i in range(20):
                f.write(json.dumps(make_ues_event(severity=3)) + "\n")
            # Add one high-severity event
            f.write(json.dumps(make_ues_event(severity=10)) + "\n")

        detector = AnomalyDetector(output_dir=tmpdir)
        stats = detector.analyze_file(ndjson_path=events_file)
        assert stats["total_events"] == 21
        assert "anomaly_rate_pct" in stats


def test_threat_ip_enrichment_scores():
    """Event with threat_ip_detected should get threat_ip score."""
    with tempfile.TemporaryDirectory() as tmpdir:
        detector = AnomalyDetector(output_dir=tmpdir)
        event = make_ues_event()
        event["enrichment"] = {"threat_ip_detected": True, "src_ip_context": {"threat_intel": ["Tor exit node"]}}
        result = detector.analyze(event)
        analytics = result.get("analytics", {})
        assert analytics.get("anomaly_score", 0) >= 0.15
