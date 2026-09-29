from pathlib import Path

from fastapi.testclient import TestClient

from ulpf_dashboard.app import create_app


def test_dashboard_starts_live_monitor_in_lifespan(tmp_path: Path):
    app = create_app(output_dir=tmp_path, enable_live_monitor=True)
    with TestClient(app) as client:
        res = client.get("/api/live-monitor/status")
        assert res.status_code == 200
        data = res.json()
        assert data["running"] is True
