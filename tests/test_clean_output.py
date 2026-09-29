from pathlib import Path
from tools.windows.launcher import bootstrap_sample_data_if_needed

def test_bootstrap_sample_data_is_noop(tmp_path: Path):
    events_file = tmp_path / "events.ndjson"
    bootstrap_sample_data_if_needed(tmp_path)
    assert not events_file.exists() or events_file.stat().st_size == 0
