"""
Unit and integration tests for CLI --raw-store {file,segmented} option.
"""
from __future__ import annotations

import sqlite3

from click.testing import CliRunner

from ulpf.cli import main
from ulpf.core.segmented_raw_store import SegmentedRawStore


def test_cli_ingest_raw_store_file_default(tmp_path):
    runner = CliRunner()
    sample_file = tmp_path / "sample.log"
    sample_file.write_text(
        "CEF:0|Cisco|ASA|9.14|106023|Deny TCP|5|src=10.1.1.5 spt=44321 dst=203.0.113.42 dpt=443 proto=TCP\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "out_file"

    result = runner.invoke(main, ["ingest", "-i", str(sample_file), "-o", str(out_dir)])
    assert result.exit_code == 0
    assert "raw_store=file" in result.output
    assert (out_dir / "raw_store").exists()
    assert not (out_dir / "raw_segments").exists()


def test_cli_ingest_raw_store_segmented(tmp_path):
    runner = CliRunner()
    sample_file = tmp_path / "sample.log"
    sample_file.write_text(
        "CEF:0|Cisco|ASA|9.14|106023|Deny TCP|5|src=10.1.1.5 spt=44321 dst=203.0.113.42 dpt=443 proto=TCP\n"
        "CEF:0|CheckPoint|VPN-1|1.0|Logon|User Logon|3|src=192.168.1.50 dst=10.0.0.1 suser=alice act=allow\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "out_seg"

    result = runner.invoke(
        main,
        ["ingest", "-i", str(sample_file), "-o", str(out_dir), "--raw-store", "segmented", "--tenant-id", "tenant_alpha"],
    )
    assert result.exit_code == 0
    assert "raw_store=segmented" in result.output

    # Check segmented storage directory & SQLite index
    raw_segments_dir = out_dir / "raw_segments"
    assert raw_segments_dir.exists()
    index_db = raw_segments_dir / "index.sqlite3"
    assert index_db.exists()

    # Query index to verify records were indexed in segmented storage
    conn = sqlite3.connect(index_db)
    try:
        cur = conn.cursor()
        rows = cur.execute("SELECT event_id, tenant_id, segment_path, offset, length, sha256 FROM raw_index").fetchall()
        assert len(rows) == 2
        for r in rows:
            assert r[1] == "tenant_alpha"
            assert "segment-" in r[2]
            assert r[4] > 0

            # Verify byte-exact retrieval using SegmentedRawStore
            store = SegmentedRawStore(raw_segments_dir)
            payload = store.get(r[0])
            assert payload is not None
            assert "CEF:0|" in payload
    finally:
        conn.close()
