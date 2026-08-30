"""
Unit tests for ULPF CLI sources command group.
"""
from __future__ import annotations

import json
from pathlib import Path
from click.testing import CliRunner
import yaml

from ulpf.cli import main


def test_cli_sources_list(tmp_path):
    runner = CliRunner()
    result = runner.invoke(main, ["sources", "list", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "Registered Log Sources" in result.output
    assert "cef_firewalls" in result.output
    assert "cisco_asa" in result.output


def test_cli_sources_infer():
    runner = CliRunner()
    sample = 'time="2026-08-30T10:00:00Z" srcip=10.0.0.1 dstip=192.168.1.1 srcport=44123 dstport=80 action=allow user=alice'
    result = runner.invoke(main, ["sources", "infer", "--sample", sample, "--name", "cli_test_fw", "--vendor", "VendorX"])
    assert result.exit_code == 0
    assert "name: cli_test_fw" in result.output
    assert "vendor: VendorX" in result.output
    assert "network.src_ip: srcip" in result.output


def test_cli_sources_infer_to_file(tmp_path):
    runner = CliRunner()
    sample = '{"time": "2026-08-30T10:00:00Z", "client_ip": "10.0.0.5", "username": "bob", "status": "login_ok"}'
    out_file = tmp_path / "inferred_auth.yaml"
    result = runner.invoke(main, ["sources", "infer", "--sample", sample, "--name", "auth_inferred", "--output", str(out_file)])
    assert result.exit_code == 0
    assert out_file.exists()
    with open(out_file, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert data["name"] == "auth_inferred"
    assert data["parser"]["type"] == "json"


def test_cli_sources_test(tmp_path):
    runner = CliRunner()
    cfg = {
        "name": "test_cfg",
        "vendor": "Acme",
        "product": "Gate",
        "version": "1.0.0",
        "parser": {
            "type": "key_value",
            "pair_delimiter": " ",
            "kv_delimiter": "=",
        },
        "normalize": {
            "source.vendor": "Acme",
            "network.src_ip": "src",
            "event.action": "act",
        }
    }
    cfg_file = tmp_path / "test_cfg.yaml"
    cfg_file.write_text(yaml.dump(cfg), encoding="utf-8")

    sample = "src=192.168.1.50 dst=10.0.0.1 act=allow"
    result = runner.invoke(main, ["sources", "test", "--config", str(cfg_file), "--sample", sample])
    assert result.exit_code == 0
    assert "Match status: [MATCHED]" in result.output
    assert "Acme" in result.output
    assert "192.168.1.50" in result.output


def test_cli_sources_add_enable_disable(tmp_path):
    runner = CliRunner()
    cfg = {
        "name": "dynamic_sensor",
        "vendor": "SensorCorp",
        "product": "SensorPro",
        "version": "1.0.0",
        "parser": {
            "type": "json",
        },
        "normalize": {
            "source.vendor": "SensorCorp",
        }
    }
    cfg_file = tmp_path / "sensor.yaml"
    cfg_file.write_text(yaml.dump(cfg), encoding="utf-8")

    # Add
    res_add = runner.invoke(main, ["sources", "add", "--config", str(cfg_file), "--output-dir", str(tmp_path)])
    assert res_add.exit_code == 0
    assert "dynamic_sensor" in res_add.output

    # Disable
    res_dis = runner.invoke(main, ["sources", "disable", "dynamic_sensor", "--output-dir", str(tmp_path)])
    assert res_dis.exit_code == 0
    assert "disabled" in res_dis.output

    # Enable
    res_en = runner.invoke(main, ["sources", "enable", "dynamic_sensor", "--output-dir", str(tmp_path)])
    assert res_en.exit_code == 0
    assert "enabled" in res_en.output
