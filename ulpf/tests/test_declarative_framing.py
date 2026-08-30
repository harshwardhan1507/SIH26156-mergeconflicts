"""
Unit tests for Declarative Source Framing Integration.
"""
from __future__ import annotations

import yaml
from pathlib import Path

from ulpf.core.declarative import DeclarativeSourceParser, validate_declarative_config


def test_declarative_multiline_framing_and_extraction():
    config_path = Path(__file__).parent.parent / "schemas" / "declarative_sources" / "app_stacktrace_multiline.yaml"
    assert config_path.exists()

    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    valid, errors = validate_declarative_config(cfg)
    assert valid, f"Config validation errors: {errors}"

    parser = DeclarativeSourceParser(cfg)

    # Multiline stream: 1 multi-line event with Java stack trace + 1 single line event
    raw_stream = [
        "2026-08-30 12:00:00 [http-nio-8080-exec-1] ERROR com.enterprise.auth.AuthController - Database connection timeout\n",
        "java.sql.SQLException: Connection pool exhausted\n",
        "\tat com.enterprise.db.Pool.getConnection(Pool.java:42)\n",
        "\tat com.enterprise.auth.AuthController.login(AuthController.java:115)\n",
        "2026-08-30 12:00:01 [http-nio-8080-exec-2] INFO com.enterprise.auth.AuthController - Retry connection successful\n",
    ]

    # Frame the incoming stream
    frames = list(parser.frame(raw_stream))
    assert len(frames) == 2, f"Expected 2 framed events, got {len(frames)}"

    # First event contains multiline stack trace
    event1_text = frames[0].raw_text
    assert "Database connection timeout" in event1_text
    assert "java.sql.SQLException: Connection pool exhausted" in event1_text
    assert "\tat com.enterprise.db.Pool.getConnection" in event1_text

    # Extract fields from framed event
    extracted1 = parser.extract(event1_text)
    assert extracted1["timestamp"] == "2026-08-30 12:00:00"
    assert extracted1["thread"] == "http-nio-8080-exec-1"
    assert extracted1["level"] == "ERROR"
    assert extracted1["logger"] == "com.enterprise.auth.AuthController"
    assert "Connection pool exhausted" in extracted1["message"]

    # Second event is discrete and cleanly isolated
    event2_text = frames[1].raw_text
    assert "Retry connection successful" in event2_text
    assert "java.sql.SQLException" not in event2_text

    extracted2 = parser.extract(event2_text)
    assert extracted2["timestamp"] == "2026-08-30 12:00:01"
    assert extracted2["level"] == "INFO"
