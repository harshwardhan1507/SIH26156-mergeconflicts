"""Tests for LEEF 1.0 and 2.0 parser."""
import pytest

from ulpf.parsers.leef import LEEFParser

PARSER = LEEFParser()


def test_leef10_match():
    line = "LEEF:1.0|Cisco|ASA|9.14|106023|src=10.0.0.1\tspt=1234\tdst=203.0.113.5\tdpt=443\tproto=TCP"
    assert PARSER.match(line)


def test_leef20_match():
    line = "LEEF:2.0|Palo Alto Networks|PAN-OS|9.0|TRAFFIC|^|src=10.0.1.1^dst=8.8.8.8^proto=UDP"
    assert PARSER.match(line)


def test_no_match():
    assert not PARSER.match("Nov 15 12:00:00 host sshd[1234]: Failed")
    assert not PARSER.match("CEF:0|Cisco|ASA|1.0|106023|Deny|5|src=1.2.3.4")


def test_leef10_extract_basic():
    line = "LEEF:1.0|Cisco|ASA|9.14|106023|src=10.0.0.1\tspt=1234\tdst=203.0.113.5\tdpt=443\tproto=TCP\tusrName=alice"
    result = PARSER.extract(line)
    assert result["vendor"] == "Cisco"
    assert result["product"] == "ASA"
    assert result["event_id"] == "106023"
    assert result["src_ip"] == "10.0.0.1"
    assert result["dst_ip"] == "203.0.113.5"
    assert result["src_port"] == 1234
    assert result["dst_port"] == 443
    assert result["protocol"] == "tcp"
    assert result["username"] == "alice"


def test_leef10_severity_numeric():
    line = "LEEF:1.0|IBM|QRadar|7.0|EVT|src=1.1.1.1\tsev=8"
    result = PARSER.extract(line)
    assert result["severity_numeric"] == 8


def test_leef10_severity_text():
    line = "LEEF:1.0|IBM|QRadar|7.0|EVT|src=1.1.1.1\tsev=high"
    result = PARSER.extract(line)
    assert result["severity_numeric"] == 8


def test_leef20_custom_delimiter():
    line = "LEEF:2.0|Vendor|Product|1.0|E1|^|src=10.0.0.1^dst=8.8.8.8^proto=udp^sev=3"
    result = PARSER.extract(line)
    assert result["src_ip"] == "10.0.0.1"
    assert result["dst_ip"] == "8.8.8.8"
    assert result["severity_numeric"] == 3


def test_leef_bytes():
    line = "LEEF:1.0|F5|BigIP|15.0|REQ|src=10.1.1.1\tsrcBytes=1024\tdstBytes=4096"
    result = PARSER.extract(line)
    assert result["bytes_in"] == 1024
    assert result["bytes_out"] == 4096


def test_leef_log_format():
    line = "LEEF:1.0|Vendor|Product|1.0|EVT|src=1.1.1.1"
    result = PARSER.extract(line)
    assert result["_log_format"] == "leef"


def test_leef_invalid_raises():
    with pytest.raises(Exception):
        PARSER.extract("this is not a leef line at all")
