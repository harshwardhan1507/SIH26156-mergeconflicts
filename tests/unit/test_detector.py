"""Tests for the FormatDetector."""
import pytest

from ulpf.core.detector import FormatDetector


@pytest.fixture
def det() -> FormatDetector:
    return FormatDetector()


_CASES = [
    # (raw_line, expected_format_id)
    ('<134>1 2024-03-15T10:22:45.123456+00:00 fw01 sshd 1234 ID47 - User login', 'syslog_rfc5424'),
    ('<38>Aug 15 12:34:56 proxy01 squid[2048]: TCP_MISS/200 4321 GET http://example.com/', 'syslog_rfc3164'),
    ('CEF:0|Cisco|ASA|9.14|106023|Deny TCP|5|src=10.1.1.5 dst=203.0.113.42', 'cef'),
    ('<166>Aug 15 14:22:10 asa01 %ASA-6-106100: access-list OUTSIDE_IN permitted tcp', 'cisco_asa'),
    ('{"ts":"2024-03-15T10:22:45Z","host":"vpn-gw01","event":"vpn_connect"}', 'json_passthrough'),
    ('2024-03-15T10:22:45.000+00:00,0101010101,TRAFFIC,start,0,2024-03-15 10:22:45,10.1.0.5,198.51.100.20,10.1.0.5,198.51.100.20,allow-internet,alice,,web-browsing,vsys1,trust,untrust,eth1,eth2,log,fin,1,1,443,58432,0,0,0x0,tcp,allow,0,0,0,0,2024-03-15 10:22:50,1,any,0,0,0x0,US,CN,0,1,0', 'paloalto_csv'),
    ('LEEF:1.0|Vendor|Product|1.0|event_id|', 'leef'),
]


@pytest.mark.parametrize('raw_line,expected', _CASES)
def test_detect(det, raw_line, expected):
    assert det.detect(raw_line) == expected
