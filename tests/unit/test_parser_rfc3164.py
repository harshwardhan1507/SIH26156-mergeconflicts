"""Tests for the RFC 3164 syslog parser."""
import pytest

from ulpf.parsers.syslog_rfc3164 import SyslogRFC3164Parser


@pytest.fixture
def parser():
    return SyslogRFC3164Parser()


SAMPLE = '<38>Aug 15 12:34:56 proxy01 squid[2048]: TCP_MISS/200 4321 GET http://cdn.example.com/asset.js'


def test_match(parser):
    assert parser.match(SAMPLE)
    # Should not match RFC5424
    assert not parser.match('<134>1 2024-03-15T10:22:45.123456+00:00 host app 1 - - msg')
    # Should not match ASA
    assert not parser.match('<166>Aug 15 14:22:10 asa01 %ASA-6-106100: access-list OUT permitted tcp')


def test_extract_fields(parser):
    fields = parser.extract(SAMPLE)
    assert fields['hostname'] == 'proxy01'
    assert fields['tag'] == 'squid'
    assert fields['pid'] == '2048'
    assert 'TCP_MISS' in fields['message']
    assert fields['priority'] == 38
    assert fields['facility'] == 4
    assert fields['syslog_severity'] == 6  # 38 & 7 = 6


def test_timestamp_injects_year(parser):
    fields = parser.extract(SAMPLE)
    assert fields['timestamp_dt'] is not None
    # Year should be injected (current year)
    import datetime
    assert str(datetime.datetime.now().year) in fields['timestamp_dt']


def test_severity_ues(parser):
    fields = parser.extract(SAMPLE)
    assert 0 <= fields['severity_ues'] <= 10
