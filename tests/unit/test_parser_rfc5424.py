"""Tests for the RFC 5424 syslog parser."""
import pytest

from ulpf.parsers.syslog_rfc5424 import SyslogRFC5424Parser


@pytest.fixture
def parser():
    return SyslogRFC5424Parser()


SAMPLE = (
    '<134>1 2024-03-15T10:22:45.123456+00:00 fw01.corp.example.com sshd 1234 ID47 '
    '[exampleSDID@32473 iut="3" eventSource="Application"] User login accepted'
)


def test_match(parser):
    assert parser.match(SAMPLE)
    assert not parser.match('<38>Aug 15 12:34:56 host tag: msg')
    assert not parser.match('CEF:0|Vendor|Product|1.0|id|name|5|ext=val')


def test_extract_fields(parser):
    fields = parser.extract(SAMPLE)
    assert fields['hostname'] == 'fw01.corp.example.com'
    assert fields['appname'] == 'sshd'
    assert fields['procid'] == '1234'
    assert fields['msgid'] == 'ID47'
    assert 'User login accepted' in fields['message']
    assert fields['priority'] == 134
    assert fields['syslog_severity'] == 6  # 134 & 7 = 6
    assert fields['syslog_severity_name'] == 'informational'


def test_structured_data(parser):
    fields = parser.extract(SAMPLE)
    assert fields.get('sd_exampleSDID@32473_iut') == '3'
    assert fields.get('sd_exampleSDID@32473_eventSource') == 'Application'


def test_timestamp_parsed(parser):
    fields = parser.extract(SAMPLE)
    assert fields['timestamp_dt'] is not None
    assert '2024-03-15' in fields['timestamp_dt']


def test_severity_ues(parser):
    fields = parser.extract(SAMPLE)
    assert isinstance(fields['severity_ues'], int)
    assert 0 <= fields['severity_ues'] <= 10


def test_nil_fields():
    parser = SyslogRFC5424Parser()
    line = '<165>1 2024-03-15T10:23:01.000000+00:00 ids01 snort 5678 - - ALERT'
    fields = parser.extract(line)
    assert fields['hostname'] == 'ids01'
    assert fields['msgid'] is None
