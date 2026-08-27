"""Tests for the JSON passthrough parser."""
import pytest
from ulpf.parsers.json_passthrough import JSONPassthroughParser


@pytest.fixture
def parser():
    return JSONPassthroughParser()


SAMPLE = '{"ts":"2024-03-15T10:22:45Z","host":"vpn-gw01","event":"vpn_connect","user":"alice","src":"203.0.113.5","dst":"10.0.0.1","proto":"udp","bytes_in":1234,"bytes_out":5678,"result":"success","severity":3}'


def test_match(parser):
    assert parser.match(SAMPLE)
    assert not parser.match('<134>1 2024-03-15T10:22:45Z host app 1 - - msg')
    assert not parser.match('CEF:0|Vendor|Product|1|id|name|5|ext=val')
    assert not parser.match('not json at all')


def test_extract_fields(parser):
    fields = parser.extract(SAMPLE)
    assert fields['host'] == 'vpn-gw01'
    assert fields['event'] == 'vpn_connect'
    assert fields['user'] == 'alice'
    assert fields['proto'] == 'udp'
    assert fields['bytes_in'] == 1234
    assert fields['bytes_out'] == 5678
    assert fields['result'] == 'success'


def test_ip_validation(parser):
    fields = parser.extract(SAMPLE)
    assert fields['src'] == '203.0.113.5'
    assert fields['dst'] == '10.0.0.1'


def test_timestamp_parsed(parser):
    fields = parser.extract(SAMPLE)
    assert fields['timestamp_dt'] is not None
    assert '2024-03-15' in fields['timestamp_dt']


def test_severity_ues(parser):
    fields = parser.extract(SAMPLE)
    assert fields['severity_ues'] == 3


def test_invalid_json(parser):
    from ulpf.parsers.base import ParseError
    with pytest.raises(ParseError):
        parser.extract('{invalid json}')
