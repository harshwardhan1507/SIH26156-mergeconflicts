"""Tests for the Palo Alto Networks CSV parser."""
import pytest
from ulpf.parsers.paloalto_csv import PaloAltoCSVParser


@pytest.fixture
def parser():
    return PaloAltoCSVParser()


SAMPLE = (
    '2024-03-15T10:22:45.000+00:00,0101010101,TRAFFIC,start,0,'
    '2024-03-15 10:22:45,10.1.0.5,198.51.100.20,10.1.0.5,198.51.100.20,'
    'allow-internet,alice,,web-browsing,vsys1,trust,untrust,ethernet1/1,ethernet1/2,'
    'log-default,tcp-fin,4567,1,443,58432,0,0,0x401a,tcp,allow,3072,1024,2048,10,'
    '2024-03-15 10:22:50,5,any,0,2345678,0x0,US,CN,0,5,4'
)


def test_match(parser):
    assert parser.match(SAMPLE)
    assert not parser.match('<38>Aug 15 12:34:56 host tag: msg')
    assert not parser.match('{"key": "value"}')


def test_extract_ips(parser):
    fields = parser.extract(SAMPLE)
    assert fields['src_ip'] == '10.1.0.5'
    assert fields['dst_ip'] == '198.51.100.20'


def test_extract_ports(parser):
    fields = parser.extract(SAMPLE)
    assert fields['src_port'] == 443  # col 23
    assert fields['dst_port'] == 58432  # col 24


def test_extract_action(parser):
    fields = parser.extract(SAMPLE)
    assert fields['action_raw'] == 'allow'
    assert fields['action_ues'] == 'allow'


def test_extract_user(parser):
    fields = parser.extract(SAMPLE)
    assert fields['src_user'] == 'alice'


def test_extract_proto(parser):
    fields = parser.extract(SAMPLE)
    assert fields['proto'] == 'tcp'


def test_extract_bytes(parser):
    fields = parser.extract(SAMPLE)
    assert fields['bytes_sent'] == 1024
    assert fields['bytes_received'] == 2048


def test_vendor_product(parser):
    fields = parser.extract(SAMPLE)
    assert fields['vendor'] == 'Palo Alto Networks'
    assert fields['product'] == 'PAN-OS'


def test_timestamp_parsed(parser):
    fields = parser.extract(SAMPLE)
    assert fields['timestamp_dt'] is not None
    assert '2024-03-15' in fields['timestamp_dt']
