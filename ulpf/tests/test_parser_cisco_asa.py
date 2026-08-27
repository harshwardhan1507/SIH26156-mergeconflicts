"""Tests for the Cisco ASA parser."""
import pytest
from ulpf.parsers.cisco_asa import CiscoASAParser


@pytest.fixture
def parser():
    return CiscoASAParser()


SAMPLE_PERMIT = (
    '<166>Aug 15 14:22:10 asa01.corp.example.com '
    '%ASA-6-106100: access-list OUTSIDE_IN permitted tcp '
    'OUTSIDE/10.0.0.5(44123) -> INSIDE/192.168.1.100(443) hit-cnt 1'
)

SAMPLE_DENY = (
    '<162>Aug 15 14:23:01 asa01.corp.example.com '
    '%ASA-2-106016: Deny IP spoof from (10.0.0.99) to 192.168.1.50 on interface OUTSIDE'
)


def test_match(parser):
    assert parser.match(SAMPLE_PERMIT)
    assert parser.match(SAMPLE_DENY)
    assert not parser.match('<38>Aug 15 12:34:56 proxy01 squid[2048]: TCP_MISS')


def test_extract_vendor_product(parser):
    fields = parser.extract(SAMPLE_PERMIT)
    assert fields['vendor'] == 'Cisco'
    assert fields['product'] == 'ASA'


def test_extract_permit(parser):
    fields = parser.extract(SAMPLE_PERMIT)
    assert fields['asa_mnemonic'] == '106100'
    assert fields['acl_name'] == 'OUTSIDE_IN'
    assert fields['acl_action'] == 'permitted'
    assert fields['proto'] == 'tcp'
    assert fields['src_ip'] == '10.0.0.5'
    assert fields['src_port'] == 44123
    assert fields['dst_ip'] == '192.168.1.100'
    assert fields['dst_port'] == 443


def test_severity_ues_critical(parser):
    fields = parser.extract(SAMPLE_DENY)
    assert fields['severity_ues'] == 8  # ASA severity 2 = critical = 8


def test_hostname_extracted(parser):
    fields = parser.extract(SAMPLE_PERMIT)
    assert fields['hostname'] == 'asa01.corp.example.com'


def test_timestamp_parsed(parser):
    fields = parser.extract(SAMPLE_PERMIT)
    assert fields['timestamp_dt'] is not None
