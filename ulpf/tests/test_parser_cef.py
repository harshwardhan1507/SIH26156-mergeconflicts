"""Tests for the CEF parser."""
import pytest
from ulpf.parsers.cef import CEFParser


@pytest.fixture
def parser():
    return CEFParser()


SAMPLE = (
    'CEF:0|Cisco|ASA|9.14|106023|Deny TCP (no connection)|5|'
    'src=10.1.1.5 spt=44321 dst=203.0.113.42 dpt=443 proto=TCP act=deny dhost=fw01'
)


def test_match(parser):
    assert parser.match(SAMPLE)
    assert not parser.match('<134>1 2024-03-15T10:22:45Z host app 1 - - msg')


def test_extract_header_fields(parser):
    fields = parser.extract(SAMPLE)
    assert fields['DeviceVendor'] == 'Cisco'
    assert fields['DeviceProduct'] == 'ASA'
    assert fields['DeviceVersion'] == '9.14'
    assert fields['SignatureID'] == '106023'
    assert fields['Name'] == 'Deny TCP (no connection)'
    assert fields['Severity'] == '5'


def test_extract_extension_fields(parser):
    fields = parser.extract(SAMPLE)
    assert fields.get('src') == '10.1.1.5'
    assert fields.get('dpt') == '443'
    assert fields.get('proto') == 'TCP'
    assert fields.get('act') == 'deny'


def test_severity_ues(parser):
    fields = parser.extract(SAMPLE)
    assert isinstance(fields['severity_ues'], int)
    assert fields['severity_ues'] == 5  # CEF 5 -> UES 5


def test_syslog_prefix_stripped(parser):
    line = 'CEF:0|Palo Alto Networks|PAN-OS|10.2|threat-12345|Malware|9|src=10.0.5.100 dst=198.51.100.200'
    assert parser.match(line)
    fields = parser.extract(line)
    assert fields['DeviceVendor'] == 'Palo Alto Networks'
    assert fields['severity_ues'] == 9
