"""Tests for Generic XML and Windows Event Log parser."""
import pytest

from ulpf.parsers.base import ParseError
from ulpf.parsers.xml_generic import XMLGenericParser

PARSER = XMLGenericParser()

WIN_EVENT_4624 = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2026-08-27T08:00:00.000000Z"/>
    <Computer>WIN-SERVER01</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">alice</Data>
    <Data Name="IpAddress">192.168.1.10</Data>
    <Data Name="WorkstationName">DESKTOP-ABC</Data>
  </EventData>
</Event>"""

WIN_EVENT_4625 = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2026-08-27T08:00:01.000000Z"/>
    <Computer>WIN-SERVER01</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">bob</Data>
    <Data Name="IpAddress">203.0.113.5</Data>
  </EventData>
</Event>"""

GENERIC_XML = """<log><timestamp>2026-08-27T08:00:00Z</timestamp><level>ERROR</level><message>Disk full</message></log>"""


def test_windows_event_match():
    assert PARSER.match(WIN_EVENT_4624)
    assert PARSER.match(WIN_EVENT_4625)


def test_generic_xml_match():
    assert PARSER.match(GENERIC_XML)
    assert PARSER.match("<?xml version=\"1.0\"?><root/>")


def test_no_match():
    assert not PARSER.match("Nov 15 12:00:00 host sshd: Failed")
    assert not PARSER.match("LEEF:1.0|...")
    assert not PARSER.match("{\"key\": \"value\"}")


def test_4624_logon_success():
    result = PARSER.extract(WIN_EVENT_4624)
    assert result["windows_event_id"] == 4624
    assert result["category"] == "authentication"
    assert result["severity_numeric"] == 3
    assert result["username"] == "alice"
    assert result["hostname"] == "WIN-SERVER01"
    assert result["src_ip"] == "192.168.1.10"
    assert result["is_windows_event_log"] is True


def test_4625_logon_failure():
    result = PARSER.extract(WIN_EVENT_4625)
    assert result["windows_event_id"] == 4625
    assert result["category"] == "authentication"
    assert result["severity_numeric"] == 7
    assert result["username"] == "bob"


def test_generic_xml_extract():
    result = PARSER.extract(GENERIC_XML)
    assert result["_log_format"] == "xml"
    assert result["is_windows_event_log"] is False


def test_invalid_xml_raises():
    with pytest.raises(Exception):
        PARSER.extract("<unclosed>")


def test_doctype_declarations_are_rejected():
    """
    DTDs are refused so entity expansion cannot amplify a log record.

    A few hundred bytes of nested entity definitions otherwise expand into
    hundreds of kilobytes. CPython's expat caps the amplification factor, but
    that backstop is runtime-dependent, so the parser must not rely on it.
    """
    bomb = (
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
        "]><lolz>&lol2;</lolz>"
    )
    assert PARSER.match(bomb) is False
    with pytest.raises(ParseError, match="document type definitions"):
        PARSER.extract(bomb)


def test_external_entity_references_are_rejected():
    """An XXE payload must never reach the filesystem."""
    xxe = (
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        "<r>&x;</r>"
    )
    assert PARSER.match(xxe) is False
    with pytest.raises(ParseError):
        PARSER.extract(xxe)


def test_ordinary_windows_event_xml_still_parses():
    """Hardening must not reject the Windows Event XML the parser exists for."""
    event = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>4624</EventID><Computer>DC01</Computer></System></Event>"
    )
    fields = PARSER.extract(event)
    assert fields["Computer"] == "DC01"
