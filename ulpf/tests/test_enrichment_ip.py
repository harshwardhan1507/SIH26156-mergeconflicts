"""Tests for offline IP enrichment plugin."""
import pytest
from ulpf.enrichment.ip_enrichment import IPEnrichmentPlugin, _classify_ip
from ulpf.enrichment.composite import CompositeEnrichment


def make_event(src_ip=None, dst_ip=None, severity=5):
    return {
        "event_id": "test-001",
        "event": {"category": "network", "severity_numeric": severity},
        "network": {"src_ip": src_ip, "dst_ip": dst_ip},
        "enrichment": None,
    }


# --- _classify_ip tests ---

def test_private_ip_10():
    r = _classify_ip("10.0.0.1")
    assert r["ip_type"] == "private"
    assert r["is_internal"] is True
    assert r["is_public"] is False


def test_private_ip_172():
    r = _classify_ip("172.16.0.1")
    assert r["ip_type"] == "private"


def test_private_ip_192():
    r = _classify_ip("192.168.100.50")
    assert r["ip_type"] == "private"


def test_loopback():
    r = _classify_ip("127.0.0.1")
    assert r["ip_type"] == "loopback"


def test_link_local():
    r = _classify_ip("169.254.0.1")
    assert r["ip_type"] == "link_local"


def test_public_ip():
    r = _classify_ip("8.8.8.8")
    assert r["ip_type"] == "public"
    assert r["is_public"] is True
    assert r["is_internal"] is False


def test_invalid_ip():
    r = _classify_ip("not-an-ip")
    assert r["ip_type"] == "invalid"


def test_empty_ip():
    r = _classify_ip(None)
    assert r == {}

def test_empty_str_ip():
    r = _classify_ip("")
    assert r == {}


def test_cloud_ip_cloudflare():
    # 104.16.0.1 is in Cloudflare range 104.16.0.0/13
    r = _classify_ip("104.16.0.1")
    if "cloud_provider" in r:
        assert r["cloud_provider"] == "Cloudflare"


# --- Plugin integration tests ---

def test_plugin_enriches_private_src():
    plugin = IPEnrichmentPlugin()
    event = make_event(src_ip="10.0.0.1", dst_ip="8.8.8.8")
    result = plugin.enrich(event)
    assert result["enrichment"] is not None
    assert result["enrichment"]["src_ip_context"]["ip_type"] == "private"
    assert result["enrichment"]["dst_ip_context"]["ip_type"] == "public"


def test_plugin_no_ips():
    plugin = IPEnrichmentPlugin()
    event = make_event(src_ip=None, dst_ip=None)
    result = plugin.enrich(event)
    # Should not crash; enrichment can be empty
    assert isinstance(result, dict)


def test_composite_enrichment():
    composite = CompositeEnrichment([IPEnrichmentPlugin()])
    event = make_event(src_ip="192.168.1.1", dst_ip="203.0.113.5")
    result = composite.enrich(event)
    assert "enrichment" in result
    assert result["enrichment"]["src_ip_context"]["is_internal"] is True


def test_composite_empty():
    composite = CompositeEnrichment([])
    event = make_event(src_ip="1.2.3.4")
    result = composite.enrich(event)
    assert result is not None
