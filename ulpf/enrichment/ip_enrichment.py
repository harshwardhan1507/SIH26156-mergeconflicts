"""
Offline IP Enrichment Plugin — air-gap safe, no external calls.

Provides:
1. RFC 1918 / special-purpose IP classification (private, loopback, link-local, multicast, public)
2. Static threat intel CIDR matching (known malicious ranges from public free lists)
3. Cloud/CDN ASN recognition (AWS, Azure, GCP, Cloudflare, Akamai, Fastly)

All data is embedded as static Python dicts — no database files, no internet required.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Any

from ulpf.enrichment.base import EnrichmentPlugin

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Static CIDR tables (embedded, air-gap safe)
# ---------------------------------------------------------------------------

# RFC 1918 / special-purpose ranges
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
    ipaddress.ip_network("224.0.0.0/4"),      # multicast
    ipaddress.ip_network("240.0.0.0/4"),      # reserved
    ipaddress.ip_network("100.64.0.0/10"),    # CGN / shared address space
]

# Known malicious / threat intelligence CIDR ranges (sampled from Emerging Threats / abuse.ch free data)
# These are ILLUSTRATIVE examples of known bad actors — real deployment should load from STIX/TAXII feed.
# Only ranges that are themselves malicious/abuse infrastructure belong here — legitimate
# CDN/platform infrastructure (even if occasionally abused as a C2 channel by malware) does
# NOT belong, since flagging it as "threat" mislabels ordinary user traffic to that platform.
_THREAT_INTEL_RANGES = [
    ("185.220.100.0/22",   "Tor exit nodes (torproject.org bulk list)"),
    ("185.220.101.0/24",   "Tor exit nodes"),
    ("45.142.212.0/24",    "Known scanner / Shodan-crawled malicious"),
    ("194.165.16.0/22",    "Bulletproof hosting (AS49877)"),
    ("195.54.160.0/23",    "Known spam/botnet infrastructure"),
    ("5.188.206.0/24",     "Bulletproof VPS provider"),
    ("192.42.116.0/22",    "Tor exit nodes (NL)"),
    ("199.87.154.0/24",    "Known malicious hosting"),
]

# Well-known cloud / CDN CIDR blocks for provider identification
# (simplified — production should use cloud provider published JSON IP ranges)
_CLOUD_ASN_RANGES = [
    # AWS
    ("3.0.0.0/9",         "AWS", "Amazon Web Services"),
    ("52.0.0.0/6",        "AWS", "Amazon Web Services"),
    ("54.64.0.0/11",      "AWS", "Amazon Web Services"),
    ("13.32.0.0/12",      "AWS CloudFront", "Amazon Web Services"),
    # Azure
    ("13.64.0.0/11",      "Azure", "Microsoft"),
    ("20.0.0.0/11",       "Azure", "Microsoft"),
    ("40.64.0.0/10",      "Azure", "Microsoft"),
    ("104.208.0.0/13",    "Azure", "Microsoft"),
    # GCP
    ("34.0.0.0/9",        "GCP", "Google"),
    ("35.184.0.0/13",     "GCP", "Google"),
    ("104.154.0.0/15",    "GCP", "Google"),
    ("130.211.0.0/22",    "GCP Load Balancer", "Google"),
    # Cloudflare
    ("103.21.244.0/22",   "Cloudflare", "Cloudflare"),
    ("103.22.200.0/22",   "Cloudflare", "Cloudflare"),
    ("173.245.48.0/20",   "Cloudflare", "Cloudflare"),
    ("104.16.0.0/13",     "Cloudflare", "Cloudflare"),
    ("108.162.192.0/18",  "Cloudflare", "Cloudflare"),
    # Akamai
    ("23.0.0.0/12",       "Akamai", "Akamai Technologies"),
    ("2.16.0.0/13",       "Akamai", "Akamai Technologies"),
    ("96.16.0.0/15",      "Akamai", "Akamai Technologies"),
    # Fastly
    ("23.235.32.0/20",    "Fastly", "Fastly"),
    ("151.101.0.0/16",    "Fastly", "Fastly"),
]

# Pre-parse all networks for performance
_PARSED_PRIVATE = [n for n in _PRIVATE_RANGES]
_PARSED_THREAT_INTEL: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
_PARSED_CLOUD: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str, str]] = []

for _cidr, _desc in _THREAT_INTEL_RANGES:
    try:
        _PARSED_THREAT_INTEL.append((ipaddress.ip_network(_cidr), _desc))
    except ValueError:
        pass

for _cidr, _product, _vendor in _CLOUD_ASN_RANGES:
    try:
        _PARSED_CLOUD.append((ipaddress.ip_network(_cidr), _product, _vendor))
    except ValueError:
        pass


def _classify_ip(ip_str: str | None) -> dict[str, Any]:
    """Classify an IP address and return enrichment context dict."""
    if not ip_str:
        return {}

    result: dict[str, Any] = {"ip": ip_str}

    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        result["ip_type"] = "invalid"
        return result

    # Check special ranges
    if ip_obj.is_loopback:
        result["ip_type"] = "loopback"
        result["is_internal"] = True
        return result
    if ip_obj.is_link_local:
        result["ip_type"] = "link_local"
        result["is_internal"] = True
        return result
    if ip_obj.is_multicast:
        result["ip_type"] = "multicast"
        result["is_internal"] = False
        return result

    # Check RFC 1918 private ranges
    for private_net in _PARSED_PRIVATE:
        try:
            if ip_obj in private_net:
                result["ip_type"] = "private"
                result["is_internal"] = True
                result["is_public"] = False
                result["is_threat"] = False
                return result
        except TypeError:
            continue

    # Public IP — check threat intel
    result["ip_type"] = "public"
    result["is_internal"] = False
    result["is_public"] = True

    threat_matches = []
    for net, desc in _PARSED_THREAT_INTEL:
        try:
            if ip_obj in net:
                threat_matches.append(desc)
        except TypeError:
            continue

    result["is_threat"] = len(threat_matches) > 0
    if threat_matches:
        result["threat_intel"] = threat_matches

    # Check cloud provider
    for net, product, vendor in _PARSED_CLOUD:
        try:
            if ip_obj in net:
                result["cloud_provider"] = vendor
                result["cloud_service"] = product
                break
        except TypeError:
            continue

    return result


class IPEnrichmentPlugin(EnrichmentPlugin):
    """
    Offline IP enrichment — classifies src/dst IPs without any network calls.
    Adds enrichment.src_ip_context and enrichment.dst_ip_context to every event.
    """

    name = "ip_enrichment"
    version = "1.0.0"

    def enrich(self, event: dict[str, Any]) -> dict[str, Any]:
        network = event.get("network") or {}
        src_ip = network.get("src_ip")
        dst_ip = network.get("dst_ip")

        src_context = _classify_ip(src_ip)
        dst_context = _classify_ip(dst_ip)

        # Build enrichment block
        enrichment = event.get("enrichment") or {}
        if src_context:
            enrichment["src_ip_context"] = src_context
        if dst_context:
            enrichment["dst_ip_context"] = dst_context

        # Flag events with threat IPs for fast filtering. This is pure
        # annotation — it must NEVER overwrite event.severity_numeric, which
        # is the source-derived value and part of the traceability contract.
        # Downstream risk scoring (ulpf.analytics.anomaly) is the place to
        # combine this flag with severity into a derived score.
        if src_context.get("is_threat") or dst_context.get("is_threat"):
            enrichment["threat_ip_detected"] = True

        event["enrichment"] = enrichment
        return event
