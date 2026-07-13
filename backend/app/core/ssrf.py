"""SSRF guard for server-side enrichment.

Attacker-controlled IOCs (URLs/domains/IPs) must never let the platform reach
internal services or cloud metadata. Every outbound enrichment target is checked
here before a request is issued.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from app.core.exceptions import SsrfBlockedError

# Vendor APIs we are allowed to call server-side. Live connectors only ever talk
# to these hosts; user-supplied URLs are NEVER fetched directly.
ALLOWED_HOSTS: frozenset[str] = frozenset(
    {
        "www.virustotal.com",
        "api.abuseipdb.com",
        "api.greynoise.io",
        "otx.alienvault.com",
        # Keyless public feeds (no registration required)
        "isc.sans.edu",
        "hashlookup.circl.lu",
    }
)

_BLOCKED_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",  # link-local incl. 169.254.169.254 metadata
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
]


def _is_blocked_ip(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return True  # unresolvable → block
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return True
        if any(ip in net for net in _BLOCKED_NETS):
            return True
    return False


def assert_allowed_url(url: str) -> str:
    """Allow only https to a vendor host that does not resolve internally."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise SsrfBlockedError(f"Scheme not allowed: {parsed.scheme}")
    host = parsed.hostname or ""
    if host not in ALLOWED_HOSTS:
        raise SsrfBlockedError(f"Host not on egress allow-list: {host}")
    if _is_blocked_ip(host):
        raise SsrfBlockedError("Host resolves to a blocked address range")
    return url
