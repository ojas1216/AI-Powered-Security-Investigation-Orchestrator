"""Deterministic IOC extraction engine.

Pipeline: refang → extract URLs (and their hosts) → extract remaining indicators
→ validate → de-duplicate → classify hash length → emit typed IOC objects.

Validation rejects common false positives (private/reserved IPs, extension-only
'domains', hashes that are really IPv6/version strings) to keep enrichment cost
and analyst noise down.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from app.engines.ioc_extraction import patterns as P
from app.engines.ioc_extraction.defang import refang
from app.schemas.common import IOCType
from app.schemas.ioc import IOC


def _valid_public_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast)


def _valid_domain(value: str) -> bool:
    value = value.rstrip(".").lower()
    tld = value.rsplit(".", 1)[-1]
    if tld in P.EXTENSION_TLDS:
        return False
    if len(value) > 253:
        return False
    # reject pure-numeric "domains" (those are IPs handled elsewhere)
    return not value.replace(".", "").isdigit()


class IOCExtractor:
    """Extract structured IOCs from arbitrary text (email body, alert, cmdline)."""

    def extract(self, text: str) -> list[IOC]:
        if not text:
            return []
        text = refang(text)
        seen: set[str] = set()
        out: list[IOC] = []

        def add(ioc_type: IOCType, value: str, context: str | None = None) -> None:
            value = value.strip().strip(".,;:)]}'\"")
            if not value:
                return
            key = f"{ioc_type.value}:{value.lower()}"
            if key in seen:
                return
            seen.add(key)
            out.append(IOC(type=ioc_type, value=value, context=context))

        # 1. URLs first; record their hostnames as domains/IPs.
        url_hosts: set[str] = set()
        for m in P.URL.finditer(text):
            url = m.group(0)
            add(IOCType.URL, url, context="url")
            host = (urlparse(url).hostname or "").lower()
            if host:
                url_hosts.add(host)

        # 2. Emails before bare domains (so user@dom doesn't surface dom twice oddly).
        for m in P.EMAIL.finditer(text):
            add(IOCType.EMAIL, m.group(0).lower())

        # 3. Hashes — longest first so a SHA256 is not split into MD5 substrings.
        for m in P.SHA256.finditer(text):
            add(IOCType.SHA256, m.group(0).lower())
        for m in P.SHA1.finditer(text):
            add(IOCType.SHA1, m.group(0).lower())
        for m in P.MD5.finditer(text):
            add(IOCType.MD5, m.group(0).lower())

        # 4. IPs.
        for m in P.IPV4.finditer(text):
            if _valid_public_ipv4(m.group(0)):
                add(IOCType.IPV4, m.group(0))
        for m in P.IPV6.finditer(text):
            try:
                ipaddress.IPv6Address(m.group(0))
            except ValueError:
                continue
            add(IOCType.IPV6, m.group(0).lower())

        # 5. Domains (include URL hosts; skip ones already captured as emails).
        domain_candidates = {m.group(0).lower() for m in P.DOMAIN.finditer(text)}
        domain_candidates |= url_hosts
        for dom in domain_candidates:
            if _valid_domain(dom):
                add(IOCType.DOMAIN, dom, context="domain")

        # 6. Host artifacts.
        for m in P.REGISTRY_KEY.finditer(text):
            add(IOCType.REGISTRY_KEY, m.group(0))
        for m in P.MUTEX.finditer(text):
            add(IOCType.MUTEX, m.group(0))
        for m in P.FILENAME.finditer(text):
            add(IOCType.FILENAME, m.group(0))

        return out


_default = IOCExtractor()


def extract_iocs(text: str) -> list[IOC]:
    return _default.extract(text)
