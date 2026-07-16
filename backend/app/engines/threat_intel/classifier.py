"""IOC classifier: turn a raw indicator string into a typed IOC.

Defang-aware (hxxp, [.], (.)), and recognizes the extended TI indicator types
(ASN, CIDR, JA3/JA4, TLS cert fingerprints) in addition to the network/file/
identity types. Deterministic and dependency-free.
"""
from __future__ import annotations

import ipaddress
import re

from app.engines.ioc_extraction.defang import refang
from app.schemas.common import IOCType
from app.schemas.ioc import IOC

_SHA256 = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)
_SHA1 = re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE)
_MD5 = re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE)
_JA4 = re.compile(r"^[a-z0-9]{10}_[a-f0-9]{12}_[a-f0-9]{12}$", re.IGNORECASE)
_ASN = re.compile(r"^AS\d+$", re.IGNORECASE)
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,63}$", re.IGNORECASE)
_URL = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def classify(raw: str) -> IOC:
    """Classify a raw indicator into a typed IOC. Never raises."""
    value = refang(raw).strip()
    lowered = value.lower()

    if _URL.match(value):
        return IOC(type=IOCType.URL, value=value)
    if _EMAIL.match(value):
        return IOC(type=IOCType.EMAIL, value=lowered)
    if _ASN.match(value):
        return IOC(type=IOCType.ASN, value=value.upper())

    # CIDR before bare IP.
    if "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
            return IOC(type=IOCType.CIDR, value=value)
        except ValueError:
            pass

    try:
        ip = ipaddress.ip_address(value)
        return IOC(type=IOCType.IPV6 if ip.version == 6 else IOCType.IPV4,
                   value=value)
    except ValueError:
        pass

    if _SHA256.match(value):
        return IOC(type=IOCType.SHA256, value=lowered)
    if _JA4.match(value):
        return IOC(type=IOCType.JA4, value=lowered)
    if _SHA1.match(value):
        return IOC(type=IOCType.SHA1, value=lowered)
    if _MD5.match(value):
        # 32-hex is ambiguous: MD5 vs JA3 (also a 32-hex md5). Default MD5;
        # callers with TLS context can override to JA3.
        return IOC(type=IOCType.MD5, value=lowered)
    if _DOMAIN.match(value):
        return IOC(type=IOCType.DOMAIN, value=lowered)

    # Fallback: opaque token (filename/mutex/process/registry) — treat as filename.
    return IOC(type=IOCType.FILENAME, value=value)
