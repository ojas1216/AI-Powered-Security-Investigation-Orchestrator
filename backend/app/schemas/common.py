"""Shared enums and base types."""
from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Verdict(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class IOCType(StrEnum):
    URL = "url"
    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"
    EMAIL = "email"
    FILENAME = "filename"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    # Extended threat-intelligence indicator types
    ASN = "asn"
    CIDR = "cidr"
    JA3 = "ja3"
    JA4 = "ja4"
    TLS_CERT = "tls_cert"
    PROCESS = "process"


class InvestigationStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class SourceProduct(StrEnum):
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    SENTINEL = "sentinel"
    QRADAR = "qradar"
    WAZUH = "wazuh"
    CHRONICLE = "chronicle"
    GENERIC = "generic"
