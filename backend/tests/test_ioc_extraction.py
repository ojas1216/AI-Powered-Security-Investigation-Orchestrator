"""Unit tests for the IOC extraction engine."""
from __future__ import annotations

from app.engines.ioc_extraction import extract_iocs
from app.engines.ioc_extraction.defang import refang
from app.schemas.common import IOCType


def _by_type(iocs, t):
    return [i.value for i in iocs if i.type == t]


def test_refang_common_forms():
    assert refang("hxxps://evil[.]com/pay") == "https://evil.com/pay"
    assert refang("1.2.3[.]4") == "1.2.3.4"
    assert refang("user[at]bad(dot)com") == "user@bad.com"


def test_extract_url_and_host():
    iocs = extract_iocs("Click hxxps://evil[.]com/pay now")
    assert "https://evil.com/pay" in _by_type(iocs, IOCType.URL)
    assert "evil.com" in _by_type(iocs, IOCType.DOMAIN)


def test_extract_public_ip_only():
    iocs = extract_iocs("external 45.155.205.99 internal 10.0.0.5 loopback 127.0.0.1")
    ips = _by_type(iocs, IOCType.IPV4)
    assert "45.155.205.99" in ips
    assert "10.0.0.5" not in ips  # private filtered
    assert "127.0.0.1" not in ips  # loopback filtered


def test_hash_classification_by_length():
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    iocs = extract_iocs(f"payload {sha256} and {md5}")
    assert sha256 in _by_type(iocs, IOCType.SHA256)
    assert md5 in _by_type(iocs, IOCType.MD5)


def test_email_extraction():
    iocs = extract_iocs("from billing@evil.com to jdoe@acme.example")
    emails = _by_type(iocs, IOCType.EMAIL)
    assert "billing@evil.com" in emails
    assert "jdoe@acme.example" in emails


def test_registry_and_filename():
    text = r"persistence HKCU\Software\Microsoft\Windows\CurrentVersion\Run dropped updater.exe"
    iocs = extract_iocs(text)
    assert any(i.type == IOCType.REGISTRY_KEY for i in iocs)
    assert "updater.exe" in _by_type(iocs, IOCType.FILENAME)


def test_deduplication():
    iocs = extract_iocs("evil.com evil.com EVIL.COM")
    assert _by_type(iocs, IOCType.DOMAIN).count("evil.com") == 1


def test_extension_tld_not_a_domain():
    iocs = extract_iocs("ran payload.exe")
    assert "payload.exe" not in _by_type(iocs, IOCType.DOMAIN)
