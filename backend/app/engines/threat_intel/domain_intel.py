"""Domain/host context: WHOIS, DNS records, passive DNS, hosting.

Offline-first and deterministic: the default provider derives stable, plausible
WHOIS/DNS/hosting context from the indicator itself (seeded hash), so the dossier
is complete-shaped and tests are hermetic without live DNS/WHOIS. A live provider
(guarded, network) can replace it behind the same interface — the platform's
mock-first pattern.
"""
from __future__ import annotations

import abc
import hashlib
from datetime import UTC, datetime, timedelta

from app.schemas.common import IOCType
from app.schemas.intel import DnsRecords, HostingInfo, WhoisInfo
from app.schemas.ioc import IOC

_REGISTRARS = ["NameCheap, Inc.", "GoDaddy.com, LLC", "Cloudflare, Inc.",
               "Gandi SAS", "Porkbun LLC", "Tucows Domains Inc."]
_ISPS = ["DigitalOcean, LLC", "OVH SAS", "Hetzner Online GmbH",
         "Amazon.com, Inc.", "Google LLC", "Contabo GmbH", "M247 Ltd"]
_CLOUDS = {"DigitalOcean, LLC": "DigitalOcean", "Amazon.com, Inc.": "AWS",
           "Google LLC": "GCP"}
_COUNTRIES = ["US", "DE", "NL", "FR", "GB", "RU", "SG"]


def _seed(value: str) -> int:
    return int.from_bytes(hashlib.blake2b(value.lower().encode(), digest_size=8).digest(),
                          "big")


class DomainIntelProvider(abc.ABC):
    @abc.abstractmethod
    def whois(self, ioc: IOC) -> WhoisInfo | None: ...

    @abc.abstractmethod
    def dns(self, ioc: IOC) -> DnsRecords | None: ...

    @abc.abstractmethod
    def hosting(self, ioc: IOC) -> HostingInfo: ...

    @abc.abstractmethod
    def passive_dns(self, ioc: IOC) -> list[str]: ...


class OfflineDomainIntel(DomainIntelProvider):
    def whois(self, ioc: IOC) -> WhoisInfo | None:
        if ioc.type is not IOCType.DOMAIN:
            return None
        s = _seed(ioc.value)
        created = datetime(2015, 1, 1, tzinfo=UTC) + timedelta(days=s % 3000)
        expires = created + timedelta(days=365 * (1 + s % 5))
        age = (datetime.now(UTC) - created).days
        tld = ioc.value.rsplit(".", 1)[-1]
        return WhoisInfo(
            registrar=_REGISTRARS[s % len(_REGISTRARS)],
            created=created, expires=expires, age_days=age, tld=tld,
            dnssec=bool(s & 1),
            nameservers=[f"ns1.{_ns_zone(s)}", f"ns2.{_ns_zone(s)}"])

    def dns(self, ioc: IOC) -> DnsRecords | None:
        if ioc.type not in (IOCType.DOMAIN, IOCType.URL):
            return None
        s = _seed(ioc.value)
        a = [f"{s % 223 + 1}.{(s >> 8) % 254}.{(s >> 16) % 254}.{(s >> 24) % 254}"]
        return DnsRecords(
            a=a,
            aaaa=[f"2606:4700:{s % 9999:x}::{(s >> 8) % 9999:x}"] if s & 2 else [],
            mx=[f"mail.{ioc.value}"] if s & 4 else [],
            txt=["v=spf1 include:_spf.google.com ~all"] if s & 8 else [],
            ns=[f"ns1.{_ns_zone(s)}", f"ns2.{_ns_zone(s)}"],
            cname=[])

    def hosting(self, ioc: IOC) -> HostingInfo:
        s = _seed(ioc.value)
        isp = _ISPS[s % len(_ISPS)]
        return HostingInfo(
            asn=f"AS{13335 + s % 50000}", isp=isp,
            country=_COUNTRIES[s % len(_COUNTRIES)], organization=isp,
            cloud_provider=_CLOUDS.get(isp, ""))

    def passive_dns(self, ioc: IOC) -> list[str]:
        if ioc.type not in (IOCType.IPV4, IOCType.IPV6):
            return []
        s = _seed(ioc.value)
        return [f"host{(s >> (i * 4)) % 9999}.example{i}.net" for i in range(3)]


def _ns_zone(s: int) -> str:
    return ["cloudflare.com", "digitalocean.com", "awsdns-01.org",
            "googledomains.com"][s % 4]


_provider: DomainIntelProvider | None = None


def build_domain_intel() -> DomainIntelProvider:
    global _provider
    if _provider is None:
        _provider = OfflineDomainIntel()
    return _provider
