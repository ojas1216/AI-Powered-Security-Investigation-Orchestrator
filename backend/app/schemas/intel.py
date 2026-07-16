"""Threat-intelligence dossier — the complete intelligence report for one IOC.

A dossier is the enterprise-grade replacement for a shallow reputation lookup:
it aggregates every provider verdict, DNS/WHOIS/hosting context, relationships,
campaign correlation, threat-actor attribution, MITRE mapping, a timeline,
business impact, and explainable evidence into one normalized schema.
"""
from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from app.schemas.common import IOCType, Verdict
from app.schemas.investigation import Attribution, FingerprintMatch, MitreTechnique


class ProviderResult(BaseModel):
    """One threat-intel provider's contribution to the dossier."""

    source: str
    verdict: Verdict = Verdict.UNKNOWN
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    malware_family: str = ""
    threat_category: str = ""
    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    detail: str = ""
    ok: bool = True  # False when the provider errored (failure-isolated)


class WhoisInfo(BaseModel):
    registrar: str = ""
    created: datetime | None = None
    expires: datetime | None = None
    age_days: int | None = None
    tld: str = ""
    dnssec: bool = False
    nameservers: list[str] = Field(default_factory=list)


class DnsRecords(BaseModel):
    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)
    mx: list[str] = Field(default_factory=list)
    txt: list[str] = Field(default_factory=list)
    ns: list[str] = Field(default_factory=list)
    cname: list[str] = Field(default_factory=list)


class HostingInfo(BaseModel):
    asn: str = ""
    isp: str = ""
    country: str = ""
    organization: str = ""
    cloud_provider: str = ""


class Relationships(BaseModel):
    related_ips: list[str] = Field(default_factory=list)
    related_domains: list[str] = Field(default_factory=list)
    related_urls: list[str] = Field(default_factory=list)
    related_hashes: list[str] = Field(default_factory=list)
    related_emails: list[str] = Field(default_factory=list)
    campaigns: list[str] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)


class DossierTimeline(BaseModel):
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    events: list[str] = Field(default_factory=list)


class MitreContext(BaseModel):
    techniques: list[MitreTechnique] = Field(default_factory=list)
    kill_chain: list[str] = Field(default_factory=list)
    predicted_next: list[str] = Field(default_factory=list)


class DossierBusinessImpact(BaseModel):
    technical_impact: str = ""
    business_impact: str = ""
    potential_data_exposure: str = ""
    recommended_actions: list[str] = Field(default_factory=list)


class DossierConfidence(BaseModel):
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    rationale: list[str] = Field(default_factory=list)
    supporting: list[str] = Field(default_factory=list)
    rejected: list[str] = Field(default_factory=list)


class ThreatIntelligenceDossier(BaseModel):
    # Basic information
    indicator: str
    ioc_type: IOCType
    status: str = "unknown"  # active | inactive | unknown
    verdict: Verdict = Verdict.UNKNOWN
    confidence: DossierConfidence = Field(default_factory=DossierConfidence)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    classification: str = ""

    # Context sections
    whois: WhoisInfo | None = None
    dns: DnsRecords | None = None
    passive_dns: list[str] = Field(default_factory=list)
    hosting: HostingInfo | None = None

    threat_intel: list[ProviderResult] = Field(default_factory=list)
    relationships: Relationships = Field(default_factory=Relationships)
    timeline: DossierTimeline = Field(default_factory=DossierTimeline)
    mitre: MitreContext = Field(default_factory=MitreContext)
    attribution: Attribution | None = None
    campaign_matches: list[FingerprintMatch] = Field(default_factory=list)
    business_impact: DossierBusinessImpact | None = None

    references: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    executive_summary: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
