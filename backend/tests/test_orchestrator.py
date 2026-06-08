"""End-to-end orchestration test against mock connectors."""
from __future__ import annotations

import pytest

from app.ingestion.normalizers import get_normalizer
from app.orchestrator import run_investigation
from app.schemas.common import InvestigationStatus, SourceProduct, Verdict


@pytest.mark.asyncio
async def test_phishing_investigation_end_to_end():
    raw = {
        "source": "sentinel",
        "properties": {
            "incidentNumber": "INC-204815",
            "title": "Phishing email reported by user",
            "description": "Body has hxxps://evil[.]com/pay and Invoice_8841.lnk on WS-FIN-042",
            "severity": "high",
            "entities": [
                {"kind": "Host", "hostName": "WS-FIN-042"},
                {"kind": "Account", "accountName": "jdoe"},
            ],
        },
        "message_id": "phish-0001",
    }
    alert = get_normalizer(SourceProduct.SENTINEL).normalize(raw)
    alert.extra["message_id"] = "phish-0001"

    pkg = await run_investigation("acme", alert)

    assert pkg.status == InvestigationStatus.COMPLETE
    assert pkg.tenant == "acme"
    # Known-bad evil.com / c2 should drive a malicious verdict
    assert pkg.overall_verdict == Verdict.MALICIOUS
    assert pkg.risk is not None and pkg.risk.score > 50
    assert pkg.iocs, "should have extracted+enriched IOCs"
    assert pkg.mitre, "should map MITRE techniques"
    assert pkg.affected_hosts, "EDR hunt should find affected hosts"
    assert pkg.playbook, "should recommend a playbook"
    assert pkg.tickets, "malicious verdict should open a ticket"
    assert pkg.executive_summary
    # Evidence is content-hashed
    assert all(len(e.sha256) == 64 for e in pkg.evidence)
