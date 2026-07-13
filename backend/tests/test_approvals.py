"""Approval workflow tests: state machine, four-eyes, expiry, API, integration."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.engines.approvals import ApprovalError, ApprovalNotFound, ApprovalService
from app.schemas.approval import ApprovalStatus
from app.schemas.common import InvestigationStatus, Verdict
from app.schemas.investigation import InvestigationPackage, PlaybookStep
from tests.test_agents import make_phishing_alert


def make_package(tenant: str = "acme", steps: int = 2) -> InvestigationPackage:
    return InvestigationPackage(
        investigation_id="inv-1",
        tenant=tenant,
        status=InvestigationStatus.COMPLETE,
        alert=make_phishing_alert(),
        overall_verdict=Verdict.MALICIOUS,
        playbook=[
            PlaybookStep(phase="containment", action=f"Action {i}",
                         rationale="because", requires_approval=True)
            for i in range(steps)
        ],
    )


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 7, 13, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


# ---------------------------------------------------------------- service


def test_create_one_request_per_approval_required_step():
    svc = ApprovalService()
    pkg = make_package(steps=3)
    pkg.playbook.append(PlaybookStep(
        phase="detection", action="informational", rationale="no approval",
        requires_approval=False))
    requests = svc.create_for_package(pkg)
    assert len(requests) == 3
    assert all(r.status is ApprovalStatus.PENDING for r in requests)
    assert svc.list("acme", status=ApprovalStatus.PENDING,
                    investigation_id="inv-1")


def test_approve_then_execute_happy_path():
    svc = ApprovalService()
    req = svc.create_for_package(make_package())[0]

    decided = svc.decide("acme", req.approval_id, actor="jdoe",
                         approve=True, note="contain it")
    assert decided.status is ApprovalStatus.APPROVED
    assert decided.decided_by == "jdoe" and decided.decision_note == "contain it"

    executed = svc.mark_executed("acme", req.approval_id, actor="asmith",
                                 note="host isolated via EDR")
    assert executed.status is ApprovalStatus.EXECUTED
    assert executed.executed_by == "asmith"


def test_reject_blocks_execution():
    svc = ApprovalService()
    req = svc.create_for_package(make_package())[0]
    svc.decide("acme", req.approval_id, actor="jdoe", approve=False)
    with pytest.raises(ApprovalError, match="only approved"):
        svc.mark_executed("acme", req.approval_id, actor="jdoe")


def test_double_decision_is_rejected():
    svc = ApprovalService()
    req = svc.create_for_package(make_package())[0]
    svc.decide("acme", req.approval_id, actor="jdoe", approve=True)
    with pytest.raises(ApprovalError, match="cannot decide"):
        svc.decide("acme", req.approval_id, actor="asmith", approve=False)


def test_four_eyes_requester_cannot_self_approve():
    svc = ApprovalService()
    req = svc.create_for_package(make_package(), requested_by="jdoe")[0]
    with pytest.raises(ApprovalError, match="four-eyes"):
        svc.decide("acme", req.approval_id, actor="jdoe", approve=True)


def test_expiry_transitions_pending_and_blocks_decision():
    clock = Clock()
    svc = ApprovalService(ttl=timedelta(hours=1), now_fn=clock)
    req = svc.create_for_package(make_package())[0]

    clock.now += timedelta(hours=2)
    assert svc.get("acme", req.approval_id).status is ApprovalStatus.EXPIRED
    with pytest.raises(ApprovalError, match="expired"):
        svc.decide("acme", req.approval_id, actor="jdoe", approve=True)


def test_tenant_isolation_in_service():
    svc = ApprovalService()
    req = svc.create_for_package(make_package(tenant="acme"))[0]
    with pytest.raises(ApprovalNotFound):
        svc.get("globex", req.approval_id)
    assert svc.list("globex") == []


# ---------------------------------------------------------------- loop integration


@pytest.mark.asyncio
async def test_malicious_investigation_raises_approval_requests():
    from tests.test_agents import make_investigator

    agent = make_investigator()
    agent.approvals = ApprovalService()
    pkg = await agent.investigate("acme", make_phishing_alert())

    assert pkg.overall_verdict == Verdict.MALICIOUS
    assert pkg.approval_ids, "actionable verdict must raise approval requests"
    pending = agent.approvals.list("acme", status=ApprovalStatus.PENDING,
                                   investigation_id=pkg.investigation_id)
    assert {r.approval_id for r in pending} == set(pkg.approval_ids)
    assert all(r.requested_by == "aegisflow-agent" for r in pending)
    assert any(s.action == "request_approvals" for s in pkg.agent_trace)


# ---------------------------------------------------------------- API


def responder_headers(tenant: str = "acme") -> dict[str, str]:
    return {"X-Tenant-ID": tenant, "X-Roles": "incident_responder",
            "Authorization": "Bearer dev"}


def _ingest_malicious(client, auth_headers) -> dict:
    payload = {
        "source": "sentinel",
        "properties": {
            "incidentNumber": "INC-APPR-1",
            "title": "Phishing email reported",
            "description": "hxxps://evil[.]com/pay Invoice_8841.lnk",
            "severity": "high",
        },
        "message_id": "phish-appr-1",
    }
    resp = client.post("/api/v1/alerts/ingest", json=payload, headers=auth_headers)
    assert resp.status_code == 201
    return resp.json()


def test_approval_api_lifecycle(client, auth_headers):
    pkg = _ingest_malicious(client, auth_headers)
    assert pkg["approval_ids"]

    listed = client.get(
        f"/api/v1/approvals?investigation_id={pkg['investigation_id']}",
        headers=auth_headers)
    assert listed.status_code == 200
    approval_id = listed.json()[0]["approval_id"]

    decided = client.post(f"/api/v1/approvals/{approval_id}/decision",
                          json={"approve": True, "note": "go"},
                          headers=responder_headers())
    assert decided.status_code == 200
    assert decided.json()["status"] == "approved"

    executed = client.post(f"/api/v1/approvals/{approval_id}/executed",
                           json={"note": "mailbox purged"},
                           headers=responder_headers())
    assert executed.status_code == 200
    assert executed.json()["status"] == "executed"

    # Double-decide now conflicts.
    again = client.post(f"/api/v1/approvals/{approval_id}/decision",
                        json={"approve": False},
                        headers=responder_headers())
    assert again.status_code == 409


def test_approval_decision_requires_act_permission(client, auth_headers):
    pkg = _ingest_malicious(client, auth_headers)
    approval_id = pkg["approval_ids"][0]

    tier1 = {"X-Tenant-ID": "acme", "X-Roles": "tier1_analyst",
             "Authorization": "Bearer dev"}
    resp = client.post(f"/api/v1/approvals/{approval_id}/decision",
                       json={"approve": True}, headers=tier1)
    assert resp.status_code == 403


def test_approval_api_is_tenant_isolated(client, auth_headers):
    pkg = _ingest_malicious(client, auth_headers)
    approval_id = pkg["approval_ids"][0]

    resp = client.post(f"/api/v1/approvals/{approval_id}/decision",
                       json={"approve": True},
                       headers=responder_headers("globex"))
    assert resp.status_code == 404
