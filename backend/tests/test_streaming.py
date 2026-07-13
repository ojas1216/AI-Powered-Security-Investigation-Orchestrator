"""Streaming ingestion tests: async dispatch, capacity, Kafka message handling."""
from __future__ import annotations

import asyncio
import time

import pytest
from fastapi.testclient import TestClient

from app.ingestion.kafka_consumer import PoisonMessage, parse_message
from app.main import app
from app.orchestrator.dispatch import CapacityError, InvestigationDispatcher
from app.repository import get_repo
from app.schemas.common import InvestigationStatus
from tests.test_agents import make_phishing_alert

AUTH = {"X-Tenant-ID": "acme", "X-Roles": "tier3_analyst",
        "Authorization": "Bearer dev"}

PAYLOAD = {
    "source": "sentinel",
    "properties": {
        "incidentNumber": "INC-ASYNC-1",
        "title": "Phishing email reported",
        "description": "hxxps://evil[.]com/pay Invoice_8841.lnk",
        "severity": "high",
    },
    "message_id": "phish-async-1",
}


# ---------------------------------------------------------------- dispatcher


@pytest.mark.asyncio
async def test_dispatcher_queues_then_completes():
    dispatcher = InvestigationDispatcher(max_concurrent=4)
    inv_id = await dispatcher.submit("acme", make_phishing_alert())

    # Placeholder visible immediately (client can poll from the 202 onward).
    queued = get_repo().get("acme", inv_id)
    assert queued.status in (InvestigationStatus.QUEUED,
                             InvestigationStatus.RUNNING,
                             InvestigationStatus.COMPLETE)

    for _ in range(100):
        pkg = get_repo().get("acme", inv_id)
        if pkg.status is InvestigationStatus.COMPLETE:
            break
        await asyncio.sleep(0.05)
    assert pkg.status is InvestigationStatus.COMPLETE
    assert pkg.overall_verdict.value == "malicious"
    assert dispatcher.inflight == 0


@pytest.mark.asyncio
async def test_dispatcher_enforces_capacity():
    dispatcher = InvestigationDispatcher(max_concurrent=1)
    # Fill the single slot with a long-running fake by grabbing the accounting
    # directly — the bound is checked before task creation.
    dispatcher._inflight = 1
    with pytest.raises(CapacityError):
        await dispatcher.submit("acme", make_phishing_alert())
    dispatcher._inflight = 0


@pytest.mark.asyncio
async def test_failed_investigation_is_never_lost(monkeypatch):
    async def explode(tenant, alert, investigation_id=None):
        raise RuntimeError("engine down")

    import app.orchestrator.investigation as inv_mod
    monkeypatch.setattr(inv_mod, "run_investigation", explode)

    dispatcher = InvestigationDispatcher(max_concurrent=2)
    inv_id = await dispatcher.submit("acme", make_phishing_alert())
    for _ in range(100):
        pkg = get_repo().get("acme", inv_id)
        if pkg.status is InvestigationStatus.FAILED:
            break
        await asyncio.sleep(0.02)
    assert pkg.status is InvestigationStatus.FAILED


# ---------------------------------------------------------------- API async mode


def test_async_ingest_returns_202_and_completes():
    with TestClient(app) as client:  # context manager keeps the loop alive
        resp = client.post("/api/v1/alerts/ingest?mode=async",
                           json=PAYLOAD, headers=AUTH)
        assert resp.status_code == 202, resp.text
        body = resp.json()
        assert body["status"] == "queued"
        inv_id = body["investigation_id"]

        deadline = time.monotonic() + 10
        status = "queued"
        while time.monotonic() < deadline:
            got = client.get(f"/api/v1/investigations/{inv_id}", headers=AUTH)
            assert got.status_code == 200
            status = got.json()["status"]
            if status == "complete":
                break
            time.sleep(0.05)
        assert status == "complete"
        assert got.json()["overall_verdict"] == "malicious"


def test_sync_ingest_unchanged():
    with TestClient(app) as client:
        resp = client.post("/api/v1/alerts/ingest", json=PAYLOAD, headers=AUTH)
        assert resp.status_code == 201
        assert resp.json()["status"] == "complete"


# ---------------------------------------------------------------- kafka parsing


def envelope(**overrides) -> bytes:
    import json
    body = {"tenant": "acme", "alert": PAYLOAD}
    body.update(overrides)
    return json.dumps(body).encode()


def test_parse_message_happy_path():
    tenant, alert = parse_message(envelope())
    assert tenant == "acme"
    assert alert.source_alert_id == "INC-ASYNC-1"
    assert alert.title == "Phishing email reported"


@pytest.mark.parametrize("raw,match", [
    (b"not json {", "invalid JSON"),
    (b'"just a string"', "JSON object"),
    (envelope(tenant=""), "tenant"),
    (envelope(tenant="BAD TENANT!!"), "invalid tenant"),
    (envelope(alert="nope"), "alert"),
])
def test_parse_message_poison_paths(raw: bytes, match: str):
    with pytest.raises(PoisonMessage, match=match):
        parse_message(raw)
