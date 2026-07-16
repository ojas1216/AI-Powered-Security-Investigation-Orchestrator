"""Production-hardening checks: payload caps, concurrency/throughput, RBAC audit."""
from __future__ import annotations

import asyncio
import time

import pytest

# ---------------------------------------------------------------- payload caps


def test_agent_payload_size_capped(client):
    headers = {"X-Tenant-ID": "acme", "X-Roles": "threat_hunter",
               "Authorization": "Bearer dev"}
    huge = {"text": "x" * 1_100_000}
    resp = client.post("/api/v1/agents/ioc_extraction/run", headers=headers,
                       json={"payload": huge})
    assert resp.status_code == 422  # rejected before doing any work


def test_ingest_file_size_capped(client):
    import base64

    headers = {"X-Tenant-ID": "acme", "X-Roles": "tier3_analyst",
               "Authorization": "Bearer dev"}
    oversized = base64.b64encode(b"A" * (10 * 1024 * 1024 + 1)).decode()
    resp = client.post("/api/v1/alerts/ingest-file", headers=headers,
                       json={"filename": "big.txt", "content_b64": oversized})
    assert resp.status_code == 413


# ---------------------------------------------------------------- concurrency


@pytest.mark.asyncio
async def test_dispatcher_handles_many_concurrent_investigations():
    """Toward the 10k-concurrent goal: the bounded dispatcher must complete a
    burst without errors or lost investigations."""
    from app.orchestrator.dispatch import InvestigationDispatcher
    from app.repository import get_repo
    from app.schemas.common import InvestigationStatus
    from tests.test_agents import make_phishing_alert

    # Admit the whole burst (capacity-rejection backpressure is covered in
    # test_streaming); here we exercise concurrent execution + semaphore release.
    n = 40
    dispatcher = InvestigationDispatcher(max_concurrent=64)
    ids = []
    for i in range(n):
        ids.append(await dispatcher.submit(
            "perf-tenant", make_phishing_alert(source_alert_id=f"PERF-{i}")))

    # Drain: every submitted investigation reaches a terminal state.
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        pkgs = [get_repo().get("perf-tenant", i) for i in ids]
        if all(p.status is InvestigationStatus.COMPLETE for p in pkgs):
            break
        await asyncio.sleep(0.05)

    pkgs = [get_repo().get("perf-tenant", i) for i in ids]
    assert all(p.status is InvestigationStatus.COMPLETE for p in pkgs)
    assert all(p.overall_verdict.value == "malicious" for p in pkgs)
    assert dispatcher.inflight == 0  # semaphore fully released


# ---------------------------------------------------------------- RBAC audit


def test_every_new_endpoint_enforces_auth(client):
    """Anti-regression: the Phase 2-8 endpoints must all reject anonymous access."""
    unauth_paths = [
        ("get", "/api/v1/agents"),
        ("post", "/api/v1/agents/mitre/run"),
        ("get", "/api/v1/graph/neighbors?node=x"),
        ("get", "/api/v1/graph/campaign?node=x"),
        ("post", "/api/v1/search/cases"),
        ("get", "/api/v1/offline/status"),
        ("get", "/api/v1/offline/cve/CVE-2021-44228"),
        ("post", "/api/v1/alerts/ingest-file"),
    ]
    for method, path in unauth_paths:
        resp = (client.get(path) if method == "get"
                else client.post(path, json={}))
        assert resp.status_code == 401, f"{method} {path} did not require auth"
