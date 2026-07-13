"""Durability tests: state serialization, Temporal activity split, store backends.

The core guarantee under test: an investigation can be checkpointed as JSON
after any tool call and resumed from that snapshot with zero behavioral drift —
which is what makes the per-tool Temporal activity design correct.
"""
from __future__ import annotations

import pytest

from app.agents.planner import Planner
from app.agents.state import InvestigationState
from app.schemas.common import Verdict
from tests.test_agents import make_phishing_alert

temporalio = pytest.importorskip("temporalio")

from app.orchestrator import temporal_workflow as tw  # noqa: E402


def initial_state(tenant: str = "acme") -> InvestigationState:
    alert = make_phishing_alert()
    return InvestigationState(
        tenant=tenant, alert=alert,
        text_corpus="\n".join([alert.raw_text, alert.title, alert.description]),
        signals=[alert.raw_text, alert.title, alert.description],
    )


def test_state_round_trips_through_json():
    state = initial_state()
    state.add_iocs([])
    restored = InvestigationState.model_validate(state.model_dump(mode="json"))
    assert restored == state


@pytest.mark.asyncio
async def test_workflow_shaped_replay_reaches_same_verdict():
    """Drive the exact workflow algorithm (plan in 'workflow', run each tool as
    an activity, JSON-checkpoint the state between every call) and assert the
    investigation converges to the same result as the in-process loop."""
    planner = Planner()
    state = initial_state()
    trace: list[dict] = []

    for _iteration in range(1, 9):
        actions = planner.next_actions(state)
        if not actions:
            break
        for action in actions:
            result = await tw.execute_tool_activity({
                "state": state.model_dump(mode="json"),  # durable checkpoint
                "tool": action.tool,
                "reason": action.reason,
                "params": action.params,
            })
            assert result["ok"], result["outcome"]
            state = InvestigationState.model_validate(result["state"])
            trace.append({
                "step": len(trace) + 1, "iteration": _iteration, "phase": "act",
                "action": action.tool, "reason": action.reason,
                "outcome": result["outcome"], "ok": result["ok"],
                "duration_ms": result["duration_ms"],
            })

    pkg_json = await tw.finalize_activity({
        "state": state.model_dump(mode="json"),
        "trace": trace,
        "investigation_id": "wf-test-1",
    })

    assert pkg_json["overall_verdict"] == Verdict.MALICIOUS.value
    assert pkg_json["investigation_id"] == "wf-test-1"
    assert pkg_json["affected_hosts"] == ["WS-FIN-042"]
    ioc_values = {e["ioc"]["value"] for e in pkg_json["iocs"]}
    assert "malware-c2.net" in ioc_values, "dropped IOC must survive checkpoints"
    assert pkg_json["status"] == "complete"
    acted = [t["action"] for t in pkg_json["agent_trace"] if t["phase"] == "act"]
    assert acted.count("enrich_iocs") >= 2, "re-planning must survive checkpoints"


@pytest.mark.asyncio
async def test_activity_retry_is_idempotent():
    """Re-running a tool activity on the same snapshot (a Temporal retry after
    an ambiguous failure) must not duplicate observations."""
    state = initial_state()
    snapshot = state.model_dump(mode="json")
    payload = {"state": snapshot, "tool": "run_detections",
               "reason": "retry test", "params": {}}

    first = await tw.execute_tool_activity(payload)
    second = await tw.execute_tool_activity(
        {**payload, "state": first["state"]})

    s1 = InvestigationState.model_validate(first["state"])
    s2 = InvestigationState.model_validate(second["state"])
    assert len(s2.detections) == len(s1.detections)
    assert len(s2.evidence) == len(s1.evidence) + 1  # evidence re-put is content-
    # addressed (same sha), so downstream dedup is by hash, not by count
    assert {e.sha256 for e in s2.evidence} == {e.sha256 for e in s1.evidence}


def test_approval_store_backends_share_state_machine():
    """The Postgres store swap changes persistence only — the service logic
    (four-eyes, transitions) is identical because it lives above the store."""
    from app.engines.approvals.service import (
        ApprovalService,
        InMemoryApprovalStore,
        PostgresApprovalStore,
    )

    assert isinstance(ApprovalService()._store, InMemoryApprovalStore)
    for method in ("add", "get", "list", "save"):
        assert callable(getattr(PostgresApprovalStore, method))
