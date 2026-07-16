"""Planning layer: TaskGraph, PriorityScheduler, and the taskgraph strategy."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.agents.planning import PlanningEngine, PriorityScheduler, TaskGraph
from app.agents.planning.task import Task, TaskStatus, dedup_key
from app.agents.state import InvestigationState
from tests.test_agents import make_investigator, make_phishing_alert

# ---------------------------------------------------------------- TaskGraph


def test_graph_dedups_identical_work():
    g = TaskGraph()
    a = g.add(Task(id="", tool="enrich_iocs", reason="x"))
    b = g.add(Task(id="", tool="enrich_iocs", reason="y"))  # same tool+params
    assert a == b
    assert len(g.all()) == 1


def test_ready_respects_dependencies_and_priority():
    g = TaskGraph()
    first = g.add(Task(id="", tool="run_detections", reason="", priority=90))
    g.add(Task(id="", tool="hunt_edr", reason="", priority=50,
               depends_on={first}, params={"ioc_keys": ["a"]}))
    # Only the dependency-free task is ready.
    ready = g.ready()
    assert [t.tool for t in ready] == ["run_detections"]

    g.get(first).status = TaskStatus.DONE
    ready = g.ready()
    assert [t.tool for t in ready] == ["hunt_edr"]


def test_progress_and_terminal():
    g = TaskGraph()
    t1 = g.add(Task(id="", tool="a", reason=""))
    g.add(Task(id="", tool="b", reason=""))
    assert g.progress() == (0, 2) and not g.all_terminal()
    g.get(t1).status = TaskStatus.DONE
    assert g.progress() == (1, 2) and g.remaining() == 1


def test_dedup_key_is_param_order_independent():
    assert dedup_key("t", {"a": 1, "b": 2}) == dedup_key("t", {"b": 2, "a": 1})


# ---------------------------------------------------------------- engine


@pytest.mark.asyncio
async def test_engine_expands_first_wave_tasks():
    state = InvestigationState(tenant="t", alert=make_phishing_alert())
    g = TaskGraph()
    added = PlanningEngine().expand(state, g, wave=1)
    tools = {t.tool for t in g.all()}
    # detections + email context are the independent first-wave tasks
    assert added >= 1
    assert "run_detections" in tools


# ---------------------------------------------------------------- scheduler


@pytest.mark.asyncio
async def test_scheduler_reaches_terminal_and_tracks_progress():
    state = InvestigationState(
        tenant="acme", alert=make_phishing_alert(),
        text_corpus="phishing evil.com Invoice_8841.lnk",
        signals=["phishing"])

    async def execute(st, tool, params):
        # Delegate to a real investigator's tool executor.
        from app.agents.planner import PlannedAction
        return await agent.run_tool(st, PlannedAction(tool=tool, reason="", params=params))

    agent = make_investigator()
    sched = PriorityScheduler(execute)
    result = await sched.run(state)
    assert result.graph.all_terminal()
    done, total = result.graph.progress()
    assert done == total and total > 0
    # detections + extraction + enrichment + hunt all became tasks
    tools = {t.tool for t in result.graph.all()}
    assert {"run_detections", "extract_iocs", "enrich_iocs"} <= tools


@pytest.mark.asyncio
async def test_scheduler_retries_transient_failure():
    calls = {"n": 0}

    async def flaky(st, tool, params):
        calls["n"] += 1
        if tool == "run_detections" and calls["n"] == 1:
            return False, "error: transient", 1.0, datetime.now(UTC)
        return True, "ok", 1.0, datetime.now(UTC)

    # A graph with a single detections task; scheduler must retry it once.
    from app.agents.planning.engine import PlanningEngine as _Engine

    class OneShot(_Engine):
        def __init__(self):
            super().__init__()
            self._done = False

        def expand(self, state, graph, wave):
            if self._done:
                return 0
            self._done = True
            graph.add(Task(id="", tool="run_detections", reason="", max_attempts=2))
            return 1

    state = InvestigationState(tenant="t", alert=make_phishing_alert())
    sched = PriorityScheduler(flaky, engine=OneShot())
    result = await sched.run(state)
    task = result.graph.all()[0]
    assert task.status is TaskStatus.DONE
    assert task.attempts == 2  # failed once, retried, succeeded


# ---------------------------------------------------------------- integration


@pytest.mark.asyncio
async def test_taskgraph_strategy_matches_batch_verdict():
    """Parity: the taskgraph strategy must reach the same verdict as batch and
    still follow sandbox-dropped IOCs — plus expose a plan graph."""
    agent = make_investigator()
    agent.strategy = "taskgraph"
    pkg = await agent.investigate("acme", make_phishing_alert())

    assert pkg.overall_verdict.value == "malicious"
    assert "malware-c2.net" in {e.ioc.value for e in pkg.iocs}  # dropped IOC followed
    assert pkg.affected_hosts == ["WS-FIN-042"]
    assert pkg.plan_graph, "taskgraph strategy must expose the execution graph"
    node_tools = {n.tool for n in pkg.plan_graph}
    assert {"run_detections", "enrich_iocs", "hunt_edr"} <= node_tools
    assert all(n.status in ("done", "failed", "skipped") for n in pkg.plan_graph)
    # dependency edges are recorded for visualization
    assert any(n.depends_on for n in pkg.plan_graph)


@pytest.mark.asyncio
async def test_taskgraph_degrades_on_tool_failure():
    from app.engines.edr.base import EDRConnector

    class BrokenEDR(EDRConnector):
        name = "broken"

        async def hunt(self, iocs):
            raise ConnectionError("EDR 503")

    agent = make_investigator(edr=BrokenEDR())
    agent.strategy = "taskgraph"
    pkg = await agent.investigate("acme", make_phishing_alert())
    # TI still confirms malicious; the hunt task is marked failed after retries.
    assert pkg.overall_verdict.value == "malicious"
    hunt_nodes = [n for n in pkg.plan_graph if n.tool == "hunt_edr"]
    assert hunt_nodes and all(n.status == "failed" for n in hunt_nodes)
