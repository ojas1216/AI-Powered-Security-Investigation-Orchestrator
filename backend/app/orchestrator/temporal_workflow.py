"""Durable agentic investigation on Temporal.

The autonomous loop is split so that **every tool call is its own activity**:
the serializable InvestigationState checkpoints between activities, so a worker
crash mid-investigation resumes from the last completed tool call instead of
restarting the whole case. The planner runs inside the workflow — it is pure
and deterministic over the state, which is exactly what Temporal's replay model
requires (and why LLM judgement is kept out of action selection).

Import-guarded so the module loads where temporalio isn't installed
(dev/test run the in-process path in app/agents/loop.py).

Run a worker:  python -m app.orchestrator.temporal_workflow
"""
from __future__ import annotations

from datetime import timedelta

try:
    from temporalio import activity, workflow
    from temporalio.client import Client
    from temporalio.common import RetryPolicy
    from temporalio.worker import Worker

    _HAVE_TEMPORAL = True
except Exception:  # pragma: no cover - optional dep
    _HAVE_TEMPORAL = False


TASK_QUEUE = "aegisflow-investigations"

if _HAVE_TEMPORAL:
    with workflow.unsafe.imports_passed_through():
        from app.agents.planner import Budget, PlannedAction, Planner
        from app.agents.state import InvestigationState
        from app.schemas.alert import Alert
        from app.schemas.common import InvestigationStatus
        from app.schemas.investigation import AgentTraceStep, InvestigationPackage

    _agent = None

    def _get_agent():
        """One engine composition per worker process (used by activities only)."""
        global _agent
        if _agent is None:
            from app.orchestrator.investigation import InvestigationOrchestrator

            _agent = InvestigationOrchestrator().agent
        return _agent

    @activity.defn
    async def execute_tool_activity(payload: dict) -> dict:
        """Run one planned tool against the checkpointed state; return new state.

        Tools are effectively idempotent on retry: they fold observations into
        the passed-in state through keyed/deduplicated collections, so re-running
        after a crash re-derives the same result.
        """
        state = InvestigationState.model_validate(payload["state"])
        action = PlannedAction(
            tool=payload["tool"], reason=payload["reason"],
            params=payload.get("params", {}),
        )
        ok, outcome, duration_ms, _started = await _get_agent().run_tool(state, action)
        return {
            "state": state.model_dump(mode="json"),
            "ok": ok,
            "outcome": outcome,
            "duration_ms": duration_ms,
        }

    @activity.defn
    async def finalize_activity(payload: dict) -> dict:
        """Timeline/graph/MITRE/risk/memory/copilot/playbook/approvals/ticket."""
        state = InvestigationState.model_validate(payload["state"])
        trace = [AgentTraceStep.model_validate(t) for t in payload["trace"]]
        pkg = InvestigationPackage(
            investigation_id=payload["investigation_id"],
            tenant=state.tenant,
            status=InvestigationStatus.RUNNING,
            alert=state.alert,
        )
        await _get_agent().finalize(pkg, state, trace, step_no=len(trace))
        return pkg.model_dump(mode="json")

    @activity.defn
    async def persist_package_activity(pkg_json: dict) -> None:
        from app.core.tenancy import set_current_tenant
        from app.repository import get_repo

        pkg = InvestigationPackage.model_validate(pkg_json)
        set_current_tenant(pkg.tenant)
        get_repo().save(pkg)

    @workflow.defn
    class InvestigationWorkflow:
        @workflow.run
        async def run(self, tenant: str, alert_json: dict) -> dict:
            alert = Alert.model_validate(alert_json)
            planner = Planner()
            budget = Budget()
            state = InvestigationState(
                tenant=tenant, alert=alert,
                text_corpus="\n".join(
                    [alert.raw_text, alert.title, alert.description]),
                signals=[alert.raw_text, alert.title, alert.description],
            )
            trace: list[dict] = []
            tool_calls = 0

            tool_retry = RetryPolicy(
                initial_interval=timedelta(seconds=2),
                backoff_coefficient=2.0,
                maximum_attempts=3,
            )

            for iteration in range(1, budget.max_iterations + 1):
                actions = planner.next_actions(state)
                if not actions:
                    break
                if tool_calls + len(actions) > budget.max_tool_calls:
                    actions = actions[: max(0, budget.max_tool_calls - tool_calls)]
                    if not actions:
                        trace.append(self._trace_step(
                            len(trace) + 1, iteration, "plan", "stop",
                            "tool-call budget exhausted",
                            "finalizing on partial evidence", ok=False))
                        break

                # Sequential execution: each completed tool call is a durable
                # checkpoint (the state snapshot lives in workflow history).
                for action in actions:
                    result = await workflow.execute_activity(
                        execute_tool_activity,
                        {
                            "state": state.model_dump(mode="json"),
                            "tool": action.tool,
                            "reason": action.reason,
                            "params": action.params,
                        },
                        start_to_close_timeout=timedelta(minutes=10),
                        retry_policy=tool_retry,
                    )
                    state = InvestigationState.model_validate(result["state"])
                    tool_calls += 1
                    trace.append(self._trace_step(
                        len(trace) + 1, iteration, "act", action.tool,
                        action.reason, result["outcome"], ok=result["ok"],
                        duration_ms=result["duration_ms"]))

            pkg_json = await workflow.execute_activity(
                finalize_activity,
                {
                    "state": state.model_dump(mode="json"),
                    "trace": trace,
                    "investigation_id": workflow.info().workflow_id,
                },
                start_to_close_timeout=timedelta(minutes=5),
                # Finalize opens tickets; cap retries to avoid duplicates on
                # ambiguous failures.
                retry_policy=RetryPolicy(maximum_attempts=2),
            )
            await workflow.execute_activity(
                persist_package_activity,
                pkg_json,
                start_to_close_timeout=timedelta(minutes=1),
                retry_policy=RetryPolicy(maximum_attempts=5),
            )
            return pkg_json

        @staticmethod
        def _trace_step(step: int, iteration: int, phase: str, action: str,
                        reason: str, outcome: str, *, ok: bool = True,
                        duration_ms: float = 0.0) -> dict:
            return {
                "step": step, "iteration": iteration, "phase": phase,
                "action": action, "reason": reason, "outcome": outcome,
                "ok": ok, "duration_ms": duration_ms,
                "started_at": workflow.now().isoformat(),
            }

    async def start_worker(host: str) -> None:  # pragma: no cover - infra
        client = await Client.connect(host)
        worker = Worker(
            client,
            task_queue=TASK_QUEUE,
            workflows=[InvestigationWorkflow],
            activities=[execute_tool_activity, finalize_activity,
                        persist_package_activity],
        )
        await worker.run()


def main() -> None:  # pragma: no cover - infra entrypoint
    import asyncio

    from app.core.config import settings

    if not _HAVE_TEMPORAL:
        raise SystemExit("temporalio not installed: pip install '.[temporal]'")
    asyncio.run(start_worker(settings.temporal_host))


if __name__ == "__main__":  # pragma: no cover
    main()
