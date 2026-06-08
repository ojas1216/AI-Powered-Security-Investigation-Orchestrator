"""Temporal workflow + activities for durable production execution.

Each orchestrator stage is an activity (retried, timed-out, checkpointed) so an
8-minute sandbox detonation survives worker restarts. Import-guarded so the module
loads even where temporalio isn't installed (dev/test run the in-process path).

Run a worker:  python -m app.orchestrator.temporal_workflow
"""
from __future__ import annotations

from datetime import timedelta

try:
    from temporalio import activity, workflow
    from temporalio.client import Client
    from temporalio.worker import Worker

    _HAVE_TEMPORAL = True
except Exception:  # pragma: no cover - optional dep
    _HAVE_TEMPORAL = False


TASK_QUEUE = "aegisflow-investigations"


if _HAVE_TEMPORAL:

    @activity.defn
    async def run_investigation_activity(tenant: str, alert_json: dict) -> dict:
        from app.orchestrator.investigation import run_investigation
        from app.schemas.alert import Alert

        pkg = await run_investigation(tenant, Alert.model_validate(alert_json))
        return pkg.model_dump(mode="json")

    @workflow.defn
    class InvestigationWorkflow:
        @workflow.run
        async def run(self, tenant: str, alert_json: dict) -> dict:
            return await workflow.execute_activity(
                run_investigation_activity,
                args=[tenant, alert_json],
                start_to_close_timeout=timedelta(minutes=15),
                retry_policy=workflow.RetryPolicy(maximum_attempts=3),
            )

    async def start_worker(host: str) -> None:  # pragma: no cover - infra
        client = await Client.connect(host)
        worker = Worker(
            client,
            task_queue=TASK_QUEUE,
            workflows=[InvestigationWorkflow],
            activities=[run_investigation_activity],
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
