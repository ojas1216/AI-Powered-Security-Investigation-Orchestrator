"""Investigation dispatch: one submission surface for API and streaming paths.

Modes (AEGIS_DISPATCH):
- inline   — run in this process as a supervised asyncio task, bounded by a
             semaphore so an alert storm cannot exhaust the worker (backpressure:
             submissions beyond the queue bound raise CapacityError -> 429).
- temporal — start the durable InvestigationWorkflow on the Temporal cluster
             (production default; survives worker crashes and redeploys).

In both modes a QUEUED placeholder is persisted immediately so the client can
poll GET /investigations/{id} from the moment the 202 is returned, and a FAILED
package is persisted if the run raises — an investigation is never silently lost.
"""
from __future__ import annotations

import asyncio
import uuid

from app.core.config import settings
from app.core.logging import get_logger
from app.core.tenancy import set_current_tenant
from app.repository import get_repo
from app.schemas.alert import Alert
from app.schemas.common import InvestigationStatus
from app.schemas.investigation import InvestigationPackage

log = get_logger("orchestrator.dispatch")


class CapacityError(Exception):
    """Concurrent-investigation bound reached; caller should back off (429)."""


class InvestigationDispatcher:
    def __init__(self, *, max_concurrent: int | None = None) -> None:
        limit = max_concurrent or settings.max_concurrent_investigations
        self._semaphore = asyncio.Semaphore(limit)
        self._limit = limit
        self._inflight = 0
        self._tasks: set[asyncio.Task] = set()

    @property
    def inflight(self) -> int:
        return self._inflight

    async def submit(self, tenant: str, alert: Alert) -> str:
        """Queue an investigation; returns its id immediately."""
        investigation_id = str(uuid.uuid4())
        set_current_tenant(tenant)
        get_repo().save(InvestigationPackage(
            investigation_id=investigation_id, tenant=tenant,
            status=InvestigationStatus.QUEUED, alert=alert,
        ))

        if settings.dispatch == "temporal":
            await self._submit_temporal(tenant, alert, investigation_id)
        else:
            self._submit_inline(tenant, alert, investigation_id)

        log.info("investigation_queued", investigation_id=investigation_id,
                 tenant=tenant, mode=settings.dispatch, inflight=self._inflight)
        return investigation_id

    # ------------------------------------------------------------- inline

    def _submit_inline(self, tenant: str, alert: Alert,
                       investigation_id: str) -> None:
        if self._inflight >= self._limit:
            raise CapacityError(
                f"at capacity ({self._limit} concurrent investigations)")
        self._inflight += 1
        task = asyncio.create_task(
            self._run_supervised(tenant, alert, investigation_id))
        # Keep a strong reference until done (create_task result may be GC'd).
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _run_supervised(self, tenant: str, alert: Alert,
                              investigation_id: str) -> None:
        from app.orchestrator.investigation import run_investigation

        async with self._semaphore:
            try:
                set_current_tenant(tenant)
                pkg = await run_investigation(tenant, alert, investigation_id)
                get_repo().save(pkg)
            except Exception as exc:  # noqa: BLE001 - never lose an investigation
                log.error("investigation_failed",
                          investigation_id=investigation_id, error=str(exc))
                set_current_tenant(tenant)
                get_repo().save(InvestigationPackage(
                    investigation_id=investigation_id, tenant=tenant,
                    status=InvestigationStatus.FAILED, alert=alert,
                ))
            finally:
                self._inflight -= 1

    # ------------------------------------------------------------- temporal

    async def _submit_temporal(self, tenant: str, alert: Alert,
                               investigation_id: str) -> None:
        from temporalio.client import Client

        from app.orchestrator.temporal_workflow import (
            TASK_QUEUE,
            InvestigationWorkflow,
        )

        client = await Client.connect(settings.temporal_host)
        await client.start_workflow(
            InvestigationWorkflow.run,
            args=[tenant, alert.model_dump(mode="json")],
            id=investigation_id,
            task_queue=TASK_QUEUE,
        )


_dispatcher: InvestigationDispatcher | None = None


def get_dispatcher() -> InvestigationDispatcher:
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = InvestigationDispatcher()
    return _dispatcher
