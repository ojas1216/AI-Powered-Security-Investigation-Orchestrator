"""Priority scheduler: drive the task graph to completion.

Loop: expand the graph from the current state → run all ready tasks concurrently
(highest priority first) → fold results into the state → retry transient failures
(bounded) → re-expand as new evidence unlocks new tasks → stop when the graph is
terminal or a budget trips. This is the autonomous execution core; it reuses the
existing tool executor and specialist agents, adding explicit dependencies,
deduplication, per-task retry, and progress tracking over the flat batch loop.
"""
from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from datetime import datetime

from app.agents.planner import Budget
from app.agents.planning.engine import PlanningEngine
from app.agents.planning.graph import TaskGraph
from app.agents.planning.task import Task, TaskStatus
from app.agents.state import InvestigationState
from app.core.logging import get_logger

log = get_logger("planning.scheduler")

# (ok, outcome, duration_ms, started_at)
ExecFn = Callable[[InvestigationState, str, dict], Awaitable[tuple[bool, str, float, datetime]]]


class SchedulerResult:
    def __init__(self, graph: TaskGraph, waves: int, tool_calls: int) -> None:
        self.graph = graph
        self.waves = waves
        self.tool_calls = tool_calls


class PriorityScheduler:
    def __init__(self, execute: ExecFn, *, engine: PlanningEngine | None = None,
                 budget: Budget | None = None) -> None:
        self._execute = execute
        self._engine = engine or PlanningEngine()
        self._budget = budget or Budget()

    async def run(self, state: InvestigationState) -> SchedulerResult:
        graph = TaskGraph()
        started = time.monotonic()
        tool_calls = 0
        waves = 0

        for wave in range(1, self._budget.max_iterations + 1):
            if time.monotonic() - started > self._budget.max_wall_clock_seconds:
                log.warning("scheduler_walltime_exhausted", wave=wave)
                break

            self._engine.expand(state, graph, wave)
            ready = graph.ready()
            if not ready:
                break  # converged: no runnable tasks and nothing retryable

            budget_left = self._budget.max_tool_calls - tool_calls
            if budget_left <= 0:
                log.warning("scheduler_toolcall_budget_exhausted", wave=wave)
                break
            ready = ready[:budget_left]

            waves = wave
            for t in ready:
                t.status = TaskStatus.RUNNING
                t.attempts += 1

            results = await asyncio.gather(
                *(self._run_one(state, t) for t in ready))
            tool_calls += len(ready)

            for task, (ok, outcome, duration_ms, _started_at) in zip(
                    ready, results, strict=True):
                task.outcome = outcome
                task.ok = ok
                task.duration_ms = duration_ms
                if ok:
                    task.status = TaskStatus.DONE
                elif task.attempts < task.max_attempts:
                    task.status = TaskStatus.PENDING  # retry next wave
                    log.info("task_retry_scheduled", task=task.id, tool=task.tool,
                             attempt=task.attempts)
                else:
                    task.status = TaskStatus.FAILED

        done, total = graph.progress()
        log.info("scheduler_complete", waves=waves, tool_calls=tool_calls,
                 tasks_done=done, tasks_total=total)
        return SchedulerResult(graph, waves, tool_calls)

    async def _run_one(self, state: InvestigationState, task: Task):
        return await self._execute(state, task.tool, task.params)
