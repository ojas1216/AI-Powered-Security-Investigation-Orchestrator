"""Priority scheduler: drive the task graph to completion, with reflection.

Two nested loops:
- **drain**: expand the graph from the current state → run all ready tasks
  concurrently (highest priority first) → fold results into the state → retry
  transient failures (bounded) → re-expand as new evidence unlocks new tasks →
  stop when no task is ready (converged) or a budget trips.
- **reflect**: once drained, ask the reflection engine whether anything was
  missed; if it proposes follow-up actions, inject them as a new task wave and
  drain again. Repeat until reflection proposes nothing (confidence stabilizes)
  or the reflection-round budget is hit.

Reuses the existing tool executor and specialist agents; adds explicit
dependencies, deduplication, per-task retry, progress tracking, and the
self-review loop over the flat batch loop.
"""
from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from datetime import datetime

from app.agents.planner import Budget, PlannedAction
from app.agents.planning.engine import PlanningEngine
from app.agents.planning.graph import TaskGraph
from app.agents.planning.task import DEFAULT_PRIORITY, Task, TaskStatus
from app.agents.state import InvestigationState
from app.core.logging import get_logger

log = get_logger("planning.scheduler")

# (ok, outcome, duration_ms, started_at)
ExecFn = Callable[[InvestigationState, str, dict],
                  Awaitable[tuple[bool, str, float, datetime]]]
ReflectFn = Callable[[InvestigationState], list[PlannedAction]]


class SchedulerResult:
    def __init__(self, graph: TaskGraph, waves: int, tool_calls: int,
                 reflection_rounds: int = 0) -> None:
        self.graph = graph
        self.waves = waves
        self.tool_calls = tool_calls
        self.reflection_rounds = reflection_rounds


class PriorityScheduler:
    def __init__(self, execute: ExecFn, *, engine: PlanningEngine | None = None,
                 budget: Budget | None = None, reflect: ReflectFn | None = None,
                 max_reflection_rounds: int = 2) -> None:
        self._execute = execute
        self._engine = engine or PlanningEngine()
        self._budget = budget or Budget()
        self._reflect = reflect
        self._max_reflection_rounds = max_reflection_rounds

    async def run(self, state: InvestigationState) -> SchedulerResult:
        graph = TaskGraph()
        started = time.monotonic()
        wave = 0
        tool_calls = 0
        reflection_round = 0

        while True:
            wave, tool_calls, budget_hit = await self._drain(
                state, graph, started, wave, tool_calls)
            if budget_hit:
                break
            if self._reflect is None or reflection_round >= self._max_reflection_rounds:
                break
            extra = self._reflect(state)
            if not extra:
                break  # confidence stabilized: nothing new to collect
            reflection_round += 1
            inject_wave = wave + 1
            prior = {t.id for t in graph.all()}  # reflection depends on all prior work
            for action in extra:
                graph.add(Task(
                    id="", tool=action.tool, reason=action.reason,
                    params=dict(action.params),
                    priority=DEFAULT_PRIORITY.get(action.tool, 50),
                    depends_on=set(prior), wave=inject_wave))
            log.info("reflection_round", round=reflection_round,
                     follow_ups=len(extra))

        done, total = graph.progress()
        log.info("scheduler_complete", waves=wave, tool_calls=tool_calls,
                 reflection_rounds=reflection_round, tasks_done=done,
                 tasks_total=total)
        return SchedulerResult(graph, wave, tool_calls, reflection_round)

    async def _drain(self, state: InvestigationState, graph: TaskGraph,
                     started: float, wave: int, tool_calls: int,
                     ) -> tuple[int, int, bool]:
        """Run planner-driven waves until convergence or a budget. Returns
        (wave, tool_calls, budget_hit)."""
        while wave < self._budget.max_iterations:
            if time.monotonic() - started > self._budget.max_wall_clock_seconds:
                log.warning("scheduler_walltime_exhausted", wave=wave)
                return wave, tool_calls, True

            self._engine.expand(state, graph, wave + 1)
            ready = graph.ready()
            if not ready:
                return wave, tool_calls, False  # converged

            budget_left = self._budget.max_tool_calls - tool_calls
            if budget_left <= 0:
                log.warning("scheduler_toolcall_budget_exhausted", wave=wave)
                return wave, tool_calls, True
            ready = ready[:budget_left]

            wave += 1
            for t in ready:
                t.status = TaskStatus.RUNNING
                t.attempts += 1

            results = await asyncio.gather(
                *(self._execute(state, t.tool, t.params) for t in ready))
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

        return wave, tool_calls, True  # hit iteration cap
