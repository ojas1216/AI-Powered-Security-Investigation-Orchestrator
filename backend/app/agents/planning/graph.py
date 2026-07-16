"""Task graph: dependency-aware, deduplicated set of investigation tasks.

The graph is the single source of truth for what work exists, what is ready to
run (all dependencies satisfied), and overall progress. It deduplicates by
(tool, params) so the same work is never scheduled twice, and it is directly
serializable for visualization (execution-graph view).
"""
from __future__ import annotations

from app.agents.planning.task import Task, TaskStatus
from app.schemas.investigation import PlanNode


class TaskGraph:
    def __init__(self) -> None:
        self._tasks: dict[str, Task] = {}       # id -> task
        self._counter = 0

    def add(self, task: Task) -> str:
        """Insert a task unless an identical (tool, params) one is still *active*
        (pending/running). A completed same-key task may be re-created when new
        evidence re-proposes the work (e.g. re-enriching sandbox-dropped IOCs) —
        this mirrors the batch loop while still preventing duplicate concurrent
        work. Returns the id of the task occupying that slot."""
        active = self._active_with_key(task.key)
        if active is not None:
            return active.id
        if not task.id:
            self._counter += 1
            task.id = f"t{self._counter}"
        self._tasks[task.id] = task
        return task.id

    def _active_with_key(self, key: str) -> Task | None:
        for t in self._tasks.values():
            if t.key == key and not t.terminal:
                return t
        return None

    def get(self, task_id: str) -> Task:
        return self._tasks[task_id]

    def has_key(self, key: str) -> bool:
        """True if a non-terminal task with this key already exists."""
        return self._active_with_key(key) is not None

    def all(self) -> list[Task]:
        return list(self._tasks.values())

    def pending_ids(self) -> set[str]:
        return {t.id for t in self._tasks.values() if not t.terminal}

    def ready(self) -> list[Task]:
        """Pending tasks whose dependencies have all finished (terminal), highest
        priority first. A failed upstream is 'finished' too, so a single failure
        degrades gracefully instead of deadlocking the graph — the planner's
        state logic, not the edge, decides whether a task is still appropriate."""
        out = [
            t for t in self._tasks.values()
            if t.status is TaskStatus.PENDING
            and all(self._tasks[d].terminal
                    for d in t.depends_on if d in self._tasks)
        ]
        out.sort(key=lambda t: (-t.priority, t.wave, t.id))
        return out

    def all_terminal(self) -> bool:
        return all(t.terminal for t in self._tasks.values())

    def progress(self) -> tuple[int, int]:
        """(#terminal, #total)."""
        total = len(self._tasks)
        done = sum(1 for t in self._tasks.values() if t.terminal)
        return done, total

    def remaining(self) -> int:
        return sum(1 for t in self._tasks.values() if not t.terminal)

    def to_plan_nodes(self) -> list[PlanNode]:
        return [
            PlanNode(
                id=t.id, tool=t.tool, reason=t.reason, status=t.status.value,
                priority=t.priority, attempts=t.attempts,
                depends_on=sorted(t.depends_on), outcome=t.outcome, ok=t.ok,
                duration_ms=t.duration_ms,
            )
            for t in sorted(self._tasks.values(), key=lambda t: (t.wave, t.id))
        ]
