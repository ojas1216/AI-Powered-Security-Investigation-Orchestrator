"""Task model for the planning layer.

A Task is one unit of investigative work (run a specialist tool with params),
with an explicit dependency set, a priority, and a bounded retry budget. Tasks
are the nodes of the TaskGraph; the PriorityScheduler executes them.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum


class TaskStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"     # exhausted retries
    SKIPPED = "skipped"   # cancelled as irrelevant


# Higher runs first. Earlier investigation phases get higher priority so the
# scheduler front-loads context-gathering before enrichment/hunting.
DEFAULT_PRIORITY: dict[str, int] = {
    "run_detections": 90,
    "fetch_email_context": 90,
    "extract_iocs": 80,
    "enrich_iocs": 70,
    "detonate_attachment": 60,
    "hunt_edr": 50,
}


def dedup_key(tool: str, params: dict) -> str:
    """Stable identity for a (tool, params) pair so identical work is never
    scheduled twice."""
    return f"{tool}:{json.dumps(params, sort_keys=True, default=str)}"


@dataclass
class Task:
    id: str
    tool: str
    reason: str
    params: dict = field(default_factory=dict)
    priority: int = 50
    depends_on: set[str] = field(default_factory=set)
    status: TaskStatus = TaskStatus.PENDING
    attempts: int = 0
    max_attempts: int = 2
    wave: int = 0
    outcome: str = ""
    ok: bool = True
    duration_ms: float = 0.0

    @property
    def key(self) -> str:
        return dedup_key(self.tool, self.params)

    @property
    def terminal(self) -> bool:
        return self.status in (TaskStatus.DONE, TaskStatus.FAILED,
                               TaskStatus.SKIPPED)

    @property
    def retryable(self) -> bool:
        return self.status is TaskStatus.PENDING and self.attempts > 0
