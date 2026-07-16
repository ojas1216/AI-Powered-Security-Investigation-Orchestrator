"""Planning engine: turn the rule-based Planner's actions into graph tasks.

Reuses the existing deterministic `Planner` (auditable control flow) but lifts
each proposed action into an explicit, deduplicated, dependency-linked Task. A
new wave's tasks depend on the tasks created in prior waves that produced the
state they build on — the planner only proposes actions whose prerequisites are
met, so this dependency chain is both correct and useful for visualization.
"""
from __future__ import annotations

from app.agents.planner import Planner
from app.agents.planning.graph import TaskGraph
from app.agents.planning.task import DEFAULT_PRIORITY, Task
from app.agents.state import InvestigationState


class PlanningEngine:
    def __init__(self, planner: Planner | None = None) -> None:
        self._planner = planner or Planner()

    def expand(self, state: InvestigationState, graph: TaskGraph, wave: int) -> int:
        """Add newly-proposed tasks to the graph. Returns how many were new.

        Dependencies: a fresh task depends on all not-yet-terminal tasks already
        in the graph (they represent the prior phases whose output the planner
        just consumed). Dedup prevents re-adding identical work.
        """
        proposed = self._planner.next_actions(state)
        # This wave's actions became possible because the previous wave ran, so
        # link them to it — an honest, visualizable dependency chain.
        prior = {t.id for t in graph.all() if t.wave == wave - 1}
        added = 0
        for action in proposed:
            task = Task(
                id="",
                tool=action.tool,
                reason=action.reason,
                params=dict(action.params),
                priority=DEFAULT_PRIORITY.get(action.tool, 50),
                depends_on=set(prior),
                wave=wave,
            )
            if graph.has_key(task.key):
                continue  # identical work already tracked
            graph.add(task)
            added += 1
        return added
