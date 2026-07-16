"""Reflection engine: the investigation's self-review.

After evidence collection converges, the platform asks itself the questions a
senior analyst would: did we leave work undone, did we miss an obvious pivot,
does a conclusion rest on a single unconfirmed source, do our sources contradict
each other? Each concern becomes a `ReflectionFinding`; where a concern is
actionable, it also yields a follow-up action the scheduler re-opens as a task,
and the loop repeats until nothing new is proposed (confidence stabilizes).

Two entry points over one analysis:
- `suggest(state)` → follow-up actions the scheduler executes (drives collection).
- `review(state)`  → residual findings recorded on every package (self-review
  record, both strategies).

The engine is stateless and deterministic — like the planner, it must be
auditable, so it never asks an LLM whether the investigation is "done".
"""
from __future__ import annotations

from dataclasses import dataclass

from app.agents.planner import PlannedAction
from app.agents.planning.task import dedup_key
from app.agents.state import InvestigationState
from app.schemas.common import Verdict
from app.schemas.investigation import ReflectionFinding


@dataclass
class _Issue:
    category: str
    detail: str
    action: PlannedAction | None = None


class ReflectionEngine:
    def _analyze(self, state: InvestigationState) -> list[_Issue]:
        issues: list[_Issue] = []
        enriched = state.enriched
        edr_values = {h.ioc.value.lower() for h in state.edr_hits}

        # 1. Coverage — IOCs left un-enriched (collection cut short by a budget).
        if state.pending_iocs:
            issues.append(_Issue(
                "coverage",
                f"{len(state.pending_iocs)} IOC(s) were never enriched",
                PlannedAction(tool="enrich_iocs",
                              reason="reflection: enrich residual IOCs"),
            ))

        # 2. Coverage — attachments never detonated.
        if state.email_msg:
            for att in state.email_msg.attachments:
                if att.sha256 not in state.detonated:
                    issues.append(_Issue(
                        "coverage",
                        f"attachment {att.filename} was never detonated",
                        PlannedAction(
                            tool="detonate_attachment",
                            params={"filename": att.filename, "sha256": att.sha256},
                            reason="reflection: detonate residual attachment"),
                    ))

        # 3. Gap — suspicious IOCs were never hunted (the planner only hunts
        #    malicious ones); on-host evidence could confirm or clear them.
        susp_unhunted = sorted(
            k for k, e in enriched.items()
            if e.verdict is Verdict.SUSPICIOUS and k not in state.hunted_keys)
        if susp_unhunted:
            issues.append(_Issue(
                "gap",
                f"{len(susp_unhunted)} suspicious IOC(s) were not hunted in EDR",
                PlannedAction(tool="hunt_edr", params={"ioc_keys": susp_unhunted},
                              reason="reflection: hunt suspicious IOCs for "
                                     "on-host confirmation"),
            ))

        # 4. Unverified — a malicious verdict resting on a single source with no
        #    independent (on-host) corroboration.
        for k, e in enriched.items():
            mal_sources = [s for s in e.sources if s.verdict is Verdict.MALICIOUS]
            if e.verdict is Verdict.MALICIOUS and len(mal_sources) <= 1:
                if e.ioc.value.lower() in edr_values:
                    continue  # EDR independently confirms it
                if k not in state.hunted_keys:
                    issues.append(_Issue(
                        "unverified",
                        f"{e.ioc.value} is malicious on a single source with no "
                        "on-host confirmation",
                        PlannedAction(tool="hunt_edr", params={"ioc_keys": [k]},
                                      reason="reflection: independently verify a "
                                             "single-source malicious IOC in EDR"),
                    ))
                else:
                    issues.append(_Issue(
                        "unverified",
                        f"{e.ioc.value} is malicious on a single source and EDR "
                        "found no on-host activity — verdict rests on one feed",
                    ))

        # 5. Contradiction — sources disagree on the same indicator.
        for e in enriched.values():
            verdicts = {s.verdict for s in e.sources}
            if Verdict.MALICIOUS in verdicts and Verdict.BENIGN in verdicts:
                issues.append(_Issue(
                    "contradiction",
                    f"sources disagree on {e.ioc.value} (both malicious and "
                    "benign verdicts returned)",
                ))
        return issues

    def suggest(self, state: InvestigationState) -> list[PlannedAction]:
        """Follow-up actions to re-open as tasks (deduplicated)."""
        seen: set[str] = set()
        actions: list[PlannedAction] = []
        for issue in self._analyze(state):
            if issue.action is None:
                continue
            key = dedup_key(issue.action.tool, issue.action.params)
            if key not in seen:
                seen.add(key)
                actions.append(issue.action)
        return actions

    def review(self, state: InvestigationState) -> list[ReflectionFinding]:
        """Residual findings for the package (self-review record)."""
        return [
            ReflectionFinding(
                category=i.category, detail=i.detail,
                action_recommended=(i.action.tool if i.action else ""))
            for i in self._analyze(state)
        ]


_engine: ReflectionEngine | None = None


def build_reflection_engine() -> ReflectionEngine:
    global _engine
    if _engine is None:
        _engine = ReflectionEngine()
    return _engine
