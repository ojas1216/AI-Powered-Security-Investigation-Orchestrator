"""Dynamic investigation planner.

Given the current InvestigationState, emit the next batch of actions with an
explicit reason per action. Actions inside one batch are independent and run
concurrently; the loop re-plans after every batch, so evidence discovered by one
iteration (e.g. IOCs dropped by a sandbox detonation) changes what the next
iteration does. An empty plan means evidence collection has converged and the
loop moves to finalization.

The planner is deterministic and rule-driven by design: investigation control
flow must be auditable and reproducible. LLM judgement lives in the copilot
(narrative) layer, never in the action-selection layer — that boundary is what
keeps prompt-injection in evidence from steering the investigation itself
(see docs/THREAT_MODEL.md).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.agents.state import InvestigationState


@dataclass(frozen=True)
class PlannedAction:
    tool: str
    reason: str
    params: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Budget:
    """Hard limits so an adversarial or pathological alert cannot run forever."""

    max_iterations: int = 8
    max_tool_calls: int = 32
    max_wall_clock_seconds: float = 300.0


class Planner:
    def next_actions(self, state: InvestigationState) -> list[PlannedAction]:
        # Phase 1 — widen the corpus before extraction so one extraction pass
        # sees alert text + email body + urls together. Detection rules run on
        # the raw alert and are independent, so they join the first batch.
        first_batch: list[PlannedAction] = []
        if not state.detections_ran:
            first_batch.append(PlannedAction(
                tool="run_detections",
                reason="Evaluate detection rules against the raw alert so behavioral "
                       "matches steer MITRE mapping and risk from the start",
            ))
        if state.looks_like_phishing() and not state.email_checked:
            first_batch.append(PlannedAction(
                tool="fetch_email_context",
                reason="Alert references a reported email; pull the message, "
                       "campaign recipients and attachments before extracting IOCs",
            ))
        if first_batch:
            return first_batch

        if not state.extracted:
            return [PlannedAction(
                tool="extract_iocs",
                reason="Corpus changed since last extraction; find fanged and "
                       "defanged IOCs plus SIEM-provided entities",
            )]

        # Phase 2 — independent evidence collection, batched for concurrency.
        actions: list[PlannedAction] = []

        if state.pending_iocs:
            actions.append(PlannedAction(
                tool="enrich_iocs",
                reason=f"{len(state.pending_iocs)} IOCs lack threat-intel verdicts",
            ))

        if state.email_msg:
            for att in state.email_msg.attachments:
                if att.sha256 not in state.detonated:
                    actions.append(PlannedAction(
                        tool="detonate_attachment",
                        params={"filename": att.filename, "sha256": att.sha256},
                        reason=f"Attachment {att.filename} is undetonated; sandbox "
                               "verdict and dropped IOCs feed the hunt",
                    ))

        # Phase 3 — hunt. Prefer confirmed-malicious IOCs; if TI knows nothing,
        # hunt everything once so on-host evidence can still surface. Never hunt
        # while enrichment/detonation is queued: their output changes the target set.
        if not actions:
            malicious = state.malicious_unhunted()
            if malicious:
                actions.append(PlannedAction(
                    tool="hunt_edr",
                    params={"ioc_keys": [e.ioc.key() for e in malicious]},
                    reason=f"{len(malicious)} malicious IOCs not yet hunted in EDR; "
                           "confirm whether any host touched them",
                ))
            elif not state.hunted_keys and state.unhunted():
                unhunted = state.unhunted()
                actions.append(PlannedAction(
                    tool="hunt_edr",
                    params={"ioc_keys": [e.ioc.key() for e in unhunted]},
                    reason="No IOC is TI-confirmed malicious; hunt the full set once "
                           "since on-host sightings outrank feed silence",
                ))

        return actions
