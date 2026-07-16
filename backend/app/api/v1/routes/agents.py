"""Specialist-agent API: discover and independently invoke any agent.

Each investigation capability (threat_intel, edr_hunt, detection, mitre, risk,
memory, sandbox, email, ioc_extraction) is callable on its own here — the same
agents the autonomous loop composes. Useful for ad-hoc analysis, tooling, and
external orchestration without running a full investigation.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from app.agents.specialists import AgentInfo, AgentResult, get_agent_bundle
from app.api.deps import require
from app.core.authz import Permission
from app.core.logging import get_logger
from app.core.security import Principal

router = APIRouter()
log = get_logger("api.agents")

_orchestrator = get_agent_bundle().orchestrator()


_MAX_PAYLOAD_BYTES = 1_000_000  # 1 MiB cap on an agent invocation payload


class AgentRunRequest(BaseModel):
    payload: dict = Field(default_factory=dict,
                          description="Agent-specific input; see the agent's input_hint")

    @field_validator("payload")
    @classmethod
    def _cap_payload(cls, value: dict) -> dict:
        import json

        if len(json.dumps(value, default=str)) > _MAX_PAYLOAD_BYTES:
            raise ValueError("agent payload exceeds 1 MiB")
        return value


@router.get("", response_model=list[AgentInfo])
async def list_agents(
    principal: Principal = Depends(require(Permission.AGENT_RUN)),
) -> list[AgentInfo]:
    return _orchestrator.catalog()


@router.post("/{name}/run", response_model=AgentResult)
async def run_agent(
    name: str,
    body: AgentRunRequest,
    principal: Principal = Depends(require(Permission.AGENT_RUN)),
) -> AgentResult:
    try:
        agent = _orchestrator.get(name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"unknown agent: {name}") from exc
    log.info("agent_invoked", agent=name, tenant=principal.tenant,
             actor=principal.username)
    from app.core.metrics import registry

    registry().inc("aegis_agent_runs_total", agent=name)
    return await agent.run(body.payload, tenant=principal.tenant)
