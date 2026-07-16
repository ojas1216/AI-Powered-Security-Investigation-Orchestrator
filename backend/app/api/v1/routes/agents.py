"""Specialist-agent API: discover and independently invoke any agent.

Each investigation capability (threat_intel, edr_hunt, detection, mitre, risk,
memory, sandbox, email, ioc_extraction) is callable on its own here — the same
agents the autonomous loop composes. Useful for ad-hoc analysis, tooling, and
external orchestration without running a full investigation.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.agents.specialists import AgentInfo, AgentResult, get_agent_bundle
from app.api.deps import require
from app.core.authz import Permission
from app.core.logging import get_logger
from app.core.security import Principal

router = APIRouter()
log = get_logger("api.agents")

_orchestrator = get_agent_bundle().orchestrator()


class AgentRunRequest(BaseModel):
    payload: dict = Field(default_factory=dict,
                          description="Agent-specific input; see the agent's input_hint")


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
    return await agent.run(body.payload, tenant=principal.tenant)
