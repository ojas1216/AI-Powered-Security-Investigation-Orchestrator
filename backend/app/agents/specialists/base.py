"""Specialist-agent framework.

Every investigation capability (threat-intel, EDR hunt, detection, MITRE
mapping, risk, memory, ...) is exposed as a `SpecialistAgent`: a typed,
stateless, **independently callable** unit with a uniform contract. The
autonomous loop composes them via its Toolbox (delegating the analytic work
here so there is exactly one implementation), and an operator can invoke any
single agent directly through the `/agents` API.

Design rules that keep this auditable (see docs/THREAT_MODEL.md):
- Agents are the single source of truth for their analytic step; the loop's
  state-folding tools call the agent, never re-implement it.
- Agents are stateless and side-effect-scoped to their engines; they never
  read ambient request context — tenant is always an explicit argument.
- The registry rejects duplicate names (no silent capability shadowing).
"""
from __future__ import annotations

import abc
import inspect
from typing import Any

from pydantic import BaseModel, Field


class AgentResult(BaseModel):
    """Uniform envelope returned by every agent's generic `run`."""

    agent: str
    ok: bool = True
    summary: str = ""
    data: dict[str, Any] = Field(default_factory=dict)


class AgentInfo(BaseModel):
    """Discovery metadata for the /agents API."""

    name: str
    description: str
    input_hint: dict[str, str] = Field(default_factory=dict)


class SpecialistAgent(abc.ABC):
    name: str = "base"
    description: str = ""
    #: field -> human hint, surfaced by the API so callers know the payload shape
    input_hint: dict[str, str] = {}

    def info(self) -> AgentInfo:
        return AgentInfo(name=self.name, description=self.description,
                         input_hint=self.input_hint)

    @abc.abstractmethod
    async def run(self, payload: dict, *, tenant: str) -> AgentResult:
        """Invoke the agent from an untyped payload (API / ad-hoc use)."""
        raise NotImplementedError


class AgentRegistry:
    """Name -> agent lookup with strict registration."""

    def __init__(self) -> None:
        self._agents: dict[str, SpecialistAgent] = {}

    def register(self, agent: SpecialistAgent) -> None:
        if agent.name in self._agents:
            raise ValueError(f"agent already registered: {agent.name}")
        if not inspect.iscoroutinefunction(agent.run):
            raise TypeError(f"agent {agent.name}.run must be async")
        self._agents[agent.name] = agent

    def get(self, name: str) -> SpecialistAgent:
        try:
            return self._agents[name]
        except KeyError:
            raise KeyError(f"unknown agent: {name}") from None

    def names(self) -> list[str]:
        return sorted(self._agents)

    def list_info(self) -> list[AgentInfo]:
        return [self._agents[n].info() for n in self.names()]


class AgentOrchestrator:
    """Facade the API and higher layers use to compose specialists."""

    def __init__(self, registry: AgentRegistry) -> None:
        self._registry = registry

    def catalog(self) -> list[AgentInfo]:
        return self._registry.list_info()

    def get(self, name: str) -> SpecialistAgent:
        return self._registry.get(name)

    async def run(self, name: str, payload: dict, *, tenant: str) -> AgentResult:
        return await self._registry.get(name).run(payload, tenant=tenant)
