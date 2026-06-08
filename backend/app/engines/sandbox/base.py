"""Sandbox detonation contract (Joe / Falcon / CAPE / Any.Run)."""
from __future__ import annotations

import abc

from pydantic import BaseModel, Field

from app.schemas.ioc import IOC


class ProcessNode(BaseModel):
    pid: int
    name: str
    cmdline: str = ""
    children: list["ProcessNode"] = Field(default_factory=list)


class SandboxReport(BaseModel):
    sample_ref: str
    malscore: float = Field(ge=0.0, le=1.0)
    verdict: str = "unknown"
    signatures: list[str] = Field(default_factory=list)
    dropped_iocs: list[IOC] = Field(default_factory=list)
    process_tree: ProcessNode | None = None
    persistence: list[str] = Field(default_factory=list)
    registry_changes: list[str] = Field(default_factory=list)


class SandboxConnector(abc.ABC):
    name = "base-sandbox"

    @abc.abstractmethod
    async def detonate(self, *, filename: str, content: bytes | None = None,
                       url: str | None = None) -> SandboxReport:
        raise NotImplementedError
