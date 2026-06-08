"""IOC and enrichment schemas."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.common import IOCType, Verdict


class IOC(BaseModel):
    type: IOCType
    value: str = Field(min_length=1, max_length=2048)
    # defanged form is normalized back to canonical on extraction
    first_seen: datetime | None = None
    context: str | None = Field(default=None, max_length=512)

    def key(self) -> str:
        return f"{self.type.value}:{self.value.lower()}"


class SourceVerdict(BaseModel):
    source: str
    verdict: Verdict
    score: float = Field(ge=0.0, le=1.0, description="malice confidence 0..1")
    detail: str | None = None
    raw_ref: str | None = None  # pointer to stored raw evidence


class EnrichedIOC(BaseModel):
    ioc: IOC
    verdict: Verdict = Verdict.UNKNOWN
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    sources: list[SourceVerdict] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)
    sightings: int = 0
