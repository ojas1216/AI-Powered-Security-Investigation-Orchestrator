"""Executive intelligence: aggregate, board-level view of the SOC."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ActorCount(BaseModel):
    actor_type: str
    count: int


class DepartmentCount(BaseModel):
    department: str
    incidents: int


class RiskTrendPoint(BaseModel):
    period: str  # ISO date bucket
    avg_risk: float
    count: int


class ExecutiveSummary(BaseModel):
    generated_at: datetime
    window_days: int

    # Volume & quality
    investigation_volume: int = 0
    malicious_count: int = 0
    suspicious_count: int = 0
    benign_count: int = 0
    false_positive_rate: float = 0.0

    # Risk & exposure
    business_risk: str = "low"  # critical | high | medium | low
    average_risk_score: float = 0.0
    financial_exposure_band: str = "$0"
    high_impact_incidents: int = 0

    # Efficiency
    estimated_mttr_minutes: float = 0.0
    ai_time_saved_hours: float = 0.0
    analyst_productivity_multiplier: float = 0.0

    # Threat landscape
    active_campaigns: int = 0
    top_threat_actors: list[ActorCount] = Field(default_factory=list)
    departments_affected: list[DepartmentCount] = Field(default_factory=list)
    compliance_impact: list[str] = Field(default_factory=list)
    risk_trend: list[RiskTrendPoint] = Field(default_factory=list)
