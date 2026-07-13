"""The common normalized Alert schema — every source maps into this."""
from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import Severity, SourceProduct


class RawAlert(BaseModel):
    """Loosely-typed inbound payload from a SIEM webhook/API."""

    model_config = ConfigDict(extra="allow")
    source: SourceProduct = SourceProduct.GENERIC


class Alert(BaseModel):
    """Normalized alert. The single contract the orchestrator consumes."""

    source: SourceProduct
    source_alert_id: str = Field(max_length=256)
    title: str = Field(max_length=512)
    description: str = Field(default="", max_length=8192)
    severity: Severity = Severity.MEDIUM
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # Entities the source already extracted (we still re-extract from raw text).
    src_ips: list[str] = Field(default_factory=list)
    dst_ips: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)

    # Free-form fields that frequently carry IOCs (email body, command line, url)
    raw_text: str = Field(default="", max_length=200_000)
    extra: dict = Field(default_factory=dict)
