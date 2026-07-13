"""Detection rule model — a Sigma-inspired, strictly-typed rule DSL.

A rule is a boolean condition over the normalized Alert's fields:

    condition:
      all:  every matcher must hit          (AND)
      any:  at least one matcher must hit   (OR)   — optional
      none: no matcher may hit              (NOT)  — optional

Field matchers address alert fields by dot-path (`extra.command_line`) with a
modifier (contains / equals / startswith / endswith / regex / in). Regexes are
compiled and validated at rule-load time, so a malformed rule can never enter
the engine; matching is case-insensitive unless the rule opts out.

Rules carry their own ATT&CK mapping so a match contributes techniques to the
investigation directly — detection engineering and MITRE coverage stay in sync.
"""
from __future__ import annotations

import re
from enum import StrEnum
from functools import cached_property
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.alert import Alert
from app.schemas.common import Severity

# Bound regex source length; combined with re2-style review of builtin rules this
# keeps pathological patterns (ReDoS) out of the hot path.
_MAX_PATTERN_LEN = 512


class Modifier(StrEnum):
    EQUALS = "equals"
    CONTAINS = "contains"
    STARTSWITH = "startswith"
    ENDSWITH = "endswith"
    REGEX = "regex"
    IN = "in"


class FieldMatcher(BaseModel):
    model_config = ConfigDict(frozen=True)

    field: str = Field(min_length=1, max_length=128)
    modifier: Modifier = Modifier.CONTAINS
    values: tuple[str, ...] = Field(min_length=1, max_length=64)
    case_sensitive: bool = False

    @field_validator("values")
    @classmethod
    def _validate_values(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for v in values:
            if not v:
                raise ValueError("matcher value must be non-empty")
            if len(v) > _MAX_PATTERN_LEN:
                raise ValueError(f"matcher value exceeds {_MAX_PATTERN_LEN} chars")
        return values

    @model_validator(mode="after")
    def _compile_regexes(self) -> FieldMatcher:
        # Fail fast at load time; cached for the hot path.
        _ = self.compiled
        return self

    @cached_property
    def compiled(self) -> tuple[re.Pattern[str], ...]:
        if self.modifier is not Modifier.REGEX:
            return ()
        flags = 0 if self.case_sensitive else re.IGNORECASE
        try:
            return tuple(re.compile(v, flags) for v in self.values)
        except re.error as exc:
            raise ValueError(f"invalid regex in matcher for '{self.field}': {exc}") from exc

    def matches(self, value: str) -> bool:
        hay = value if self.case_sensitive else value.lower()
        needles = self.values if self.case_sensitive else tuple(
            v.lower() for v in self.values)
        match self.modifier:
            case Modifier.EQUALS:
                return hay in needles
            case Modifier.CONTAINS:
                return any(n in hay for n in needles)
            case Modifier.STARTSWITH:
                return hay.startswith(needles)
            case Modifier.ENDSWITH:
                return hay.endswith(needles)
            case Modifier.IN:
                return hay in needles
            case Modifier.REGEX:
                return any(p.search(value) for p in self.compiled)
        return False  # pragma: no cover - exhaustive match above


class RuleCondition(BaseModel):
    model_config = ConfigDict(frozen=True)

    all: tuple[FieldMatcher, ...] = ()
    any: tuple[FieldMatcher, ...] = ()
    none: tuple[FieldMatcher, ...] = ()

    @model_validator(mode="after")
    def _require_positive_clause(self) -> RuleCondition:
        if not self.all and not self.any:
            raise ValueError("condition needs at least one 'all' or 'any' matcher")
        return self


class TechniqueRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    name: str = Field(min_length=1, max_length=256)
    tactic: str = Field(min_length=1, max_length=64)


class DetectionRule(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str = Field(pattern=r"^[A-Z0-9][A-Z0-9\-]{2,63}$")
    title: str = Field(min_length=3, max_length=256)
    description: str = Field(default="", max_length=2048)
    severity: Severity = Severity.MEDIUM
    condition: RuleCondition
    techniques: tuple[TechniqueRef, ...] = ()
    tags: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    false_positives: tuple[str, ...] = ()
    enabled: bool = True
    author: str = "aegisflow"
    version: int = Field(default=1, ge=1)


def flatten_alert(alert: Alert) -> dict[str, str]:
    """Project the alert into dot-path -> searchable-string fields."""
    fields: dict[str, str] = {
        "title": alert.title,
        "description": alert.description,
        "raw_text": alert.raw_text,
        "severity": alert.severity.value,
        "source": alert.source.value,
        "src_ips": " ".join(alert.src_ips),
        "dst_ips": " ".join(alert.dst_ips),
        "users": " ".join(alert.users),
        "hosts": " ".join(alert.hosts),
        "text": "\n".join([alert.title, alert.description, alert.raw_text]),
    }
    for key, value in alert.extra.items():
        fields[f"extra.{key}"] = _stringify(value)
    return fields


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list | tuple | set):
        return " ".join(_stringify(v) for v in value)
    if isinstance(value, dict):
        return " ".join(f"{k}={_stringify(v)}" for k, v in value.items())
    return str(value)
