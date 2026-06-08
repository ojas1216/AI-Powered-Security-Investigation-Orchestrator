"""Elastic Security (ECS) signal → Alert."""
from __future__ import annotations

from app.ingestion.normalizers.base import Normalizer
from app.schemas.alert import Alert
from app.schemas.common import Severity, SourceProduct

_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
        "medium": Severity.MEDIUM, "low": Severity.LOW}


class ElasticNormalizer(Normalizer):
    source = "elastic"

    def normalize(self, raw: dict) -> Alert:
        src = raw.get("_source", raw)
        rule = src.get("kibana.alert.rule", src.get("signal", {}).get("rule", {})) or {}
        return Alert(
            source=SourceProduct.ELASTIC,
            source_alert_id=str(raw.get("_id") or src.get("event", {}).get("id") or "unknown"),
            title=str(rule.get("name") or src.get("message") or "Elastic signal"),
            description=str(rule.get("description", "")),
            severity=_SEV.get(str(src.get("kibana.alert.severity",
                              rule.get("severity", "medium"))).lower(), Severity.MEDIUM),
            src_ips=self._as_list(src.get("source", {}).get("ip")),
            dst_ips=self._as_list(src.get("destination", {}).get("ip")),
            users=self._as_list(src.get("user", {}).get("name")),
            hosts=self._as_list(src.get("host", {}).get("name")),
            raw_text=" ".join(
                str(x) for x in (
                    src.get("message", ""),
                    src.get("process", {}).get("command_line", ""),
                    src.get("url", {}).get("full", ""),
                )
            ),
        )
