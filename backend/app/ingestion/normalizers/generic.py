"""Generic / fallback normalizer for QRadar, Wazuh, Chronicle, or raw input."""
from __future__ import annotations

from app.ingestion.normalizers.base import Normalizer
from app.schemas.alert import Alert
from app.schemas.common import Severity, SourceProduct


class GenericNormalizer(Normalizer):
    source = "generic"

    def normalize(self, raw: dict) -> Alert:
        return Alert(
            source=SourceProduct(raw.get("source", "generic"))
            if raw.get("source") in SourceProduct.__members__.values()
            else SourceProduct.GENERIC,
            source_alert_id=str(raw.get("id") or raw.get("alert_id") or "unknown"),
            title=str(raw.get("title") or raw.get("name") or "Security alert"),
            description=str(raw.get("description", "")),
            severity=Severity(raw["severity"])
            if raw.get("severity") in Severity.__members__.values()
            else Severity.MEDIUM,
            src_ips=self._as_list(raw.get("src_ips") or raw.get("src_ip")),
            dst_ips=self._as_list(raw.get("dst_ips") or raw.get("dst_ip")),
            users=self._as_list(raw.get("users") or raw.get("user")),
            hosts=self._as_list(raw.get("hosts") or raw.get("host")),
            raw_text=str(raw.get("raw_text") or raw.get("body") or raw.get("description", "")),
            extra={k: v for k, v in raw.items() if k not in {
                "id", "title", "description", "severity", "raw_text"}},
        )
