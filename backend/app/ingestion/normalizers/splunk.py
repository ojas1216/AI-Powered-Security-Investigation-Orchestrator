"""Splunk ES notable-event → Alert."""
from __future__ import annotations

from app.ingestion.normalizers.base import Normalizer
from app.schemas.alert import Alert
from app.schemas.common import Severity, SourceProduct

_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
        "medium": Severity.MEDIUM, "low": Severity.LOW, "informational": Severity.INFO}


class SplunkNormalizer(Normalizer):
    source = "splunk"

    def normalize(self, raw: dict) -> Alert:
        result = raw.get("result", raw)
        return Alert(
            source=SourceProduct.SPLUNK,
            source_alert_id=str(result.get("event_id") or raw.get("sid") or "unknown"),
            title=str(result.get("search_name") or result.get("signature") or "Splunk notable"),
            description=str(result.get("description", "")),
            severity=_SEV.get(str(result.get("urgency", "medium")).lower(), Severity.MEDIUM),
            src_ips=self._as_list(result.get("src_ip") or result.get("src")),
            dst_ips=self._as_list(result.get("dest_ip") or result.get("dest")),
            users=self._as_list(result.get("user")),
            hosts=self._as_list(result.get("dvc") or result.get("host")),
            raw_text=" ".join(
                str(result.get(k, "")) for k in ("description", "_raw", "url", "process")
            ),
            extra={"orig_sid": raw.get("sid")},
        )
