"""Microsoft Sentinel incident → Alert."""
from __future__ import annotations

from app.ingestion.normalizers.base import Normalizer
from app.schemas.alert import Alert
from app.schemas.common import Severity, SourceProduct

_SEV = {"high": Severity.HIGH, "medium": Severity.MEDIUM,
        "low": Severity.LOW, "informational": Severity.INFO}


class SentinelNormalizer(Normalizer):
    source = "sentinel"

    def normalize(self, raw: dict) -> Alert:
        props = raw.get("properties", raw)
        entities = props.get("relatedEntities", []) or props.get("entities", [])
        ips = [e.get("address") for e in entities if e.get("kind") == "Ip"]
        hosts = [e.get("hostName") for e in entities if e.get("kind") == "Host"]
        users = [e.get("accountName") for e in entities if e.get("kind") == "Account"]
        return Alert(
            source=SourceProduct.SENTINEL,
            source_alert_id=str(props.get("incidentNumber") or raw.get("name") or "unknown"),
            title=str(props.get("title", "Sentinel incident")),
            description=str(props.get("description", "")),
            severity=_SEV.get(str(props.get("severity", "medium")).lower(), Severity.MEDIUM),
            src_ips=[ip for ip in ips if ip],
            hosts=[h for h in hosts if h],
            users=[u for u in users if u],
            raw_text=str(props.get("description", "")),
            extra={"alert_product_names": props.get("alertProductNames", [])},
        )
