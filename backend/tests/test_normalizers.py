"""Unit tests for SIEM alert normalizers."""
from __future__ import annotations

from app.ingestion.normalizers import get_normalizer
from app.schemas.common import SourceProduct


def test_splunk_normalizer():
    raw = {
        "source": "splunk",
        "result": {
            "event_id": "ES-1",
            "search_name": "Malicious PowerShell",
            "urgency": "critical",
            "src_ip": "45.155.205.99",
            "user": "jdoe",
            "dvc": "WS-FIN-042",
        },
    }
    alert = get_normalizer(SourceProduct.SPLUNK).normalize(raw)
    assert alert.source == SourceProduct.SPLUNK
    assert alert.source_alert_id == "ES-1"
    assert "45.155.205.99" in alert.src_ips
    assert "WS-FIN-042" in alert.hosts


def test_sentinel_normalizer_entities():
    raw = {
        "properties": {
            "incidentNumber": "INC-1",
            "title": "Phishing",
            "severity": "high",
            "entities": [
                {"kind": "Ip", "address": "45.155.205.99"},
                {"kind": "Host", "hostName": "WS-FIN-042"},
                {"kind": "Account", "accountName": "jdoe"},
            ],
        },
    }
    alert = get_normalizer(SourceProduct.SENTINEL).normalize(raw)
    assert alert.source_alert_id == "INC-1"
    assert alert.src_ips == ["45.155.205.99"]
    assert alert.hosts == ["WS-FIN-042"]
    assert alert.users == ["jdoe"]


def test_elastic_normalizer():
    raw = {
        "_id": "sig-1",
        "_source": {
            "signal": {"rule": {"name": "Suspicious Process", "severity": "high"}},
            "source": {"ip": "45.155.205.99"},
            "host": {"name": "WS-FIN-042"},
        },
    }
    alert = get_normalizer(SourceProduct.ELASTIC).normalize(raw)
    assert alert.source == SourceProduct.ELASTIC
    assert alert.title == "Suspicious Process"
