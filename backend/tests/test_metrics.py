"""Observability: zero-dep metrics registry + /metrics + loop instrumentation."""
from __future__ import annotations

import pytest

from app.core.metrics import MetricsRegistry
from app.core.observability import span

# ---------------------------------------------------------------- registry


def test_counter_with_labels_renders_prometheus():
    reg = MetricsRegistry()
    reg.inc("aegis_test_total", verdict="malicious")
    reg.inc("aegis_test_total", verdict="malicious")
    reg.inc("aegis_test_total", verdict="benign")
    out = reg.render()
    assert "# TYPE aegis_test_total counter" in out
    assert 'aegis_test_total{verdict="malicious"} 2' in out
    assert 'aegis_test_total{verdict="benign"} 1' in out


def test_histogram_renders_buckets_sum_count():
    reg = MetricsRegistry()
    reg.histogram("aegis_dur_seconds", buckets=(0.1, 1.0, 10.0))
    for v in (0.05, 0.5, 5.0):
        reg.observe("aegis_dur_seconds", v)
    out = reg.render()
    assert "# TYPE aegis_dur_seconds histogram" in out
    assert 'aegis_dur_seconds_bucket{le="0.1"} 1' in out   # only 0.05
    assert 'aegis_dur_seconds_bucket{le="1"} 2' in out      # 0.05, 0.5
    assert 'aegis_dur_seconds_bucket{le="+Inf"} 3' in out
    assert "aegis_dur_seconds_count 3" in out
    assert "aegis_dur_seconds_sum 5.55" in out


def test_label_values_are_escaped():
    reg = MetricsRegistry()
    reg.inc("aegis_x_total", tool='we"ird')
    assert 'we\\"ird' in reg.render()


def test_span_is_noop_without_otel_sdk():
    # No OTel SDK in the test env -> span() must be a harmless context manager.
    with span("test.span", foo="bar"):
        pass


# ---------------------------------------------------------------- endpoint + loop


def test_metrics_endpoint_exposes_registry(client):
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    assert "aegis_investigations_total" in resp.text  # pre-registered


@pytest.mark.asyncio
async def test_investigation_records_metrics():
    from app.core.metrics import registry
    from tests.test_agents import make_investigator, make_phishing_alert

    before = registry().render()
    await make_investigator().investigate("metrics-tenant", make_phishing_alert())
    after = registry().render()

    # A malicious investigation + its tool calls + duration were recorded.
    assert 'aegis_investigations_total{verdict="malicious"}' in after
    assert "aegis_tool_calls_total" in after
    assert "aegis_investigation_duration_seconds_count" in after
    assert after != before


def test_ingest_increments_alert_counter(client):
    headers = {"X-Tenant-ID": "acme", "X-Roles": "tier3_analyst",
               "Authorization": "Bearer dev"}
    client.post("/api/v1/alerts/ingest",
                json={"source": "generic", "id": "M-1", "title": "t",
                      "raw_text": "8.8.8.8"},
                headers=headers)
    metrics = client.get("/metrics").text
    assert 'aegis_alerts_ingested_total{mode="sync"}' in metrics


def test_agent_run_increments_counter(client):
    headers = {"X-Tenant-ID": "acme", "X-Roles": "threat_hunter",
               "Authorization": "Bearer dev"}
    client.post("/api/v1/agents/mitre/run",
                json={"payload": {"signals": ["powershell -enc"]}}, headers=headers)
    metrics = client.get("/metrics").text
    assert 'aegis_agent_runs_total{agent="mitre"}' in metrics
