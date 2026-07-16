"""Zero-dependency Prometheus metrics.

A tiny thread-safe registry (counters + histograms with labels) that renders the
Prometheus text exposition format. No client library required, so `/metrics`
works in minimal/air-gapped deployments and is fully hermetic for tests. When a
real Prometheus/OTel stack is present it simply scrapes this endpoint.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field

_DURATION_BUCKETS = (0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0)


def _fmt_labels(labels: tuple[tuple[str, str], ...]) -> str:
    if not labels:
        return ""
    inner = ",".join(f'{k}="{_escape(v)}"' for k, v in labels)
    return "{" + inner + "}"


def _escape(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


@dataclass
class _Counter:
    help: str
    values: dict[tuple[tuple[str, str], ...], float] = field(default_factory=dict)

    def inc(self, labels: tuple[tuple[str, str], ...], amount: float = 1.0) -> None:
        self.values[labels] = self.values.get(labels, 0.0) + amount


@dataclass
class _Histogram:
    help: str
    buckets: tuple[float, ...]
    # per label-set: (bucket counts, sum, count)
    series: dict[tuple[tuple[str, str], ...], list] = field(default_factory=dict)

    def observe(self, labels: tuple[tuple[str, str], ...], value: float) -> None:
        s = self.series.get(labels)
        if s is None:
            s = [[0] * len(self.buckets), 0.0, 0]  # counts, sum, count
            self.series[labels] = s
        for i, b in enumerate(self.buckets):
            if value <= b:
                s[0][i] += 1
        s[1] += value
        s[2] += 1


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, _Counter] = {}
        self._histograms: dict[str, _Histogram] = {}

    def counter(self, name: str, help: str = "") -> None:
        with self._lock:
            self._counters.setdefault(name, _Counter(help))

    def histogram(self, name: str, help: str = "",
                  buckets: tuple[float, ...] = _DURATION_BUCKETS) -> None:
        with self._lock:
            self._histograms.setdefault(name, _Histogram(help, buckets))

    def inc(self, name: str, amount: float = 1.0, **labels: str) -> None:
        key = tuple(sorted(labels.items()))
        with self._lock:
            c = self._counters.setdefault(name, _Counter(""))
            c.inc(key, amount)

    def observe(self, name: str, value: float, **labels: str) -> None:
        key = tuple(sorted(labels.items()))
        with self._lock:
            h = self._histograms.setdefault(name, _Histogram("", _DURATION_BUCKETS))
            h.observe(key, value)

    def render(self) -> str:
        lines: list[str] = []
        with self._lock:
            for name, c in sorted(self._counters.items()):
                if c.help:
                    lines.append(f"# HELP {name} {c.help}")
                lines.append(f"# TYPE {name} counter")
                for labels, val in sorted(c.values.items()):
                    lines.append(f"{name}{_fmt_labels(labels)} {_num(val)}")
            for name, h in sorted(self._histograms.items()):
                if h.help:
                    lines.append(f"# HELP {name} {h.help}")
                lines.append(f"# TYPE {name} histogram")
                for labels, (counts, total, n) in sorted(h.series.items()):
                    base = dict(labels)
                    # counts[i] is already cumulative (observe increments every
                    # bucket the value falls into), matching Prometheus semantics.
                    for i, b in enumerate(h.buckets):
                        le = {**base, "le": _num(b)}
                        bucket_labels = tuple(sorted(le.items()))
                        lines.append(
                            f"{name}_bucket{_fmt_labels(bucket_labels)} {counts[i]}")
                    inf_labels = tuple(sorted({**base, "le": "+Inf"}.items()))
                    lines.append(f"{name}_bucket{_fmt_labels(inf_labels)} {n}")
                    lines.append(f"{name}_sum{_fmt_labels(labels)} {_num(total)}")
                    lines.append(f"{name}_count{_fmt_labels(labels)} {n}")
        return "\n".join(lines) + "\n"


def _num(v: float) -> str:
    return str(int(v)) if float(v).is_integer() else repr(v)


# ---------------------------------------------------------------- singleton

_registry = MetricsRegistry()
_registry.counter("aegis_investigations_total", "Investigations by verdict")
_registry.counter("aegis_tool_calls_total", "Agent tool calls by tool and outcome")
_registry.counter("aegis_agent_runs_total", "Specialist agent invocations by agent")
_registry.counter("aegis_alerts_ingested_total", "Alerts ingested by mode")
_registry.counter("aegis_detections_fired_total", "Detection-rule matches")
_registry.histogram("aegis_investigation_duration_seconds",
                    "End-to-end investigation duration")


def registry() -> MetricsRegistry:
    return _registry
