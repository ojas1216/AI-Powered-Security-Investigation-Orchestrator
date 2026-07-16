"""Reusable circuit breaker for threat-intel connectors.

Opens after N consecutive failures and stays open for a cooldown, so a dead
upstream costs one timeout rather than one per lookup. Half-opens after the
cooldown to probe recovery. Deterministic (injectable clock) for tests.
"""
from __future__ import annotations

import time
from collections.abc import Callable


class CircuitBreaker:
    def __init__(self, threshold: int = 3, cooldown_seconds: float = 60.0,
                 now_fn: Callable[[], float] = time.monotonic) -> None:
        self._threshold = threshold
        self._cooldown = cooldown_seconds
        self._now = now_fn
        self._failures = 0
        self._opened_at: float | None = None

    def available(self) -> bool:
        if self._opened_at is None:
            return True
        if self._now() - self._opened_at >= self._cooldown:
            self._opened_at = None            # half-open: allow one probe
            self._failures = self._threshold - 1
            return True
        return False

    def record_success(self) -> None:
        self._failures = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self._threshold:
            self._opened_at = self._now()
