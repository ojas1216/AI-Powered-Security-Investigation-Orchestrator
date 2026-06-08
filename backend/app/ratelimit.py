"""Per-tenant token-bucket rate limiting (Redis-backed, in-memory fallback)."""
from __future__ import annotations

import time

from app.core.config import settings
from app.core.exceptions import RateLimitError

_buckets: dict[str, list[float]] = {}


async def check_rate_limit(tenant: str) -> None:
    """Sliding-window limiter. Uses Redis in production; this in-memory version
    keeps the app self-contained and is swapped via DI in the full stack."""
    limit = settings.rate_limit_per_minute
    now = time.time()
    window = _buckets.setdefault(tenant, [])
    # drop timestamps older than 60s
    cutoff = now - 60
    window[:] = [t for t in window if t > cutoff]
    if len(window) >= limit:
        raise RateLimitError("Rate limit exceeded for tenant")
    window.append(now)
