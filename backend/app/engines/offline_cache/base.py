"""Offline dataset cache.

Every dataset (ATT&CK, CVE, Sigma) ships with a **bundled seed** so the platform
runs fully air-gapped out of the box. When online, `refresh()` pulls the upstream
source, transforms it, and writes it to the cache dir; subsequent loads prefer the
refreshed copy. Loads are lazy and memoized. Refresh is best-effort and never
required — an offline deployment simply keeps using the bundle.
"""
from __future__ import annotations

import abc
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger("offline_cache")

_BUNDLED_DIR = Path(__file__).parent / "data"


class DatasetStatus(BaseModel):
    name: str
    records: int
    loaded_from: str  # "bundled" | "cache"
    source_url: str
    version: str = ""
    refreshed_at: str | None = None


class DatasetCache(abc.ABC):
    name: str = "base"
    source_url: str = ""
    bundled_file: str = ""

    def __init__(self) -> None:
        self._data: Any | None = None
        self._loaded_from = "bundled"
        self._refreshed_at: str | None = None

    # -- loading -------------------------------------------------------------

    def _cache_path(self) -> Path:
        return Path(settings.offline_cache_dir) / self.bundled_file

    def _raw(self) -> dict:
        """Load the freshest available JSON: cache dir if present, else bundle."""
        cache = self._cache_path()
        if cache.is_file():
            self._loaded_from = "cache"
            return json.loads(cache.read_text(encoding="utf-8"))
        self._loaded_from = "bundled"
        return json.loads((_BUNDLED_DIR / self.bundled_file).read_text(encoding="utf-8"))

    def data(self) -> Any:
        if self._data is None:
            self._data = self._parse(self._raw())
        return self._data

    @abc.abstractmethod
    def _parse(self, raw: dict) -> Any:
        """Transform the on-disk JSON into the in-memory structure."""

    @abc.abstractmethod
    def count(self) -> int: ...

    def status(self) -> DatasetStatus:
        self.data()  # ensure loaded so _loaded_from is set
        return DatasetStatus(
            name=self.name, records=self.count(), loaded_from=self._loaded_from,
            source_url=self.source_url, refreshed_at=self._refreshed_at)

    # -- refresh (online, best-effort) --------------------------------------

    async def refresh(self) -> int:
        """Download upstream, transform, persist to the cache dir. Returns count."""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as c:
                resp = await c.get(self.source_url)
                resp.raise_for_status()
                transformed = self._transform_upstream(resp)
        except Exception as exc:  # noqa: BLE001 - refresh must never crash a request
            log.warning("dataset_refresh_failed", dataset=self.name, error=str(exc))
            raise

        cache = self._cache_path()
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(transformed), encoding="utf-8")
        self._data = None  # invalidate memoized copy
        self._refreshed_at = datetime.now(UTC).isoformat()
        count = self.count()
        log.info("dataset_refreshed", dataset=self.name, records=count)
        return count

    def _transform_upstream(self, resp) -> dict:  # pragma: no cover - needs network
        """Map the upstream payload into our on-disk schema. Override per source;
        the default assumes the upstream already matches (mirror deployments)."""
        return resp.json()
