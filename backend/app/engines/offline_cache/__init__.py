"""Offline dataset caches: ATT&CK, CVE, Sigma — bundled seed + online refresh."""
from __future__ import annotations

from app.engines.offline_cache.base import DatasetCache, DatasetStatus
from app.engines.offline_cache.datasets import (
    AttackTechnique,
    CveCache,
    CveRecord,
    MitreAttackCache,
    SigmaCache,
)

__all__ = [
    "AttackTechnique",
    "CveCache",
    "CveRecord",
    "DatasetCache",
    "DatasetStatus",
    "MitreAttackCache",
    "OfflineDatasets",
    "SigmaCache",
    "build_offline_datasets",
]


class OfflineDatasets:
    def __init__(self) -> None:
        self.attack = MitreAttackCache()
        self.cve = CveCache()
        self.sigma = SigmaCache()

    def by_name(self, name: str) -> DatasetCache:
        mapping = {"attack": self.attack, "cve": self.cve, "sigma": self.sigma}
        try:
            return mapping[name]
        except KeyError:
            raise KeyError(f"unknown dataset: {name}") from None

    def statuses(self) -> list[DatasetStatus]:
        return [self.attack.status(), self.cve.status(), self.sigma.status()]


_datasets: OfflineDatasets | None = None


def build_offline_datasets() -> OfflineDatasets:
    global _datasets
    if _datasets is None:
        _datasets = OfflineDatasets()
    return _datasets
