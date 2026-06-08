"""Source-specific normalizers → common Alert schema."""
from __future__ import annotations

from app.ingestion.normalizers.base import Normalizer
from app.ingestion.normalizers.elastic import ElasticNormalizer
from app.ingestion.normalizers.generic import GenericNormalizer
from app.ingestion.normalizers.sentinel import SentinelNormalizer
from app.ingestion.normalizers.splunk import SplunkNormalizer
from app.schemas.common import SourceProduct

_REGISTRY: dict[SourceProduct, Normalizer] = {
    SourceProduct.SPLUNK: SplunkNormalizer(),
    SourceProduct.SENTINEL: SentinelNormalizer(),
    SourceProduct.ELASTIC: ElasticNormalizer(),
    SourceProduct.GENERIC: GenericNormalizer(),
}


def get_normalizer(source: SourceProduct) -> Normalizer:
    return _REGISTRY.get(source, _REGISTRY[SourceProduct.GENERIC])


__all__ = ["Normalizer", "get_normalizer"]
