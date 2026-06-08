"""Normalizer contract."""
from __future__ import annotations

import abc

from app.schemas.alert import Alert


class Normalizer(abc.ABC):
    source = "generic"

    @abc.abstractmethod
    def normalize(self, raw: dict) -> Alert:
        raise NotImplementedError

    @staticmethod
    def _as_list(value) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(v) for v in value if v]
        return [str(value)]
