"""Text embedding — offline-first, pluggable.

The default `HashingEmbedder` needs **no model, no network, no heavy deps**: it
maps text to a fixed-dimension unit vector via signed feature hashing over word
and character-trigram tokens (the "hashing trick"). Cosine similarity over these
vectors gives robust lexical/fuzzy matching that works fully offline and is
perfectly deterministic — which keeps the whole platform air-gap-capable and the
test suite hermetic.

For higher-quality semantics, `build_embedder()` returns an `OllamaEmbedder`
(local models like `nomic-embed-text`) when `AEGIS_EMBEDDER=ollama` — still
local/offline, just a real model. Both satisfy the same interface, so the vector
store and search layer are agnostic to which is in use.
"""
from __future__ import annotations

import abc
import hashlib
import math
import re

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger("semantic.embedder")

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._:/@-]*", re.IGNORECASE)


class Embedder(abc.ABC):
    dim: int

    @abc.abstractmethod
    def embed(self, text: str) -> list[float]:
        raise NotImplementedError

    def embed_many(self, texts: list[str]) -> list[list[float]]:
        return [self.embed(t) for t in texts]


def _tokens(text: str) -> list[str]:
    """Word tokens plus character trigrams of each word (fuzzy overlap)."""
    words = _TOKEN_RE.findall(text.lower())
    out: list[str] = []
    for w in words:
        out.append(w)
        if len(w) > 3:
            out.extend(w[i:i + 3] for i in range(len(w) - 2))
    return out


def _hash(token: str) -> int:
    # blake2b, not Python's salted hash(), so vectors are stable across processes.
    return int.from_bytes(hashlib.blake2b(token.encode(), digest_size=8).digest(),
                          "big")


class HashingEmbedder(Embedder):
    def __init__(self, dim: int = 256) -> None:
        self.dim = dim

    def embed(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        for token in _tokens(text):
            h = _hash(token)
            idx = h % self.dim
            sign = 1.0 if (h >> 63) & 1 else -1.0  # signed hashing halves collisions
            vec[idx] += sign
        norm = math.sqrt(sum(v * v for v in vec))
        if norm == 0.0:
            return vec
        return [v / norm for v in vec]


class OllamaEmbedder(Embedder):  # pragma: no cover - requires a local Ollama
    """Local embedding model via Ollama's /api/embeddings (still offline)."""

    def __init__(self, model: str, base_url: str, dim: int) -> None:
        self._model = model
        self._base = base_url.rstrip("/")
        self.dim = dim

    def embed(self, text: str) -> list[float]:
        import httpx

        try:
            resp = httpx.post(f"{self._base}/api/embeddings",
                              json={"model": self._model, "prompt": text},
                              timeout=settings.llm_timeout_seconds)
            resp.raise_for_status()
            vec = resp.json().get("embedding") or []
        except Exception as exc:
            log.warning("ollama_embed_failed_fallback_hashing", error=str(exc))
            return HashingEmbedder(self.dim).embed(text)
        if not vec:
            return HashingEmbedder(self.dim).embed(text)
        norm = math.sqrt(sum(v * v for v in vec))
        return [v / norm for v in vec] if norm else list(vec)


def cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity of two (ideally unit) vectors."""
    if len(a) != len(b):
        return 0.0
    return sum(x * y for x, y in zip(a, b, strict=True))


_embedder: Embedder | None = None


def build_embedder() -> Embedder:
    global _embedder
    if _embedder is not None:
        return _embedder
    if settings.embedder == "ollama":
        _embedder = OllamaEmbedder(
            settings.embedding_model, settings.ollama_base_url,
            settings.embedding_dim)
    else:
        _embedder = HashingEmbedder(settings.embedding_dim)
    return _embedder
