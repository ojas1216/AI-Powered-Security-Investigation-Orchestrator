"""Semantic memory: offline embeddings + vector store + natural-language search."""
from __future__ import annotations

from app.engines.semantic.embedder import (
    Embedder,
    HashingEmbedder,
    build_embedder,
    cosine,
)
from app.engines.semantic.index import CaseIndex, CaseSearchHit, build_case_index
from app.engines.semantic.store import (
    InMemoryVectorStore,
    ScoredRecord,
    VectorRecord,
    VectorStore,
    build_vector_store,
)

__all__ = [
    "CaseIndex",
    "CaseSearchHit",
    "Embedder",
    "HashingEmbedder",
    "InMemoryVectorStore",
    "ScoredRecord",
    "VectorRecord",
    "VectorStore",
    "build_case_index",
    "build_embedder",
    "build_vector_store",
    "cosine",
]
