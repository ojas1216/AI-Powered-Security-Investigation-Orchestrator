"""Immutable, content-addressed evidence store.

Each artifact is hashed (SHA-256) on write; the hash is the tamper-evidence and
part of the storage key, so altering an artifact changes its address. Offline we
store in a per-tenant temp dir; in production this is an object store (S3/MinIO)
with object-lock / WORM.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from app.schemas.investigation import Evidence


class EvidenceStore:
    def __init__(self, backend: dict | None = None) -> None:
        # backend maps sha256 -> bytes; swapped for S3 in production.
        self._backend = backend if backend is not None else {}

    def put(self, tenant: str, kind: str, label: str, content: bytes) -> Evidence:
        digest = hashlib.sha256(content).hexdigest()
        key = f"{tenant}/{digest}"
        self._backend.setdefault(key, content)  # idempotent; never overwrite
        return Evidence(
            kind=kind,
            label=label,
            sha256=digest,
            uri=f"evidence://{key}",
            collected_at=datetime.now(timezone.utc),
        )

    def put_json(self, tenant: str, kind: str, label: str, obj: object) -> Evidence:
        data = json.dumps(obj, default=str, sort_keys=True).encode()
        return self.put(tenant, kind, label, data)


def build_evidence_store() -> EvidenceStore:
    return EvidenceStore()
