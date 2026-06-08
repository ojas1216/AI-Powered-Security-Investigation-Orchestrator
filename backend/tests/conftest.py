"""Shared test fixtures. Force mock connectors + local dev auth bypass so the
suite is hermetic (no network, no Keycloak, no databases)."""
from __future__ import annotations

import os

os.environ.setdefault("AEGIS_ENV", "local")
os.environ.setdefault("AEGIS_CONNECTOR_MODE", "mock")
os.environ.setdefault("AEGIS_AUTH_DEV_BYPASS", "true")

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture()
def auth_headers() -> dict[str, str]:
    return {"X-Tenant-ID": "acme", "X-Roles": "tier3_analyst", "Authorization": "Bearer dev"}
