"""Centralized, validated configuration.

All settings are read from the environment (12-factor). In production the values
originate from Vault via the External Secrets Operator, never from a committed file.
"""
from __future__ import annotations

from enum import StrEnum
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ConnectorMode(StrEnum):
    MOCK = "mock"
    LIVE = "live"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AEGIS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── Core ──────────────────────────────────────────────────────────────────
    env: str = "local"
    log_level: str = "INFO"
    secret_key: str = Field(
        default="change-me-32-bytes-min-rotate-via-vault", min_length=16
    )
    allowed_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    connector_mode: ConnectorMode = ConnectorMode.MOCK

    # ── Datastores ────────────────────────────────────────────────────────────
    database_url: str = "postgresql+psycopg://aegis:aegis@localhost:5432/aegis"
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "aegis-neo4j"
    redis_url: str = "redis://localhost:6379/0"
    kafka_bootstrap: str = "localhost:9092"
    temporal_host: str = "localhost:7233"

    # ── OIDC / Keycloak ───────────────────────────────────────────────────────
    oidc_issuer: str = "http://localhost:8080/realms/aegisflow"
    oidc_audience: str = "aegisflow-api"
    oidc_jwks_url: str = (
        "http://localhost:8080/realms/aegisflow/protocol/openid-connect/certs"
    )
    # Local/dev escape hatch ONLY. Must be False in any deployed environment; a
    # startup check (main.py) refuses to boot with this enabled outside `local`.
    auth_dev_bypass: bool = False

    # ── Threat intel (live mode) ──────────────────────────────────────────────
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    greynoise_api_key: str = ""
    otx_api_key: str = ""
    opencti_url: str = ""
    opencti_token: str = ""
    misp_url: str = ""
    misp_key: str = ""

    # ── AI copilot ────────────────────────────────────────────────────────────
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"

    # ── Ticketing ─────────────────────────────────────────────────────────────
    servicenow_instance: str = ""
    servicenow_user: str = ""
    servicenow_password: str = ""
    jira_url: str = ""
    jira_user: str = ""
    jira_token: str = ""

    # ── Rate limiting ─────────────────────────────────────────────────────────
    rate_limit_per_minute: int = 240

    @property
    def is_local(self) -> bool:
        return self.env == "local"

    @property
    def use_mock_connectors(self) -> bool:
        return self.connector_mode == ConnectorMode.MOCK


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
