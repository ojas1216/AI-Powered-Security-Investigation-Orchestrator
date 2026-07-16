"""Centralized, validated configuration.

All settings are read from the environment (12-factor). In production the values
originate from Vault via the External Secrets Operator, never from a committed file.
"""
from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


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
    # NoDecode: take the raw env string (the settings source won't JSON-decode it)
    # so the validator below can accept a comma-separated list — the natural form.
    allowed_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:5173"]
    )
    connector_mode: ConnectorMode = ConnectorMode.MOCK

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def _split_origins(cls, v: object) -> object:
        # Accept a comma-separated string or a JSON list:
        #   AEGIS_ALLOWED_ORIGINS=http://a,http://b   or   ["http://a","http://b"]
        if isinstance(v, str):
            import json

            s = v.strip()
            if s.startswith("["):
                return json.loads(s)
            return [o.strip() for o in s.split(",") if o.strip()]
        return v
    # Persistence backend: "memory" (self-contained) or "postgres" (RLS-isolated).
    persistence: str = "memory"

    # ── Datastores ────────────────────────────────────────────────────────────
    # NOTE: in postgres mode the app must connect as a NON-superuser role
    # (superusers bypass Row-Level Security). See infra/docker/postgres-init.sql.
    database_url: str = "postgresql+psycopg://aegis_app:aegis_app@localhost:5432/aegis"
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "aegis-neo4j"  # noqa: S105 - local-dev default; prod injects via Vault/env
    redis_url: str = "redis://localhost:6379/0"
    kafka_bootstrap: str = "localhost:9092"
    kafka_alerts_topic: str = "aegis.alerts"
    kafka_dlq_topic: str = "aegis.alerts.dlq"
    kafka_group_id: str = "aegisflow-ingest"
    temporal_host: str = "localhost:7233"

    # ── Investigation dispatch ────────────────────────────────────────────
    # inline: supervised asyncio task in-process; temporal: durable workflow.
    # Evidence-collection strategy: "batch" (flat re-plan loop, default) or
    # "taskgraph" (dependency-aware Task Graph + Priority Scheduler w/ retry).
    investigation_strategy: str = "batch"
    dispatch: str = "inline"
    max_concurrent_investigations: int = 100

    # ── OIDC / Keycloak ───────────────────────────────────────────────────────
    oidc_issuer: str = "http://localhost:8080/realms/aegisflow"
    oidc_audience: str = "aegisflow-api"
    oidc_jwks_url: str = (
        "http://localhost:8080/realms/aegisflow/protocol/openid-connect/certs"
    )
    # Local/dev escape hatch ONLY. Must be False in any deployed environment; a
    # startup check (main.py) refuses to boot with this enabled outside `local`.
    auth_dev_bypass: bool = False

    # ── Native accounts + Google sign-in ──────────────────────────────────────
    # Google OAuth client id (free: https://console.cloud.google.com/apis/credentials
    # -> Create OAuth client ID -> Web application). Empty disables Google sign-in.
    google_client_id: str = ""
    allow_self_registration: bool = True
    default_tenant: str = "acme"
    default_user_role: str = "tier1_analyst"  # least privilege; admin promotes
    session_ttl_hours: float = 8.0

    # ── Threat intel (live mode) ──────────────────────────────────────────────
    # Keyless public feeds (SANS ISC DShield, CIRCL hashlookup) — free, no
    # registration. Enabled by default so live mode works with zero API keys.
    ti_enable_public_feeds: bool = True
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    greynoise_api_key: str = ""
    otx_api_key: str = ""
    threatfox_api_key: str = ""  # abuse.ch Auth-Key (free); offline cache used otherwise
    urlhaus_api_key: str = ""
    opencti_url: str = ""
    opencti_token: str = ""
    misp_url: str = ""
    misp_key: str = ""
    # Verify TLS to self-hosted TI/sandbox platforms. Only set False for lab use.
    internal_tls_verify: bool = True

    # ── Sandbox (live) ────────────────────────────────────────────────────────
    cape_url: str = ""  # e.g. https://cape.internal
    cape_token: str = ""

    # ── AI copilot / model routing ────────────────────────────────────────────
    # Preference-ordered provider chain; first configured+healthy provider wins.
    llm_provider_order: str = "anthropic,ollama"
    llm_timeout_seconds: float = 60.0
    anthropic_api_key: str = ""
    anthropic_model_fast: str = "claude-haiku-4-5-20251001"  # exec summaries
    anthropic_model_deep: str = "claude-sonnet-5"  # analyst reports
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"
    ollama_model_fast: str = ""  # optional smaller local model for fast tier

    # ── Semantic memory ───────────────────────────────────────────────────────
    # embedder: "hashing" (offline, zero-dep, default) | "ollama" (local model)
    embedder: str = "hashing"
    embedding_dim: int = 256
    embedding_model: str = "nomic-embed-text"

    # ── Offline dataset caches (ATT&CK / CVE / Sigma) ─────────────────────────
    # Refreshed copies land here; the bundled seed is always the fallback.
    offline_cache_dir: str = "./data/offline_cache"

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

    @property
    def use_postgres(self) -> bool:
        return self.persistence == "postgres"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
