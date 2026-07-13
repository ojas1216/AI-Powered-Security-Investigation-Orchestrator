"""AI model routing for the copilot.

Routes each generation to the best available provider:

- **Task tiers**: `fast` (executive summaries, short narratives) and `deep`
  (analyst reports, complex reasoning) map to different models per provider —
  cost/latency discipline without a second code path.
- **Provider chain**: configured order (e.g. "anthropic,ollama"); the first
  configured+closed provider that answers wins. Anthropic serves cloud
  deployments; Ollama serves air-gapped/local ones. If every provider fails
  the caller's deterministic fallback is used, so the investigation pipeline
  never blocks on an LLM.
- **Circuit breaker**: consecutive failures open a provider's circuit for a
  cooldown, so a dead endpoint costs one timeout, not one per investigation.

The router carries *no prompt logic* — fencing/validation of untrusted text
stays in guards.py and the calling Copilot.
"""
from __future__ import annotations

import abc
import time
from enum import StrEnum

import httpx

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger("copilot.router")

_ANTHROPIC_VERSION = "2023-06-01"


class TaskTier(StrEnum):
    FAST = "fast"
    DEEP = "deep"


class ProviderError(Exception):
    """Provider unreachable or returned an unusable response."""


class LLMProvider(abc.ABC):
    name = "base"

    @abc.abstractmethod
    def configured(self) -> bool:
        """True when this provider has the config it needs to be tried."""

    @abc.abstractmethod
    async def generate(self, *, tier: TaskTier, system: str, prompt: str,
                       temperature: float = 0.2) -> str:
        raise NotImplementedError


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, *, api_key: str | None = None,
                 base_url: str = "https://api.anthropic.com") -> None:
        self._api_key = api_key if api_key is not None else settings.anthropic_api_key
        self._base_url = base_url.rstrip("/")

    def configured(self) -> bool:
        return bool(self._api_key)

    def _model(self, tier: TaskTier) -> str:
        return (settings.anthropic_model_fast if tier is TaskTier.FAST
                else settings.anthropic_model_deep)

    async def generate(self, *, tier: TaskTier, system: str, prompt: str,
                       temperature: float = 0.2) -> str:
        payload = {
            "model": self._model(tier),
            "max_tokens": 1024,
            "temperature": temperature,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": _ANTHROPIC_VERSION,
        }
        try:
            async with httpx.AsyncClient(timeout=settings.llm_timeout_seconds) as client:
                resp = await client.post(f"{self._base_url}/v1/messages",
                                         json=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPError as exc:
            raise ProviderError(f"anthropic: {exc}") from exc
        blocks = data.get("content") or []
        text = "".join(b.get("text", "") for b in blocks
                       if b.get("type") == "text").strip()
        if not text:
            raise ProviderError("anthropic: empty completion")
        return text


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self, *, base_url: str | None = None) -> None:
        self._base_url = (base_url or settings.ollama_base_url).rstrip("/")

    def configured(self) -> bool:
        return bool(self._base_url)

    def _model(self, tier: TaskTier) -> str:
        return (settings.ollama_model_fast or settings.ollama_model
                if tier is TaskTier.FAST else settings.ollama_model)

    async def generate(self, *, tier: TaskTier, system: str, prompt: str,
                       temperature: float = 0.2) -> str:
        payload = {
            "model": self._model(tier),
            "system": system,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature},
        }
        try:
            async with httpx.AsyncClient(timeout=settings.llm_timeout_seconds) as client:
                resp = await client.post(f"{self._base_url}/api/generate", json=payload)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPError as exc:
            raise ProviderError(f"ollama: {exc}") from exc
        text = (data.get("response") or "").strip()
        if not text:
            raise ProviderError("ollama: empty completion")
        return text


class _Circuit:
    """Per-provider circuit breaker: open after N consecutive failures."""

    def __init__(self, threshold: int, cooldown_seconds: float,
                 now_fn=time.monotonic) -> None:
        self._threshold = threshold
        self._cooldown = cooldown_seconds
        self._now = now_fn
        self._failures = 0
        self._opened_at: float | None = None

    def available(self) -> bool:
        if self._opened_at is None:
            return True
        if self._now() - self._opened_at >= self._cooldown:
            self._opened_at = None  # half-open: allow one probe
            self._failures = self._threshold - 1
            return True
        return False

    def record_success(self) -> None:
        self._failures = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self._threshold:
            self._opened_at = self._now()


class ModelRouter:
    def __init__(self, providers: list[LLMProvider] | None = None, *,
                 failure_threshold: int = 3, cooldown_seconds: float = 60.0,
                 now_fn=time.monotonic) -> None:
        self._providers = providers if providers is not None else _default_chain()
        self._circuits = {
            p.name: _Circuit(failure_threshold, cooldown_seconds, now_fn)
            for p in self._providers
        }

    async def generate(self, *, tier: TaskTier, system: str, prompt: str,
                       temperature: float = 0.2) -> tuple[str, str]:
        """Return (text, provider_name); raises ProviderError if all fail."""
        errors: list[str] = []
        for provider in self._providers:
            if not provider.configured():
                continue
            circuit = self._circuits[provider.name]
            if not circuit.available():
                errors.append(f"{provider.name}: circuit open")
                continue
            try:
                text = await provider.generate(
                    tier=tier, system=system, prompt=prompt,
                    temperature=temperature)
                circuit.record_success()
                log.info("llm_generation", provider=provider.name, tier=tier.value,
                         chars=len(text))
                return text, provider.name
            except ProviderError as exc:
                circuit.record_failure()
                errors.append(str(exc))
                log.warning("llm_provider_failed", provider=provider.name,
                            tier=tier.value, error=str(exc))
        raise ProviderError("; ".join(errors) or "no provider configured")


def _default_chain() -> list[LLMProvider]:
    chain: list[LLMProvider] = []
    for name in [p.strip() for p in settings.llm_provider_order.split(",") if p.strip()]:
        if name == "anthropic":
            chain.append(AnthropicProvider())
        elif name == "ollama":
            chain.append(OllamaProvider())
        else:
            log.warning("unknown_llm_provider_ignored", provider=name)
    return chain
