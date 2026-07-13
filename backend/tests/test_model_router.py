"""Model-routing tests: provider chain, tiers, circuit breaker, fallback."""
from __future__ import annotations

import httpx
import pytest
import respx

from app.engines.copilot.client import Copilot
from app.engines.copilot.router import (
    AnthropicProvider,
    LLMProvider,
    ModelRouter,
    OllamaProvider,
    ProviderError,
    TaskTier,
)


class StubProvider(LLMProvider):
    def __init__(self, name: str, *, text: str | None = "ok",
                 configured: bool = True) -> None:
        self.name = name
        self._text = text
        self._configured = configured
        self.calls = 0

    def configured(self) -> bool:
        return self._configured

    async def generate(self, *, tier: TaskTier, system: str, prompt: str,
                       temperature: float = 0.2) -> str:
        self.calls += 1
        if self._text is None:
            raise ProviderError(f"{self.name}: down")
        return self._text


# ---------------------------------------------------------------- routing


@pytest.mark.asyncio
async def test_first_configured_provider_wins():
    unconfigured = StubProvider("cloud", configured=False)
    local = StubProvider("local", text="from-local")
    router = ModelRouter([unconfigured, local])

    text, provider = await router.generate(
        tier=TaskTier.FAST, system="s", prompt="p")
    assert (text, provider) == ("from-local", "local")
    assert unconfigured.calls == 0


@pytest.mark.asyncio
async def test_failover_to_next_provider():
    down = StubProvider("primary", text=None)
    backup = StubProvider("backup", text="from-backup")
    router = ModelRouter([down, backup])

    text, provider = await router.generate(
        tier=TaskTier.DEEP, system="s", prompt="p")
    assert (text, provider) == ("from-backup", "backup")
    assert down.calls == 1


@pytest.mark.asyncio
async def test_all_providers_failing_raises():
    router = ModelRouter([StubProvider("a", text=None),
                          StubProvider("b", text=None)])
    with pytest.raises(ProviderError, match="a: down; b: down"):
        await router.generate(tier=TaskTier.FAST, system="s", prompt="p")


@pytest.mark.asyncio
async def test_circuit_breaker_opens_and_recovers():
    clock = {"t": 0.0}
    down = StubProvider("flaky", text=None)
    backup = StubProvider("backup", text="ok")
    router = ModelRouter([down, backup], failure_threshold=2,
                         cooldown_seconds=30.0, now_fn=lambda: clock["t"])

    # Two failures open the circuit...
    for _ in range(2):
        await router.generate(tier=TaskTier.FAST, system="s", prompt="p")
    assert down.calls == 2
    # ...so the third request skips the dead provider entirely.
    await router.generate(tier=TaskTier.FAST, system="s", prompt="p")
    assert down.calls == 2

    # After the cooldown one probe is allowed again (half-open).
    clock["t"] = 31.0
    await router.generate(tier=TaskTier.FAST, system="s", prompt="p")
    assert down.calls == 3


# ---------------------------------------------------------------- providers


@pytest.mark.asyncio
@respx.mock
async def test_anthropic_provider_request_shape():
    route = respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(200, json={
            "content": [{"type": "text", "text": "summary text"}],
        }))
    provider = AnthropicProvider(api_key="test-key")

    text = await provider.generate(tier=TaskTier.FAST, system="sys", prompt="hi")
    assert text == "summary text"

    request = route.calls.last.request
    assert request.headers["x-api-key"] == "test-key"
    assert request.headers["anthropic-version"] == "2023-06-01"
    import json
    body = json.loads(request.content)
    assert body["system"] == "sys"
    assert body["messages"] == [{"role": "user", "content": "hi"}]
    assert body["model"]  # tier-mapped model id


@pytest.mark.asyncio
@respx.mock
async def test_anthropic_provider_http_error_is_provider_error():
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(529, json={"error": "overloaded"}))
    provider = AnthropicProvider(api_key="k")
    with pytest.raises(ProviderError, match="anthropic"):
        await provider.generate(tier=TaskTier.DEEP, system="s", prompt="p")


@pytest.mark.asyncio
@respx.mock
async def test_ollama_provider_parses_response():
    respx.post("http://llm.local:11434/api/generate").mock(
        return_value=httpx.Response(200, json={"response": " local answer "}))
    provider = OllamaProvider(base_url="http://llm.local:11434")
    text = await provider.generate(tier=TaskTier.DEEP, system="s", prompt="p")
    assert text == "local answer"


def test_anthropic_unconfigured_without_key():
    assert AnthropicProvider(api_key="").configured() is False
    assert AnthropicProvider(api_key="k").configured() is True


# ---------------------------------------------------------------- copilot


@pytest.mark.asyncio
async def test_copilot_uses_router_and_validates_output():
    router = ModelRouter([StubProvider("stub", text="A grounded summary.")])
    copilot = Copilot(use_llm=True, router=router)
    from tests.test_agents import make_investigator, make_phishing_alert

    pkg = await make_investigator().investigate("acme", make_phishing_alert())
    text = await copilot.executive_summary(pkg)
    assert text == "A grounded summary."


@pytest.mark.asyncio
async def test_copilot_falls_back_to_deterministic_when_all_providers_fail():
    router = ModelRouter([StubProvider("dead", text=None)])
    copilot = Copilot(use_llm=True, router=router)
    from tests.test_agents import make_investigator, make_phishing_alert

    pkg = await make_investigator().investigate("acme", make_phishing_alert())
    text = await copilot.executive_summary(pkg)
    assert "malicious" in text.lower()  # deterministic grounded narrative
