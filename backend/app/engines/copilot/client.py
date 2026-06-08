"""SOC copilot client.

Talks to a self-hosted Ollama instance. When connectors are in mock mode (or
Ollama is unreachable) it falls back to a deterministic template generator so the
investigation package always has a readable summary and the pipeline/tests are
hermetic. All untrusted context is fenced; all output is validated.
"""
from __future__ import annotations

import httpx

from app.core.config import settings
from app.core.logging import get_logger
from app.engines.copilot import prompts
from app.engines.copilot.guards import validate_output, wrap_untrusted
from app.schemas.investigation import InvestigationPackage

log = get_logger("copilot")


class Copilot:
    def __init__(self, use_llm: bool) -> None:
        self._use_llm = use_llm

    async def _generate(self, instruction: str, context: str) -> str:
        if not self._use_llm:
            return self._template(instruction, context)
        try:
            payload = {
                "model": settings.ollama_model,
                "system": prompts.SYSTEM_PROMPT,
                "prompt": f"{instruction}\n\n{wrap_untrusted('investigation', context)}",
                "stream": False,
                "options": {"temperature": 0.2},
            }
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    f"{settings.ollama_base_url}/api/generate", json=payload
                )
                resp.raise_for_status()
                return validate_output(resp.json().get("response", "").strip())
        except httpx.HTTPError as exc:  # pragma: no cover - network
            log.warning("ollama_unavailable_fallback_template", error=str(exc))
            return self._template(instruction, context)

    @staticmethod
    def _template(instruction: str, context: str) -> str:
        # Deterministic, grounded fallback — never echoes untrusted text verbatim
        # as instructions; just summarizes the structured facts passed in.
        return validate_output(f"{instruction}\n\nBased on the investigation:\n{context}")

    async def executive_summary(self, package: InvestigationPackage) -> str:
        ctx = self._summarize_facts(package)
        return await self._generate(prompts.EXEC_SUMMARY_INSTRUCTION, ctx)

    async def analyst_report(self, package: InvestigationPackage) -> str:
        ctx = self._summarize_facts(package)
        return await self._generate(prompts.ANALYST_REPORT_INSTRUCTION, ctx)

    @staticmethod
    def _summarize_facts(p: InvestigationPackage) -> str:
        mal = [e for e in p.iocs if e.verdict.value == "malicious"]
        risk = f"{p.risk.score} ({p.risk.severity.value})" if p.risk else "n/a"
        lines = [
            f"Alert: {p.alert.title}",
            f"Verdict: {p.overall_verdict.value}; Risk: {risk}",
            f"Malicious IOCs: {', '.join(e.ioc.value for e in mal) or 'none'}",
            f"Affected hosts: {', '.join(p.affected_hosts) or 'none'}",
            f"Affected users: {', '.join(p.affected_users) or 'none'}",
            f"MITRE: {', '.join(t.technique_id for t in p.mitre) or 'none'}",
        ]
        return "\n".join(lines)


def build_copilot() -> Copilot:
    # Use the LLM only in live mode; mock mode stays fully offline/deterministic.
    return Copilot(use_llm=not settings.use_mock_connectors)
