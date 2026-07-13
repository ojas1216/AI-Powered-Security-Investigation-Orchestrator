"""SOC copilot client.

Generations are routed through the ModelRouter (Anthropic for cloud, Ollama for
local/air-gapped; see router.py). When connectors are in mock mode, or every
provider fails, it falls back to a deterministic template generator so the
investigation package always has a readable summary and the pipeline/tests are
hermetic. All untrusted context is fenced; all output is validated.
"""
from __future__ import annotations

from app.core.config import settings
from app.core.logging import get_logger
from app.engines.copilot import prompts
from app.engines.copilot.guards import validate_output, wrap_untrusted
from app.engines.copilot.router import ModelRouter, ProviderError, TaskTier
from app.schemas.investigation import InvestigationPackage

log = get_logger("copilot")


class Copilot:
    def __init__(self, use_llm: bool, router: ModelRouter | None = None) -> None:
        self._use_llm = use_llm
        self._router = router or (ModelRouter() if use_llm else None)

    async def _generate(self, instruction: str, context: str, fallback: str,
                        tier: TaskTier) -> str:
        if not self._use_llm or self._router is None:
            return validate_output(fallback)
        try:
            text, provider = await self._router.generate(
                tier=tier,
                system=prompts.SYSTEM_PROMPT,
                prompt=f"{instruction}\n\n{wrap_untrusted('investigation', context)}",
                temperature=0.2,
            )
            log.info("copilot_generated", provider=provider, tier=tier.value)
            return validate_output(text)
        except ProviderError as exc:
            log.warning("all_llm_providers_failed_fallback_template", error=str(exc))
            return validate_output(fallback)

    async def executive_summary(self, package: InvestigationPackage) -> str:
        ctx = self._summarize_facts(package)
        return await self._generate(
            prompts.EXEC_SUMMARY_INSTRUCTION, ctx, self._exec_narrative(package),
            TaskTier.FAST,
        )

    async def analyst_report(self, package: InvestigationPackage) -> str:
        ctx = self._summarize_facts(package)
        return await self._generate(
            prompts.ANALYST_REPORT_INSTRUCTION, ctx, self._analyst_narrative(package),
            TaskTier.DEEP,
        )

    @staticmethod
    def _exec_narrative(p: InvestigationPackage) -> str:
        """Deterministic, grounded executive summary (used in mock mode / on LLM error)."""
        mal = [e for e in p.iocs if e.verdict.value == "malicious"]
        risk = f"{p.risk.score:.0f}/100 ({p.risk.severity.value})" if p.risk else "n/a"
        hosts = len(p.affected_hosts)
        users = len(p.affected_users)
        if p.overall_verdict.value == "malicious":
            head = (
                f"A confirmed malicious {('phishing ' if 'phish' in p.alert.title.lower() else '')}"
                f"incident was identified from alert \"{p.alert.title}\"."
            )
            blast = (
                f"Impact spans {hosts} endpoint(s) and {users} user(s); "
                f"{len(mal)} indicator(s) were corroborated as malicious."
            )
            risk_line = (
                f"Current risk is {risk}, driven by confirmed on-host activity and "
                f"sandbox detonation."
            )
            action = "Immediate containment is recommended (see the playbook in this package)."
        elif p.overall_verdict.value == "suspicious":
            head = f"A suspicious activity was flagged from alert \"{p.alert.title}\"."
            blast = f"Potential exposure: {hosts} endpoint(s), {users} user(s)."
            risk_line = f"Current risk is {risk}; further analyst review is warranted."
            action = "Triage by a Tier-2 analyst is recommended before action."
        else:
            head = f"Alert \"{p.alert.title}\" was investigated."
            blast = "No malicious indicators were corroborated."
            risk_line = f"Current risk is {risk}."
            action = "No immediate action is required; close or monitor."
        return " ".join([head, blast, risk_line, action])

    @staticmethod
    def _analyst_narrative(p: InvestigationPackage) -> str:
        """Deterministic technical narrative grounded in the package's evidence."""
        mal = [e.ioc.value for e in p.iocs if e.verdict.value == "malicious"]
        tactics = {t.tactic: [] for t in p.mitre}
        for t in p.mitre:
            tactics[t.tactic].append(f"{t.technique_id} ({t.name})")
        parts = [
            f"Verdict: {p.overall_verdict.value.upper()}; "
            f"risk {p.risk.score:.0f} ({p.risk.severity.value})." if p.risk else
            f"Verdict: {p.overall_verdict.value.upper()}.",
        ]
        for tactic, techs in tactics.items():
            parts.append(f"{tactic.replace('-', ' ').title()}: {', '.join(techs)}.")
        if mal:
            parts.append("Malicious indicators: " + ", ".join(mal) + ".")
        if p.affected_hosts:
            parts.append("Confirmed on hosts: " + ", ".join(p.affected_hosts) + ".")
        if p.evidence:
            parts.append(
                f"{len(p.evidence)} evidence artifact(s) collected and content-hashed."
            )
        return " ".join(parts)

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
