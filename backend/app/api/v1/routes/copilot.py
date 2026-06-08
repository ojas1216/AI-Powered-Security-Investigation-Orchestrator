"""Natural-language SOC copilot over an investigation (guarded)."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.api.deps import require
from app.core.authz import Permission
from app.core.security import Principal
from app.engines.copilot.guards import sanitize_untrusted, validate_output
from app.repository import repo

router = APIRouter()


class CopilotQuery(BaseModel):
    investigation_id: str
    question: str = Field(min_length=1, max_length=2000)


class CopilotAnswer(BaseModel):
    answer: str
    grounded_on: list[str]


@router.post("/ask", response_model=CopilotAnswer)
async def ask(
    body: CopilotQuery,
    principal: Principal = Depends(require(Permission.COPILOT_QUERY)),
) -> CopilotAnswer:
    """Answer a question grounded strictly in one investigation's evidence.

    The question is treated as untrusted input (sanitized). The answer is built from
    structured facts only and validated before return — no tool execution, ever.
    """
    pkg = repo.get(principal.tenant, body.investigation_id)
    question = sanitize_untrusted(body.question).lower()

    # Deterministic, grounded responses to common analyst questions. (In live mode
    # this delegates to the guarded LLM copilot with the same grounding facts.)
    if "why" in question and "malicious" in question:
        mal = [e for e in pkg.iocs if e.verdict.value == "malicious"]
        answer = (
            "Verdict is malicious because: "
            + "; ".join(
                f"{e.ioc.value} corroborated at confidence {e.confidence}" for e in mal
            )
            + f". Risk score {pkg.risk.score if pkg.risk else 'n/a'}."
        ) if mal else "No IOCs reached a malicious verdict in this investigation."
        grounded = [e.ioc.value for e in mal]
    elif "host" in question:
        answer = "Affected hosts: " + (", ".join(pkg.affected_hosts) or "none")
        grounded = pkg.affected_hosts
    elif "user" in question:
        answer = "Impacted users: " + (", ".join(pkg.affected_users) or "none")
        grounded = pkg.affected_users
    elif "att" in question or "mitre" in question or "technique" in question:
        answer = "Observed techniques: " + (
            ", ".join(f"{t.technique_id} {t.name}" for t in pkg.mitre) or "none")
        grounded = [t.technique_id for t in pkg.mitre]
    elif "sandbox" in question:
        sandbox = [e for e in pkg.evidence if e.kind == "sandbox_report"]
        answer = f"{len(sandbox)} sandbox report(s) attached; see evidence store."
        grounded = [e.uri for e in sandbox]
    else:
        answer = pkg.executive_summary or "See the investigation package for details."
        grounded = ["executive_summary"]

    return CopilotAnswer(answer=validate_output(answer), grounded_on=grounded)
