"""AI safety guards for the SOC copilot.

Threat model: the copilot reads attacker-authored text (emails, sandbox notes,
IOC context). That text must be treated as *data*, never instructions.

Controls here:
1. sanitize_untrusted: strip/escape known prompt-injection markers, cap length.
2. wrap_untrusted: fence data so the model can distinguish it from instructions.
3. validate_output: ensure the model's reply is plain narrative — no tool calls,
   no executable directives — before it is stored or shown.

The copilot NEVER executes actions; it only emits text + structured recommendations
that a human (or a signed playbook) must approve.
"""
from __future__ import annotations

import re

_INJECTION_MARKERS = [
    re.compile(r"ignore (all|previous|the above).*instructions", re.IGNORECASE),
    re.compile(r"disregard .* (system|prior) prompt", re.IGNORECASE),
    re.compile(r"you are now", re.IGNORECASE),
    re.compile(r"\bsystem prompt\b", re.IGNORECASE),
    re.compile(r"</?(system|assistant|tool)\b[^>]*>", re.IGNORECASE),
    re.compile(r"\bdeveloper mode\b", re.IGNORECASE),
]

# Output markers that would indicate the model is trying to invoke tooling.
_FORBIDDEN_OUTPUT = [
    re.compile(r"<tool_call", re.IGNORECASE),
    re.compile(r"```(?:bash|sh|powershell)\b", re.IGNORECASE),
    re.compile(r"\bexecute:\s", re.IGNORECASE),
]

MAX_UNTRUSTED_CHARS = 12_000


def sanitize_untrusted(text: str) -> str:
    text = (text or "")[:MAX_UNTRUSTED_CHARS]
    for marker in _INJECTION_MARKERS:
        text = marker.sub("[redacted-injection]", text)
    # Neutralize attempts to break out of the data fence.
    return text.replace("```", "ʼʼʼ")


def wrap_untrusted(label: str, text: str) -> str:
    """Fence untrusted data with explicit, non-spoofable delimiters."""
    safe = sanitize_untrusted(text)
    return (
        f"<<UNTRUSTED_DATA name=\"{label}\">>\n"
        f"{safe}\n"
        f"<<END_UNTRUSTED_DATA>>"
    )


def validate_output(text: str) -> str:
    """Reject/neutralize outputs that look like they want to take action."""
    for marker in _FORBIDDEN_OUTPUT:
        if marker.search(text):
            return (
                "[Copilot output withheld: response contained a directive that is not "
                "permitted. The copilot only provides analysis, never executable actions.]"
            )
    return text
