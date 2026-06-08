"""Refang utilities.

Analysts and threat feeds share IOCs in 'defanged' form to prevent accidental
clicks: hxxp://, 1.2.3[.]4, evil(dot)com, foo[at]bar.com. We refang before
matching so the extractor recognizes the real indicator, then store the canonical
value.
"""
from __future__ import annotations

import re

_SUBS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"h\s*x\s*x\s*p", re.IGNORECASE), "http"),
    (re.compile(r"\[\s*\.\s*\]"), "."),
    (re.compile(r"\(\s*\.\s*\)"), "."),
    (re.compile(r"\{\s*\.\s*\}"), "."),
    (re.compile(r"\(\s*dot\s*\)", re.IGNORECASE), "."),
    (re.compile(r"\[\s*dot\s*\]", re.IGNORECASE), "."),
    (re.compile(r"\[\s*at\s*\]", re.IGNORECASE), "@"),
    (re.compile(r"\(\s*at\s*\)", re.IGNORECASE), "@"),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*/\s*/\s*\]"), "//"),
]


def refang(text: str) -> str:
    out = text
    for pattern, repl in _SUBS:
        out = pattern.sub(repl, out)
    return out
