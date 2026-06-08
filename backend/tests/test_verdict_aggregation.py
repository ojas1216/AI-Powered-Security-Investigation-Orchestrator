"""Unit tests for threat-intel verdict fusion."""
from __future__ import annotations

from app.engines.threat_intel.aggregator import fuse_verdicts
from app.schemas.common import Verdict
from app.schemas.ioc import SourceVerdict


def sv(source, verdict, score):
    return SourceVerdict(source=source, verdict=verdict, score=score)


def test_all_unknown_returns_unknown():
    verdict, conf = fuse_verdicts([sv("a", Verdict.UNKNOWN, 0.0)])
    assert verdict is Verdict.UNKNOWN
    assert conf == 0.0


def test_single_strong_malicious_dominates():
    sources = [
        sv("vt", Verdict.MALICIOUS, 0.95),
        sv("gn", Verdict.BENIGN, 0.05),
    ]
    verdict, conf = fuse_verdicts(sources)
    assert verdict is Verdict.MALICIOUS
    assert conf > 0.4


def test_corroboration_increases_confidence():
    one = fuse_verdicts([sv("a", Verdict.MALICIOUS, 0.9)])[1]
    three = fuse_verdicts([
        sv("a", Verdict.MALICIOUS, 0.9),
        sv("b", Verdict.MALICIOUS, 0.9),
        sv("c", Verdict.MALICIOUS, 0.9),
    ])[1]
    assert three > one


def test_benign_consensus():
    verdict, _ = fuse_verdicts([
        sv("a", Verdict.BENIGN, 0.05),
        sv("b", Verdict.BENIGN, 0.1),
    ])
    assert verdict is Verdict.BENIGN


def test_confidence_capped():
    _, conf = fuse_verdicts([sv("a", Verdict.MALICIOUS, 1.0)] * 10)
    assert conf <= 0.99
