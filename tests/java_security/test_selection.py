"""The selection file: verdicts only, per pack or per rule; version 1 read as it was written."""

from __future__ import annotations

import json

import pytest
from chock_security.decision import ALLOW, ASK, DENY
from chock_security.rules import registry
from chock_security.selection import LEGACY_RULES, SelectionError, parse, render

RULES = registry()
XSS = "java-xss-unescaped-template"  # one of the first eight, now in the templates pack
CSRF = "spring-csrf-disabled"  # new in 0.4.0


def _v2(packs: dict) -> str:
    return json.dumps({"version": 2, "packs": packs})


def test_silence_enforces_every_rule() -> None:
    assert set(parse(_v2({}), RULES).values()) == {DENY}


def test_a_rule_verdict_applies_to_that_rule_only() -> None:
    verdicts = parse(_v2({"templates": {"rules": {XSS: ALLOW}}}), RULES)
    assert verdicts[XSS] == ALLOW
    assert {v for k, v in verdicts.items() if k != XSS} == {DENY}


def test_a_pack_verdict_covers_that_pack_and_no_other() -> None:
    verdicts = parse(_v2({"spring": {"verdict": ASK}}), RULES)
    assert {verdicts[r] for r, rule in RULES.items() if rule.pack == "spring"} == {ASK}
    assert {verdicts[r] for r, rule in RULES.items() if rule.pack != "spring"} == {DENY}


@pytest.mark.parametrize(
    ("document", "complaint"),
    [
        (_v2({"templates": {"rules": {XSS: "maybe"}}}), "program in disguise"),
        (_v2({"templates": {"rules": {XSS: {"pattern": "x"}}}}), "program in disguise"),
        (_v2({"java": {"rules": {XSS: ALLOW}}}), "does not contain"),
        (_v2({"no-such-pack": {"verdict": ALLOW}}), "no-such-pack"),
        (_v2({"templates": {"rules": {}, "severity": "high"}}), "unknown key"),
        (json.dumps({"version": 3, "packs": {}}), "version must be"),
        ("{not json", "not valid JSON"),
        ("[]", "selection must be an object"),
        (json.dumps({"version": 2, "packs": ["templates"]}), "'packs' must be an object"),
        (_v2({"templates": "deny"}), "must be an object with keys"),
        (_v2({"templates": {"rules": [XSS]}}), "'rules' must be an object"),
    ],
    ids=[
        "unknown-verdict",
        "pattern-for-verdict",
        "rule-under-wrong-pack",
        "unknown-pack",
        "extra-pack-key",
        "future-version",
        "not-json",
        "document-not-an-object",
        "packs-not-an-object",
        "pack-not-an-object",
        "rules-not-an-object",
    ],
)
def test_anything_but_a_verdict_is_refused(document: str, complaint: str) -> None:
    with pytest.raises(SelectionError, match=complaint):
        parse(document, RULES)


def test_version_1_speaks_for_the_first_eight_rules_only() -> None:
    doc = json.dumps({"version": 1, "packs": {"java": {"verdict": ALLOW}}})
    verdicts = parse(doc, RULES)
    assert {verdicts[r] for r in LEGACY_RULES} == {ALLOW}
    assert verdicts[CSRF] == DENY, "a rule a version-1 file could not have named enforces"


def test_version_1_names_only_its_own_pack() -> None:
    doc = json.dumps({"version": 1, "packs": {"templates": {"verdict": ALLOW}}})
    with pytest.raises(SelectionError, match="version-1"):
        parse(doc, RULES)


def test_install_writes_every_rule_at_deny_under_its_pack() -> None:
    written = json.loads(render(RULES))
    assert written["version"] == 2
    listed = {rule for pack in written["packs"].values() for rule in pack["rules"]}
    assert listed == set(RULES)
    assert set(parse(render(RULES), RULES).values()) == {DENY}
