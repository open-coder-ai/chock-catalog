"""The selection file: verdicts only, per pack or per rule; version 1 read as it was written."""

from __future__ import annotations

import json

import pytest
from chock_security.decision import ALLOW, ASK, DENY
from chock_security.rules import packs, registry
from chock_security.selection import LEGACY_RULES, SelectionError, default, load, parse, render

RULES = registry()
QUALITY = {r for r, rule in RULES.items() if packs()[rule.pack].kind == "quality"}
SECURITY = set(RULES) - QUALITY
#: Silence: every security rule denies, every quality rule allows.
DEFAULTS = {r: ALLOW if r in QUALITY else DENY for r in RULES}
XSS = "java-xss-unescaped-template"  # one of the first eight, now in the templates pack
CSRF = "spring-csrf-disabled"  # new in 0.4.0
EMPTY_CATCH = "exceptions-empty-catch"  # quality


def _v2(packs: dict) -> str:
    return json.dumps({"version": 2, "packs": packs})


def _others(verdicts: dict[str, str], *spoken: str) -> dict[str, str]:
    return {r: v for r, v in verdicts.items() if r not in spoken}


def test_silence_denies_every_security_rule_and_allows_every_quality_rule() -> None:
    verdicts = parse(_v2({}), RULES)
    assert verdicts == DEFAULTS
    assert {verdicts[r] for r in SECURITY} == {DENY}
    assert {verdicts[r] for r in QUALITY} == {ALLOW}
    assert all(verdicts[r] == default(RULES[r]) for r in RULES)


def test_no_file_reads_as_silence(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert load(tmp_path, RULES) == DEFAULTS


def test_a_rule_verdict_applies_to_that_rule_only() -> None:
    verdicts = parse(_v2({"templates": {"rules": {XSS: ALLOW}}}), RULES)
    assert verdicts[XSS] == ALLOW
    assert _others(verdicts, XSS) == _others(DEFAULTS, XSS)


def test_a_pack_verdict_covers_that_pack_and_no_other() -> None:
    verdicts = parse(_v2({"spring": {"verdict": ASK}}), RULES)
    assert {verdicts[r] for r, rule in RULES.items() if rule.pack == "spring"} == {ASK}
    spring = {r for r, rule in RULES.items() if rule.pack == "spring"}
    assert _others(verdicts, *spring) == _others(DEFAULTS, *spring)


@pytest.mark.parametrize("verdict", [DENY, ASK])
def test_an_explicit_quality_pack_verdict_keeps_its_value(verdict: str) -> None:
    verdicts = parse(_v2({"exceptions": {"verdict": verdict}}), RULES)
    assert {verdicts[r] for r, rule in RULES.items() if rule.pack == "exceptions"} == {verdict}


@pytest.mark.parametrize("verdict", [DENY, ASK])
def test_an_explicit_quality_rule_verdict_keeps_its_value(verdict: str) -> None:
    verdicts = parse(_v2({"exceptions": {"rules": {EMPTY_CATCH: verdict}}}), RULES)
    assert verdicts[EMPTY_CATCH] == verdict
    siblings = {r for r, rule in RULES.items() if rule.pack == "exceptions"} - {EMPTY_CATCH}
    assert {verdicts[r] for r in siblings} == {ALLOW}


def test_a_file_written_before_the_flip_keeps_every_verdict_it_spells() -> None:
    """What install and the setup page wrote until now: every rule spelled out at deny."""
    spelled = {}
    for r, rule in RULES.items():
        spelled.setdefault(rule.pack, {"rules": {}})["rules"][r] = DENY
    assert set(parse(_v2(spelled), RULES).values()) == {DENY}


def test_an_explicit_security_allow_is_not_widened_and_silence_never_allows_security() -> None:
    verdicts = parse(_v2({"bugs": {"verdict": DENY}, "spring": {"rules": {CSRF: ALLOW}}}), RULES)
    assert verdicts[CSRF] == ALLOW
    assert {verdicts[r] for r in SECURITY - {CSRF}} == {DENY}


def test_a_repo_file_still_governs_over_the_user_file(tmp_path, monkeypatch) -> None:
    home = tmp_path / "home"
    (home / ".chock").mkdir(parents=True)
    (home / ".chock" / "security.json").write_text(_v2({"crypto": {"verdict": ALLOW}}), encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    (tmp_path / ".chock").mkdir()
    (tmp_path / ".chock" / "security.json").write_text(_v2({"bugs": {"verdict": DENY}}), encoding="utf-8")
    verdicts = load(tmp_path, RULES)
    assert {verdicts[r] for r, rule in RULES.items() if rule.pack == "crypto"} == {DENY}
    assert {verdicts[r] for r, rule in RULES.items() if rule.pack == "bugs"} == {DENY}


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
    assert verdicts[CSRF] == DENY, "a security rule a version-1 file could not have named enforces"
    assert _others(verdicts, *LEGACY_RULES) == _others(DEFAULTS, *LEGACY_RULES)


def test_version_1_names_only_its_own_pack() -> None:
    doc = json.dumps({"version": 1, "packs": {"templates": {"verdict": ALLOW}}})
    with pytest.raises(SelectionError, match="version-1"):
        parse(doc, RULES)


def test_install_writes_every_rule_at_its_default_under_its_pack() -> None:
    written = json.loads(render(RULES))
    assert written["version"] == 2
    listed = {rule for pack in written["packs"].values() for rule in pack["rules"]}
    assert listed == set(RULES)
    assert parse(render(RULES), RULES) == DEFAULTS
