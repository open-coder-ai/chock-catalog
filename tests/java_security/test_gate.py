"""The gate's protocol: its exit code is the verdict the runner carries, whatever `evaluate` says."""

from __future__ import annotations

from chock_security.decision import ALLOW, ASK, DENY
from java_security.conftest import GateRun

UNESCAPED = '<p th:utext="${bio}"></p>\n'
ESCAPED = '<p th:text="${bio}"></p>\n'
XSS = "java-xss-unescaped-template"
REFUSE, PASS = 1, 0


def test_a_violating_write_with_no_selection_is_refused(gate: GateRun) -> None:
    code, err = gate({"p.html": UNESCAPED})
    assert code == REFUSE
    assert XSS in err


def test_correct_markup_passes(gate: GateRun) -> None:
    assert gate({"p.html": ESCAPED})[0] == PASS


def test_nothing_written_is_nothing_to_refuse(gate: GateRun) -> None:
    assert gate({})[0] == PASS


def test_a_rule_set_to_allow_is_honoured(gate: GateRun) -> None:
    assert gate({"p.html": UNESCAPED}, {"version": 2, "packs": {"templates": {"rules": {XSS: ALLOW}}}})[0] == PASS


def test_a_pack_set_to_allow_is_honoured(gate: GateRun) -> None:
    assert gate({"p.html": UNESCAPED}, {"version": 2, "packs": {"templates": {"verdict": ALLOW}}})[0] == PASS


def test_allowing_one_pack_does_not_allow_another(gate: GateRun) -> None:
    assert gate({"p.html": UNESCAPED}, {"version": 2, "packs": {"java": {"verdict": ALLOW}}})[0] == REFUSE


def test_a_version_1_selection_keeps_its_meaning(gate: GateRun) -> None:
    assert gate({"p.html": UNESCAPED}, {"version": 1, "packs": {"java": {"rules": {XSS: ALLOW}}}})[0] == PASS


def test_an_ask_with_nobody_to_ask_refuses(gate: GateRun) -> None:
    code, err = gate({"p.html": UNESCAPED}, {"version": 2, "packs": {"templates": {"rules": {XSS: ASK}}}})
    assert code == REFUSE
    assert "no terminal to ask" in err


def test_an_unreadable_selection_refuses_in_words(gate: GateRun) -> None:
    code, err = gate({"p.html": UNESCAPED}, "{not json")
    assert code == REFUSE
    assert "chock-security:" in err


def test_a_pattern_in_place_of_a_verdict_refuses(gate: GateRun) -> None:
    code, err = gate({"p.html": UNESCAPED}, {"version": 2, "packs": {"templates": {"rules": {XSS: {"pattern": "x"}}}}})
    assert code == REFUSE
    assert "program in disguise" in err


def test_a_rule_the_engine_does_not_have_refuses(gate: GateRun) -> None:
    assert (
        gate({"p.html": ESCAPED}, {"version": 2, "packs": {"templates": {"rules": {"no-such-rule": DENY}}}})[0]
        == REFUSE
    )


def test_a_waiver_names_the_rule_it_waives(gate: GateRun) -> None:
    waived = '<p th:utext="${bio}"></p> <!-- chock: allow java-xss-unescaped-template -->\n'
    other = '<p th:utext="${bio}"></p> <!-- chock: allow some-other-rule -->\n'
    assert gate({"p.html": waived})[0] == PASS
    assert gate({"p.html": other})[0] == REFUSE
