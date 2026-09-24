"""Every rule, case by case: the construct it names is refused, and correct code is left alone.

Each row in cases/<pack>.py is one test here, named for its rule, so a failure names the rule and
the direction it failed in. `test_rule_is_proven_both_ways` then holds every registered rule to
the bar: a rule with no case that could have failed in each direction cannot merge.
"""

from __future__ import annotations

import pytest
from chock_security.decision import FileText
from chock_security.engine import evaluate
from chock_security.rules import registry
from java_security.cases import CASES, FLOW_CASES
from java_security.conftest import ALL_DENY

RULES = registry()


def _case_id(case: tuple[str, str, str, list[int]]) -> str:
    rule_id, path, _text, lines = case
    return f"{rule_id}::{'refuses' if lines else 'silent'}::{path}"


@pytest.mark.parametrize("case", CASES, ids=[_case_id(c) for c in CASES])
def test_rule_case(case: tuple[str, str, str, list[int]]) -> None:
    rule_id, path, text, expected = case
    assert rule_id in RULES, f"a case names {rule_id!r}, which no pack registers"
    rule = RULES[rule_id]
    file = FileText(path, text)
    reported = [f.line_no for f in rule.scan(file)] if rule.reads(file) else []
    assert reported == expected


@pytest.mark.parametrize("case", FLOW_CASES, ids=[c[0] for c in FLOW_CASES])
def test_flow_case(case: tuple[str, str, str, set[str], set[str]]) -> None:
    _label, path, body, expected, _about = case
    fired = {f.rule_id for f in evaluate([FileText(path, body)], ALL_DENY)}
    assert fired == expected


def _evidence() -> tuple[set[str], set[str]]:
    refusing = {c[0] for c in CASES if c[3]} | {r for c in FLOW_CASES for r in c[3]}
    silent = {c[0] for c in CASES if not c[3]} | {r for c in FLOW_CASES for r in c[4] - c[3]}
    return refusing, silent


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_rule_is_proven_both_ways(rule_id: str) -> None:
    refusing, silent = _evidence()
    assert rule_id in refusing, f"{rule_id} has no case showing it refuses anything"
    assert rule_id in silent, f"{rule_id} has no case showing it stays silent on correct code"


def test_a_refusal_says_what_to_do_without_echoing_the_line() -> None:
    download = (
        "public class C {\n"
        '  @GetMapping("/download")\n'
        "  public byte[] download(@RequestParam String file) throws Exception {\n"
        '    return Files.readAllBytes(Paths.get("/srv/files/" + file));\n'
        "  }\n}\n"
    )
    rendered = evaluate([FileText("C.java", download)], ALL_DENY)[0].render()
    assert "FilenameUtils.getName" in rendered
    assert "/srv/files/" not in rendered
