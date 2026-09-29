"""Every rule refuses its constructs and stays silent on the correct form, case by case."""

from __future__ import annotations

import pytest
from agentic_code_security.cases import REFUSED, SILENT, Case
from agentic_code_security.conftest import ALL_DENY
from agentic_gate.engine import evaluate
from agentic_gate.registry import registry


def findings(case: Case) -> list[str]:
    return [f.rule_id for f in evaluate({case.path: case.text}, ALL_DENY, lambda _p: case.head, human=True)]


def _ids(cases: list[Case]) -> list[str]:
    return [f"{c.rule}::{c.path}" for c in cases]


@pytest.mark.parametrize("case", REFUSED, ids=_ids(REFUSED))
def test_refuses(case: Case) -> None:
    assert case.rule in findings(case)


@pytest.mark.parametrize("case", SILENT, ids=_ids(SILENT))
def test_silent_on_the_correct_form(case: Case) -> None:
    assert findings(case) == []


@pytest.mark.parametrize("rule_id", sorted(registry()))
def test_rule_is_proven_both_ways(rule_id: str) -> None:
    assert any(c.rule == rule_id for c in REFUSED), f"{rule_id} has never been shown refusing"
    assert any(c.rule == rule_id for c in SILENT), f"{rule_id} has never been shown silent on correct code"


def test_a_case_names_a_rule_that_exists() -> None:
    assert {c.rule for c in (*REFUSED, *SILENT)} <= set(registry())


def test_a_refused_case_is_not_owned_by_a_neighbouring_rule() -> None:
    """Each refusing case trips the rule it is about, and nothing outside its own pack."""
    rules = registry()
    for case in REFUSED:
        pack = rules[case.rule].pack
        strays = {r for r in findings(case) if rules[r].pack != pack}
        assert not strays, f"{case.path} also trips {sorted(strays)}"
