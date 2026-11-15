"""A dangerous API named only in a comment, Javadoc, advice string or commented-out config is not a finding."""

from __future__ import annotations

import pytest
from java_security.cases.comments import CASES
from java_security.conftest import GateRun

ALLOWED = 0


def test_the_review_has_forty_six_comment_cases() -> None:
    assert len(CASES) == 46
    assert len({case_id for case_id, _path, _text in CASES}) == 46


def test_the_same_secret_line_uncommented_is_refused(gate: GateRun) -> None:
    """The pair of cm-props-secret: the mask removes the comment, not the rule."""
    code, stderr = gate({"src/main/resources/application.properties": "spring.datasource.password=hunter2\n"})
    assert code != ALLOWED
    assert "hardcoded" in stderr.lower() or "password" in stderr.lower()


@pytest.mark.parametrize(("case_id", "path", "text"), CASES, ids=[c[0] for c in CASES])
def test_a_construct_named_only_where_no_code_runs_is_allowed(
    gate: GateRun, case_id: str, path: str, text: str
) -> None:
    code, stderr = gate({path: text})
    assert code == ALLOWED, f"{case_id} refused:\n{stderr}"
