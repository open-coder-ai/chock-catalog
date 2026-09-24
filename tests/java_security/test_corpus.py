"""Ordinary, correct enterprise code: no rule may fire on any of it, whatever its own cases say."""

from __future__ import annotations

import pytest
from chock_security.decision import FileText
from chock_security.engine import evaluate
from java_security.conftest import ALL_DENY, CORPUS

FILES = sorted(p for p in CORPUS.rglob("*") if p.is_file())


def test_the_corpus_has_not_quietly_emptied() -> None:
    assert len(FILES) >= 15


@pytest.mark.parametrize("path", FILES, ids=[p.relative_to(CORPUS).as_posix() for p in FILES])
def test_no_rule_fires_on_correct_code(path) -> None:
    text = FileText(path.relative_to(CORPUS).as_posix(), path.read_text(encoding="utf-8"))
    findings = [f"{f.rule_id} at line {f.line_no}" for f in evaluate([text], ALL_DENY)]
    assert findings == []
