"""One gate run parses each written file once, however many rules read it.

Every rule that reads code blanks the file through the lexer, and every flow rule walks its
methods. Parsed per rule, the engine's cost grew with the rule count; parsed once, a new rule
adds only its own scan. These tests count parses, not milliseconds, so they cannot flake.
"""

from __future__ import annotations

from chock_security import flow, source
from chock_security.decision import FileText
from chock_security.engine import evaluate
from java_security.conftest import ALL_DENY, CORPUS

CONTROLLER = next(path for path in sorted(CORPUS.rglob("*.java")) if "Controller" in path.name)


def _fresh() -> FileText:
    source.blank.cache_clear()
    source._code_lines.cache_clear()
    flow._methods.cache_clear()
    return FileText(CONTROLLER.name, CONTROLLER.read_text(encoding="utf-8"))


def test_every_rule_reads_one_lexed_copy_of_the_file() -> None:
    evaluate([_fresh()], ALL_DENY)
    assert source._code_lines.cache_info().misses == 1


def test_every_flow_rule_walks_one_parse_of_the_methods() -> None:
    evaluate([_fresh()], ALL_DENY)
    assert flow._methods.cache_info().misses == 1


def test_a_rule_cannot_change_what_the_next_rule_reads() -> None:
    text = _fresh()
    source.code(text).clear()
    flow.methods(text).clear()
    assert source.code(text) == source.blank(text.text).splitlines()
    assert flow.methods(text)
