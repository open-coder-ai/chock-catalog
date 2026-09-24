"""The per-line waiver works for every rule, whatever line text the rule itself reports.

A rule that reads through `source.code()` reports its line with comments blanked -- and the waiver
is a comment -- so the engine reads the waiver off the file's own line. This proves it rule by
rule: each rule's first refusing case, with `// chock: allow <rule-id>` added to every line it
reported, draws nothing from that rule.
"""

from __future__ import annotations

import pytest
from chock_security.decision import DENY, FileText
from chock_security.engine import PRAGMA, evaluate
from chock_security.rules import registry
from java_security.cases import CASES, FLOW_CASES

FIRST_REFUSAL = {}
for _rule_id, _path, _text, _lines in CASES:
    if _lines and _rule_id not in FIRST_REFUSAL:
        FIRST_REFUSAL[_rule_id] = (_path, _text, _lines)
#: A flow case names the rules it expects, not their lines: the engine says where they fired.
for _label, _path, _text, _expected, _about in FLOW_CASES:
    for _rule_id in sorted(set(_expected) - set(FIRST_REFUSAL)):
        _found = [f.line_no for f in evaluate([FileText(_path, _text)], {_rule_id: DENY})]
        FIRST_REFUSAL[_rule_id] = (_path, _text, _found)

#: A waiver is a comment in the file's own syntax.
COMMENT = {".xml": "<!-- {} -->", ".html": "<!-- {} -->", ".jsp": "<%-- {} --%>", ".ftl": "<#-- {} -->"}
COMMENT |= dict.fromkeys((".properties", ".yml", ".yaml"), "# {}")


def _waive(path: str, text: str, lines: list[int], rule_id: str) -> str:
    suffix = "." + path.rsplit(".", 1)[-1].lower()
    comment = COMMENT.get(suffix, "// {}").format(f"{PRAGMA}{rule_id}")
    out = text.splitlines()
    for line_no in lines:
        out[line_no - 1] = f"{out[line_no - 1]} {comment}"
    return "\n".join(out) + "\n"


def test_every_rule_has_a_refusal_to_waive() -> None:
    assert set(FIRST_REFUSAL) == set(registry())


@pytest.mark.parametrize("rule_id", sorted(FIRST_REFUSAL))
def test_a_waiver_on_the_reported_line_silences_the_rule(rule_id: str) -> None:
    path, text, lines = FIRST_REFUSAL[rule_id]
    waived = FileText(path, _waive(path, text, lines, rule_id))
    assert [f.line_no for f in evaluate([waived], {rule_id: DENY})] == []
