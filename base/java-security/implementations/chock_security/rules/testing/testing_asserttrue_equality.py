"""assertTrue(a.equals(b)) and assertTrue(a == b) both pass or fail exactly like assertEquals(a, b)
would, but on failure they only say "expected true" -- assertEquals would have shown both values."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule
from chock_security.source import code

RULE_ID = "testing-asserttrue-equality"

_CALL = re.compile(r"\bassertTrue\(([^;]*)\)")

_MESSAGE = (
    'assertTrue({argument}) checks an equality but reports only "expected true" on failure. '
    "Use assertEquals(...) instead: it prints both values when they differ."
)


def _compares_equality(argument: str) -> bool:
    return ".equals(" in argument or "==" in argument


def scan(text: FileText) -> Iterator[Finding]:
    """Every assertTrue(...) whose single argument is itself an equality check -- `.equals(...)`
    or `==` -- the two forms assertEquals already exists to replace."""
    for line_no, line in enumerate(code(text), 1):
        for match in _CALL.finditer(line):
            argument = match.group(1)
            if _compares_equality(argument):
                yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE.format(argument=argument.strip()))


RULE = Rule(
    id=RULE_ID,
    pack="testing",
    title="assertTrue used for an equality check",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(call): assertTrue(a.equals(b)) / assertTrue(a == b) -- use assertEquals(a, b)",
    refuses="`assertTrue(actual.equals(expected))`, `assertTrue(count == 3)`",
    silent_on="`assertEquals(expected, actual)`; `assertTrue(list.isEmpty())`; `assertTrue(user.isActive())` (no equality inside)",
    references=("https://pmd.github.io/pmd/pmd_rules_java_bestpractices.html#simplifiabletestassertion",),
)
