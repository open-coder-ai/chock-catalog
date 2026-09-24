"""assertFalse(a.equals(b)) passes or fails exactly like assertNotEquals(a, b), but its failure
message only says "expected false" instead of showing the two values that turned out equal."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule
from chock_security.source import code

RULE_ID = "testing-assertfalse-equals"

_CALL = re.compile(r"\bassertFalse\(([^;]*)\)")

_MESSAGE = (
    'assertFalse({argument}) checks an equals() call but reports only "expected false" on '
    "failure. Use assertNotEquals(...) instead: it shows the value both sides turned out to share."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every assertFalse(...) whose single argument is an `.equals(...)` call -- the one form
    assertNotEquals already exists to replace without the ambiguity `==`/`!=` would add here."""
    for line_no, line in enumerate(code(text), 1):
        for match in _CALL.finditer(line):
            argument = match.group(1)
            if ".equals(" in argument:
                yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE.format(argument=argument.strip()))


RULE = Rule(
    id=RULE_ID,
    pack="testing",
    title="assertFalse used for an equals() check",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(call): assertFalse(a.equals(b)) -- use assertNotEquals(a, b)",
    refuses='`assertFalse(actual.equals(expected))`, `assertFalse(user.getName().equals("admin"))`',
    silent_on="`assertNotEquals(expected, actual)`; `assertFalse(list.isEmpty())`; `assertFalse(count == 0)` (an inequality, not an equals() call)",
    references=("https://pmd.github.io/pmd/pmd_rules_java_bestpractices.html#simplifiabletestassertion",),
)
