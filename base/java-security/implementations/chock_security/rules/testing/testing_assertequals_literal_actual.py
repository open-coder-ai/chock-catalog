"""JUnit's assertEquals takes (expected, actual). A literal in the second slot is usually the
expected value written on the wrong side -- harmless until the assertion fails and the message
says the opposite of what actually went wrong."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule
from chock_security.source import code

RULE_ID = "testing-assertequals-literal-actual"

_CALL = re.compile(r"\bassert(?:Not)?Equals\(\s*([^,()]+?)\s*,\s*([^,()]+?)\s*\)")
_NUMBER = re.compile(r"-?\d[\d_]*(?:\.\d+)?[fFdDlL]?")
_STRING = re.compile(r'"[^"]*"')
_CHAR = re.compile(r"'[^']*'")

_MESSAGE = (
    "{actual} looks like the expected value, but it is in the actual-value slot: "
    "assertEquals(expected, actual) takes the expected value first. Swap the two arguments."
)


def _is_literal(arg: str) -> bool:
    return bool(_NUMBER.fullmatch(arg) or _STRING.fullmatch(arg) or _CHAR.fullmatch(arg))


def scan(text: FileText) -> Iterator[Finding]:
    """A two-argument assertEquals/assertNotEquals whose second argument is a bare literal and
    whose first is not -- the shape a literal-versus-expression check can decide without a parser.
    No test-path guard is needed: assertEquals/assertNotEquals are JUnit's own names and do not
    appear outside test code."""
    for line_no, line in enumerate(code(text), 1):
        for match in _CALL.finditer(line):
            expected, actual = match.group(1), match.group(2)
            if _is_literal(actual) and not _is_literal(expected):
                yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE.format(actual=actual))


RULE = Rule(
    id=RULE_ID,
    pack="testing",
    title="assertEquals literal in the actual-value position",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(call): assertEquals(actual, 42) -- assertEquals(expected, actual) takes the expected value first",
    refuses='`assertEquals(result, 42)`, `assertEquals(computedTotal, "5")`, `assertNotEquals(userId, 7)`',
    silent_on="`assertEquals(42, result)`; `assertEquals(expected, actual)` (neither is a literal); `assertEquals(1, 2)` (both are literals); "
    '`assertEquals(total(), "5")` (a nested call, outside this rule\'s plain two-argument shape)',
    references=("https://rules.sonarsource.com/java/RSPEC-3415/",),
)
