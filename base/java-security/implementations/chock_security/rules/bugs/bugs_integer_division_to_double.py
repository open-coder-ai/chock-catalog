"""`double d = 7 / 2;` divides two ints first -- 3, truncated -- and only then widens the result
to a double: 3.0, not 3.5. The division needed a double operand before it ran, not after."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule
from chock_security.source import code

RULE_ID = "bugs-integer-division-to-double"

#: Both operands are plain integer literals -- unambiguous without type information. A literal
#: with a decimal point, or a variable, is a different (and not necessarily buggy) shape.
_INT_DIV_TO_DOUBLE = re.compile(r"\bdouble\s+\w+\s*=\s*(-?\d+)\s*/\s*(-?\d+)\s*;")

_MESSAGE = (
    "{a} / {b} divides as integers first -- {truncated}, truncated toward zero -- and only then "
    "widens the result to double. Make one operand a double before dividing (e.g. {a}.0 / {b}, "
    "or (double) {a} / {b}) to get the fractional result."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every `double x = <int literal> / <int literal>;` -- integer division, widened too late."""
    for line_no, line in enumerate(code(text), 1):
        match = _INT_DIV_TO_DOUBLE.search(line)
        if not match:
            continue
        a, b = int(match.group(1)), int(match.group(2))
        if b == 0:
            continue  # a different bug (division by zero), not this rule's to report
        truncated = int(a / b) if (a < 0) != (b < 0) else a // b
        message = _MESSAGE.format(a=a, b=b, truncated=truncated)
        yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], message)


RULE = Rule(
    id=RULE_ID,
    pack="bugs",
    title="Integer division cast to double after the fact",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(assign): double d = intLiteral / intLiteral; -- divides as integers, truncating, before widening; make an operand a double first",
    refuses="double d = 7 / 2; and other assignments dividing two plain integer literals",
    silent_on="double d = 7.0 / 2; double d = a / b; (variables); int n = 7 / 2;",
    references=("https://rules.sonarsource.com/java/RSPEC-2184/",),
)
