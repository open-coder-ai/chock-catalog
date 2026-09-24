"""`new BigDecimal(0.1)` does not construct 0.1 -- it constructs whatever binary double 0.1
actually rounds to (0.1000000000000000055511151231257827021181583404541015625), because the
double literal has already lost precision before BigDecimal ever sees it."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule
from chock_security.source import code

RULE_ID = "bugs-bigdecimal-double-constructor"

#: A single floating-point literal argument -- the one shape that is unambiguous without type
#: information: a variable's type isn't visible here, but a literal with a decimal point is
#: unmistakably a double.
_FLOAT_LITERAL_ARG = re.compile(r"new\s+BigDecimal\s*\(\s*(-?[\d_]*\.[\d_]+(?:[eE][+-]?\d+)?[fFdD]?)\s*\)")

_MESSAGE = (
    "new BigDecimal({literal}) does not construct the decimal {literal} -- it constructs "
    "whatever binary double {literal} actually rounds to, with all of that value's imprecision "
    'baked in. Use new BigDecimal("{literal}") (the String constructor) or '
    "BigDecimal.valueOf({literal}) instead, both of which use the value's canonical decimal "
    f"text. 'chock: allow {RULE_ID}' on this line if the imprecision is intentional (e.g. "
    "converting an existing double whose exact bits matter)."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every `new BigDecimal(...)` whose single argument is a floating-point literal."""
    for line_no, line in enumerate(code(text), 1):
        match = _FLOAT_LITERAL_ARG.search(line)
        if not match:
            continue
        yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE.format(literal=match.group(1)))


RULE = Rule(
    id=RULE_ID,
    pack="bugs",
    title="BigDecimal constructed from a double literal",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(construct): new BigDecimal(<floating-point literal>) -- the literal has already "
        'lost precision as a double; use new BigDecimal("literal") or BigDecimal.valueOf(literal)'
    ),
    refuses="new BigDecimal(0.1), new BigDecimal(3.14f) and other single floating-point-literal calls",
    silent_on='new BigDecimal("0.1"); BigDecimal.valueOf(0.1); new BigDecimal(100); new BigDecimal(aDoubleVariable)',
    references=("https://rules.sonarsource.com/java/RSPEC-2111/",),
)
